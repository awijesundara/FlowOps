"""SSRF-safe outbound HTTP: DNS pinning and address policy."""
from __future__ import annotations

import ipaddress
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request



# --- SSRF-resistant outbound requests -------------------------------------
# Every outbound call this app makes to an admin/user-supplied URL (webhook
# delivery, automation task URLs, the ServiceNow connector) goes through
# safe_urlopen() below rather than urllib.request.urlopen() directly, so a
# maliciously or carelessly configured destination can't be used to probe
# the pod's own loopback interface or other in-cluster services. Behavior
# (not code) is modeled on ServiceOps's own webhook SSRF hardening
# (serviceops_core/dns_pin.py, app.py's _integration_address_allowed()) --
# ServiceOps uses the third-party `requests` library; this reimplements the
# same protections with stdlib urllib/socket/ipaddress only, consistent
# with this app's zero-dependency architecture.

_dns_pin_local = threading.local()

_real_getaddrinfo = socket.getaddrinfo

def _dns_pin_matching_addresses(infos, port, family, type_, proto):
    """The pin is captured via a bare socket.getaddrinfo(host, None), which
    returns one entry per (address, socket-type) combination, all with
    port 0. The real caller (urllib's HTTPConnection) asks for a specific
    family/type/proto and a real port -- this filters the pinned entries to
    what the caller actually asked for and substitutes the real port."""
    port = 0 if port is None else port
    matches = []
    for fam, socktype, sockproto, canonname, sockaddr in infos:
        if family and fam != family: continue
        if type_ and socktype != type_: continue
        if proto and sockproto != proto: continue
        matches.append((fam, socktype, sockproto, canonname, (sockaddr[0], port) + tuple(sockaddr[2:])))
    if not matches:
        # Every pinned address was already validated safe regardless of
        # socket type -- if the filter matches nothing, fall back to the
        # full pinned set with the port substituted rather than silently
        # resolving fresh (which would reopen the TOCTOU window this exists
        # to close).
        matches = [(fam, socktype, sockproto, canonname, (sockaddr[0], port) + tuple(sockaddr[2:])) for fam, socktype, sockproto, canonname, sockaddr in infos]
    return matches

def _dns_pin_patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    pins = getattr(_dns_pin_local, "pins", None)
    if pins and host in pins:
        return _dns_pin_matching_addresses(pins[host], port, family, type, proto)
    return _real_getaddrinfo(host, port, family, type, proto, flags)

if socket.getaddrinfo is not _dns_pin_patched_getaddrinfo:
    socket.getaddrinfo = _dns_pin_patched_getaddrinfo

class pin_resolved_addresses:
    """Context manager: for the calling thread only, socket.getaddrinfo(host,
    ...) returns exactly `infos` instead of performing a fresh DNS lookup --
    closing the gap between validating a hostname's addresses and the HTTP
    client's own, independent resolution of the same hostname a moment
    later (classic DNS-rebinding TOCTOU). Always clears the pin on exit,
    including on exception, so a failed delivery never leaves a stale pin
    behind for a later, unrelated call on the same thread."""

    def __init__(self, host: str, infos):
        self.host = host; self.infos = infos

    def __enter__(self):
        pins = getattr(_dns_pin_local, "pins", None)
        if pins is None:
            pins = {}; _dns_pin_local.pins = pins
        self._previous = pins.get(self.host)
        pins[self.host] = self.infos
        return self

    def __exit__(self, exc_type, exc_value, traceback_obj):
        pins = getattr(_dns_pin_local, "pins", None)
        if pins is None: return False
        if self._previous is None: pins.pop(self.host, None)
        else: pins[self.host] = self._previous
        return False

def _integration_address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private_network: bool) -> bool:
    """True if `address` is safe to connect to. Loopback/link-local/
    multicast/reserved/unspecified addresses are always rejected (they'd
    point the request at the app's own host or network infrastructure
    regardless of who configured the endpoint). Ordinary private-network
    addresses (RFC1918 etc.) are rejected too UNLESS allow_private_network
    is set -- opt-in, for trusted admin-configured integrations expected to
    live on the internal network (e.g. ServiceNow reachable only via a
    cluster-internal hostname), as opposed to arbitrary user-supplied
    targets like webhook URLs."""
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved or address.is_unspecified:
        return False
    if address.is_global: return True
    return allow_private_network and address.is_private

def resolve_endpoint_addresses_safely(endpoint: str, allow_private_network: bool = False):
    """Re-resolves endpoint's hostname and rejects it if any A/AAAA record
    is disallowed -- closes the gap a literal-string check alone can't (a
    public-looking hostname that resolves to a private address). Returns
    (ok, hostname, infos): hostname is None when endpoint was already a
    literal IP (nothing to pin, no resolver step to race); infos is the raw
    socket.getaddrinfo() result, in the shape pin_resolved_addresses()
    expects, for the caller to pin for the connection that follows."""
    hostname = urllib.parse.urlparse(endpoint).hostname
    if not hostname: return False, None, None
    try:
        address = ipaddress.ip_address(hostname)
        return _integration_address_allowed(address, allow_private_network), None, None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return False, hostname, None
    if not infos: return False, hostname, None
    for info in infos:
        raw_address = info[4][0]
        try:
            if not _integration_address_allowed(ipaddress.ip_address(raw_address), allow_private_network):
                return False, hostname, None
        except ValueError:
            return False, hostname, None
    return True, hostname, infos

class _NoAutoRedirectOrErrorOpener:
    """A minimal urllib opener that returns every response as-is -- no
    automatic redirect-following (urllib.request's default HTTPRedirectHandler
    would silently reopen the SSRF hole on a 3xx to an unvalidated
    destination) and no automatic HTTPError-on-non-2xx (so callers can
    inspect response.status themselves, same as they'd check
    response.status_code with requests' allow_redirects=False)."""
    _opener = urllib.request.OpenerDirector()
    for _handler in (urllib.request.ProxyHandler(), urllib.request.HTTPHandler(), urllib.request.HTTPSHandler(), urllib.request.UnknownHandler()):
        _opener.add_handler(_handler)

    @classmethod
    def open(cls, request, timeout):
        return cls._opener.open(request, timeout=timeout)

def safe_urlopen(url: str, data: bytes | None = None, headers: dict[str, str] | None = None, method: str = "GET", timeout: float = 8, allow_private_network: bool = False, max_redirects: int = 3):
    """SSRF-resistant, DNS-rebinding-resistant replacement for
    urllib.request.urlopen(), used for every outbound call this app makes
    to an admin/user-supplied destination. Validates and pins the resolved
    addresses immediately before each connection attempt (including on
    every redirect hop, re-validated and re-pinned, capped at
    max_redirects, rather than trusting urllib to follow a redirect to an
    unvalidated destination). Returns an opened response object (same
    context-manager/.read()/.status interface as urlopen's) on success;
    raises RuntimeError with a caller-safe message on any SSRF rejection or
    network failure."""
    target = url
    for _ in range(max_redirects + 1):
        ok, hostname, infos = resolve_endpoint_addresses_safely(target, allow_private_network)
        if not ok:
            raise RuntimeError("Destination resolves to a non-routable or private address")
        request = urllib.request.Request(target, data=data, method=method, headers=headers or {})
        try:
            if hostname and infos:
                with pin_resolved_addresses(hostname, infos):
                    response = _NoAutoRedirectOrErrorOpener.open(request, timeout)
            else:
                response = _NoAutoRedirectOrErrorOpener.open(request, timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(str(exc)[:300]) from exc
        if response.status in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            response.close()
            if not location:
                raise RuntimeError("Redirect response missing Location header")
            target = urllib.parse.urljoin(target, location)
            continue
        return response
    raise RuntimeError("Too many redirects")
