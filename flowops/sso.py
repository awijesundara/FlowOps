"""Cloudflare Access and OIDC token verification."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import flowops.config
import flowops.net


_cf_access_jwks_cache: dict[str, Any] = {"fetched_at": 0.0, "keys": {}}

_cf_access_jwks_lock = threading.Lock()

def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)

def _cf_access_jwks() -> dict[str, tuple[int, int]]:
    """Fetches (and caches for 1 hour) Cloudflare Access's RS256 public keys
    for this team, keyed by kid, as (n, e) integer tuples -- no external
    crypto dependency, matching this app's stdlib-only design."""
    with _cf_access_jwks_lock:
        if time.monotonic() - _cf_access_jwks_cache["fetched_at"] < 3600 and _cf_access_jwks_cache["keys"]:
            return _cf_access_jwks_cache["keys"]
        url = f"https://{flowops.config.CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs"
        with urllib.request.urlopen(url, timeout=5) as response:
            document = json.loads(response.read())
        keys = {}
        for jwk in document.get("keys", []):
            if jwk.get("kty") != "RSA":
                continue
            n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
            keys[jwk["kid"]] = (n, e)
        _cf_access_jwks_cache["keys"] = keys
        _cf_access_jwks_cache["fetched_at"] = time.monotonic()
        return keys

def _rsa_pkcs1_sha256_verify(message: bytes, signature: bytes, n: int, e: int) -> bool:
    """RS256 (RSASSA-PKCS1-v1_5 with SHA-256) verification using only
    built-in big-integer exponentiation -- no cryptography library."""
    digest_info_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    digest = hashlib.sha256(message).digest()
    key_bytes = (n.bit_length() + 7) // 8
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n:
        return False
    decrypted = pow(sig_int, e, n).to_bytes(key_bytes, "big")
    padded_len = key_bytes - 3 - len(digest_info_prefix) - len(digest)
    if padded_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * padded_len + b"\x00" + digest_info_prefix + digest
    return hmac.compare_digest(decrypted, expected)

def verify_cf_access_jwt(token: str) -> dict[str, Any] | None:
    """Verifies a Cloudflare Access-issued JWT (from the
    Cf-Access-Jwt-Assertion header) against this team's public keys,
    checking signature, audience, and expiry. Returns the claims on
    success, None on any failure -- never raises, since a missing/invalid
    header must fall back to normal login, not error out."""
    if not flowops.config.CF_ACCESS_TEAM_DOMAIN or not flowops.config.CF_ACCESS_AUD:
        return None
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
        if header.get("alg") != "RS256":
            return None
        keys = _cf_access_jwks()
        key = keys.get(header.get("kid"))
        if not key:
            return None
        if not _rsa_pkcs1_sha256_verify(f"{header_b64}.{payload_b64}".encode(), signature, *key):
            return None
        if flowops.config.CF_ACCESS_AUD not in (claims.get("aud") or []):
            return None
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
        return claims
    except Exception:
        return None

_oidc_discovery_cache: dict[str, dict[str, Any]] = {}

_oidc_discovery_lock = threading.Lock()

_oidc_jwks_cache: dict[str, dict[str, Any]] = {}

_oidc_jwks_lock = threading.Lock()

def oidc_discovery_document(issuer: str) -> dict[str, Any]:
    """Fetches (and caches for 1 hour) an OIDC provider's discovery
    document. Keyed by issuer so multiple providers can be swapped in
    without stale cross-contamination."""
    with _oidc_discovery_lock:
        entry = _oidc_discovery_cache.get(issuer)
        if entry and time.monotonic() - entry["fetched_at"] < 3600:
            return entry["document"]
        url = issuer.rstrip("/") + "/.well-known/openid-configuration"
        with flowops.net.safe_urlopen(url, timeout=5, allow_private_network=True) as response:
            document = json.loads(response.read())
        _oidc_discovery_cache[issuer] = {"document": document, "fetched_at": time.monotonic()}
        return document

def _fetch_jwks(jwks_url: str) -> dict[str, tuple[int, int]]:
    """Generalized version of _cf_access_jwks() -- fetches (and caches for
    1 hour) any provider's RS256 public keys by JWKS URL, no external
    crypto dependency."""
    with _oidc_jwks_lock:
        entry = _oidc_jwks_cache.get(jwks_url)
        if entry and time.monotonic() - entry["fetched_at"] < 3600:
            return entry["keys"]
        with flowops.net.safe_urlopen(jwks_url, timeout=5, allow_private_network=True) as response:
            document = json.loads(response.read())
        keys = {}
        for jwk in document.get("keys", []):
            if jwk.get("kty") != "RSA":
                continue
            n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
            e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
            keys[jwk["kid"]] = (n, e)
        _oidc_jwks_cache[jwks_url] = {"keys": keys, "fetched_at": time.monotonic()}
        return keys

def verify_oidc_id_token(jwks_url: str, issuer: str, audience: str, token: str) -> dict[str, Any] | None:
    """Generalized version of verify_cf_access_jwt() -- verifies any
    OIDC provider's RS256 id_token: signature (via _fetch_jwks), issuer,
    audience, and expiry. Returns claims on success, None on any failure."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
        if header.get("alg") != "RS256":
            return None
        keys = _fetch_jwks(jwks_url)
        key = keys.get(header.get("kid"))
        if not key:
            return None
        if not _rsa_pkcs1_sha256_verify(f"{header_b64}.{payload_b64}".encode(), signature, *key):
            return None
        if claims.get("iss") != issuer:
            return None
        aud = claims.get("aud")
        if audience != aud and audience not in (aud if isinstance(aud, list) else []):
            return None
        if int(claims.get("exp", 0)) < int(time.time()):
            return None
        return claims
    except Exception:
        return None
