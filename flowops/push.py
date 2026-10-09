"""Web Push (VAPID) notifications."""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import flowops.net
from flowops.crypto import settings_cipher
from flowops.db import now


# --- Web Push (VAPID, RFC 8030/8292) ------------------------------------
# The Web Push payload-encryption spec (RFC 8291) needs ECDH over P-256 +
# AES-GCM + HKDF -- none of which exist in Python's stdlib, unlike the RSA
# modexp trick that makes the hand-rolled JWT verifier above possible.
# Resolution: ship push with NO encrypted payload -- an empty-body wake-up
# ping (a legitimate, RFC-8030-compliant pattern), and the service worker
# fetches real content from FlowOps's own authenticated API once woken.
# VAPID JWT signing (ES256 / ECDSA P-256) still has no stdlib primitive,
# so it shells out to `openssl`, the exact same external-process pattern
# SettingsCipher already establishes and this codebase already trusts.
def _der_ecdsa_signature_to_raw(der: bytes, size: int = 32) -> bytes:
    """Converts an openssl DER-encoded ECDSA signature (SEQUENCE of two
    INTEGERs) into the fixed-width raw r||s format JOSE's ES256 requires."""
    if der[0] != 0x30: raise ValueError("Not a DER SEQUENCE")
    idx = 2
    if der[idx] != 0x02: raise ValueError("Expected INTEGER (r)")
    rlen = der[idx+1]; r = der[idx+2:idx+2+rlen]; idx = idx+2+rlen
    if der[idx] != 0x02: raise ValueError("Expected INTEGER (s)")
    slen = der[idx+1]; s = der[idx+2:idx+2+slen]
    def fixed(component: bytes) -> bytes:
        component = component.lstrip(b"\x00")
        if len(component) < size: component = b"\x00" * (size - len(component)) + component
        return component[-size:]
    return fixed(r) + fixed(s)

def generate_vapid_keypair() -> tuple[str, str]:
    """Generates a real P-256 EC keypair via openssl. Returns
    (private_key_pem, public_key_b64url) -- the public key is the raw
    65-byte uncompressed point, exactly the shape browsers' PushManager
    expects for applicationServerKey."""
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = os.path.join(tmp, "vapid.pem")
        subprocess.run(["openssl","ecparam","-genkey","-name","prime256v1","-noout","-out",priv_path], check=True, capture_output=True)
        private_key_pem = Path(priv_path).read_text()
        pub_der = subprocess.run(["openssl","ec","-in",priv_path,"-pubout","-conv_form","uncompressed","-outform","DER"], check=True, capture_output=True).stdout
        raw_point = pub_der[-65:]
        if raw_point[0] != 0x04: raise RuntimeError("Unexpected EC public key encoding")
        return private_key_pem, base64.urlsafe_b64encode(raw_point).rstrip(b"=").decode()

def vapid_keypair(db: sqlite3.Connection, instance_id: int) -> tuple[str, str]:
    """Lazily generates and persists one VAPID keypair per instance (the
    private key encrypted at rest with the same SettingsCipher already
    used for admin-managed credentials elsewhere in this file)."""
    row = db.execute("SELECT private_key_pem_encrypted,public_key_b64url FROM vapid_keys WHERE instance_id=?", (instance_id,)).fetchone()
    if row:
        private_key_pem = settings_cipher().decrypt(row["private_key_pem_encrypted"].encode()).decode()
        return private_key_pem, row["public_key_b64url"]
    private_key_pem, public_key_b64url = generate_vapid_keypair()
    encrypted = settings_cipher().encrypt(private_key_pem.encode()).decode()
    db.execute("INSERT INTO vapid_keys(instance_id,private_key_pem_encrypted,public_key_b64url,created_at) VALUES(?,?,?,?)", (instance_id, encrypted, public_key_b64url, now()))
    return private_key_pem, public_key_b64url

def vapid_jwt(private_key_pem: str, audience: str, subject: str = "mailto:admin@flowops.local") -> str:
    """Signs a VAPID authentication JWT (RFC 8292) for a single push
    request -- ES256, 12-hour expiry, audience is the push service's own
    origin (not the subscriber's origin)."""
    header = base64.urlsafe_b64encode(json.dumps({"typ":"JWT","alg":"ES256"}, separators=(",",":")).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"aud":audience,"exp":int(time.time())+43200,"sub":subject}, separators=(",",":")).encode()).rstrip(b"=").decode()
    signing_input = f"{header}.{payload}".encode()
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = os.path.join(tmp, "vapid.pem")
        Path(priv_path).write_text(private_key_pem)
        sig_der = subprocess.run(["openssl","dgst","-sha256","-sign",priv_path], input=signing_input, check=True, capture_output=True).stdout
    raw_sig = _der_ecdsa_signature_to_raw(sig_der)
    signature = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
    return f"{header}.{payload}.{signature}"

def send_web_push(db: sqlite3.Connection, subscription: dict[str, Any], instance_id: int) -> None:
    """Sends a no-payload wake-up ping (RFC 8030) to one push subscription.
    Never raises -- a push-service outage or an expired subscription must
    not block whatever real action (task assignment, etc.) triggered it;
    a 404/410 from the push service means the subscription is gone and is
    cleaned up here instead of retried forever."""
    try:
        private_key_pem, public_key_b64url = vapid_keypair(db, instance_id)
        endpoint = subscription["endpoint"]
        audience = f"{urllib.parse.urlsplit(endpoint).scheme}://{urllib.parse.urlsplit(endpoint).netloc}"
        token = vapid_jwt(private_key_pem, audience)
        headers = {"TTL": "2419200", "Authorization": f"vapid t={token}, k={public_key_b64url}", "Content-Length": "0"}
        try:
            response = flowops.net.safe_urlopen(endpoint, data=b"", headers=headers, method="POST", timeout=8, allow_private_network=False)
            with response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        if status in (404, 410):
            db.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint,)); db.commit()
    except Exception as exc:
        print(json.dumps({"ts":now(),"level":"warn","message":f"web push delivery failed: {exc}"}), flush=True)

def notify_task_assignment(db: sqlite3.Connection, instance_id: int, user_id: int | None) -> None:
    if not user_id: return
    for row in db.execute("SELECT * FROM push_subscriptions WHERE user_id=? AND instance_id=?", (user_id, instance_id)).fetchall():
        send_web_push(db, dict(row), instance_id)
