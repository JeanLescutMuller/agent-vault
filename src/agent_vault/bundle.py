"""The mask-only copy for another machine (the NAS, task D5): what `vault mask` needs there and nothing else, sealed so that
only that machine's av-vault can open it.

  the NAS  vault-admin mask-key        av-vault's own X25519 key pair (HOME/import_x25519.key, 600) → its public half
  the Mac  tools/mask_to_nas.sh        root, in the root-owned code: seal_from(/var/agent-vault, public half) → a file on the
                                       NAS (the key is never in a process of Jean's user); categories may be left out
  the NAS  sudo vault-admin import-mask < bundle    open() with the private half → HOME/key, HOME/fingerprints.json

What travels: agent-vault's 32-byte key and the fingerprints (keyed BLAKE2b of 12-character pieces; never a value), item ids
and names. Sealed: an ephemeral X25519 key, HKDF-SHA256, AES-256-GCM; the file can sit in Jean's home on the NAS (an agent
there reads only ciphertext). Opening needs root (`sudo vault-admin import-mask`), so no agent can swap the fingerprints.
"""
import base64
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"agent-vault mask bundle v1"
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _b64(b):
    return base64.b64encode(b).decode()


def _aes(shared, eph_pub, pub):
    return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + pub, info=INFO).derive(shared))


def key_pair(path):
    """av-vault's import key (created once, 600) → its public half, Base64."""
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, X25519PrivateKey.generate().private_bytes_raw())
        os.close(fd)
    return _b64(X25519PrivateKey.from_private_bytes(open(path, "rb").read()).public_key().public_bytes(**RAW))


def seal(d_payload, pub_b64):
    """{"key": <Base64 of the 32-byte key>, "fingerprints": {...}} → the sealed bundle (JSON text)."""
    pub = base64.b64decode(pub_b64.strip())
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(**RAW)
    nonce = os.urandom(12)
    ct = _aes(eph.exchange(X25519PublicKey.from_public_bytes(pub)), eph_pub, pub).encrypt(nonce, json.dumps(d_payload).encode(), INFO)
    return json.dumps({"v": 1, "eph": _b64(eph_pub), "nonce": _b64(nonce), "ct": _b64(ct)})


def open_bundle(text, key_path):
    """The sealed bundle → (key bytes, fingerprints dict); checked: 32 bytes, {"fp": {hex: [id, category]}, "short": [...]}."""
    d = json.loads(text)
    if d.get("v") != 1:
        raise RuntimeError("not a agent-vault mask bundle (v1)")
    priv = X25519PrivateKey.from_private_bytes(open(key_path, "rb").read())
    pub = priv.public_key().public_bytes(**RAW)
    eph_pub = base64.b64decode(d["eph"])
    try:
        raw = _aes(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, pub).decrypt(base64.b64decode(d["nonce"]), base64.b64decode(d["ct"]), INFO)
    except Exception:
        raise RuntimeError("the bundle does not open with this machine's import key (sealed for another one, or changed)") from None
    p = json.loads(raw)
    key, fp = base64.b64decode(p.get("key", "")), p.get("fingerprints")
    if len(key) != 32 or not isinstance(fp, dict) or not isinstance(fp.get("fp"), dict) or not isinstance(fp.get("short", []), list):
        raise RuntimeError("the bundle holds no key and fingerprints")
    return key, fp


def seal_from(home, pub_b64, leave_out=""):
    """Root's side on the Mac: agent-vault's key and fingerprints from <home>, without the categories named in leave_out
    ("card,iban,ahv": the NAS then cannot mask them, nor guess them offline) → (items kept, the sealed bundle)."""
    s_out = {c for c in leave_out.split(",") if c}
    d = json.load(open(os.path.join(home, "fingerprints.json")))
    d_fp = {h: v for h, v in d.get("fp", {}).items() if v[1] not in s_out}
    s_item = {v[0] for v in d_fp.values()}
    d_keep = {"short": d.get("short", []), "fp": d_fp, "names": {i: n for i, n in d.get("names", {}).items() if i in s_item}}
    key = open(os.path.join(home, "key"), "rb").read()
    return len(s_item), seal({"key": base64.b64encode(key).decode(), "fingerprints": d_keep}, pub_b64)

