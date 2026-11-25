"""Per-user RSA key registration and multi-recipient CFS encryption helpers."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from typing import Mapping
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC_V2 = b"CFS-HYBRID-ENCRYPTED-V2\n"
MAX_PUBLIC_KEY_BYTES = 64 * 1024


def normalize_public_key(pem: bytes) -> tuple[bytes, str]:
    if len(pem) > MAX_PUBLIC_KEY_BYTES:
        raise ValueError("Public key file exceeds 64 KiB.")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
        raise ValueError("Public key must be RSA with at least 3072 bits.")
    normalized = key.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return normalized, hashlib.sha256(der).hexdigest()


def generate_keypair(private_path: str, public_path: str, passphrase: bytes) -> str:
    if len(passphrase) < 12:
        raise ValueError("Private-key passphrase must contain at least 12 bytes/characters.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase))
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(private_path, "xb") as f:
        f.write(private_bytes)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    with open(public_path, "xb") as f:
        f.write(public_bytes)
    return normalize_public_key(public_bytes)[1]


def encrypt_for_recipients(plaintext: bytes, filename: str,
                           recipients: Mapping[str, tuple[str, bytes]]) -> bytes:
    """recipients maps user_id string to (fingerprint, public PEM)."""
    if not recipients:
        raise ValueError("Select at least one recipient with an active public key.")
    envelopes = []
    for user_id, (fingerprint, pem) in sorted(recipients.items()):
        public_key = serialization.load_pem_public_key(pem)
        if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
            raise ValueError(f"Recipient {user_id} has an invalid RSA public key.")
        # Recompute the fingerprint rather than trusting caller-supplied metadata.
        der = public_key.public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
        actual_fingerprint = hashlib.sha256(der).hexdigest()
        if actual_fingerprint != fingerprint:
            raise ValueError(f"Recipient {user_id} public-key fingerprint mismatch.")
        envelopes.append({"user_id": str(user_id), "fingerprint": fingerprint,
                          "wrapped_key": None, "_public_key": public_key})
    aad_recipients = [{"user_id": e["user_id"], "fingerprint": e["fingerprint"]}
                      for e in envelopes]
    aad = json.dumps({"filename": filename, "recipients": aad_recipients},
                     sort_keys=True, separators=(",", ":")).encode("utf-8")
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
    for envelope in envelopes:
        wrapped = envelope.pop("_public_key").encrypt(
            aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                  algorithm=hashes.SHA256(), label=None))
        envelope["wrapped_key"] = base64.b64encode(wrapped).decode("ascii")
    document = {"version": 2, "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
                "filename": filename, "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "recipients": envelopes}
    return MAGIC_V2 + json.dumps(document, separators=(",", ":")).encode("utf-8")



def validate_cfs_v2_envelopes(payload: bytes,
                              expected_recipients: Mapping[str, tuple[str, bytes]]) -> dict:
    """Validate that a CFS v2 file has exactly one valid RSA envelope per expected user.

    This checks envelope structure and binds each envelope to the registered public-key
    fingerprint. It does not decrypt/authenticate the AES-GCM payload; that requires a
    recipient private key and is performed by decrypt_for_user().
    """
    if not isinstance(payload, (bytes, bytearray)) or not payload.startswith(MAGIC_V2):
        raise ValueError("Not a CFS v2 multi-recipient file.")
    try:
        doc = json.loads(bytes(payload)[len(MAGIC_V2):].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed CFS v2 document.") from exc
    if not isinstance(doc, dict) or doc.get("version") != 2:
        raise ValueError("Unsupported encrypted file version.")
    if doc.get("algorithm") != "AES-256-GCM + RSA-OAEP-SHA256":
        raise ValueError("Unsupported CFS v2 encryption algorithm.")
    filename = doc.get("filename")
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise ValueError("Invalid encrypted filename.")
    try:
        nonce = base64.b64decode(doc.get("nonce", ""), validate=True)
        ciphertext = base64.b64decode(doc.get("ciphertext", ""), validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid CFS v2 nonce or ciphertext encoding.") from exc
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("Invalid CFS v2 nonce or ciphertext length.")
    envelopes = doc.get("recipients")
    expected = {str(uid): (fingerprint, pem) for uid, (fingerprint, pem) in expected_recipients.items()}
    # Compatibility with the earlier Node MVC v1.3.2 V2 variant, which keyed
    # wrapped content keys by fingerprint and did not include recipient AAD.
    if not isinstance(envelopes, list) and isinstance(doc.get("wrapped_keys"), dict):
        wrapped_keys = doc["wrapped_keys"]
        expected_fingerprints = {fp for fp, _pem in expected.values()}
        if set(wrapped_keys) != expected_fingerprints:
            raise ValueError("Missing or unexpected recipient key envelope(s).")
        for uid, (fp, pem) in expected.items():
            public_key = serialization.load_pem_public_key(pem)
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
                raise ValueError("Registered recipient key is not RSA-3072 or stronger.")
            der = public_key.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
            if not hmac_compare(hashlib.sha256(der).hexdigest(), fp):
                raise ValueError("Registered public key fingerprint does not match its key material.")
            wrapped = base64.b64decode(wrapped_keys[fp], validate=True)
            if len(wrapped) != (public_key.key_size + 7) // 8:
                raise ValueError(f"Invalid wrapped-key length for recipient {uid}.")
        return doc
    if not isinstance(envelopes, list) or not envelopes:
        raise ValueError("CFS v2 file has no recipient envelopes.")
    if not expected:
        raise ValueError("At least one expected recipient is required.")
    seen_users, seen_fingerprints = set(), set()
    actual = {}
    for envelope in envelopes:
        if not isinstance(envelope, dict):
            raise ValueError("Invalid recipient envelope entry.")
        uid = envelope.get("user_id")
        fingerprint = envelope.get("fingerprint")
        if not isinstance(uid, str) or not uid or not isinstance(fingerprint, str):
            raise ValueError("Recipient envelope is missing its identity or fingerprint.")
        if uid in seen_users or fingerprint in seen_fingerprints:
            raise ValueError("Duplicate recipient identity or key fingerprint in CFS v2 file.")
        seen_users.add(uid)
        seen_fingerprints.add(fingerprint)
        if uid not in expected or not hmac_compare(fingerprint, expected[uid][0]):
            raise ValueError(f"Unexpected or mismatched key envelope for recipient {uid}.")
        try:
            public_key = serialization.load_pem_public_key(expected[uid][1])
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < 3072:
                raise ValueError("Registered recipient key is not RSA-3072 or stronger.")
            public_der = public_key.public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
            registered_fingerprint = hashlib.sha256(public_der).hexdigest()
            if not hmac_compare(registered_fingerprint, expected[uid][0]):
                raise ValueError("Registered public key fingerprint does not match its key material.")
            wrapped = base64.b64decode(envelope.get("wrapped_key", ""), validate=True)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid RSA key envelope for recipient {uid}.") from exc
        if len(wrapped) != (public_key.key_size + 7) // 8:
            raise ValueError(f"Invalid wrapped-key length for recipient {uid}.")
        actual[uid] = fingerprint
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        raise ValueError("Missing recipient key envelope(s): " + ", ".join(missing))
    return doc


def hmac_compare(left: str, right: str) -> bool:
    import hmac
    return hmac.compare_digest(left, right)


def decrypt_for_user(payload: bytes, private_key_pem: bytes, passphrase: bytes,
                     user_id: str | None = None) -> tuple[str, bytes]:
    if not payload.startswith(MAGIC_V2):
        raise ValueError("Not a CFS v2 multi-recipient file.")
    doc = json.loads(payload[len(MAGIC_V2):].decode("utf-8"))
    if doc.get("version") != 2:
        raise ValueError("Unsupported encrypted file version.")
    private_key = serialization.load_pem_private_key(private_key_pem, password=passphrase)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Private key is not RSA.")
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hashlib.sha256(public_der).hexdigest()
    envelopes = doc.get("recipients")
    aad = None
    if isinstance(envelopes, list):
        matches = [r for r in envelopes
                   if r.get("fingerprint") == fingerprint and
                   (user_id is None or str(r.get("user_id")) == str(user_id))]
        if len(matches) != 1:
            raise ValueError("No unique key envelope matches this private key and user.")
        wrapped = base64.b64decode(matches[0]["wrapped_key"], validate=True)
        aad_recipients = [{"user_id": str(r["user_id"]), "fingerprint": r["fingerprint"]}
                          for r in envelopes]
        aad = json.dumps({"filename": doc["filename"], "recipients": aad_recipients},
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        # Backward compatibility for v1.3.2 Node MVC V2 fingerprint map.
        wrapped_value = doc.get("wrapped_keys", {}).get(fingerprint)
        if not wrapped_value:
            raise ValueError("No unique key envelope matches this private key and user.")
        wrapped = base64.b64decode(wrapped_value, validate=True)
    aes_key = private_key.decrypt(
        wrapped, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None))
    try:
        plaintext = AESGCM(aes_key).decrypt(
            base64.b64decode(doc["nonce"], validate=True),
            base64.b64decode(doc["ciphertext"], validate=True), aad)
    except InvalidTag as exc:
        raise ValueError("Ciphertext or recipient metadata authentication failed.") from exc
    return doc["filename"], plaintext
