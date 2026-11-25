#!/usr/bin/env python3
"""
Hybrid public-key file encryption for secure file transfer.

The recipient generates an RSA key pair and shares ONLY the public key.
The sender encrypts the file with a fresh AES-256-GCM key, then wraps that
AES key with the recipient's RSA-3072 public key using OAEP-SHA256.
The recipient uses their private key to unwrap the AES key and decrypt.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
from key_management import generate_keypair, decrypt_for_user

MAGIC = b"CFS-HYBRID-ENCRYPTED-V1\n"
MAGIC_V2 = b"CFS-HYBRID-ENCRYPTED-V2\n"

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)

def generate_keys(private_path: Path, public_path: Path) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    public_path.write_bytes(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Created private key: {private_path}")
    print(f"Created public key:  {public_path}")
    print("Keep the private key secret. Share only the public key.")

def encrypt_file(source: Path, recipient_public_path: Path, destination: Path) -> None:
    public_key = serialization.load_pem_public_key(recipient_public_path.read_bytes())
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Recipient key must be an RSA public key.")
    plaintext = source.read_bytes()
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    envelope = {
        "version": 1,
        "algorithm": "AES-256-GCM + RSA-OAEP-SHA256",
        "filename": source.name,
        "wrapped_key": b64e(wrapped_key),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }
    destination.write_bytes(MAGIC + json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
    print(f"Encrypted {source} -> {destination}")

def decrypt_file(source: Path, recipient_private_path: Path, destination: Path) -> None:
    private_key = serialization.load_pem_private_key(recipient_private_path.read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Recipient key must be an RSA private key.")
    raw = source.read_bytes()
    if raw.startswith(MAGIC_V2):
        magic, expected_version = MAGIC_V2, 2
    elif raw.startswith(MAGIC):
        magic, expected_version = MAGIC, 1
    else:
        raise ValueError("Unrecognized encrypted file format.")
    envelope = json.loads(raw[len(magic):].decode("utf-8"))
    if envelope.get("version") != expected_version or envelope.get("algorithm") != "AES-256-GCM + RSA-OAEP-SHA256":
        raise ValueError("Unsupported encrypted file version or algorithm.")
    if expected_version == 1:
        wrapped_key = envelope["wrapped_key"]
    else:
        public_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_fingerprint = hashlib.sha256(public_der).hexdigest()
        wrapped_key = envelope.get("wrapped_keys", {}).get(key_fingerprint)
        if not wrapped_key:
            raise ValueError("This file has no RSA envelope for the supplied private key.")
    aes_key = private_key.decrypt(
        b64d(wrapped_key),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )
    plaintext = AESGCM(aes_key).decrypt(b64d(envelope["nonce"]), b64d(envelope["ciphertext"]), None)
    destination.write_bytes(plaintext)
    print(f"Decrypted file -> {destination}")

def main():
    parser = argparse.ArgumentParser(description="Cloud File Server secure transfer utility")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keygen", help="Generate a recipient RSA key pair")
    keys.add_argument("--private", default="recipient_private.pem")
    keys.add_argument("--public", default="recipient_public.pem")
    enc = sub.add_parser("encrypt", help="Encrypt a file for the recipient public key")
    enc.add_argument("input")
    enc.add_argument("--public", required=True)
    enc.add_argument("--output", required=True)
    dec = sub.add_parser("decrypt", help="Decrypt a legacy v1 file using an unencrypted private key")
    dec.add_argument("input")
    dec.add_argument("--private", required=True)
    dec.add_argument("--output", required=True)
    secure_keys = sub.add_parser("keygen-secure", help="Generate a passphrase-encrypted per-user RSA key pair")
    secure_keys.add_argument("--private", default="user_private.pem")
    secure_keys.add_argument("--public", default="user_public.pem")
    dec2 = sub.add_parser("decrypt-v2", help="Decrypt a v2 multi-recipient file with your encrypted private key")
    dec2.add_argument("input")
    dec2.add_argument("--private", required=True)
    dec2.add_argument("--output", required=True)
    dec2.add_argument("--user-id", help="Account ID assigned by this server")
    args = parser.parse_args()
    if args.command == "keygen":
        generate_keys(Path(args.private), Path(args.public))
    elif args.command == "keygen-secure":
        password = getpass("Private-key passphrase (12+ characters): ").encode("utf-8")
        confirm = getpass("Confirm passphrase: ").encode("utf-8")
        if password != confirm:
            raise SystemExit("Passphrases do not match.")
        fingerprint = generate_keypair(args.private, args.public, password)
        print(f"Created encrypted private key: {args.private}")
        print(f"Created public key: {args.public}")
        print(f"SHA-256 fingerprint: {fingerprint}")
        print("Keep the private key and passphrase under your control. Upload only the public key.")
    elif args.command == "encrypt":
        encrypt_file(Path(args.input), Path(args.public), Path(args.output))
    elif args.command == "decrypt-v2":
        password = getpass("Private-key passphrase: ").encode("utf-8")
        filename, plaintext = decrypt_for_user(Path(args.input).read_bytes(), Path(args.private).read_bytes(), password, args.user_id)
        Path(args.output).write_bytes(plaintext)
        print(f"Decrypted {filename} -> {args.output}")
    else:
        decrypt_file(Path(args.input), Path(args.private), Path(args.output))

if __name__ == "__main__":
    main()
