import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from key_management import normalize_public_key, encrypt_for_recipients, decrypt_for_user, validate_cfs_v2_envelopes, MAGIC_V2


class MultiRecipientCryptoTests(unittest.TestCase):
    def setUp(self):
        self.keys = {}
        for user_id in ("10", "20"):
            private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            private_pem = private.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"correct horse battery"))
            public_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo)
            _, fingerprint = normalize_public_key(public_pem)
            self.keys[user_id] = (fingerprint, public_pem, private_pem)

    def test_two_recipients_can_decrypt_same_payload(self):
        recipients = {uid: (item[0], item[1]) for uid, item in self.keys.items()}
        payload = encrypt_for_recipients(b"confidential payload", "secret.txt", recipients)
        for uid, item in self.keys.items():
            filename, plaintext = decrypt_for_user(payload, item[2], b"correct horse battery", uid)
            self.assertEqual(filename, "secret.txt")
            self.assertEqual(plaintext, b"confidential payload")

    def test_non_recipient_cannot_decrypt(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        private_pem = private.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"correct horse battery"))
        payload = encrypt_for_recipients(b"secret", "x.txt", {"10": (self.keys["10"][0], self.keys["10"][1])})
        with self.assertRaises(ValueError):
            decrypt_for_user(payload, private_pem, b"correct horse battery")

    def test_recipient_metadata_is_authenticated(self):
        import json
        from key_management import MAGIC_V2
        recipients = {"10": (self.keys["10"][0], self.keys["10"][1])}
        payload = encrypt_for_recipients(b"secret", "x.txt", recipients)
        doc = json.loads(payload[len(MAGIC_V2):].decode("utf-8"))
        doc["recipients"][0]["user_id"] = "999"
        tampered = MAGIC_V2 + json.dumps(doc, separators=(",", ":")).encode("utf-8")
        with self.assertRaises(ValueError):
            decrypt_for_user(tampered, self.keys["10"][2], b"correct horse battery", "999")

    def test_validator_accepts_exact_matching_envelope_set(self):
        recipients = {uid: (item[0], item[1]) for uid, item in self.keys.items()}
        payload = encrypt_for_recipients(b"payload", "x.txt", recipients)
        doc = validate_cfs_v2_envelopes(payload, recipients)
        self.assertEqual({r["user_id"] for r in doc["recipients"]}, set(recipients))

    def test_validator_rejects_missing_recipient_envelope(self):
        recipients = {uid: (item[0], item[1]) for uid, item in self.keys.items()}
        payload = encrypt_for_recipients(b"payload", "x.txt", {"10": recipients["10"]})
        with self.assertRaisesRegex(ValueError, "Missing recipient"):
            validate_cfs_v2_envelopes(payload, recipients)

    def test_validator_rejects_mismatched_fingerprint(self):
        recipients = {"10": (self.keys["10"][0], self.keys["10"][1])}
        payload = encrypt_for_recipients(b"payload", "x.txt", recipients)
        with self.assertRaisesRegex(ValueError, "mismatched"):
            validate_cfs_v2_envelopes(payload, {"10": ("0" * 64, self.keys["10"][1])})

    def test_validator_rejects_duplicate_recipient(self):
        import json
        recipients = {"10": (self.keys["10"][0], self.keys["10"][1])}
        payload = encrypt_for_recipients(b"payload", "x.txt", recipients)
        doc = json.loads(payload[len(MAGIC_V2):].decode("utf-8"))
        doc["recipients"].append(dict(doc["recipients"][0]))
        tampered = MAGIC_V2 + json.dumps(doc).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_cfs_v2_envelopes(tampered, recipients)

    def test_validator_rejects_invalid_wrapped_key_length(self):
        import json
        import base64
        recipients = {"10": (self.keys["10"][0], self.keys["10"][1])}
        payload = encrypt_for_recipients(b"payload", "x.txt", recipients)
        doc = json.loads(payload[len(MAGIC_V2):].decode("utf-8"))
        doc["recipients"][0]["wrapped_key"] = base64.b64encode(b"short").decode("ascii")
        tampered = MAGIC_V2 + json.dumps(doc).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "wrapped-key length"):
            validate_cfs_v2_envelopes(tampered, recipients)

    def test_rejects_small_or_non_rsa_keys(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = small.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(ValueError):
            normalize_public_key(pem)


if __name__ == "__main__":
    unittest.main()
