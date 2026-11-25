"""v1.3.0 ownership, ACL, CSRF and audit integration tests."""
import json
import tempfile
import unittest
from pathlib import Path
from io import BytesIO

import app as server
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class SharingIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.old_db, self.old_storage, self.old_audit = server.DB_PATH, server.STORAGE, server.AUDIT_PATH
        server.DB_PATH = root / "test.sqlite3"
        server.STORAGE = root / "storage"
        server.STORAGE.mkdir()
        server.AUDIT_PATH = root / "audit.jsonl"
        server.init_db()
        with server.db_connect() as db:
            db.execute("DELETE FROM file_permissions")
            db.execute("DELETE FROM files")
            db.execute("DELETE FROM user_keys")
            db.execute("DELETE FROM users")
        server.create_user("owner1", "owner password phrase 123", "user")
        server.create_user("reader1", "reader password phrase 123", "user")
        server.app.config.update(TESTING=True, SECRET_KEY="sharing-test-secret")
        self.client = server.app.test_client()

    def tearDown(self):
        server.DB_PATH, server.STORAGE, server.AUDIT_PATH = self.old_db, self.old_storage, self.old_audit
        self.tmp.cleanup()

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def login(self, username, password):
        self.client.get("/login")
        return self.client.post("/login", data={"username": username, "password": password, "csrf_token": self.csrf()})

    def test_owner_upload_grant_viewer_cannot_download_then_revoke(self):
        self.login("owner1", "owner password phrase 123")
        token = self.csrf()
        up = self.client.post("/api/files", data={"file": (BytesIO(b"private document"), "report.txt")}, headers={"X-CSRF-Token": token}, content_type="multipart/form-data")
        self.assertEqual(up.status_code, 201, up.data)
        file_id = up.get_json()["id"]
        with server.db_connect() as db:
            reader = db.execute("SELECT id FROM users WHERE username='reader1'").fetchone()["id"]
        grant = self.client.post(f"/api/files/{file_id}/permissions", json={"user_id": reader, "role": "viewer"}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(grant.status_code, 201, grant.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("reader1", "reader password phrase 123")
        self.assertEqual(self.client.get("/api/files").status_code, 200)
        self.assertEqual(self.client.get(f"/api/files/{file_id}/download").status_code, 404)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("owner1", "owner password phrase 123")
        grant = self.client.post(f"/api/files/{file_id}/permissions", json={"user_id": reader, "role": "download"}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(grant.status_code, 201, grant.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("reader1", "reader password phrase 123")
        self.assertEqual(self.client.get(f"/api/files/{file_id}/download").status_code, 200)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("owner1", "owner password phrase 123")
        revoke = self.client.delete(f"/api/files/{file_id}/permissions/{reader}", headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(revoke.status_code, 200, revoke.data)
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("reader1", "reader password phrase 123")
        self.assertEqual(self.client.get(f"/api/files/{file_id}/download").status_code, 404)
        events = [json.loads(x) for x in server.AUDIT_PATH.read_text().splitlines()]
        actions = [x["action"] for x in events]
        self.assertIn("file.upload", actions)
        self.assertIn("permission.grant", actions)
        self.assertIn("permission.revoke", actions)
        self.assertIn("file.download", actions)

    def test_download_rejects_storage_tampering(self):
        self.login("owner1", "owner password phrase 123")
        up = self.client.post("/api/files", data={"file": (BytesIO(b"original"), "integrity.txt")}, headers={"X-CSRF-Token": self.csrf()}, content_type="multipart/form-data")
        file_id = up.get_json()["id"]
        with server.db_connect() as db:
            row = db.execute("SELECT storage_name FROM files WHERE id=?", (file_id,)).fetchone()
        (server.STORAGE / row["storage_name"]).write_bytes(b"tampered")
        response = self.client.get(f"/api/files/{file_id}/download")
        self.assertEqual(response.status_code, 409)
        events = [json.loads(x) for x in server.AUDIT_PATH.read_text().splitlines()]
        self.assertTrue(any(e["details"].get("reason") == "storage_integrity_check" for e in events))

    def test_non_owner_cannot_grant_permission(self):
        self.login("owner1", "owner password phrase 123")
        up = self.client.post("/api/files", data={"file": (BytesIO(b"x"), "x.txt")}, headers={"X-CSRF-Token": self.csrf()}, content_type="multipart/form-data")
        file_id = up.get_json()["id"]
        self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.login("reader1", "reader password phrase 123")
        with server.db_connect() as db:
            uid = db.execute("SELECT id FROM users WHERE username='owner1'").fetchone()["id"]
        response = self.client.post(f"/api/files/{file_id}/permissions", json={"user_id": uid, "role": "download"}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(response.status_code, 403)


    def register_rsa_key(self, username, password):
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.login(username, password)
        response = self.client.post("/keys/me", data={"csrf_token": self.csrf(), "public_key": (BytesIO(public_pem), "public.pem")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 302)
        self.client.post("/logout", data={"csrf_token": self.csrf()})

    def test_encrypted_grant_requires_existing_matching_envelope(self):
        self.register_rsa_key("owner1", "owner password phrase 123")
        self.register_rsa_key("reader1", "reader password phrase 123")
        self.login("owner1", "owner password phrase 123")
        response = self.client.post("/api/files/encrypted", data={
            "csrf_token": self.csrf(),
            "file": (BytesIO(b"top secret"), "secret.txt"),
        }, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 201, response.data)
        file_id = response.get_json()["id"]
        with server.db_connect() as db:
            reader_id = db.execute("SELECT id FROM users WHERE username='reader1'").fetchone()["id"]
        denied = self.client.post(f"/api/files/{file_id}/permissions", json={"user_id": reader_id, "role": "download"}, headers={"X-CSRF-Token": self.csrf()})
        self.assertEqual(denied.status_code, 409, denied.data)
        self.assertIn(b"no envelope", denied.data.lower())

    def test_json_mutations_require_csrf_header(self):
        self.login("owner1", "owner password phrase 123")
        response = self.client.post("/api/files/1/permissions", json={"user_id": 2, "role": "download"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
