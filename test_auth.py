import tempfile
import unittest
from pathlib import Path

import app as server


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = server.DB_PATH
        server.DB_PATH = Path(self.tmp.name) / "test.sqlite3"
        server.init_db()
        with server.db_connect() as db:
            db.execute("DELETE FROM users")
        server.create_user("testadmin", "correct horse battery staple", "admin")
        server.create_user("testuser", "another secure passphrase", "user")
        server.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = server.app.test_client()

    def tearDown(self):
        server.DB_PATH = self.old_db
        self.tmp.cleanup()

    def csrf(self):
        with self.client.session_transaction() as sess:
            return sess["csrf_token"]

    def login(self, username, password):
        self.client.get("/login")
        return self.client.post("/login", data={
            "username": username, "password": password, "csrf_token": self.csrf()
        }, follow_redirects=False)

    def test_protected_dashboard_redirects_to_login(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_admin_can_login_and_view_dashboard(self):
        self.login("testadmin", "correct horse battery staple")
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Account provisioning", response.data)

    def test_standard_user_cannot_access_shared_admin_workspace(self):
        self.login("testuser", "another secure passphrase")
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/download/anything").status_code, 403)

    def test_invalid_password_is_rejected(self):
        response = self.login("testadmin", "wrong password")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_post_without_csrf_is_rejected(self):
        self.login("testadmin", "correct horse battery staple")
        response = self.client.post("/admin/users", data={
            "username": "newuser", "password": "a sufficiently long passphrase", "role": "user"
        })
        self.assertEqual(response.status_code, 400)

    def test_admin_can_provision_user(self):
        self.login("testadmin", "correct horse battery staple")
        response = self.client.post("/admin/users", data={
            "username": "newuser", "password": "a sufficiently long passphrase",
            "role": "user", "csrf_token": self.csrf()
        })
        self.assertEqual(response.status_code, 302)
        with server.db_connect() as db:
            row = db.execute("SELECT role FROM users WHERE username='newuser'").fetchone()
        self.assertEqual(row["role"], "user")


if __name__ == "__main__":
    unittest.main()
