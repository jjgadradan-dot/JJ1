import os
import tempfile
import unittest

TMP = tempfile.mkdtemp(prefix="rvg-node-")
os.environ["DATA_DIR"] = TMP
os.environ["NODE_API_TOKEN"] = "test-node-token"
os.environ["ADMIN_PASSWORD"] = "secret"
os.environ["SECRET_KEY"] = "unit-test-secret"

from fastapi.testclient import TestClient

import main


class NodeApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(main.app)
        cls.auth = {"Authorization": "Bearer test-node-token"}

    def test_root_is_node(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["role"], "hybrid")
        self.assertIn("master", r.json()["roles"])
        self.assertIn("node", r.json()["roles"])
        self.assertEqual(r.json()["version"], main.VERSION)

    def test_node_api_rejects_missing_token(self):
        r = self.client.get("/api/node/v1/overview")
        self.assertEqual(r.status_code, 401)

    def test_node_api_overview_and_create(self):
        r = self.client.get("/api/node/v1/overview", headers=self.auth)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["role"], "node")
        created = self.client.post("/api/node/v1/configs", headers=self.auth, json={
            "label": "from-master", "limit_bytes": 0, "protocol": "vless-ws",
        })
        self.assertEqual(created.status_code, 200)
        uid = created.json()["uuid"]
        listed = self.client.get("/api/node/v1/configs", headers=self.auth)
        self.assertTrue(any(c["uuid"] == uid for c in listed.json()["configs"]))
        patched = self.client.patch(f"/api/node/v1/configs/{uid}", headers=self.auth, json={"active": False})
        self.assertEqual(patched.status_code, 200)
        deleted = self.client.delete(f"/api/node/v1/configs/{uid}", headers=self.auth)
        self.assertEqual(deleted.status_code, 200)

    def test_dashboard_token_is_masked(self):
        login = self.client.post("/api/login", json={"password": "secret"})
        self.assertEqual(login.status_code, 200)
        r = self.client.get("/api/master")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.json()["api"]["token"])
        self.assertTrue(r.json()["api"]["has_token"])
        self.assertEqual(r.json()["api"]["role"], "node")


if __name__ == "__main__":
    unittest.main()
