import unittest
import http.server
import threading
import requests
import time
import json
from JWKSServerExtended import MyServer

class MyServerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("localhost", 8080), MyServer)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_auth_endpoint_valid_key(self):
        url = "http://localhost:8080/auth"
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        jwt_data = json.loads(response.text)
        valid_key_exists = validate_key(jwt_data['key'])
        self.assertTrue(valid_key_exists, "Valid key not found in JWT data")

    def test_auth_endpoint_expired_key(self):
        url = "http://localhost:8080/auth?expired=true"
        response = requests.get(url)
        self.assertEqual(response.status_code, 200)
        jwt_data = json.loads(response.text)
        self.assertIn('key', jwt_data, "Expired key not found in JWT data")
        expected_exp = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        self.assertTrue(jwt_data['exp'] < int(expected_exp.timestamp()), "JWT has not expired")

if __name__ == '__main__':
    unittest.main()
