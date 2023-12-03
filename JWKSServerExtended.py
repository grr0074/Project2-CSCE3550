from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

hostName = "localhost"
serverPort = 8080


db_filename = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_filename)
cursor = conn.cursor()


cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()


def save_private_key_to_db(key, exp):
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp))
    conn.commit()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)


save_private_key_to_db(pem, int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()))
save_private_key_to_db(expired_pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()))


def get_valid_private_key():
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (now,))
    key_data = cursor.fetchone()
    return key_data[0] if key_data else None

def get_all_valid_private_keys():
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (now,))
    return [row[0] for row in cursor.fetchall()]



class MyServer(BaseHTTPRequestHandler):
    

    def do_POST(self):
    

        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            private_key_data = get_valid_private_key()
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                private_key_data = get_expired_private_key()
            if private_key_data:
                encoded_jwt = jwt.encode(token_payload, private_key_data, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(500)
                self.end_headers()
            return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            
            keys_from_db = get_all_valid_private_keys()
            for i, key_data in enumerate(keys_from_db):
                key = serialization.load_pem_private_key(key_data, password=None)
                key_info = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": f"db_key_{i}",
                    "n": int_to_base64(key.public_key().public_numbers.n),
                    "e": int_to_base64(key.public_key().public_numbers.e),
                }
                keys["keys"].append(key_info)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
