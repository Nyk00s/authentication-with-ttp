import os
import sys
import json
import socket
import base64
import logging
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from generator import get_keys, get_public_key_pem, get_cert_pem, get_public_key_from_pem, decrypt_with_private_key, \
    get_cert


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
logging.basicConfig(filename='ttp.log', level=logging.DEBUG, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)


HOST, PORT = '0.0.0.0', 9000
TTP_PRIVATE_KEY, TTP_PUBLIC_KEY = get_keys()
TTP_CERT = get_cert(TTP_PRIVATE_KEY, TTP_PUBLIC_KEY, 'TTP_CA')
REGISTERED_ENTITIES = {}


def handle_register(data: dict) -> dict:
    decrypted_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data['ID'])).decode()
    if decrypted_id in REGISTERED_ENTITIES:
        return {
            'status': 'error',
            'message': 'id exists'
        }
    else:
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.COMMON_NAME, decrypted_id),
            ]
        )
        cert = (x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(TTP_CERT.subject)
                .public_key(get_public_key_from_pem(data['public_key'].encode()))
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(TTP_PRIVATE_KEY, hashes.SHA256())
                )
        cert_pem = get_cert_pem(cert)
        REGISTERED_ENTITIES[decrypted_id] = {
            "password": data['password'],
            "certificate": cert_pem,
            "public_key": data['public_key']
        }
        return {
            'status': 'ok',
            'cert': cert_pem
        }


def handle_login(data: dict) -> dict:
    decrypted_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data['ID'])).decode()
    if decrypted_id in REGISTERED_ENTITIES and \
            REGISTERED_ENTITIES[decrypted_id]['password'] == data['password']:
        return {
            'status': 'ok',
            'cert': REGISTERED_ENTITIES[decrypted_id]['certificate']
        }
    else:
        return {
            'status': 'error',
            'message': "id doesn't exist or wrong password"
        }


def handle_authenticate_request(data: dict) -> dict:
    server_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data['SERVER_ID'])).decode()
    if server_id not in REGISTERED_ENTITIES:
        return {
            'status': 'error',
            'message': "server not registered"
        }
    else:
        return {
            'status': 'ok',
            'message': 'server has been authenticated'
        }


def handle_request(data: dict) -> dict:
    action = data.get('action')

    if action == 'get_ttp_public_key':
        return {
            "status": "ok",
            "ttp_public_key": get_public_key_pem(TTP_PUBLIC_KEY),
            "ttp_cert": get_cert_pem(TTP_CERT)
        }
    elif action == 'register':
        return handle_register(data)
    elif action == 'login':
        return handle_login(data)
    elif action == 'authenticate_request':
        return handle_authenticate_request(data)
    else:
        logging.warning(f'Got unknown request: {action}')
        return {
            "status": "error",
            "message": f"Unknown request: {action}",
            "echo": data
        }


def handle_client(conn: socket.socket, addr):
    try:
        bytes_data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            bytes_data += chunk
            if bytes_data.endswith(b'\n'):
                break

        json_data = json.loads(bytes_data.decode().strip())
        logging.debug(f"request ({addr}): " + str(json_data))
        response = handle_request(json_data)
        logging.debug(f"response ({addr}): " + str(response))
        conn.sendall((json.dumps(response) + '\n').encode())
    except Exception:
        logging.exception(f'Error: {addr}')
    finally:
        conn.close()


def main():
    logging.info("Start TTP")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
