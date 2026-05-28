import os
import sys
import json
import time
import socket
import base64
import logging
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from generator import get_keys, get_public_key_pem, get_cert_pem, get_public_key_from_pem, decrypt_with_private_key, \
    get_cert, encrypt_with_public_key


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
            "public_key": data['public_key'],
            "HOST": data['HOST'],
            "PORT": data['PORT']
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


def send_request(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect((data['HOST'], int(data['PORT'])))
            sock.sendall((json.dumps(data) + '\n').encode())
            logging.info(f"Request \'{data.get('action')}\' has been sent to ({data['HOST']})")
            received_bytes = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received_bytes += chunk
                if received_bytes.endswith(b'\n'):
                    break

            if not received_bytes:
                raise ConnectionError(f"Empty response from {data['HOST']}")

            string_data = received_bytes.decode().strip()
            logging.info(f'Data from {data["HOST"]} received')
            logging.debug(f'Data received from {data["HOST"]}: {string_data}')
            return json.loads(string_data)
    except (socket.timeout, socket.error) as e:
        logging.error(f'Network error while communicating with {data["HOST"]}: {e}')
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except json.JSONDecodeError:
        logging.error(f'Invalid JSON received from {data["HOST"]}: {received_bytes}')
        return {'status': 'error', 'message': 'Invalid JSON response'}
    except Exception as e:
        logging.exception(f'Unexpected error while communicating with {data["HOST"]}')
        return {'status': 'error', 'message': str(e)}


def authenticate_user(user_id, server_id):
    time.sleep(1)
    data_from_user = send_request(
        {
            "action": "authenticate_user",
            "HOST": REGISTERED_ENTITIES[user_id]["HOST"],
            "PORT": REGISTERED_ENTITIES[user_id]["PORT"]
        }
    )
    user_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data_from_user['USER_ID'])).decode()
    if user_id not in REGISTERED_ENTITIES:
        return {
            'status': 'error',
            'message': "User not authenticated"
        }
    session_key = os.urandom(32)
    encrypted_user_session_key = base64.b64encode(
        encrypt_with_public_key(
            REGISTERED_ENTITIES[user_id]["public_key"],
            session_key)).decode()
    encrypted_server_session_key = base64.b64encode(
        encrypt_with_public_key(
            REGISTERED_ENTITIES[server_id]["public_key"],
            session_key)).decode()

    send_request(
        {
            'action': 'session_key',
            'server_session_key': encrypted_server_session_key,
            'user_session_key': encrypted_user_session_key,
            "HOST": REGISTERED_ENTITIES[server_id]["HOST"],
            "PORT": REGISTERED_ENTITIES[server_id]["PORT"],
            "USER_HOST": REGISTERED_ENTITIES[user_id]["HOST"],
            "USER_PORT": REGISTERED_ENTITIES[user_id]["PORT"]
        }
    )


def handle_authenticate_request(data: dict) -> dict:
    server_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data['SERVER_ID'])).decode()
    user_id = decrypt_with_private_key(TTP_PRIVATE_KEY, base64.b64decode(data['USER_ID'])).decode()
    if server_id not in REGISTERED_ENTITIES:
        return {
            'status': 'error',
            'message': "server not registered"
        }
    else:
        t = threading.Thread(target=authenticate_user, args=(user_id, server_id), daemon=True)
        t.start()
        return {
            'status': 'ok',
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
