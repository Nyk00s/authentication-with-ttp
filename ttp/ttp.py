"""!
@file ttp.py
@brief Trusted Third Party (TTP) Central Authority module.
@details Implements a centralized public key infrastructure (PKI) subsystem. Handles 
         X.509 validation issuance, credential records lookup, and asymmetric distribution 
         of dual-wrapped symmetric session keys over concurrent thread socket structures.
@author Franciszek Kuczkowski, Nikodem Falkowski
@version 1.0
@date 2026-06-06
"""

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

# --- LOGGING ENVIRONMENT SETUP ---
logging.basicConfig(filename='ttp.log', level=logging.DEBUG, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)

# --- NETWORK AND CRYPTO ASSETS CONFIGURATION ---
HOST, PORT = '0.0.0.0', 9000
TTP_PRIVATE_KEY, TTP_PUBLIC_KEY = get_keys()
TTP_CERT = get_cert(TTP_PRIVATE_KEY, TTP_PUBLIC_KEY, 'TTP_CA')
REGISTERED_ENTITIES = {}


def handle_register(data: dict) -> dict:
    """!
    @brief Evaluates entity parameters, constructs, signs, and registers an X.509 identity token certificate.
    @details Validates the entity name footprint by resolving asymmetric identity tokens through the 
             local private RSA context key. Locks existing IDs to enforce unique identities.
    @param data Dictionary containing the encrypted unique ID string, a password string, and public key PEM arrays.
    @return Encapsulated JSON operational metadata tracking registration states or certificate PEM strings.
    """
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
    """!
    @brief Authenticates a registered system entity matching identity and password database variables.
    @param data Data envelope containing base64-encoded encrypted identity signatures and authentication passwords.
    @return Status results mapping a success criteria token coupled directly with the valid original X.509 payload.
    """
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
    """!
    @brief Dispatches synchronous outbound JSON control packets directly to active remote socket interfaces.
    @param data Structural tracking matrix holding destination IP targets, port attributes, and target action commands.
    @return Decoded remote server responses or structural exception status code diagnostics on transmission errors.
    @exception ConnectionError Raised if remote sockets close unexpectedly yielding zero valid byte streams.
    """
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
    """!
    @brief Executes asymmetric verification steps and handles cross-network delivery of dynamic session keys.
    @details Asynchronously challenges the client entity to establish valid identities. On success, wraps 
             a fresh 32-byte pseudorandom symmetric key inside distinct RSA envelopes optimized for both participants.
    @param user_id Unique identifier key string mapping the client node data context.
    @param server_id Unique identifier key string mapping the destination application server node context.
    """
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
    """!
    @brief Handles cross-entity validation inquiries from servers seeking to securely accept client links.
    @note Boots an independent execution thread worker to handle deep key wrapping procedures out-of-band.
    @param data Data object holding asymmetric identity tracking strings for validation targets.
    @return General structural status code mapping dispatch confirmations.
    """
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
    """!
    @brief Main router function mapping inbound system payloads directly to operational functional modules.
    @param data Input structural payload data mapping network parameters.
    @return Response packet map matching functional resolution attributes.
    """
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
    """!
    @brief Threaded network connection socket data transport processor wrapper.
    @param conn Open socket reference object.
    @param addr Tuple identifying structural network configuration records (IP, Port).
    """
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
    """!
    @brief Main runtime loop pinning endpoints to local active port indicators.
    @details Spins up a persistent socket server topology ready to delegate incoming sessions 
             to background validation task thread pools.
    """
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