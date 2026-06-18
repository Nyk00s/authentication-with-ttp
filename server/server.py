"""!
@file server.py
@brief Application service Server module.
@details Implements an independent target network node. Handles automated initialization 
         with the TTP authority, process handshaking via incoming client connections, 
         and provides an echo service over symmetric AES channels.
@author Franciszek Kuczkowski, Nikodem Falkowski
@version 1.0
@date 2026-06-06
"""

import json
import uuid
import base64
import socket
import secrets
import hashlib
import logging
import threading
from generator import get_keys, encrypt_with_public_key, get_public_key_pem, decrypt_with_private_key, \
    aes_encrypt, aes_decrypt

# --- LOGGING ENVIRONMENT SETUP ---
logging.basicConfig(filename='server.log', level=logging.DEBUG, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)

# --- CONFIGURATION VARIABLES ---
TTP_HOST = "ttp"
TTP_PORT = 9000
HOST = "0.0.0.0"
PORT = 9001
REGISTRATION_HOST = 'server'
SERVER_ID = str(uuid.uuid4())
SERVER_PASSWORD = secrets.token_hex(16)
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = get_keys()
TTP_PUBLIC_KEY_PEM = ''
SESSION_KEY = ''


def send_to_ttp(data):
    """!
    @brief Dispatches a synchronous JSON control block to the central TTP instance.
    @param data Dictionary containing the specific protocol parameters and action.
    @return A dictionary payload representing the parsed response from the TTP node.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect((TTP_HOST, TTP_PORT))
            sock.sendall((json.dumps(data) + '\n').encode())
            logging.info(f"Request \'{data.get('action')}\' has been sent to ttp({TTP_HOST})")
            received_bytes = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received_bytes += chunk
                if received_bytes.endswith(b'\n'):
                    break

            if not received_bytes:
                raise ConnectionError("Empty response from TTP")

            string_data = received_bytes.decode().strip()
            logging.info(f'Data received from TTP: {string_data}')
            return json.loads(string_data)
    except (socket.timeout, socket.error) as e:
        logging.error(f'Network error while communicating with TTP: {e}')
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except json.JSONDecodeError:
        logging.error(f'Invalid JSON received from TTP: {received_bytes}')
        return {'status': 'error', 'message': 'Invalid JSON response'}
    except Exception as e:
        logging.exception('Unexpected error while communicating with TTP')
        return {'status': 'error', 'message': str(e)}


def send_request(data):
    """!
    @brief Dispatches an outbound JSON payload to arbitrary host configuration endpoints.
    @param data Dynamic connection tracker mapping destination target variables.
    @return Decoded response mapping structure dictionaries.
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


def handle_request(json_data):
    """!
    @brief Primary input validation state router resolving commands sent directly to the Server.
    @details Handles protocol phases including initial confirmation tokens, incoming symmetric 
             session injections, auth triggers, and payload traffic decryption loops.
    @param json_data Raw incoming dictionary parameter tracking matrices.
    @return Control execution message envelopes indicating status responses.
    """
    global SESSION_KEY
    action = json_data.get('action')

    if action == 'server_authenticated':
        logging.info("Server has been authenticated")
        return {
            'status': 'ok'
        }
    elif action == 'session_key':
        logging.info('Server got session key from ttp')
        SESSION_KEY = decrypt_with_private_key(SERVER_PRIVATE_KEY, base64.b64decode(json_data['server_session_key']))
        send_request(
            {
                'action': 'session_key',
                'user_session_key': json_data["user_session_key"],
                "HOST": json_data["USER_HOST"],
                "PORT": json_data["USER_PORT"]
            }
        )
        return {
            'status': 'ok'
        }
    elif action == 'request_service':
        if not TTP_PUBLIC_KEY_PEM:
            return {
                'status': 'error',
                'message': "Server doesn't have ttp public key"
            }
        encrypted_server_id = encrypt_with_public_key(TTP_PUBLIC_KEY_PEM.encode(), SERVER_ID.encode())
        send_to_ttp(
            {
                'action': 'authenticate_request',
                'USER_ID': json_data['USER_ID'],
                'SERVER_ID': base64.b64encode(encrypted_server_id).decode()
            }
        )
        return {
            'status': 'ok',
            'message': "Server has been authenticated"
        }
    elif action == 'message':
        logging.info(f"encrypted data: {json_data['data']}")
        decrypted_message = aes_decrypt(SESSION_KEY, json_data['data'])
        decrypted_message += b'ipsa'
        logging.info(f"decrypted data: {decrypted_message}")
        response_message = aes_encrypt(SESSION_KEY, decrypted_message)
        logging.info(f"encrypted data: {response_message}")
        return {
            'status': 'ok',
            'data': response_message
        }
    else:
        logging.info(f"Server got unknown request: {action}")
        return {
            'status': 'error',
            'message': 'request unknown',
            'echo': json_data
        }


def handle_client(conn, addr):
    """!
    @brief Dedicated processor mapping socket byte operations down into individual threads.
    @param conn Open network stream socket reference object.
    @param addr Structural identification tracking tuple (IP, Port).
    """
    try:
        received_bytes = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            received_bytes += chunk
            if received_bytes.endswith(b'\n'):
                break

        json_data = json.loads(received_bytes.decode().strip())
        response = handle_request(json_data)
        conn.sendall((json.dumps(response) + '\n').encode())
    except Exception as e:
        logging.exception(f"Error while receiving data from {addr}")
    finally:
        conn.close()


def listen_for_requests():
    """!
    @brief Infinite background listener thread blocking interface endpoints to accept connections.
    """
    logging.info("Start server requests listener")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


def chain_events():
    """!
    @brief Primary pipeline handling out-of-band initialization and authorization registrations.
    @details Fetches active authority parameters, registers the node context identity signature, 
             and resolves fallback logic states if registration identifiers overlap.
    @exception Exception General crash trap tracking configuration breakdowns during authorization tasks.
    """
    global TTP_PUBLIC_KEY_PEM
    data_from_ttp = send_to_ttp(
        {
            'action': 'get_ttp_public_key'
        }
    )
    logging.debug('get_ttp_public_key: ' + str(data_from_ttp))

    if data_from_ttp['status'] == 'error':
        raise Exception("Got wrong data from ttp")

    TTP_PUBLIC_KEY_PEM = data_from_ttp['ttp_public_key']
    ttp_cert = data_from_ttp['ttp_cert']
    encrypted_id = encrypt_with_public_key(TTP_PUBLIC_KEY_PEM.encode(), SERVER_ID.encode())
    client_public_key_pem = get_public_key_pem(SERVER_PUBLIC_KEY)
    hashed_password = hashlib.sha256(SERVER_PASSWORD.encode()).hexdigest()

    data_from_ttp = send_to_ttp(
        {
            'action': 'register',
            'ID': base64.b64encode(encrypted_id).decode(),
            'password': hashed_password,
            'public_key': client_public_key_pem,
            'HOST': REGISTRATION_HOST,
            'PORT': PORT
        }
    )
    logging.debug('register: ' + str(data_from_ttp))

    if data_from_ttp['status'] == 'error' and data_from_ttp['message'] == 'id exists':
        data_from_ttp = send_to_ttp(
            {
                'action': 'login',
                'ID': base64.b64encode(encrypted_id).decode(),
                'password': hashed_password,
                'public_key': client_public_key_pem
            }
        )
        logging.debug('login: ' + str(data_from_ttp))


def main():
    """!
    @brief Main entry execution container bootstrapping independent background threads.
    """
    logging.info("Start server")
    request_listener = threading.Thread(target=listen_for_requests)
    chain_events_thread = threading.Thread(target=chain_events, daemon=True)
    request_listener.start()
    chain_events_thread.start()


if __name__ == "__main__":
    main()