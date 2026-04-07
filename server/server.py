import json
import base64
import socket
import hashlib
import logging
import threading
from generator import get_keys, encrypt_with_public_key, get_public_key_pem

logging.basicConfig(filename='server.log', level=logging.DEBUG, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)


TTP_HOST = "127.0.0.1"
TTP_PORT = 9000
HOST = "127.0.0.1"
PORT = 9001
SERVER_ID = '92123f60-57a3-4511-9f9a-d83163963ee5'
SERVER_PASSWORD = '202fe311-559c-4245-9135-188f772453c4'
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = get_keys()


def send_to_ttp(data):
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


def handle_request(json_data):
    logging.info(json_data['action'])
    return {
        'status': 'ok',
        'echo': json_data
    }


def handle_client(conn, addr):
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
    data_from_ttp = send_to_ttp(
        {
            'action': 'get_ttp_public_key'
        }
    )
    logging.debug('get_ttp_public_key: ' + str(data_from_ttp))

    if data_from_ttp['status'] == 'error':
        raise Exception("Got wrong data from ttp")

    ttp_public_key_pem = data_from_ttp['ttp_public_key']
    ttp_cert = data_from_ttp['ttp_cert']
    encrypted_id = encrypt_with_public_key(ttp_public_key_pem.encode(), SERVER_ID.encode())
    client_public_key_pem = get_public_key_pem(SERVER_PUBLIC_KEY)
    hashed_password = hashlib.sha256(SERVER_PASSWORD.encode()).hexdigest()

    data_from_ttp = send_to_ttp(
        {
            'action': 'register',
            'ID': base64.b64encode(encrypted_id).decode(),
            'password': hashed_password,
            'public_key': client_public_key_pem,
            'HOST': HOST,
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
    logging.info("Start server")
    request_listener = threading.Thread(target=listen_for_requests)
    chain_events_thread = threading.Thread(target=chain_events, daemon=True)
    request_listener.start()
    chain_events_thread.start()


if __name__ == "__main__":
    main()
