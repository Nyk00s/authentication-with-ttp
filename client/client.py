import json
import socket
import logging
import threading
from generator import get_keys

logging.basicConfig(filename='client.log', level=logging.INFO, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler = logging.StreamHandler()
formatter = logging.Formatter("[%(asctime)s] :: %(levelname)s :: %(message)s")
console_handler.setFormatter(formatter)
logging.getLogger('').addHandler(console_handler)


HOST = '0.0.0.0'
PORT = 8999

TTP_HOST = '127.0.0.1'
TTP_PORT = 9000

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9001

CLIENT_ID = 'fcce5e8d-ee7d-471c-815f-8a34d8a9106e'
CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = get_keys()
logging.info('Got keys')


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


def send_to_server(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect((SERVER_HOST, SERVER_PORT))
            sock.sendall((json.dumps(data) + '\n').encode())
            logging.info(f"Request \'{data.get('action')}\' has been sent to server({SERVER_HOST})")
            received_bytes = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received_bytes += chunk
                if received_bytes.endswith(b'\n'):
                    break

            if not received_bytes:
                raise ConnectionError("Empty response from server")

            string_data = received_bytes.decode().strip()
            logging.info(f'Data received from server: {string_data}')
            return json.loads(string_data)
    except (socket.timeout, socket.error) as e:
        logging.error(f'Network error while communicating with server: {e}')
        return {'status': 'error', 'message': f'Network error: {str(e)}'}
    except json.JSONDecodeError:
        logging.error(f'Invalid JSON received from server: {received_bytes}')
        return {'status': 'error', 'message': 'Invalid JSON response'}
    except Exception as e:
        logging.exception('Unexpected error while communicating with server')
        return {'status': 'error', 'message': str(e)}


def handle_request(data):
    return {
        'status': 'ok',
        'echo': data
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
    except Exception:
        logging.exception(f"Error while receiving data from {addr}")
    finally:
        conn.close()


def listen_for_requests():
    logging.info("Start client requests listener")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            logging.info(f"New request from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


def chain_events():
    send_to_ttp(
        {
            'action': 'get_ttp_public_key'
        }
    )


def main():
    request_listener = threading.Thread(target=listen_for_requests, daemon=True)
    chain_events_thread = threading.Thread(target=chain_events, daemon=True)
    request_listener.start()
    chain_events_thread.start()


if __name__ == "__main__":
    main()
