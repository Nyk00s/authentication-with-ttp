import json
import socket
import logging
import threading

logging.basicConfig(filename='client.log', level=logging.INFO, filemode='w',
                    format="[%(asctime)s] :: %(levelname)s :: %(message)s")

HOST = '0.0.0.0'
PORT = 8999

TTP_HOST = '127.0.0.1'
TTP_PORT = 9000

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9001



def send_to_ttp(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TTP_HOST, TTP_PORT))
    sock.sendall((json.dumps(data) + '\n').encode())
    received_bytes = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        received_bytes += chunk
        if received_bytes.endswith(b'\n'):
            break

    json_data = json.loads(received_bytes.decode().strip())
    sock.close()
    return json_data


def send_to_server(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    sock.sendall((json.dumps(data) + '\n').encode())
    received_bytes = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        received_bytes += chunk
        if received_bytes.endswith(b'\n'):
            break

    json_data = json.loads(received_bytes.decode().strip())
    sock.close()
    return json_data


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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


def main():
    listener = threading.Thread(target=listen_for_requests, daemon=True)
    listener.start()



if __name__ == "__main__":
    main()
