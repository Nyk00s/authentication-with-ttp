import json
import socket
import threading
from datetime import datetime


TTP_HOST = "127.0.0.1"
TTP_PORT = 9000
HOST = "0.0.0.0"
PORT = 9001


def log(msg: str):
    print(f"[{datetime.now().strftime('%d.%m.%y %H:%M:%S')}] " + msg)


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


def handle_request(json_data):
    log(json_data['action'])
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
        log(f"Error {addr} : {e}")
    finally:
        conn.close()


def main():
    print("start server")
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
