import json
import socket
import datetime
import threading
from generator import get_ttp_keys


HOST, PORT = '0.0.0.0', 9000
TTP_PRIVATE_KEY, TTP_CERT = get_ttp_keys()
TTP_PUBLIC_KEY = TTP_PRIVATE_KEY.public_key()


def log(msg: str):
    print(f"[{datetime.datetime.now().strftime('%d.%m.%y %H:%M:%S')}] " + msg)


def handle_request(data: dict) -> dict:
    log("client has sent something")
    return {"status": "ok", "echo": data}
    

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
        response = handle_request(json_data)
        conn.sendall((json.dumps(response) + '\n').encode())
    except Exception as e:
        log(f"Error {addr} : {e}")
    finally:
        conn.close()


def main():
    print("start ttp")
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
