"""!
@file client.py
@brief Client application module with integrated GUI and MitM mitigation mechanisms.
@details Emulates the client-side interaction within a Trusted Third Party (TTP) 
         and Server ecosystem, utilizing RSA-4096 and AES-256 cryptographic standards.
@author Franciszek Kuczkowski, Nikodem Falkowski
@version 1.10
@date 2026-06-06
"""

import json
import uuid
import socket
import base64
import secrets
import hashlib
import logging
import threading
import sys
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).parent.parent))
from generator import get_keys, encrypt_with_public_key, get_public_key_pem, decrypt_with_private_key, \
    aes_encrypt, aes_decrypt

# --- NETWORK CONFIGURATION ---
HOST = '0.0.0.0'
PORT = 8999

TTP_HOST = '127.0.0.1'
TTP_PORT = 9000

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9001

REGISTRATION_HOST = 'host.docker.internal'
CLIENT_ID = str(uuid.uuid4())
CLIENT_PASSWORD = secrets.token_hex(16)
CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY = get_keys()
SESSION_KEY = b''

# --- THREAD SYNCHRONIZATION EVENTS ---
session_key_event = threading.Event()
server_auth_event = threading.Event()
TTP_PUBLIC_KEY_PEM = ''


def send_to_ttp(data):
    """!
    @brief Dispatches a synchronous JSON payload to the TTP server instance.
    @param data A dictionary containing the action protocol and necessary payload.
    @return A dictionary representing the decoded JSON response from the TTP, or an error status dictionary.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
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
            if not received_bytes:
                raise ConnectionError("Empty response from TTP")
            return json.loads(received_bytes.decode().strip())
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def send_to_server(data):
    """!
    @brief Dispatches a synchronous JSON payload to the application service Server.
    @param data A dictionary containing the action protocol and necessary payload.
    @return A dictionary representing the decoded JSON response from the Server, or an error status dictionary.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
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
            if not received_bytes:
                raise ConnectionError("Empty response from server")
            return json.loads(received_bytes.decode().strip())
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def handle_authenticate_user(data):
    """!
    @brief Compiles user response credentials upon explicit TTP request.
    @details Encrypts the local client identity signature using the established TTP asymmetric public key.
    @param data TTP query input parameters.
    @return A payload structure containing the base64-encoded encrypted USER_ID string or error state.
    """
    if not TTP_PUBLIC_KEY_PEM:
        return {'status': 'error', 'message': "Missing TTP public key"}
    else:
        encrypted_client_id = encrypt_with_public_key(TTP_PUBLIC_KEY_PEM.encode(), CLIENT_ID.encode())
        return {
            'status': 'ok',
            'USER_ID': base64.b64encode(encrypted_client_id).decode()
        }


def handle_request(data, gui_instance=None):
    """!
    @brief Centralized router for inbound socket-driven application commands.
    @param data Parsed JSON request packet object.
    @param gui_instance Reference hook back to the ClientGUI class to log transactions.
    @return Operational status code envelope.
    """
    global SESSION_KEY
    action = data.get('action')

    if action == "server_authenticated":
        if gui_instance:
            gui_instance.log("Server authenticated by TTP", "INFO")
        return {'status': 'ok'}

    elif action == 'session_key':
        if gui_instance:
            gui_instance.log("Received session key from TTP", "INFO")
        SESSION_KEY = decrypt_with_private_key(CLIENT_PRIVATE_KEY, base64.b64decode(data['user_session_key']))
        session_key_event.set()
        return {'status': 'ok'}

    elif action == 'authenticate_user':
        if gui_instance:
            gui_instance.log("TTP requested user authentication", "INFO")
        server_auth_event.wait()
        return handle_authenticate_user(data)

    else:
        return {'status': 'error', 'message': 'Unknown action'}


def handle_client(conn, addr, gui_instance):
    """!
    @brief Dedicated processing wrapper for individual socket stream sessions.
    @param conn Open active socket descriptor.
    @param addr Tuple identifying remote socket network attributes.
    @param gui_instance Reference hook back to the ClientGUI class instance.
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
        response = handle_request(json_data, gui_instance)
        conn.sendall((json.dumps(response) + '\n').encode())
    except Exception as e:
        if gui_instance:
            gui_instance.log(f"Connection error: {e}", "ERROR")
    finally:
        conn.close()


def listen_for_requests(gui_instance):
    """!
    @brief Continuous loop binding local interfaces to receive asynchronous network events.
    @note Spawns individual execution threads per connection to prevent interface lockups.
    @param gui_instance Running context instance containing cross-thread controls.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        s.settimeout(1.0)
        while gui_instance.running:
            try:
                conn, addr = s.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr, gui_instance), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break


class ClientGUI:
    """!
    @brief Graphic Controller managing asynchronous user controls and real-time transaction reporting.
    @details Governs the visualization layout, event loop threading model, and cryptographic verification flows.
    """

    def __init__(self, root):
        """!
        @brief Instantiates component states, layouts, and system background workers.
        @param root Underlying parent Tkinter layout engine container.
        """
        self.root = root
        self.root.title("SCS Client Application")
        self.root.geometry("1000x750")
        self.root.resizable(True, True)

        self.ttp_connected = tk.BooleanVar(value=False)
        self.server_connected = tk.BooleanVar(value=False)
        self.authenticated = tk.BooleanVar(value=False)
        self.session_active = tk.BooleanVar(value=False)
        self.mitm_simulation = tk.BooleanVar(value=False)

        self.running = True
        self.create_widgets()

        self.listener_thread = threading.Thread(target=listen_for_requests, args=(self,), daemon=True)
        self.listener_thread.start()

        self.log("System initialized")

    def create_widgets(self):
        """!
        @brief Builds comprehensive grid components, diagnostic frames, and log visualizers.
        """
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        status_frame = ttk.LabelFrame(main_frame, text="Status Indicators", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        status_content = ttk.Frame(status_frame)
        status_content.pack(fill=tk.X)

        self.ttp_indicator = tk.Canvas(status_content, width=15, height=15, highlightthickness=0)
        self.ttp_indicator.pack(side=tk.LEFT, padx=(10, 2))
        ttk.Label(status_content, text="TTP Key").pack(side=tk.LEFT, padx=(0, 20))

        self.server_indicator = tk.Canvas(status_content, width=15, height=15, highlightthickness=0)
        self.server_indicator.pack(side=tk.LEFT, padx=(10, 2))
        ttk.Label(status_content, text="Server Auth").pack(side=tk.LEFT, padx=(0, 20))

        self.auth_indicator = tk.Canvas(status_content, width=15, height=15, highlightthickness=0)
        self.auth_indicator.pack(side=tk.LEFT, padx=(10, 2))
        ttk.Label(status_content, text="User Auth").pack(side=tk.LEFT, padx=(0, 20))

        self.session_indicator = tk.Canvas(status_content, width=15, height=15, highlightthickness=0)
        self.session_indicator.pack(side=tk.LEFT, padx=(10, 2))
        ttk.Label(status_content, text="Session Active").pack(side=tk.LEFT, padx=(0, 20))

        self.refresh_indicators()

        auth_panel = ttk.LabelFrame(main_frame, text="Authentication Control", padding=10)
        auth_panel.pack(fill=tk.X, pady=(0, 10))

        self.auth_button = ttk.Button(auth_panel, text="Execute Protocol Flow", command=self.start_authentication)
        self.auth_button.pack(side=tk.LEFT, padx=5)

        self.mitm_checkbox = ttk.Checkbutton(
            auth_panel,
            text="Simulate MitM Attack (Forge Certificate)",
            variable=self.mitm_simulation,
            command=self._on_mitm_toggle
        )
        self.mitm_checkbox.pack(side=tk.LEFT, padx=20)

        ttk.Button(auth_panel, text="Clear Logs", command=self.clear_logs).pack(side=tk.RIGHT, padx=5)

        info_frame = ttk.LabelFrame(main_frame, text="Configuration Info", padding=10)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(info_frame, text=f"Client ID: {CLIENT_ID} | Listen: {HOST}:{PORT}").pack(anchor=tk.W)
        ttk.Label(info_frame, text=f"TTP: {TTP_HOST}:{TTP_PORT} | Server: {SERVER_HOST}:{SERVER_PORT}").pack(
            anchor=tk.W)

        msg_frame = ttk.LabelFrame(main_frame, text="Symmetric Data Exchange", padding=10)
        msg_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        input_frame = ttk.Frame(msg_frame)
        input_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(input_frame, text="Payload:").pack(side=tk.LEFT, padx=5)
        self.msg_input = ttk.Entry(input_frame)
        self.msg_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.msg_input.insert(0, "alamakota")

        self.send_button = ttk.Button(input_frame, text="Send via AES", command=self.send_message, state=tk.DISABLED)
        self.send_button.pack(side=tk.LEFT, padx=5)

        ttk.Label(msg_frame, text="Traffic Log:").pack(anchor=tk.W)
        self.msg_log = scrolledtext.ScrolledText(msg_frame, height=8, state=tk.DISABLED)
        self.msg_log.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        ttk.Label(main_frame, text="System Event Log:").pack(anchor=tk.W)
        self.event_log = scrolledtext.ScrolledText(main_frame, height=6, state=tk.DISABLED)
        self.event_log.pack(fill=tk.BOTH, expand=True)

    def _on_mitm_toggle(self):
        """!
        @brief Callback triggering informative notifications when MitM intercept options toggle.
        """
        if self.mitm_simulation.get():
            self.log("MitM Simulation enabled", "WARNING")
        else:
            self.log("MitM Simulation disabled", "INFO")

    def refresh_indicators(self):
        """!
        @brief Synchronizes state flags with user interface tracking canvas geometries.
        """
        for canvas, var in [(self.ttp_indicator, self.ttp_connected),
                            (self.server_indicator, self.server_connected),
                            (self.auth_indicator, self.authenticated),
                            (self.session_indicator, self.session_active)]:
            color = "green" if var.get() else "red"
            canvas.delete("all")
            canvas.create_oval(2, 2, 13, 13, fill=color, outline="black")

    def log(self, message, level="INFO"):
        """!
        @brief Records internal runtime tracking indicators inside the application logs pane.
        @param message String data containing the status text trace.
        @param level Logging classification tier string (e.g., INFO, ERROR, WARNING).
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {level}: {message}\n"
        self.event_log.config(state=tk.NORMAL)
        self.event_log.insert(tk.END, formatted)
        self.event_log.see(tk.END)
        self.event_log.config(state=tk.DISABLED)

    def traffic_log(self, message, direction="SYSTEM"):
        """!
        @brief Records cryptographic transformations and low-level protocol wire packets.
        @param message Raw payload representation or formatted information trace.
        @param direction Denotes traffic vectors (e.g., IN, OUT, SYSTEM).
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {direction}: {message}\n"
        self.msg_log.config(state=tk.NORMAL)
        self.msg_log.insert(tk.END, formatted)
        self.msg_log.see(tk.END)
        self.msg_log.config(state=tk.DISABLED)

    def clear_logs(self):
        """!
        @brief Wipes recorded data frames across trace logging viewboxes.
        """
        for widget in [self.event_log, self.msg_log]:
            widget.config(state=tk.NORMAL)
            widget.delete(1.0, tk.END)
            widget.config(state=tk.DISABLED)

    def start_authentication(self):
        """!
        @brief Non-blocking dispatch system firing sequence authentication threads.
        """
        self.auth_button.config(state=tk.DISABLED)
        self.traffic_log("Initiating authentication sequence", "SYSTEM")
        threading.Thread(target=self._auth_flow_thread, daemon=True).start()

    def _auth_flow_thread(self):
        """!
        @brief Primary background state-machine running core protocol execution operations.
        @details Manages key discovery, public registration, signature validation, and transport negotiation.
        @exception Exception Terminating condition throwing errors inside log frameworks on step fail states.
        """
        global TTP_PUBLIC_KEY_PEM
        try:
            self.log("Fetching TTP public key", "INFO")
            data_from_ttp = send_to_ttp({'action': 'get_ttp_public_key'})
            if data_from_ttp.get('status') != 'ok':
                raise Exception("TTP public key request failed")

            TTP_PUBLIC_KEY_PEM = data_from_ttp['ttp_public_key']
            self.ttp_connected.set(True)
            self.root.after(0, self.refresh_indicators)
            self.traffic_log("TTP public key imported", "SYSTEM")

            self.log("Registering identity with TTP", "INFO")
            encrypted_id = encrypt_with_public_key(TTP_PUBLIC_KEY_PEM.encode(), CLIENT_ID.encode())
            client_public_key_pem = get_public_key_pem(CLIENT_PUBLIC_KEY)
            hashed_password = hashlib.sha256(CLIENT_PASSWORD.encode()).hexdigest()

            data_from_ttp = send_to_ttp({
                'action': 'register',
                'ID': base64.b64encode(encrypted_id).decode(),
                'password': hashed_password,
                'public_key': client_public_key_pem,
                'HOST': REGISTRATION_HOST,
                'PORT': PORT
            })

            if data_from_ttp.get('status') == 'error' and data_from_ttp.get('message') == 'id exists':
                self.log("ID exists, executing login fallback", "INFO")
                data_from_ttp = send_to_ttp({
                    'action': 'login',
                    'ID': base64.b64encode(encrypted_id).decode(),
                    'password': hashed_password,
                    'public_key': client_public_key_pem
                })

            if data_from_ttp.get('status') != 'ok':
                raise Exception(f"Registration rejected: {data_from_ttp.get('message')}")

            cert_pem_data = data_from_ttp['cert'].encode()

            if self.mitm_simulation.get():
                self.log("MitM active: Mutating certificate payload", "WARNING")
                mutated_cert = data_from_ttp['cert'].replace("A", "B", 3)
                cert_pem_data = mutated_cert.encode()

            self.log("Verifying X.509 signature against TTP key", "INFO")

            try:
                cert = x509.load_pem_x509_certificate(cert_pem_data)
                ttp_key_obj = serialization.load_pem_public_key(TTP_PUBLIC_KEY_PEM.encode())

                ttp_key_obj.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                self.log("Certificate verification successful", "INFO")
                self.traffic_log("Obtained X.509 certificate", "SYSTEM")

            except Exception:
                self.traffic_log("MitM anomaly: Signature mismatch", "ERROR")
                self.log("Protocol terminated: Verification failed", "CRITICAL")
                return

            self.log("Submitting request to server", "INFO")
            data_from_server = send_to_server({
                'action': 'request_service',
                'USER_ID': base64.b64encode(encrypted_id).decode(),
            })

            if data_from_server.get('status') != 'ok':
                raise Exception("Server rejected request")

            self.server_connected.set(True)
            self.root.after(0, self.refresh_indicators)
            self.traffic_log("Server connection acknowledged", "SYSTEM")

            self.log("Awaiting session key distribution", "INFO")
            server_auth_event.set()

            if not session_key_event.wait(timeout=15.0):
                raise Exception("Session key timeout")

            self.authenticated.set(True)
            self.session_active.set(True)
            self.root.after(0, self.refresh_indicators)
            self.traffic_log("Secure session established", "SYSTEM")
            self.log("Session key injected into context", "INFO")

            self.send_button.config(state=tk.NORMAL)

        except Exception as e:
            self.log(f"Sequence aborted: {str(e)}", "ERROR")
            self.traffic_log(f"Protocol breakdown: {str(e)}", "ERROR")
        finally:
            self.auth_button.config(state=tk.NORMAL)

    def send_message(self):
        """!
        @brief Evaluates message configurations before dispatching threaded background routines.
        """
        message = self.msg_input.get().strip()
        if not message:
            messagebox.showwarning("Warning", "Empty payload prohibited")
            return
        self.send_button.config(state=tk.DISABLED)
        threading.Thread(target=self._send_msg_thread, args=(message,), daemon=True).start()

    def _send_msg_thread(self, message):
        """!
        @brief Manages AES-256 data exchange operations across symmetric channels.
        @param message Raw input plaintext string captured from user entry controls.
        """
        try:
            self.log("Encrypting data with AES context", "INFO")
            encrypted_payload = aes_encrypt(SESSION_KEY, message.encode())

            self.traffic_log(f"{message}", "OUT (PLAINTEXT)")
            self.traffic_log(f"{encrypted_payload[:50]}...", "OUT (AES-CIPHER)")

            response = send_to_server({
                'action': 'message',
                'data': encrypted_payload
            })

            if response.get('status') == 'ok':
                decrypted_response = aes_decrypt(SESSION_KEY, response['data'])
                self.traffic_log(f"{response['data'][:50]}...", "IN (AES-CIPHER)")
                self.traffic_log(f"{decrypted_response}", "IN (PLAINTEXT-DECRYPTED)")
                self.log("Transaction successfully completed", "INFO")
            else:
                self.traffic_log(f"Server error: {response.get('message')}", "ERROR")

        except Exception as e:
            self.log(f"Transport error: {e}", "ERROR")
            self.traffic_log(f"Transmission failed: {e}", "ERROR")
        finally:
            self.send_button.config(state=tk.NORMAL)

    def on_closing(self):
        """!
        @brief Performs housekeeping tasks and terminates open sockets before application termination.
        """
        self.running = False
        self.root.destroy()


def main():
    """!
    @brief Main entry execution target initializing parent layouts and loops.
    """
    root = tk.Tk()
    gui = ClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", gui.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()