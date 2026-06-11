import socket
import os
import zstandard as zstd
import json
import base64
import datetime
import mimetypes
import requests
import struct
import brotli
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

# === CONFIGURATION ===
LISTEN_IP = "192.168.137.1"
LISTEN_PORT = 9990

KEY = b'0123456789abcdef0123456789abcdef'  # 256-bit key
NONCE_SIZE = 12
SAVE_DIR = "remote_receiver_data"
os.makedirs(SAVE_DIR, exist_ok=True)


def decrypt_data(encrypted: bytes) -> bytes:
    nonce = encrypted[:NONCE_SIZE]
    ciphertext = encrypted[NONCE_SIZE:]
    aesgcm = AESGCM(KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_response(data: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(KEY)
    return nonce + aesgcm.encrypt(nonce, data, None)

def guess_extension(headers):
    content_type = headers.get("content-type", "")
    ext = mimetypes.guess_extension(content_type.split(";")[0].strip())
    return ext.lstrip(".") if ext else "bin"

def preview_response_body(body_bytes, headers):
    print("\n[DEBUG] 🔍 Decoded Response Preview:")
    try:
        encoding = headers.get("Content-Encoding", "")
        if "br" in encoding:
            body_bytes = brotli.decompress(body_bytes)
            print(body_bytes.decode("utf-8", errors="replace"))
        elif "gzip" in encoding:
            print("[!] Gzip encoding detected. Skipping preview.")
        else:
            print(body_bytes.decode("utf-8", errors="replace"))
    except Exception as e:
        print("[!] Failed to decode preview:", e)


def handle_connection(conn, addr):
    try:
        print(f"[+] Connection from {addr}")
        header = conn.recv(4)
        if len(header) < 4:
            print("[!] Incomplete header")
            return

        payload_len = struct.unpack(">I", header)[0]
        print(f"[→] Receiving {payload_len} bytes from client")

        encrypted_data = b""
        while len(encrypted_data) < payload_len:
            chunk = conn.recv(payload_len - len(encrypted_data))
            if not chunk:
                raise Exception("Connection closed before full payload")
            encrypted_data += chunk

        compressed = decrypt_data(encrypted_data)
        decompressed = zstd.ZstdDecompressor().decompress(compressed)
        request = json.loads(decompressed)

        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        host = request.get("url", "unknown").split("/")[2].replace(":", "_")
        base = f"{host}_{timestamp}"
        folder_path = os.path.join(SAVE_DIR, base)
        os.makedirs(folder_path, exist_ok=True)

        # Save raw request
        with open(os.path.join(folder_path, "raw.json"), "w", encoding="utf-8") as f:
            json.dump(request, f, indent=2)

        # Save compressed version
        with open(os.path.join(folder_path, "compressed.zst"), "wb") as f:
            f.write(compressed)

        # Decode and save body
        body_data = base64.b64decode(request.get("body", ""))
        ext = guess_extension(request.get("headers", {}))
        with open(os.path.join(folder_path, f"request_body.{ext}"), "wb") as f:
            f.write(body_data)

        method = request.get("method", "GET").upper()
        url = request.get("url")
        headers = request.get("headers", {})
        headers.pop("host", None)
        headers.pop("content-length", None)

        try:
            resp = requests.request(method, url, headers=headers, data=body_data, timeout=10)
            response_data = {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": base64.b64encode(resp.content).decode()
            }

            # Save response body
            ext = guess_extension(resp.headers)
            with open(os.path.join(folder_path, f"response_body.{ext}"), "wb") as f:
                f.write(resp.content)

            preview_response_body(resp.content, dict(resp.headers))

            response_json = json.dumps(response_data).encode()
            compressed_resp = zstd.ZstdCompressor().compress(response_json)
            encrypted_response = encrypt_response(compressed_resp)

            conn.sendall(struct.pack(">I", len(encrypted_response)) + encrypted_response)
            print(f"[←] Sent {len(encrypted_response)} bytes with header")

        except Exception as e:
            print(f"[!] Forwarding failed: {e}")
            conn.sendall(struct.pack(">I", 0))

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        conn.close()

def start_server():
    print(f"[🔒] Listening on {LISTEN_IP}:{LISTEN_PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((LISTEN_IP, LISTEN_PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)

if __name__ == "__main__":
    start_server()
