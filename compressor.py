from mitmproxy import http
import zstandard as zstd
import os
import datetime
import socket
import json
import base64
import secrets
import struct
import mimetypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time

# === CONFIGURATION ===
#REMOTE_IP = "172.16.15.26"
REMOTE_IP = "192.168.137.1"
REMOTE_PORT = 9990
KEY = b'0123456789abcdef0123456789abcdef'
NONCE_SIZE = 12
SAVE_DIR = "https_interceptor_data"
TARGET_DOMAINS = ["d7fc8dff5960.ngrok-free.app"]
MASTER_RESULTS_FILE = os.path.join(SAVE_DIR, "https_results_all.json")
os.makedirs(SAVE_DIR, exist_ok=True)


def encrypt_data(data: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    aesgcm = AESGCM(KEY)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_response(data: bytes) -> dict:
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(KEY)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    decompressed = zstd.ZstdDecompressor().decompress(decrypted)
    return json.loads(decompressed)

def guess_extension(content_type: str) -> str:
    if not content_type:
        return "bin"
    ext = mimetypes.guess_extension(content_type.split(";")[0].strip())
    return ext[1:] if ext else "bin"


def append_to_master_results(new_result):
    try:
        if os.path.exists(MASTER_RESULTS_FILE):
            with open(MASTER_RESULTS_FILE, "r") as f:
                all_results = json.load(f)
        else:
            all_results = []

        all_results.append(new_result)

        with open(MASTER_RESULTS_FILE, "w") as f:
            json.dump(all_results, f, indent=2)

    except Exception as e:
        print(f"[!] Could not update master results file: {e}")


def send_and_receive_response(flow, encrypted_data: bytes, folder_path: str):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((REMOTE_IP, REMOTE_PORT))
            payload = struct.pack(">I", len(encrypted_data)) + encrypted_data
            s.sendall(payload)

            header = s.recv(4)
            if len(header) < 4:
                raise Exception("Incomplete response header received")
            response_len = struct.unpack(">I", header)[0]

            received = b""
            while len(received) < response_len:
                chunk = s.recv(response_len - len(received))
                if not chunk:
                    raise Exception("Connection closed early")
                received += chunk

        response_obj = decrypt_response(received)
        decoded_body = base64.b64decode(response_obj["body"])
        response_ct = response_obj["headers"].get("content-type", "")
        ext = guess_extension(response_ct)

        # Save response body
        response_filename = f"response_body.{ext}"
        response_path = os.path.join(folder_path, response_filename)
        with open(response_path, "wb") as f:
            f.write(decoded_body)

      
        # Try to parse the response body as JSON and extract message + filename
        try:
            response_data = json.loads(decoded_body.decode("utf-8", errors="ignore"))
            response_message = response_data.get("message", "N/A")
            response_filename = response_data.get("file", {}).get("filename", "N/A")
        except Exception:
            response_message = "N/A"
            response_filename = "N/A"


        # Return to client
        flow.response = http.Response.make(
            int(response_obj["status_code"]),
            decoded_body,
            dict(response_obj["headers"])
        )

        return response_filename, response_message

    except Exception as e:
        print(f"[!] Error during response: {e}")
        flow.response = http.Response.make(502, b"Remote proxy error")
        return None, "ERROR"


def request(flow: http.HTTPFlow):
    if flow.request.pretty_host not in TARGET_DOMAINS:
        return  # Skip if not target domain

    try:
        start_time = time.time()

        raw_body = flow.request.raw_content or b""
        content_type = flow.request.headers.get("content-type", "")
        ext = guess_extension(content_type)

        request_info = {
            "url": flow.request.pretty_url,
            "method": flow.request.method,
            "headers": dict(flow.request.headers),
            "body": base64.b64encode(raw_body).decode("utf-8")
        }
        payload_json = json.dumps(request_info).encode()

        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        host = flow.request.pretty_host.replace(":", "_")
        base_filename = f"{host}_{timestamp}"
        folder_path = os.path.join(SAVE_DIR, base_filename)
        os.makedirs(folder_path, exist_ok=True)

        # Save raw JSON
        with open(os.path.join(folder_path, "raw.json"), "wb") as f:
            f.write(payload_json)

        # Compress
        compressed = zstd.ZstdCompressor().compress(payload_json)
        with open(os.path.join(folder_path, "compressed.zst"), "wb") as f:
            f.write(compressed)

        # Save request body
        with open(os.path.join(folder_path, f"request_body.{ext}"), "wb") as f:
            f.write(raw_body)

        # Compression stats
        orig = len(payload_json)
        comp = len(compressed)
        ratio = comp / orig if orig > 0 else 0
        space_saved = (1 - ratio) * 100 if orig > 0 else 0

        with open(os.path.join(folder_path, "compression_ratio.txt"), "w") as f:
            f.write(f"Original: {orig} bytes\n")
            f.write(f"Compressed: {comp} bytes\n")
            f.write(f"Ratio: {ratio:.4f}\n")
            f.write(f"Space Saved: {space_saved:.2f}%\n")

        encrypted = encrypt_data(compressed)
        response_filename, response_message = send_and_receive_response(flow, encrypted, folder_path)

        # Latency
        latency = (time.time() - start_time) * 1000
        with open(os.path.join(folder_path, "latency_with_proxy.txt"), "w") as f:
            f.write(f"{latency:.2f} ms")

        # Save per-folder result
        results = {
            "timestamp": timestamp,
            "host": host,
            "response_filename": response_filename,
            "response_message": response_message,
            "latency_with_proxy_ms": round(latency, 2),
            "latency_without_proxy_ms": None,
            "original_size_bytes": orig,
            "compressed_size_bytes": comp,
            "compression_ratio": round(ratio, 4),
            "space_saved_percent": round(space_saved, 2)            
        }

        with open(os.path.join(folder_path, "results.json"), "w") as f:
            json.dump(results, f, indent=2)

        append_to_master_results(results)

    except Exception as e:
        print(f"[!] Error in request handler: {e}")
        flow.response = http.Response.make(500, b"Internal proxy error")
