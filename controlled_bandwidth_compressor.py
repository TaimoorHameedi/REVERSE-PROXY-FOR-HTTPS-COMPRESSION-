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
import threading
import speedtest

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

UPLOAD_SPEED_FILE = os.path.join(SAVE_DIR, "upload_speed.json")
UPLOAD_CHECK_INTERVAL = 5  # seconds
UPLOAD_THRESHOLD_MBPS = 5.0  # below this → use target domain interception

# Global shared state
cached_upload_speed = 0.0
lock = threading.Lock()


# === ENCRYPTION / DECRYPTION ===
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


# === UTILS ===
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


# === UPLOAD SPEED MONITOR (ASYNC) ===
def test_upload_speed():
    """Run speed test and return upload speed in Mbps"""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        upload_bps = st.upload()
        return upload_bps / 1_000_000  # convert to Mbps
    except Exception:
        return 0.0


def upload_speed_monitor():
    """Continuously measure upload speed asynchronously and cache last good value"""
    global cached_upload_speed
    while True:
        speed = test_upload_speed()
        with lock:
            if speed > 0:
                cached_upload_speed = speed
            # Save to file for persistence
            try:
                with open(UPLOAD_SPEED_FILE, "w") as f:
                    json.dump({"last_speed_mbps": cached_upload_speed}, f)
            except Exception:
                pass
        print(f"[i] Upload speed: {cached_upload_speed:.2f} Mbps")
        time.sleep(UPLOAD_CHECK_INTERVAL)


# === COMMUNICATION WITH REMOTE ===
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

        response_filename = f"response_body.{ext}"
        response_path = os.path.join(folder_path, response_filename)
        with open(response_path, "wb") as f:
            f.write(decoded_body)

        try:
            response_data = json.loads(decoded_body.decode("utf-8", errors="ignore"))
            response_message = response_data.get("message", "N/A")
            response_filename = response_data.get("file", {}).get("filename", "N/A")
        except Exception:
            response_message = "N/A"
            response_filename = "N/A"

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


# === MAIN INTERCEPTOR ===
def request(flow: http.HTTPFlow):
    global cached_upload_speed

    # Use last cached upload speed
    with lock:
        current_speed = cached_upload_speed

    # Load from disk if just started
    if current_speed == 0.0 and os.path.exists(UPLOAD_SPEED_FILE):
        try:
            with open(UPLOAD_SPEED_FILE, "r") as f:
                cached = json.load(f)
                current_speed = cached.get("last_speed_mbps", 0.0)
        except Exception:
            pass

    # === Conditional Interception ===
    if current_speed >= UPLOAD_THRESHOLD_MBPS:
        print(f"[i] Upload speed {current_speed:.2f} Mbps → skipping interception")
        return  # skip, let request go normally

    # Else, apply interception only for target domains
    if flow.request.pretty_host not in TARGET_DOMAINS:
        return

    print(f"[i] Upload speed {current_speed:.2f} Mbps → applying interception")

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

        with open(os.path.join(folder_path, "raw.json"), "wb") as f:
            f.write(payload_json)

        compressed = zstd.ZstdCompressor().compress(payload_json)
        with open(os.path.join(folder_path, "compressed.zst"), "wb") as f:
            f.write(compressed)

        with open(os.path.join(folder_path, f"request_body.{ext}"), "wb") as f:
            f.write(raw_body)

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

        latency = (time.time() - start_time) * 1000
        with open(os.path.join(folder_path, "latency_with_proxy.txt"), "w") as f:
            f.write(f"{latency:.2f} ms")

        results = {
            "timestamp": timestamp,
            "host": host,
            "response_filename": response_filename,
            "response_message": response_message,
            "latency_with_proxy_ms": round(latency, 2),
            "original_size_bytes": orig,
            "compressed_size_bytes": comp,
            "compression_ratio": round(ratio, 4),
            "space_saved_percent": round(space_saved, 2),
            "upload_speed_mbps": round(current_speed, 2)
        }

        with open(os.path.join(folder_path, "results.json"), "w") as f:
            json.dump(results, f, indent=2)

        append_to_master_results(results)

    except Exception as e:
        print(f"[!] Error in request handler: {e}")
        flow.response = http.Response.make(500, b"Internal proxy error")


# === BACKGROUND SPEED TESTER THREAD ===
thread = threading.Thread(target=upload_speed_monitor, daemon=True)
thread.start()

