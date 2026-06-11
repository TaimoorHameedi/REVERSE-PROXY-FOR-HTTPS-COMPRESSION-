# server.py
# Simple Flask upload endpoint. Run this locally:
#   python3 server.py
# then expose with ngrok:
#   ngrok http 8081
#
# The client should POST to https://<your-ngrok>.ngrok-free.app/upload

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import time

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/upload", methods=["POST"])
def upload():
    start = time.time()
    message = request.form.get("message")
    f = request.files.get("file")
    if not f:
        return jsonify({"ok": False, "error": "no file provided"}), 400

    filename = f.filename
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    f.save(save_path)
    latency_ms = round((time.time() - start) * 1000, 2)

    # Return basic info back to client
    return jsonify({
        "ok": True,
        "filename": filename,
        "saved_to": save_path,
        "message": message,
        "server_latency_ms": latency_ms
    })

if __name__ == "__main__":
    # listen on all interfaces so ngrok can reach it
    app.run(host="0.0.0.0", port=8081, debug=True)
