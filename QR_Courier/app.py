import os, json, base64, re
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# Set this on Railway as an environment variable
PASSPHRASE = os.getenv("SECRET_PASSPHRASE", "CHANGE-ME").encode()

B64URL_RE = re.compile(r'^[A-Za-z0-9\-_]+$')

def b64url_decode(s: str) -> bytes:
    # Add required '=' padding for urlsafe_b64decode
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/decrypt")
def decrypt():
    data = request.get_json(silent=True) or {}
    enc = data.get("encoded", "")

    try:
        if not enc.startswith("ENCQR."):
            return jsonify({"ok": False, "error": "Invalid payload prefix"}), 400

        # Decode outer base64url to JSON
        tail = enc.split("ENCQR.", 1)[1]
        outer_json = json.loads(b64url_decode(tail))

        # Basic validation
        for key in ["salt", "iv", "ct"]:
            if key not in outer_json or not isinstance(outer_json[key], str) or not B64URL_RE.match(outer_json[key]):
                return jsonify({"ok": False, "error": f"Malformed field: {key}"}), 400

        iterations = int(outer_json.get("iter", 150000))
        salt = b64url_decode(outer_json["salt"])
        iv = b64url_decode(outer_json["iv"])
        ct = b64url_decode(outer_json["ct"])  # AESGCM encrypt returned ct||tag in our generator

        # Derive key via PBKDF2-SHA256
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
        key = kdf.derive(PASSPHRASE)

        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ct, None)
        obj = json.loads(plaintext.decode("utf-8"))

        return jsonify({"ok": True, "data": obj})

    except Exception as e:
        # Don’t leak internal errors; return a friendly message
        return jsonify({"ok": False, "error": "Decryption failed or QR not recognized"}), 400

if __name__ == "__main__":
    # Railway provides PORT; default to 8000 for local
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
