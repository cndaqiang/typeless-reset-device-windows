"""
Shared encryption and signing utilities for Typeless data migration (v1.3.0).

Updated from typeless-migrator for Typeless v1.3.0.98:
- HMAC_KEY and AES_PASSWORD changed
- SM3 hash removed from X-Authorization (p = sha1_hash directly)
- APP_VERSION format unchanged ("mac_1.3.0")

Handles:
- Decrypting electron-store's user-data.json (AES-256-CBC with double PBKDF2)
- Generating API security headers (HMAC-SHA1 + CryptoJS AES)
"""

import base64
import hashlib
import hmac as hmaclib
import json
import os
import platform
import random
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ── App constants (extracted from Typeless v1.3.0 renderer bundle) ──

# From BkwJw9Ll.js: export { ... s as a } where s = "mac_"
VERSION_PREFIX = "mac_"
APP_VERSION_NUM = "1.3.0"
APP_VERSION = f"{VERSION_PREFIX}{APP_VERSION_NUM}"

# From BPn-hrsg.js: Sa = "9088eaec..."
HMAC_KEY = "9088eaec863c54571b4f28f6535b5f2526be3f5015791e659e4bdb31"

# From BPn-hrsg.js: _n = "46d40fe4..."
AES_PASSWORD = "46d40fe4218b857cae25f9c01c2664a98833fc69a0fda798c709fd1f"

ENV = "prod"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Typeless/1.3.0 Chrome/130.0.6723.191 Electron/33.4.11 Safari/537.36"
)
CLIENT_URL = (
    "file:///Applications/Typeless.app/Contents/Resources/"
    "app.asar/dist/renderer/hub.html"
)
API_BASE = "https://api.typeless.com"
TYPELESS_DIR = os.path.expanduser("~/Library/Application Support/Typeless")


# ── electron-store decryption ────────────────────────────────────────


def decrypt_user_data():
    """Decrypt user-data.json and return the parsed userData dict.

    Returns dict with keys: email, access_token, refresh_token, user_id, login_time
    """
    # Derive the master encryption key (same for all users on this platform)
    # Apple Silicon = "darwin-arm64", Intel Mac = "darwin-x64"
    arch = "arm64" if platform.machine() == "arm64" else "x64"
    platform_str = f"darwin-{arch}"
    platform_hash = hashlib.sha256(platform_str.encode()).hexdigest()
    encryption_key = hashlib.pbkdf2_hmac(
        "sha256",
        (platform_hash + "Typeless").encode(),
        b"typeless-user-service",
        10000,
        32,
    )

    path = os.path.join(TYPELESS_DIR, "user-data.json")
    with open(path, "rb") as f:
        raw = f.read()

    iv = raw[:16]
    # Replicate Node.js Buffer.toString('utf-8') behavior:
    # invalid bytes become U+FFFD (3-byte UTF-8 sequence)
    iv_salt = iv.decode("utf-8", errors="replace").encode("utf-8")

    password = hashlib.pbkdf2_hmac("sha512", encryption_key, iv_salt, 10000, 32)
    cipher = AES.new(password, AES.MODE_CBC, iv)
    decrypted = json.loads(unpad(cipher.decrypt(raw[17:]), 16).decode("utf-8"))
    return json.loads(decrypted["userData"])


# ── CryptoJS-compatible AES encryption ───────────────────────────────


def _evp_bytes_to_key(password_bytes, salt, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey (MD5-based key derivation).

    CryptoJS.AES.encrypt uses this by default when given a passphrase string.
    """
    d = b""
    d_i = b""
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password_bytes + salt).digest()
        d += d_i
    return d[:key_len], d[key_len : key_len + iv_len]


def cryptojs_aes_encrypt(plaintext, password):
    """Encrypt like CryptoJS.AES.encrypt(plaintext, password).toString().

    Output format: base64("Salted__" + 8-byte salt + ciphertext)
    """
    salt = os.urandom(8)
    key, iv = _evp_bytes_to_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), 16))
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode()


# ── API security header generation ───────────────────────────────────


def get_device_id():
    """Read the device ID. Tries cache first (no password prompt), then
    app-storage.json, then Keychain as last resort."""

    # Method 1: from device.cache (no password needed, always available)
    cache_path = os.path.expanduser(
        "~/Library/Application Support/now.typeless.desktop/device.cache"
    )
    try:
        with open(cache_path) as f:
            device_id = f.read().strip()
            if device_id:
                return device_id
    except FileNotFoundError:
        pass

    # Method 2: from app-storage.json
    storage_path = os.path.join(TYPELESS_DIR, "app-storage.json")
    try:
        with open(storage_path) as f:
            data = json.load(f)
        device_id = data.get("TYPELESS_DEVICE_ID", "")
        if device_id:
            return device_id
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Method 3: from Keychain (may prompt for system password)
    import subprocess
    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-s",
                "now.typeless.desktop.deviceIdentifier",
                "-a",
                "now.typeless.desktop.security.auth_key",
                "-w",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except FileNotFoundError:
        pass

    return "UNKNOWN"


def build_security_headers(path, user_id, auth_token, device_id=None):
    """Build the full set of HTTP headers including security signing.

    v1.3.0 changes from v1.2.0:
    - HMAC_KEY and AES_PASSWORD changed
    - X-Authorization 'p' field = sha1_hash (no SM3 wrapper)

    Args:
        path: API path (e.g., "/user/dictionary/add")
        user_id: The user's UUID
        auth_token: Bearer token (refresh_token)
        device_id: Optional device UUID; auto-detected if not provided

    Returns:
        dict of HTTP headers ready for requests
    """
    if device_id is None:
        device_id = get_device_id()

    timestamp = int(time.time() * 1000)

    # In v1.3.0, the version format is "mac_1.3.0" (prefix + major version)
    # The major version is extracted: "1.3.0" → "1.3.0" (no change with split)
    # Actually: r = zn + un.split("-")[0] where zn="mac_", un="1.3.0"
    # → r = "mac_1.3.0"
    version = APP_VERSION

    # HMAC-SHA1 signing
    sign_str = f"{timestamp}:{version}:{path}:{user_id}"
    sha1_secret_key = f"{timestamp}:{HMAC_KEY}"
    sha1_hash = hmaclib.new(
        sha1_secret_key.encode(), sign_str.encode(), hashlib.sha1
    ).hexdigest()

    # In v1.3.0: p = sha1_hash directly (no SM3 wrapping like v1.2.0)
    # In v1.2.0: sm3_sign = sm3(f"{timestamp}:{sha1_hash}:{HMAC_KEY}")
    # In v1.3.0: p = sha1_hash

    # X-Authorization encrypted payload
    x_auth_data = {
        "X-Env": ENV,
        "X-Client-Domain": CLIENT_URL,
        "X-Client-Path": CLIENT_URL,
        "X-Random": str(random.randint(100000, 999999)),
        "t": timestamp,
        "p": sha1_hash,
        "d": device_id,
        "3c86e26ccbb7274f752e7d868a1541ebfb7f37e7": {"a": ""},
    }
    x_authorization = cryptojs_aes_encrypt(
        json.dumps(x_auth_data, separators=(",", ":")), AES_PASSWORD
    )

    return {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "X-App-Version": APP_VERSION,
        "X-Authorization": x_authorization,
        "X-Browser-Major": "130",
        "X-Browser-Name": "Chrome",
        "X-Browser-Version": "130.0.6723.191",
        "User-Agent": USER_AGENT,
    }


if __name__ == "__main__":
    # Quick test: decrypt user data and show account info
    user = decrypt_user_data()
    print(f"Email: {user.get('email')}")
    print(f"User ID: {user.get('user_id')}")
    print(f"Token (first 20 chars): {user.get('refresh_token', '')[:20]}...")
    print(f"Device ID: {get_device_id()}")
