import os
import json
import base64
import requests
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

app = Flask(__name__)

# ─── Constants ────────────────────────────────────────────────
OAUTH_URL        = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL  = "https://loginbp.ggpolarbear.com/MajorLogin"
TARGET_API_URL   = os.environ.get("TARGET_API_URL", "https://api-otrss.garena.com/support/callback/")
FREEFIRE_VERSION = "OB53"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# ─── Protobuf (lazy init) ─────────────────────────────────────
_proto_initialized = False

def _init_proto():
    global _proto_initialized
    if _proto_initialized:
        return
    DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
        b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01('
        b'\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07'
        b'\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08'
        b' \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18'
        b'\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32'
        b'\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
    )
    _globals = globals()
    _builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
    _builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data1_pb2', _globals)
    if not _descriptor._USE_C_DESCRIPTORS:
        DESCRIPTOR._options = None
        _globals['_DATA']._serialized_start = 15
        _globals['_DATA']._serialized_end   = 202
        _globals['_EMPTYMESSAGE']._serialized_start = 204
        _globals['_EMPTYMESSAGE']._serialized_end   = 218
    _proto_initialized = True

# ─── Helpers ──────────────────────────────────────────────────
def decode_jwt_noverify(token: str):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode())
    except Exception:
        return None

# ─── FIXED: Updated server URLs to match BIOTOOL (ggpolarbear for BD/SG/EU) ──
SERVERS = {
    "IND": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo",
    "BD":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "SG":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
    "BR":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "US":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "NA":  "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "SAC": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo",
    "EU":  "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo",
}

def get_bio_server_url(lock_region: str):
    return SERVERS.get(lock_region.upper(), "https://clientbp.ggpolarbear.com/UpdateSocialBasicInfo")

def build_encrypted_bio_payload(bio_text: str) -> bytes:
    _init_proto()
    sym_db       = _symbol_database.Default()
    Data         = sym_db.GetSymbol('Data')
    EmptyMessage = sym_db.GetSymbol('EmptyMessage')
    data = Data()
    data.field_2 = 17
    data.field_5.CopyFrom(EmptyMessage())
    data.field_6.CopyFrom(EmptyMessage())
    data.field_8 = bio_text
    data.field_9 = 1
    data.field_11.CopyFrom(EmptyMessage())
    data.field_12.CopyFrom(EmptyMessage())
    raw    = data.SerializeToString()
    padded = pad(raw, AES.block_size)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(padded)

def ff_headers(token: str) -> dict:
    return {
        "Expect":          "100-continue",
        "Authorization":   f"Bearer {token}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA":            "v1 1",
        "ReleaseVersion":  FREEFIRE_VERSION,
        "Content-Type":    "application/x-www-form-urlencoded",
        "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
    }

# ─── FIXED: Direct Garena OAuth → JWT (replaces broken 3rd-party JWT API) ────
def garena_guest_login(uid: str, password: str):
    """Step 1: Get Garena access_token + open_id via guest OAuth."""
    payload = {
        "uid":           uid,
        "password":      password,
        "response_type": "token",
        "client_type":   "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id":     "100067",
    }
    headers = {
        "User-Agent":      "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        "Connection":      "Keep-Alive",
        "Content-Type":    "application/x-www-form-urlencoded",
    }
    resp = requests.post(OAUTH_URL, data=payload, headers=headers, timeout=15, verify=False)
    resp.raise_for_status()
    d = resp.json()
    access_token = d.get("access_token")
    open_id      = d.get("open_id")
    if not access_token or not open_id:
        raise ValueError(f"OAuth failed: {d}")
    return access_token, open_id

def garena_major_login(access_token: str, open_id: str) -> str:
    """Step 2: MajorLogin → get Free Fire JWT token."""
    import my_pb2, output_pb2

    LOGIN_HEADERS = {
        "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type":    "application/octet-stream",
        "Expect":          "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA":            "v1 1",
        "ReleaseVersion":  FREEFIRE_VERSION,
    }

    for p_type in [8, 3, 4, 6]:
        try:
            gd = my_pb2.GameData()
            gd.timestamp        = "2024-12-05 18:15:32"
            gd.game_name        = "free fire"
            gd.game_version     = 1
            gd.version_code     = "1.108.3"
            gd.os_info          = "Android OS 9 / API-28"
            gd.device_type      = "Handheld"
            gd.network_provider = "Verizon Wireless"
            gd.connection_type  = "WIFI"
            gd.screen_width     = 1280
            gd.screen_height    = 960
            gd.dpi              = "240"
            gd.cpu_info         = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
            gd.total_ram        = 5951
            gd.gpu_name         = "Adreno (TM) 640"
            gd.gpu_version      = "OpenGL ES 3.0"
            gd.user_id          = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
            gd.ip_address       = "172.190.111.97"
            gd.language         = "en"
            gd.open_id          = open_id
            gd.access_token     = access_token
            gd.platform_type    = p_type
            gd.field_99         = str(p_type)
            gd.field_100        = str(p_type)

            cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
            enc = cipher.encrypt(pad(gd.SerializeToString(), AES.block_size))

            resp = requests.post(MAJOR_LOGIN_URL, data=enc, headers=LOGIN_HEADERS,
                                 verify=False, timeout=15)
            if resp.status_code == 200:
                msg = output_pb2.Garena_420()
                msg.ParseFromString(resp.content)
                if msg.token:
                    return msg.token
        except Exception:
            continue
    raise ValueError("MajorLogin failed for all platform types")

# ─── Routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ─── FIXED: /api/get-jwt now uses direct Garena OAuth (no broken 3rd-party API) ──
@app.route("/api/get-jwt", methods=["POST"])
def get_jwt():
    data = request.get_json(force=True)
    uid  = data.get("uid", "").strip()
    pwd  = data.get("password", "").strip()
    if not uid or not pwd:
        return jsonify({"ok": False, "msg": "UID and Password required"}), 400
    try:
        access_token, open_id = garena_guest_login(uid, pwd)
        jwt_token = garena_major_login(access_token, open_id)
        return jsonify({"ok": True, "token": jwt_token})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/api/eat-to-access", methods=["POST"])
def eat_to_access():
    data      = request.get_json(force=True)
    eat_token = data.get("eat_token", "").strip()
    if not eat_token:
        return jsonify({"ok": False, "msg": "EAT token required"}), 400
    try:
        sess = requests.Session()
        resp = sess.get(TARGET_API_URL, params={"access_token": eat_token},
                        allow_redirects=False, timeout=15)
        while resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                break
            if not loc.startswith(("http://", "https://")):
                base = urlparse(TARGET_API_URL)
                loc  = base._replace(path=loc).geturl()
            resp = sess.get(loc, allow_redirects=False, timeout=15)
        parsed = urlparse(resp.url)
        qp     = parse_qs(parsed.query)
        at     = qp.get("access_token", [None])[0]
        if not at:
            return jsonify({"ok": False, "msg": "Access token not found in redirect"}), 500
        return jsonify({"ok": True, "access_token": at})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/api/update-bio/jwt", methods=["POST"])
def update_bio_jwt():
    data  = request.get_json(force=True)
    token = data.get("jwt_token", "").strip()
    bio   = data.get("bio", "").strip()
    if not token or not bio:
        return jsonify({"ok": False, "msg": "JWT token and bio required"}), 400

    payload     = decode_jwt_noverify(token)
    lock_region = (payload or {}).get("lock_region", "IND")
    url_bio     = get_bio_server_url(lock_region)

    try:
        encrypted = build_encrypted_bio_payload(bio)
        r = requests.post(url_bio, headers=ff_headers(token),
                          data=encrypted, timeout=15, verify=False)
        if r.status_code == 200:
            return jsonify({"ok": True, "msg": "Bio updated successfully!",
                            "lock_region": lock_region})
        return jsonify({"ok": False,
                        "msg": f"Server error {r.status_code}: {r.text[:200]}",
                        "lock_region": lock_region}), 400
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route("/api/update-bio/access", methods=["POST"])
def update_bio_access():
    data  = request.get_json(force=True)
    token = data.get("access_token", "").strip()
    bio   = data.get("bio", "").strip()
    if not token or not bio:
        return jsonify({"ok": False, "msg": "Access token and bio required"}), 400

    lock_region = data.get("region", "BD").upper()
    url_bio     = get_bio_server_url(lock_region)

    try:
        encrypted = build_encrypted_bio_payload(bio)
        r = requests.post(url_bio, headers=ff_headers(token),
                          data=encrypted, timeout=15, verify=False)
        if r.status_code == 200:
            return jsonify({"ok": True, "msg": "Bio updated successfully!",
                            "lock_region": lock_region})
        return jsonify({"ok": False,
                        "msg": f"Server error {r.status_code}: {r.text[:200]}",
                        "lock_region": lock_region}), 400
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

# ─── FIXED: New endpoint — update bio directly with UID+Password in one shot ──
@app.route("/api/update-bio/uid", methods=["POST"])
def update_bio_uid():
    data = request.get_json(force=True)
    uid  = data.get("uid", "").strip()
    pwd  = data.get("password", "").strip()
    bio  = data.get("bio", "").strip()
    if not uid or not pwd or not bio:
        return jsonify({"ok": False, "msg": "UID, Password and bio required"}), 400
    try:
        access_token, open_id = garena_guest_login(uid, pwd)
        jwt_token = garena_major_login(access_token, open_id)
        payload     = decode_jwt_noverify(jwt_token)
        lock_region = (payload or {}).get("lock_region", "BD")
        url_bio     = get_bio_server_url(lock_region)
        encrypted   = build_encrypted_bio_payload(bio)
        r = requests.post(url_bio, headers=ff_headers(jwt_token),
                          data=encrypted, timeout=15, verify=False)
        if r.status_code == 200:
            return jsonify({"ok": True, "msg": "Bio updated successfully!",
                            "lock_region": lock_region})
        return jsonify({"ok": False,
                        "msg": f"Server error {r.status_code}: {r.text[:200]}",
                        "lock_region": lock_region}), 400
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 500

# ─── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 11130)))
