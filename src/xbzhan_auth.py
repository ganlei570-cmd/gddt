import hashlib, json, os, sys, uuid, platform, logging, threading
import requests

SOFT          = "N7vfi8ZKGlXO2SArgC"
SOFT_KEY      = "GC6tgXFhCreKn7s323CLtENVyP4CYsih"
RC4_KEY       = "BzDNbwMVTaVLqEWD4E2ISoA4dn9w0LCyLXfbup9Uj93asD6z"
SIGN_TEMPLATE = "123[data]456[key]789"
VERSION       = "1.0"
API_BASE      = "http://api2.xbzhan.com"
HEARTBEAT_INTERVAL = 120
CACHE_FILE_NAME    = "auth_cache.json"


def _rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)


def _md5(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def _get_device_info() -> dict:
    import socket
    try: hostname = socket.gethostname()
    except: hostname = "unknown"
    try:
        mac_int = uuid.getnode()
        mac_raw = ':'.join(f'{(mac_int >> (8*i)) & 0xff:02x}' for i in range(5, -1, -1))
    except: mac_raw = "00:00:00:00:00:00"
    os_info = platform.platform()
    os_name = f"Windows {platform.version()}" if platform.system() == "Windows" else platform.system()
    return {
        "mac":      _md5(hostname + mac_raw)[:12].upper(),
        "feature":  _md5(hostname + mac_raw + os_info)[:16].upper(),
        "clientid": _md5(hostname + mac_raw)[:18].upper(),
        "clientos": os_name,
    }


def _build_base(device: dict) -> dict:
    return {
        "uuid": uuid.uuid4().hex, "token": uuid.uuid4().hex,
        "clientid": device["clientid"], "version": VERSION,
        "mac": device["mac"], "feature": device["feature"],
        "clientos": device["clientos"], "md5": "",
    }


def _xb_post(path: str, data: dict) -> dict:
    data_json = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    enc_hex   = _rc4(data_json.encode('utf-8'), RC4_KEY.encode('utf-8')).hex()
    sign      = _md5(SIGN_TEMPLATE.replace("[data]", enc_hex).replace("[key]", SOFT_KEY))
    body      = {"soft": SOFT, "data": enc_hex, "sign": sign}
    try:
        resp = requests.post(
            API_BASE + path, data=json.dumps(body),
            headers={"Content-Type": "application/json; charset=utf-8"}, timeout=10
        ).json()
    except Exception as e:
        return {"code": -1, "msg": f"网络错误: {e}"}
    if resp.get("status") != "success":
        return {"code": -1, "msg": f"请求异常: {resp.get('status', '')}"}
    resp_hex = resp.get("data", "")
    if not resp_hex:
        return {"code": -1, "msg": "响应 data 为空"}
    try:
        dec = _rc4(bytes.fromhex(resp_hex), RC4_KEY.encode('utf-8'))
        return json.loads(dec.decode('utf-8'))
    except Exception as e:
        return {"code": -1, "msg": f"解密失败: {e}"}


def _cache_path() -> str:
    base = (os.path.dirname(sys.executable) if getattr(sys, 'frozen', False)
            else os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, CACHE_FILE_NAME)


def load_cached_key() -> str:
    try:
        with open(_cache_path(), 'r', encoding='utf-8') as f:
            return json.load(f).get("card_key", "")
    except: return ""


def save_cached_key(card_key: str):
    try:
        with open(_cache_path(), 'w', encoding='utf-8') as f:
            json.dump({"card_key": card_key}, f)
    except: pass


class XBAuth:
    def __init__(self):
        self._device         = _get_device_info()
        self._card_key       = ""
        self._session_cookie = ""
        self._account        = ""
        self._initialized    = False
        self._hb_stop        = threading.Event()

    def init(self) -> tuple:
        resp = _xb_post("/api/init", _build_base(self._device))
        ok = resp.get("code") == 200 or "成功" in str(resp.get("msg", ""))
        if ok: self._initialized = True
        return ok, resp.get("msg", "未知错误")

    def login(self, card_key: str) -> tuple:
        if not self._initialized:
            ok, msg = self.init()
            if not ok:
                return False, f"初始化失败: {msg}"
        data = _build_base(self._device)
        data["account"] = card_key
        resp = _xb_post("/api/login", data)
        ok = resp.get("code") == 200 or "成功" in str(resp.get("msg", ""))
        if ok:
            self._card_key = card_key
            _r = resp.get("result") or {}
            self._session_cookie = (resp.get("cookie", "")
                                    or _r.get("loginCookie", "")
                                    or resp.get("param", ""))
            self._account = "".join(c for c in card_key if c.isalnum())[:20]
            save_cached_key(card_key)
        return ok, resp.get("msg", "未知错误")

    def start_heartbeat(self):
        self._hb_stop.clear()
        threading.Thread(target=self._hb_loop, daemon=True, name="xb-hb").start()

    def stop_heartbeat(self):
        self._hb_stop.set()

    def _hb_loop(self):
        while not self._hb_stop.wait(HEARTBEAT_INTERVAL):
            try:
                data = _build_base(self._device)
                data["account"] = self._card_key
                data["cookie"]  = self._session_cookie
                resp = _xb_post("/api/heartbeat", data)
                logging.info("[XBAuth] 心跳: %s", resp.get("msg", ""))
            except Exception as e:
                logging.warning("[XBAuth] 心跳异常: %s", e)

    def unbind_all(self, card_key: str = "") -> tuple:
        if not self._initialized: self.init()
        data = _build_base(self._device)
        data["account"] = card_key or self._card_key
        resp = _xb_post("/api/un_bind_all", data)
        ok = resp.get("code") == 200 or "成功" in str(resp.get("msg", ""))
        return ok, resp.get("msg", "未知错误")

    @property
    def card_key(self) -> str: return self._card_key


xb_auth = XBAuth()
