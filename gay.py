import asyncio, aiohttp, json, socket, time, struct, re, uuid, random, requests
import threading, os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request as flask_request
import blackboxprotobuf as pb
import pytz as _pytz

# AES fallback cho iOS/a-Shell
try:
    from Crypto.Cipher import AES as _AES
    from Crypto.Util.Padding import pad as _pad

    class AESCipher:
        def __init__(self, key: bytes, iv: bytes):
            self.key = key
            self.iv  = iv
        def enc(self, data: bytes) -> bytes:
            return _AES.new(self.key, _AES.MODE_CBC, self.iv).encrypt(_pad(data, 16))
except ImportError:
    import pyaes

    class AESCipher:
        def __init__(self, key: bytes, iv: bytes):
            self.key = key
            self.iv  = iv
        def enc(self, data: bytes) -> bytes:
            pad_len = 16 - (len(data) % 16)
            data = data + bytes([pad_len]) * pad_len
            return pyaes.AESModeOfOperationCBC(self.key, self.iv).encrypt(data)


# ══════════════════════════════ CONFIG ══════════════════════════════
DB_FILE      = "accounts.txt"  # GỘP CHUNG 1 FILE DUY NHẤT
INDEX_FILE   = "accsIndex.txt"

AUTH_CONCURRENCY = 40
AUTH_JITTER      = (0.05, 0.20)
REQUEST_TIMEOUT  = 30
CONNECTION_LIMIT = 500

DEFAULT_AUTO_RESET_TOKEN_TIME = "05:00"   # HH:MM (Asia/Ho_Chi_Minh)
# ════════════════════════════════════════════════════════════════════

app = Flask(__name__)

state_lock = threading.Lock()
state = {
    "tokens": [],
    "accs_count": 0,
    "no_accs": False,
    "auto_reset_token_time": DEFAULT_AUTO_RESET_TOKEN_TIME,
    "started_ts": time.time(),
    "last_reset_ts": None,
}


# ───────────────────────────── helpers ──────────────────────────────
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        if result.wire_type in ("varint", "string", "bytes"):
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        else:
            field_data = result.data
        result_dict[result.field].append(field_data)
    return {k: v[0] if len(v) == 1 else v for k, v in result_dict.items()}


def Varint(value: int) -> bytes:
    value &= 0xFFFFFFFFFFFFFFFF
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


class PBE:
    def CVF(self, field, value):
        return Varint((field << 3) | 0) + Varint(value)

    def CLF(self, field, value):
        v = value.encode() if isinstance(value, str) else value
        return Varint((field << 3) | 2) + Varint(len(v)) + v

    def decode(self, data):
        fields, _ = pb.decode_message(data)
        inner = fields.get('1') or fields.get(1)
        if isinstance(inner, bytes):
            try:
                fields, _ = pb.decode_message(inner)
            except Exception:
                pass
        return fields

    def encode(self, fields: dict) -> bytes:
        packet = bytearray()
        for field, value in fields.items():
            field = int(field)
            values = value if isinstance(value, list) else [value]
            for item in values:
                if isinstance(item, dict):
                    packet.extend(self.CLF(field, self.encode(item)))
                elif isinstance(item, int):
                    packet.extend(self.CVF(field, item))
                elif isinstance(item, (str, bytes)):
                    packet.extend(self.CLF(field, item))
                else:
                    raise TypeError(f"Unsupported type: {type(item)}")
        return bytes(packet)


def random_android_os() -> str:
    versions = [
        (12, "SP1A", "210812.016", "Q"),
        (11, "RP1A", "200720.011", "R"),
        (13, "TP1A", "221005.002", "T"),
        (10, "QP1A", "190711.020", "Q"),
    ]
    v = random.choice(versions)
    gdpr_date = (
        f"GDPR.{random.randint(2021, 2023)}"
        f"{random.randint(1, 12):02}{random.randint(1, 28):02}"
        f"{random.randint(10, 23):02}{random.randint(10, 59):02}"
        f"{random.randint(10, 59):02}"
    )
    return f"Android OS {v[0]} / API-{30 + v[0] - 10} ({v[1]}.{v[2]}.016/{v[3]}.{gdpr_date})"


def random_opengl() -> str:
    minor = random.randint(1, 2)
    v2 = random.randint(20, 45)
    patch = ''.join(random.choices('abcdef0123456789', k=8))
    hash_str = ''.join(random.choices('abcdef0123456789', k=32))
    return f"OpenGL ES 3.{minor} v1.r{v2}p1-01eac0.{patch}{hash_str[:24]}"


def random_google_uuid() -> str:
    return f"Google|{uuid.uuid4()}"


def random_device() -> str:
    model_map = {
        "OPPO":    ["CPH2161", "CPH2219", "CPH2251", "CPH2357", "CPH2385"],
        "Samsung": ["SM-G991B", "SM-A525F", "SM-S908B", "SM-A135F"],
        "Xiaomi":  ["2201123G", "22111317I", "2107113SG", "21121119SC"],
        "Realme":  ["RMX3301", "RMX3085", "RMX3471", "RMX2001"],
        "Vivo":    ["V2109", "V2111", "V2205", "V2145"],
    }
    brand = random.choice(list(model_map))
    return f"{brand} {random.choice(model_map[brand])}"


def generate_device_info() -> dict:
    return {
        "android_os": random_android_os(),
        "opengl":     random_opengl(),
        "google_uid": random_google_uuid(),
        "device":     random_device(),
    }


sapp = lambda pkg: (
    (re.findall(r'\[\[\["(\d+\.\d+\.\d+)"\]\]',
                requests.get("https://play.google.com/store/apps/%s" % pkg).text)
     or [None])[0]
)

common = lambda ver: (
    (lambda v: requests.get(
        "https://version.common.redflamenco.com/live/ver.php"
        "?version=%s&lang=vi&device=android&region=VN" % v
    ).json())(ver or sapp("details?id=com.dts.freefireth"))
)

redflamenco = common(sapp("details?id=com.dts.freefireth"))
proto = PBE()


# ─────────────────────────── HTTP client ────────────────────────────
class HTTPRequest:
    def __init__(self, region: str = "vn", session: aiohttp.ClientSession | None = None):
        self.language = region
        self.auth_res: dict = {}
        self.base_url        = redflamenco["server_url"]
        self.client_version  = redflamenco["remote_version"]
        self.release_version = redflamenco["latest_release_version"]
        self._session: aiohttp.ClientSession | None = session
        self._owns_session = False
        self.cipher = AESCipher(
            bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56]),
            bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37]),
        )
        self.ip = socket.inet_ntoa(struct.pack(">I", random.randint(*random.choice(
            [(0x0EA00001, 0x0EBFFFFE), (0x76440001, 0x7647FFFE)]
        ))))

    def BaseHeader(self) -> dict:
        h = {}
        h["User-Agent"] = "UnityPlayer/2022.3.47f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
        h["Accept"] = "*/*"
        h["Accept-Encoding"] = "gzip, br"
        h["Cf-Visitor"] = '{"scheme":"https"}'
        h["X-Ga"] = "v1 1"
        h["X-Unity-Version"] = "2022.3.47f1"
        h["Content-Type"] = "application/x-www-form-urlencoded"
        h["Releaseversion"] = self.release_version
        h["X-Forwarded-For"] = self.ip
        h["X-Real-IP"] = self.ip
        h["Client-IP"] = self.ip
        h["X-GA-SV"] = str(int(time.time()))
        return h

    async def __aenter__(self):
        if self._session is None:
            connector = aiohttp.TCPConnector(
                limit=CONNECTION_LIMIT,
                limit_per_host=CONNECTION_LIMIT,
                ttl_dns_cache=300,
                force_close=False,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            )
            self._owns_session = True
        return self

    async def __aexit__(self, *_):
        if self._owns_session and self._session:
            await self._session.close()
            self._session = None

    async def auth_guest_token(self, uid: str, password: str):
        url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
        payload = {
            "uid": int(uid),
            "password": password,
            "response_type": "token",
            "client_type": 1,
            "client_id": 100067,
            "client_secret": bytes([
                50, 101, 101, 52, 52, 56, 49, 57, 101, 57, 98, 52, 53, 57, 56, 56, 52, 53, 49, 52, 49, 48, 54, 55,
                98, 50, 56, 49, 54, 50, 49, 56, 55, 52, 100, 48, 100, 53, 100, 55, 97, 102, 57, 100, 56, 102, 55,
                101, 48, 48, 99, 49, 101, 53, 52, 55, 49, 53, 98, 55, 100, 49, 101, 51,
            ]).decode(),
        }
        headers = {
            'User-Agent': "GarenaMSDK/4.0.44(TEST-XIAOMI-037 ;Android 13;en;HK;app 1.132.1 2019121227;)",
            'Connection': "Keep-Alive",
            'Accept': "application/json",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/json; charset=utf-8",
        }
        async with self._session.post(url, json=payload, headers=headers) as resp:
            data = await resp.json(content_type=None)
        if not data["data"].get("access_token"):
            raise ValueError("ERR_ACCOUNT_NOT_FOUND")
        self.auth_res = data["data"]

    def _login_fields(self) -> dict:
        did, ar = generate_device_info(), self.auth_res
        return {
            '100': str(ar.get("platform")),
            '102': b'KS\x11\x15XU\x0bUf',
            '104': 83297,
            '105': 1,
            '106': b'https://dl.ak.freefiremobile.com/live/ABHotUpdates/|https://core-ak.'
                   b'freefiremobile.com/live/ABHotUpdates/|211c933168f55902c7dfbfd8c4e295'
                   b'7d',
            '107': b'c8e41b7a93f02d56e1a94c7b8203f5d1',
            '11': b'WIFI',
            '12': 1666,
            '13': 750,
            '14': b'480',
            '15': b'ARM64 FP ASIMD AES | 2000 | 8',
            '16': 7535,
            '17': b'Mali-G57 MC3',
            '18': did["opengl"],
            '19': did["google_uid"],
            '20': self.ip,
            '21': self.language,
            '22': ar.get("open_id"),
            '23': str(ar.get("main_active_platform")),
            '24': 'Handheld',
            '25': did["device"],
            '26': 'VN',
            '29': ar.get("access_token"),
            '3': time.strftime("%Y-%m-%d %H:%M:%S"),
            '30': 1,
            '4': b'free fire',
            '42': b'WIFI',
            '5': 1,
            '57': b'7428b253defc164018c604a1ebbfebdf',
            '60': 111125,
            '61': 56494,
            '62': 646,
            '64': 56712,
            '65': 111125,
            '66': 56712,
            '67': 111125,
            '7': self.client_version,
            '73': 1,
            '74': b'/data/app/~~h0JP-7-LHRc8iezKCTZQYQ==/com.dts.freefireth-rdQdDZibr0Yk'
                   b'riX7zeYmew==/lib/arm64',
            '76': 1,
            '77': b'b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~h0JP-7-LHRc8iezKCTZQYQ='
                   b'=/com.dts.freefireth-rdQdDZibr0YkriX7zeYmew==/base.apk',
            '78': 3,
            '79': 2,
            '8': did["android_os"],
            '81': b'64',
            '83': b'2019121229',
            '85': 3,
            '86': b'OpenGLES2',
            '87': 4095,
            '88': 4,
            '9': b'Handheld',
            '92': 8288,
            '93': b'android',
            '94': b'KqsHT4jYHMuXpNnqCxMrcpvAA7VRIqzcddnQLgUv22cgjJmRn03mZIsMfmujKufoEieX'
                   b'Y4lZEMaea8FznYlJ7PciWLa+IjupG1nK71uk3O5woF6U',
            '95': 111207,
            '96': b'{"cur_rate":[60,90],"support_etc2":false}',
            '97': 1,
            '99': str(ar.get("platform")),
        }

    async def MajorLogin(self) -> bytes:
        x = self.cipher.enc(proto.encode(self._login_fields()))
        async with self._session.post(
            self.base_url + "MajorLogin", data=x, headers=self.BaseHeader()
        ) as r:
            return await r.read()

    async def GetPlayerBriefInfo(self, cid: int, token: str) -> bytes:
        headers = self.BaseHeader()
        headers["Authorization"] = f"Bearer {token}"
        async with self._session.post(
            "https://clientbp.ppmainecoonghj.com/GetAccountInfoByAccountID",
            data=self.cipher.enc(proto.encode({1: cid, 2: 1})),
            headers=headers,
        ) as r:
            return await r.read()

    async def LikeProfile(self, cid: int, token: str) -> bytes:
        headers = self.BaseHeader()
        headers["Authorization"] = f"Bearer {token}"
        async with self._session.post(
            "https://clientbp.ppmainecoonghj.com/LikeProfile",
            data=self.cipher.enc(proto.encode({1: cid, 2: 1})),
            headers=headers,
        ) as r:
            return await r.read()


# ─────────────────────────── account IO ─────────────────────────────
def read_accounts(filepath: str) -> list:
    accs = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    uid, pwd = line.split(":", 1)
                    accs.append((uid.strip(), pwd.strip()))
    except FileNotFoundError:
        pass
    return accs


def save_index():
    with open(INDEX_FILE, "w") as f:
        f.write(f"AccsCount: {state['accs_count']}\n")
        f.write(f"SavedAt: {time.time()}\n")
        f.write(f"AutoResetTokenTime: {state['auto_reset_token_time']}\n")
        if state["last_reset_ts"]:
            f.write(f"LastResetTs: {state['last_reset_ts']}\n")


def load_index():
    try:
        auto_time = None
        last_reset = None
        accs_count = 0
        with open(INDEX_FILE, "r") as f:
            for line in f:
                if line.startswith("AutoResetTokenTime:"):
                    auto_time = line.split(":", 1)[1].strip()
                elif line.startswith("LastResetTs:"):
                    last_reset = float(line.split(":", 1)[1].strip())
                elif line.startswith("AccsCount:"):
                    accs_count = int(line.split(":")[1].strip())
        if auto_time:
            state["auto_reset_token_time"] = auto_time
        state["last_reset_ts"] = last_reset
        state["accs_count"] = accs_count
        save_index()
    except FileNotFoundError:
        save_index()


# ───────────────────── load ALL tokens (1 file) ─────────────────────
async def _load_all_tokens(all_accs: list) -> list:
    if not all_accs:
        return []

    sem = asyncio.Semaphore(AUTH_CONCURRENCY)
    connector = aiohttp.TCPConnector(
        limit=AUTH_CONCURRENCY + 10,
        limit_per_host=AUTH_CONCURRENCY + 10,
        ttl_dns_cache=300,
    )
    async with aiohttp.ClientSession(connector=connector) as shared_session:
        async def _auth_one(uid: str, pwd: str):
            async with sem:
                try:
                    await asyncio.sleep(random.uniform(*AUTH_JITTER))
                    req = HTTPRequest(region="vn", session=shared_session)
                    await req.auth_guest_token(uid, pwd)
                    lr = await req.MajorLogin()
                    token = proto.decode(lr[64:])["8"].decode()
                    return (uid, token)
                except Exception:
                    return (uid, None)

        results = await asyncio.gather(*[_auth_one(u, p) for u, p in all_accs])

    return [(u, t) for u, t in results if t]


_refresh_lock = None


async def refresh_all_tokens():
    global _refresh_lock
    if _refresh_lock is None:
        _refresh_lock = asyncio.Lock()

    async with _refresh_lock:
        with state_lock:
            state["no_accs"] = False

        all_accs = read_accounts(DB_FILE)

        if not all_accs:
            print(f"[TOKENS] ⚠️ Không có acc nào trong {DB_FILE}")
            with state_lock:
                state["tokens"] = []
                state["no_accs"] = True
            return

        print(f"[TOKENS] Auth {len(all_accs)} accs từ {DB_FILE}...")
        t0 = time.time()
        tokens = await _load_all_tokens(all_accs)
        elapsed = time.time() - t0

        with state_lock:
            state["tokens"] = tokens
            state["no_accs"] = (len(tokens) == 0)
            state["last_reset_ts"] = time.time()
        save_index()

        print(f"[TOKENS] ✅ {len(tokens)}/{len(all_accs)} OK — {elapsed:.1f}s")


# ───────────────────── token auto-reset scheduler ────────────────────
def _next_hhmm_ts(hhmm: str) -> float:
    h, m = map(int, hhmm.split(":"))
    vn_tz = _pytz.timezone("Asia/Ho_Chi_Minh")
    now = datetime.now(vn_tz)
    nxt = vn_tz.localize(datetime(now.year, now.month, now.day, h, m, 0))
    if nxt <= now:
        nxt += timedelta(days=1)
    return nxt.timestamp()


async def token_schedule_loop():
    while True:
        with state_lock:
            tstr = state["auto_reset_token_time"]
        try:
            next_ts = _next_hhmm_ts(tstr)
        except Exception as e:
            print(f"[SCHED] Giờ không hợp lệ {tstr!r}: {e} → sleep 60s")
            await asyncio.sleep(60)
            continue

        wait_secs = max(1.0, next_ts - time.time())
        vn_tz = _pytz.timezone("Asia/Ho_Chi_Minh")
        print(f"[SCHED] Auto reset token kế tiếp: {tstr} "
              f"({datetime.fromtimestamp(next_ts, vn_tz).strftime('%Y-%m-%d %H:%M:%S')}) "
              f"— còn {int(wait_secs)}s")
        try:
            await asyncio.sleep(wait_secs)
        except asyncio.CancelledError:
            raise

        print(f"[SCHED] 🔄 Auto reset token @ "
              f"{datetime.now(vn_tz).strftime('%Y-%m-%d %H:%M:%S')}")
        try:
            await refresh_all_tokens()
        except Exception as e:
            print(f"[SCHED] ❌ Lỗi: {e}")


_token_sched_task = None


async def _restart_token_schedule():
    global _token_sched_task
    if _token_sched_task and not _token_sched_task.done():
        _token_sched_task.cancel()
        try:
            await _token_sched_task
        except (asyncio.CancelledError, Exception):
            pass
    _token_sched_task = asyncio.create_task(token_schedule_loop())


_async_loop = None


def rasc(loop):
    asyncio.set_event_loop(loop)
    loop.run_forever()


def _submit(coro):
    return asyncio.run_coroutine_threadsafe(coro, _async_loop).result()


# ────────────────────────────── Flask API ───────────────────────────
@app.route("/LikeProfile")
def v1Likes():
    uid_str = flask_request.args.get("uid")
    if not uid_str or not uid_str.isdigit():
        return "INVALID_ACCOUNT", 400
    uid = int(uid_str)

    with state_lock:
        if state["no_accs"] or not state["tokens"]:
            return "SERVICE_NOT_AVAILABLE", 503
        tokens_snapshot = list(state["tokens"])

    async def _do_all():
        async with HTTPRequest(region="vn") as req:
            try:
                raw_before = await req.GetPlayerBriefInfo(uid, tokens_snapshot[0][1])
                info = proto.decode(raw_before)
                nickname     = info.get("3",  b"").decode()
                region       = info.get("5",  b"").decode()
                likes_before = info.get("21", 0)
            except Exception:
                return 0, 0, 0, 0

            like_sem = asyncio.Semaphore(AUTH_CONCURRENCY)

            async def _one_like(token: str):
                async with like_sem:
                    try:
                        return await req.LikeProfile(uid, token)
                    except Exception:
                        return None

            await asyncio.gather(*[_one_like(t) for _, t in tokens_snapshot])

            try:
                raw_after = await req.GetPlayerBriefInfo(uid, tokens_snapshot[0][1])
                likes_after = proto.decode(raw_after).get("21", 0)
            except Exception:
                likes_after = likes_before

        return nickname, region, likes_before, likes_after

    nickname, region, likesBefore, likesAfter = _submit(_do_all())
    if not nickname:
        return "INVALID_ACCOUNT", 400

    LikesAdded = likesAfter - likesBefore
    with state_lock:
        state["accs_count"] += 1
    save_index()

    return {
        "NickName":    nickname,
        "LikesBefore": likesBefore,
        "LikesAfter":  likesAfter,
        "UserID":      uid,
        "Region":      region,
        "Added":       LikesAdded,
    }, 200


# ────────────────────────────── bootstrap ───────────────────────────
if __name__ == "__main__":
    load_index()
    print(f"[CFG] AUTH_CONCURRENCY={AUTH_CONCURRENCY}")
    print(f"[CFG] AutoResetTokenTime={state['auto_reset_token_time']} (Asia/Ho_Chi_Minh)")

    asyncLoop = asyncio.new_event_loop()
    _async_loop = asyncLoop
    threading.Thread(target=rasc, args=(asyncLoop,), daemon=True).start()

    while not asyncLoop.is_running():
        time.sleep(0.3)

    # 1) Load token lần đầu
    asyncio.run_coroutine_threadsafe(refresh_all_tokens(), asyncLoop)

    # 2) Auto-reset theo giờ HH:MM
    asyncio.run_coroutine_threadsafe(_restart_token_schedule(), asyncLoop)

    # 3) Flask API — bind 127.0.0.1 cho iOS
    app.run(host="127.0.0.1", port=2001, debug=False, use_reloader=False)