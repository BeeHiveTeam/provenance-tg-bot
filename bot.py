#!/usr/bin/env python3
"""
provenance-tg-bot — Telegram monitoring bot for the Provenance validator on ovh-117-52.

Pure stdlib. Single-threaded loop: long-polls Telegram for commands +
periodic health checks with push alerts on state change.

Validator-aware: tracks jail status, missed blocks vs the slashing window,
voting power, sync, peers, the provenanced service, and disk.

Config: /opt/provenance-tg-bot/config.env   State: /opt/provenance-tg-bot/state.json
Runs as root (systemctl/journalctl/df + provenanced query). Read-only.
"""
import calendar, json, os, re, ssl, subprocess, sys, time, urllib.parse, urllib.request

CFG_PATH   = "/opt/provenance-tg-bot/config.env"
STATE_PATH = "/opt/provenance-tg-bot/state.json"
SERVICE = "provenanced"
HOST = os.uname().nodename

def load_cfg():
    cfg = {}
    try:
        with open(CFG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1); cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg

CFG = load_cfg()
TOKEN   = CFG.get("BOT_TOKEN", "").strip()
ALLOWED = set(x.strip() for x in CFG.get("ALLOWED_CHAT_IDS", "").split(",") if x.strip())
RPC      = CFG.get("RPC_URL", "http://localhost:26657").rstrip("/")
HOME_DIR = CFG.get("HOME_DIR", "/home/provenance/.provenanced")
VALCONS  = CFG.get("VALCONS", "").strip()
CHECK_INTERVAL = int(CFG.get("CHECK_INTERVAL", "60"))
DISK_WARN_PCT  = int(CFG.get("DISK_WARN_PCT", "85"))
MISSED_WARN    = int(CFG.get("MISSED_WARN", "500"))
STALL_TICKS    = int(CFG.get("STALL_TICKS", "3"))   # тиков подряд без роста высоты до алерта
MISSED_CRIT    = int(CFG.get("MISSED_CRIT", "1500"))
# Окно slashing и порог джейла Provenance. Раньше 34560/1728 были вписаны прямо в четыре
# строки сообщений, поэтому при смене параметров сети текст соврал бы, а код продолжил
# работать по своим порогам — расхождение, которое никто не заметит.
SLASH_WINDOW = int(os.environ.get("SLASH_WINDOW", "34560"))
JAIL_THRESHOLD = int(os.environ.get("JAIL_THRESHOLD", "1728"))
# Минимальный интервал между алертами «активно пропускает блоки», сек (см. monitor()).
MISSED_ALERT_MIN_GAP = int(CFG.get("MISSED_ALERT_MIN_GAP", "900"))
# Сколько циклов подряд signing-info должна быть недоступна, прежде чем это станет алертом.
# Не 1: одиночный таймаут RPC — обычное дело и алертом быть не должен.
SIGNING_FAIL_ALERT_TICKS = int(os.environ.get("SIGNING_FAIL_ALERT_TICKS", "3"))
PEERS_FAIL_ALERT_TICKS = int(os.environ.get("PEERS_FAIL_ALERT_TICKS", "5"))
PEERS_MIN      = int(CFG.get("PEERS_MIN", "3"))
LAG_WARN       = int(CFG.get("BLOCK_LAG_WARN_SEC", "30"))
PENDING_MAX     = int(CFG.get("PENDING_MAX", "50"))      # максимум недоставленных алертов
PENDING_TTL_SEC = int(CFG.get("PENDING_TTL_SEC", "21600"))  # 6ч: позже алерт неактуален
API = "https://api.telegram.org/bot%s/" % TOKEN
SSLCTX = ssl.create_default_context()

# ---------- telegram ----------
def tg(method, params=None, timeout=35):
    data = urllib.parse.urlencode(params or {}).encode()
    req = urllib.request.Request(API + method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSLCTX) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        # тело ошибки Telegram содержит error_code/description — отдаём наверх,
        # чтобы отличать "колбэк протух" (400) от сетевых сбоев (None)
        try:
            body = json.load(e)
        except Exception:
            body = {"ok": False, "error_code": e.code}
        sys.stderr.write("tg %s error: %s %s\n" % (method, e, body.get("description", "")))
        return body
    except Exception as e:
        sys.stderr.write("tg %s error: %s\n" % (method, e)); return None

KEYBOARD = json.dumps({"inline_keyboard": [
    [{"text": "📟 Статус", "callback_data": "status"}, {"text": "🛡 Валидатор", "callback_data": "val"}],
    [{"text": "🔄 Синк", "callback_data": "sync"}, {"text": "🌐 Пиры", "callback_data": "peers"}],
    [{"text": "💾 Диск", "callback_data": "disk"}, {"text": "❓ Помощь", "callback_data": "help"}],
]})

def send(chat_id, text, kb=False):
    # kb=True — прикрепить инлайн-кнопки к последней части
    ok = True
    chunks = [text[i:i+3900] for i in range(0, len(text), 3900)]
    for n, chunk in enumerate(chunks):
        params = {"chat_id": chat_id, "text": chunk,
                  "disable_web_page_preview": "true"}
        if kb and n == len(chunks) - 1:
            params["reply_markup"] = KEYBOARD
        r = tg("sendMessage", params)
        if not (r and r.get("ok")):
            ok = False
    return ok

def broadcast(text, st=None):
    for cid in ALLOWED:
        if send(cid, text, kb=True):
            sys.stderr.write("alert delivered to %s: %s\n" % (cid, text.splitlines()[0][:60]))
        elif st is not None:
            st.setdefault("pending_alerts", []).append({"cid": cid, "text": text, "ts": time.time()})
            sys.stderr.write("alert QUEUED (send failed) for %s\n" % cid)

def retry_pending(st):
    pend = st.get("pending_alerts") or []
    if not pend:
        return
    left = []
    for a in pend[:20]:
        if not send(a["cid"], "(повтор) " + a["text"], kb=True):
            left.append(a)
    # Cap + TTL: очередь не ограничивалась и не истекала. При долгой недоступности
    # Telegram она росла без предела, а retry_pending() внутри monitor() пытался до 20
    # отправок по 35с — до ~12 минут блокировки тика: не идёт long-poll (команды не
    # отвечают) и не выполняются проверки. Старые алерты приезжали через часы без
    # отметки времени и читались как свежая авария.
    keep = (left + pend[20:])[-PENDING_MAX:]
    now = time.time()
    st["pending_alerts"] = [a for a in keep
                            if now - float(a.get("ts") or now) <= PENDING_TTL_SEC]

# ---------- helpers ----------
def sh(cmd, timeout=15):
    """Вывод команды или "" — совместимая обёртка. Для новых проверок брать sh_try."""
    return sh_try(cmd, timeout)[1]

def sh_try(cmd, timeout=15):
    """(получилось, вывод). Три состояния вместо двух.

    Прежний sh() возвращал "" и при таймауте, и при успешной команде с пустым выводом.
    Вызывающий не мог их различить, поэтому «зонд не отработал» читалось как «данных нет,
    значит всё спокойно». В monad-боте это уже исправлено, сюда не перенесли.
    """
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return False, ""
    return r.returncode == 0, r.stdout.strip()

def sh_args(argv, timeout=15):
    """Без shell: список аргументов. Значения конфигурации (VALCONS, HOME_DIR, RPC) попадали
    в строку, исполняемую shell'ом от root — точка с запятой или подстановка в config.env
    выполнялась бы как команда. Файл наш, но это ровно та ошибка, которую незачем оставлять
    в публичном репозитории."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return False, ""
    return r.returncode == 0, r.stdout.strip()

def http_get(path, timeout=6):
    try:
        with urllib.request.urlopen(RPC + path, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None

def app_version():
    v = sh("provenanced version 2>/dev/null")
    return v.splitlines()[0].strip() if v else "?"

def svc_active(): return sh("systemctl is-active %s" % SERVICE) == "active"
def svc_start():  return sh("systemctl show %s -p ExecMainStartTimestamp --value" % SERVICE)

def get_status():
    d = http_get("/status")
    if not d or "result" not in d:
        return None
    r = d["result"]; si = r.get("sync_info", {}); vi = r.get("validator_info", {})
    ni = r.get("node_info", {})
    h = si.get("latest_block_height")
    ts = si.get("latest_block_time", "")
    lag = None
    # latest_block_time приходит в UTC. `time.mktime() - time.timezone` трактует его как
    # локальное время и в зоне с DST применяет altzone, вычитая при этом timezone — ошибка
    # до часа: либо ложное «Отставание блока», либо замаскированный реальный lag.
    # Здесь хост в UTC, поэтому раньше совпадало случайно.
    bt = _parse_iso_utc(ts)
    if bt is not None:
        lag = int(time.time()) - int(bt)
    # voting_power: None, если поля validator_info нет вовсе (ранний старт comet).
    # `int(x or 0)` делал это неотличимым от «выпали из активного сета».
    vp_raw = vi.get("voting_power")
    return {"height": int(h) if h else None,
            "catching_up": bool(si.get("catching_up")),
            "vp": (int(vp_raw) if str(vp_raw).lstrip("-").isdigit() else None),
            "version": ni.get("version", "?"),
            "network": ni.get("network", "?"),
            "lag": lag}

def _parse_iso_utc(s):
    """ISO-8601 → epoch (UTC). None если не разобрать."""
    if not s:
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})", s)
    if not m:
        return None
    try:
        return calendar.timegm(tuple(int(x) for x in m.groups()) + (0, 0, 0))
    except Exception:
        return None

def get_signing():
    if not VALCONS:
        return None
    ok, out = sh_args(["provenanced", "query", "slashing", "signing-info", VALCONS,
                       "--home", HOME_DIR, "--node", RPC, "-o", "json"])
    if not ok:
        return None
    try:
        i = json.loads(out)["val_signing_info"]
        ju = i.get("jailed_until", "1970-01-01T00:00:00Z")
        # Cosmos SDK НЕ сбрасывает jailed_until при unjail — там навсегда остаётся дата
        # прошлого джейла. Прежняя проверка `not ju.startswith("1970")` поэтому считала
        # «в джейле» любого, кто когда-либо сидел: на живом mainnet это 174 валидатора из 249.
        # Последствия были каскадные: вечный алерт каждые 30 мин, st["jailed"] навсегда True,
        # и, что хуже, ВТОРОЙ реальный джейл уже не давал алерта — перехода состояния нет.
        # Признак джейла = срок в БУДУЩЕМ. Заодно снимается ловушка с «никогда не джейлился»,
        # который в части версий SDK равен 0001-01-01, а не 1970.
        ju_ts = _parse_iso_utc(ju)
        jailed = ju_ts is not None and ju_ts > time.time()
        return {"missed": int(i.get("missed_blocks_counter") or 0),
                "jailed": jailed, "jailed_until": ju,
                "tombstoned": bool(i.get("tombstoned"))}
    except Exception:
        return None

def get_peers():
    d = http_get("/net_info")
    try:
        return int(d["result"]["n_peers"])
    except Exception:
        return None

def get_disk():
    parts = sh("df -P / | tail -1").split()
    if len(parts) >= 5:
        return {"pct": int(parts[4].rstrip("%")),
                "avail_gb": round(int(parts[3])/1024/1024, 1)}
    return {"pct": None, "avail_gb": None}

# ---------- reports ----------
def fmt_status():
    L = ["🔷 Provenance — %s" % HOST]
    L.append("Сервис: " + ("✅ active" if svc_active() else "🔴 НЕ active"))
    s = get_status()
    if s:
        L.append("Сеть: %s  provenanced %s (comet %s)" % (s["network"], app_version(), s["version"]))
        sync = "✅ у типа" if not s["catching_up"] else "🟡 catching_up"
        L.append("Синк: %s  блок %s  lag %s" % (sync, s["height"],
                 "?" if s["lag"] is None else "%ds" % s["lag"]))
        L.append("Voting power: %s" % s["vp"])
    else:
        L.append("Синк: 🔴 RPC :26657 не отвечает")
    sg = get_signing()
    if sg:
        jl = "🔴 ДА" if sg["jailed"] else "✅ нет"
        tb = " 💀tombstoned" if sg["tombstoned"] else ""
        L.append("Jailed: %s%s" % (jl, tb))
        L.append("Missed blocks: %d / окно %d (джейл при >%d)" % (sg["missed"], SLASH_WINDOW, JAIL_THRESHOLD))
    else:
        # Раньше эти строки просто ПРОПАДАЛИ из сводки. Отчёт выглядел здоровым — без единого
        # признака, что джейл и пропущенные блоки не проверялись вообще: не отвечает RPC, нет
        # provenanced, не задан VALCONS. Молчание читается как «всё хорошо», а это худший из
        # возможных ответов для проверки, ради которой бот и существует.
        L.append("Jailed: ⚠️ НЕ ПРОВЕРЕНО — signing-info недоступна")
        L.append("Missed blocks: ⚠️ НЕ ПРОВЕРЕНО")
    p = get_peers()
    L.append("Пиры: %d" % p if p is not None else "Пиры: ⚠️ НЕ ПРОВЕРЕНО (/net_info недоступен)")
    d = get_disk()
    if d["pct"] is not None:
        L.append("Диск /: %s %d%% занято, %s ГБ" % (
            "✅" if d["pct"] < DISK_WARN_PCT else "🟡", d["pct"], d["avail_gb"]))
    else:
        L.append("Диск /: ⚠️ НЕ ПРОВЕРЕНО (df не дал разбираемый вывод)")
    return "\n".join(L)

def fmt_val():
    sg = get_signing(); s = get_status()
    if not sg: return "signing-info недоступна (проверь VALCONS/ноду)"
    return ("Валидатор pio-mainnet-1\nJailed: %s\njailed_until: %s\nTombstoned: %s\n"
            "Missed blocks: %d / %d (порог джейла >%d)\nVoting power: %s"
            % ("🔴 ДА" if sg["jailed"] else "✅ нет", sg["jailed_until"],
               sg["tombstoned"], sg["missed"], SLASH_WINDOW, JAIL_THRESHOLD,
               s["vp"] if s else "?"))

def fmt_sync():
    s = get_status()
    if not s: return "🔴 RPC :26657 не отвечает"
    return ("Синк %s\nблок: %s\nlag: %s\ncatching_up: %s"
            % ("✅ у типа" if not s["catching_up"] else "🟡 catching_up",
               s["height"], "?" if s["lag"] is None else "%ds" % s["lag"], s["catching_up"]))

def fmt_peers():
    p = get_peers(); return "Пиры: %s" % ("?" if p is None else p)

def fmt_disk():
    d = get_disk(); return "Диск /: %s\n%s" % (
        "—" if d["pct"] is None else "%d%% занято, %s ГБ свободно" % (d["pct"], d["avail_gb"]),
        sh("df -h / | tail -1"))

HELP = ("Provenance validator bot — %s\n\n"
        "/status — общая сводка\n/val — валидатор (jailed/missed/power)\n"
        "/sync — синхронизация\n/peers — пиры\n/disk — диск\n"
        "/id — chat id\n/help — помощь" % HOST)

# ---------- state & alerts ----------
def load_state():
    try:
        with open(STATE_PATH) as f: return json.load(f)
    except Exception: return {}

def save_state(st):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f: json.dump(st, f)
    os.replace(tmp, STATE_PATH)

def monitor(st):
    A = []
    # service
    active = svc_active(); start = svc_start()
    if st.get("active") is True and not active: A.append("🔴 СЕРВИС УПАЛ: provenanced неактивен!")
    elif st.get("active") is False and active:  A.append("✅ provenanced снова active")
    if st.get("start") and start and start != st["start"] and active:
        A.append("🔄 РЕСТАРТ: provenanced перезапущен\nстарт: %s" % start)
    st["active"], st["start"] = active, start
    # rpc / sync
    s = get_status()
    rpc_dead = s is None
    if rpc_dead and not st.get("rpc_dead"): A.append("🔴 RPC :26657 не отвечает")
    elif not rpc_dead and st.get("rpc_dead"): A.append("✅ RPC :26657 снова отвечает")
    st["rpc_dead"] = rpc_dead
    if s:
        if s["catching_up"] and not st.get("catching_up"):
            A.append("🟡 НОДА ОТСТАЁТ: catching_up=true (блок %s)" % s["height"])
        elif not s["catching_up"] and st.get("catching_up"):
            A.append("✅ Синк восстановлен (блок %s)" % s["height"])
        st["catching_up"] = s["catching_up"]
        if s["lag"] is not None:
            behind = s["lag"] > LAG_WARN
            if behind and not st.get("behind"): A.append("🟡 Отставание блока: lag %ds" % s["lag"])
            elif not behind and st.get("behind"): A.append("✅ lag в норме (%ds)" % s["lag"])
            st["behind"] = behind
        # block stall (height not advancing) — STALL_TICKS тиков подряд, не с одного
        # замера: одиночное совпадение высот ложнит при рестарте бота (первый тик
        # нового процесса стартует через секунды после последнего тика старого)
        ph = st.get("height")
        if ph is not None and s["height"] is not None and s["height"] == ph and not rpc_dead:
            st["stall_ticks"] = st.get("stall_ticks", 0) + 1
            if st["stall_ticks"] >= STALL_TICKS and not st.get("stalled"):
                A.append("🔴 БЛОКИ НЕ РАСТУТ: высота застряла на %s (~%d мин)"
                         % (s["height"], st["stall_ticks"] * CHECK_INTERVAL // 60))
                st["stalled"] = True
        elif s["height"] is None:
            # Высоты нет — CometBFT ещё поднимается или /status отдал неполный ответ. Раньше
            # эта ветка сливалась с «высота растёт»: бот слал «✅ Блоки снова растут: None» и
            # сбрасывал stalled по ОТСУТСТВУЮЩИМ данным, то есть снимал реальный алерт,
            # ничего не измерив. Состояние не трогаем.
            pass
        else:
            if st.get("stalled"):
                A.append("✅ Блоки снова растут: %s" % s["height"])
            st["stall_ticks"] = 0
            st["stalled"] = False
        if s["height"] is not None:
            st["height"] = s["height"]
        # voting power. vp is None = поля validator_info в /status нет (ранний старт comet):
        # раньше это давало 0 и было неотличимо от «выпали из активного сета» — ложный
        # алерт на здоровой ноде. И наоборот: при РЕАЛЬНОМ выпадении алерт уходил один раз
        # (pvp становился 0 и falsy), повторов не было, возврат power не сообщался.
        pvp = st.get("vp")
        vp = s["vp"]
        if vp is not None:
            if pvp and vp and vp < pvp * 0.9:
                A.append("⚠️ VOTING POWER упал: %s → %s" % (pvp, vp))
            if vp == 0 and pvp != 0:
                A.append("🔴 VOTING POWER = 0 (выпали из активного сета / джейл?)")
            elif vp > 0 and pvp == 0:
                A.append("✅ VOTING POWER восстановлен: %s" % vp)
            st["vp"] = vp
    # validator signing-info
    sg = get_signing()
    if sg:
        if sg["jailed"] and not st.get("jailed"):
            A.append("🔴🔴 ВАЛИДАТОР В ДЖЕЙЛЕ! jailed_until %s" % sg["jailed_until"])
        elif not sg["jailed"] and st.get("jailed"):
            A.append("✅ Валидатор вышел из джейла")
        st["jailed"] = sg["jailed"]
        if sg["tombstoned"] and not st.get("tombstoned"):
            A.append("💀 TOMBSTONED — валидатор перманентно выведен!")
        st["tombstoned"] = sg["tombstoned"]
        m = sg["missed"]; pm = st.get("missed")
        # threshold crossings
        if m >= MISSED_CRIT and (pm is None or pm < MISSED_CRIT):
            A.append("🔴 MISSED BLOCKS = %d (>%d, близко к джейлу %d!)" % (m, MISSED_CRIT, JAIL_THRESHOLD))
        elif m >= MISSED_WARN and (pm is None or pm < MISSED_WARN):
            A.append("🟡 MISSED BLOCKS = %d (>%d)" % (m, MISSED_WARN))
        # Активный пропуск блоков. Рейт-лимит обязателен: при блоке ~6с валидатор, который не
        # подписывает, набирает ~10 промахов в минуту, и это условие срабатывало КАЖДЫЙ тик —
        # 60 сообщений в час, которыми затирается всё остальное, включая джейл-алерт.
        if pm is not None and m - pm >= 10:
            now = time.time()
            if now - float(st.get("missed_rate_alert_ts") or 0) >= MISSED_ALERT_MIN_GAP:
                A.append("🟡 Активно пропускает блоки: +%d за цикл (всего %d)" % (m - pm, m))
                st["missed_rate_alert_ts"] = now
        st["missed"] = m
        st["signing_fail_ticks"] = 0
    else:
        # Ветки else тут не было вовсе: при недоступной signing-info проверка джейла просто
        # переставала выполняться, молча и навсегда. Бот продолжал слать бодрые сводки, а
        # единственная проверка, ради которой он существует, не работала. Отказ мониторинга
        # обязан быть слышен — иначе он неотличим от «всё хорошо».
        fails = int(st.get("signing_fail_ticks") or 0) + 1
        st["signing_fail_ticks"] = fails
        if fails == SIGNING_FAIL_ALERT_TICKS:
            A.append("⚠️ signing-info недоступна %d циклов подряд — джейл и пропущенные блоки "
                     "СЕЙЧАС НЕ ПРОВЕРЯЮТСЯ (RPC :26657 / provenanced / VALCONS)" % fails)
    # peers
    p = get_peers()
    if p is None:
        # Тот же класс, что PB-2, ставки ниже: /net_info недоступен → проверка пиров молча
        # пропускается. Раз подряд — не событие, но постоянная слепота должна быть слышна.
        _pf = int(st.get("peers_fail_ticks") or 0) + 1
        st["peers_fail_ticks"] = _pf
        if _pf == PEERS_FAIL_ALERT_TICKS:
            A.append("⚠️ /net_info недоступен %d циклов — число пиров НЕ проверяется" % _pf)
    else:
        st["peers_fail_ticks"] = 0
    if p is not None:
        low = p < PEERS_MIN
        if low and not st.get("peers_low"): A.append("🟡 Мало пиров: %d (<%d)" % (p, PEERS_MIN))
        elif not low and st.get("peers_low"): A.append("✅ Пиры в норме: %d" % p)
        st["peers_low"] = low
    # disk
    d = get_disk()
    if d["pct"] is not None:
        warn = d["pct"] >= DISK_WARN_PCT
        if warn and not st.get("disk_warn"): A.append("🟡 ДИСК /: %d%% (%s ГБ свободно)" % (d["pct"], d["avail_gb"]))
        elif not warn and st.get("disk_warn"): A.append("✅ Диск ок: %d%%" % d["pct"])
        st["disk_warn"] = warn
    # РЕ-АЛЕРТ критических состояний каждые 30 мин (урок инцидента 2026-07-19)
    now = time.time()
    crit = []
    if st.get("jailed"):     crit.append("🔴🔴 ВАЛИДАТОР ВСЁ ЕЩЁ В ДЖЕЙЛЕ")
    if st.get("tombstoned"): crit.append("💀 TOMBSTONED")
    if st.get("stalled"):    crit.append("🔴 Блоки всё ещё не растут (%s)" % st.get("height"))
    if st.get("rpc_dead"):   crit.append("🔴 RPC :26657 всё ещё не отвечает")
    # missed, застрявший у порога джейла (1728), раньше давал ОДИН алерт и дальше тишину —
    # в crit-список он не входил, хотя это именно то состояние, о котором надо напоминать.
    if (st.get("missed") or 0) >= MISSED_CRIT:
        crit.append("🔴 MISSED BLOCKS всё ещё %d (порог джейла %d)" % (st["missed"], JAIL_THRESHOLD))
    if st.get("vp") == 0:
        crit.append("🔴 VOTING POWER всё ещё 0 (вне активного сета?)")
    if st.get("active") is False: crit.append("🔴 provenanced всё ещё down")
    if crit:
        if now - st.get("last_realert", 0) >= 1800:
            A.append("⏰ НАПОМИНАНИЕ (повтор каждые 30 мин):\n" + "\n".join(crit))
            st["last_realert"] = now
    else:
        st["last_realert"] = 0
    if A: broadcast("\n\n".join(A), st)
    retry_pending(st)
    save_state(st)

# ---------- commands ----------
CB_SEEN = {}  # (cid:data) -> ts последнего исполнения кнопки, для дебаунса

def dispatch(cid, cmd):
    # общий диспетчер для /команд и нажатий кнопок
    if   cmd == "status": send(cid, fmt_status(), kb=True)
    elif cmd == "val":    send(cid, fmt_val(), kb=True)
    elif cmd == "sync":   send(cid, fmt_sync(), kb=True)
    elif cmd == "peers":  send(cid, fmt_peers(), kb=True)
    elif cmd == "disk":   send(cid, fmt_disk(), kb=True)
    elif cmd == "help":   send(cid, HELP, kb=True)
    else: send(cid, "Неизвестная команда. /help", kb=True)

def handle(msg):
    cid = str(msg.get("chat", {}).get("id", ""))
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"): return
    cmd = text.split()[0].lstrip("/").split("@")[0].lower()
    if cmd in ("id", "start"):
        send(cid, "chat_id: %s\nДобавь в ALLOWED_CHAT_IDS и перезапусти сервис.\n\n%s"
                  % (cid, HELP if cid in ALLOWED else ""), kb=cid in ALLOWED); return
    if cid not in ALLOWED:
        send(cid, "⛔ Не авторизован. Твой chat_id: %s" % cid); return
    dispatch(cid, cmd)

def handle_callback(cb):
    # нажатие инлайн-кнопки: гасим "часики" и выполняем как команду
    # message может отсутствовать (недоступное сообщение) — fallback на id нажавшего
    cid = str((cb.get("message") or {}).get("chat", {}).get("id", "")
              or cb.get("from", {}).get("id", ""))
    t0 = time.time()
    r = tg("answerCallbackQuery", {"callback_query_id": cb.get("id", "")}, timeout=15)
    sys.stderr.write("callback data=%s answer=%s took=%.1fs\n"
                     % (cb.get("data"), (r or {}).get("ok"), time.time() - t0))
    if cid not in ALLOWED:
        send(cid, "⛔ Не авторизован. Твой chat_id: %s" % cid); return
    # дебаунс: та же кнопка не чаще раза в 10с — гасит спам при серии нажатий
    # и при пачке протухших колбэков после залипания доставки. Отвечаем ВСЕГДА,
    # даже если "часики" погасить не удалось (Telegram бывает тормозит сам ответ
    # на answerCallbackQuery на 10-15с и потом отдаёт "query is too old").
    data = (cb.get("data") or "").strip().lower()
    key = cid + ":" + data
    now = time.time()
    if now - CB_SEEN.get(key, 0) < 10:
        sys.stderr.write("debounce %s\n" % key)
        return
    CB_SEEN[key] = now
    t1 = time.time()
    dispatch(cid, data)
    sys.stderr.write("dispatch %s took=%.1fs\n" % (cb.get("data"), time.time() - t1))

def main():
    if not TOKEN:
        sys.stderr.write("BOT_TOKEN не задан\n"); sys.exit(1)
    st = load_state(); offset = st.get("offset", 0)
    monitor(st)
    broadcast("🟢 provenance-tg-bot запущен на %s. /help — команды." % HOST)
    last = time.time()
    # net_fail ДОЛЖЕН существовать до первой итерации: он инкрементируется в ветке
    # сетевого сбоя, а обнулялся только в ветках успеха — первый же сбой сразу после
    # старта давал UnboundLocalError и убивал бота (воспроизведено).
    net_fail = 0
    while True:
        # allowed_updates явно: настройка ПЕРСИСТЕНТНА на стороне Telegram —
        # без callback_query в списке нажатия кнопок молча не доставляются
        upd = tg("getUpdates", {"offset": offset, "timeout": 20,
                                "allowed_updates": '["message","edited_message","callback_query"]'},
                 timeout=35)
        if upd and upd.get("ok"):
            for u in upd["result"]:
                offset = u["update_id"] + 1; st["offset"] = offset
                m = u.get("message") or u.get("edited_message")
                if m:
                    try: handle(m)
                    except Exception as e: sys.stderr.write("handle: %s\n" % e)
                cb = u.get("callback_query")
                if cb:
                    try: handle_callback(cb)
                    except Exception as e: sys.stderr.write("callback: %s\n" % e)
            save_state(st)
            net_fail = 0
        elif upd is not None:
            time.sleep(2)  # HTTP-ошибка API (401/409/429): не долбим в busy-loop
            net_fail = 0
        else:
            # upd is None = не-HTTP сбой (DNS, ECONNREFUSED, обрыв). Раньше паузы тут не было
            # вообще: getaddrinfo падает за доли миллисекунды, и цикл крутился ~155 раз в
            # секунду — ядро в полке рядом с боевой нодой плюс флуд в journald.
            net_fail += 1
            time.sleep(min(2 * (2 ** min(net_fail - 1, 4)), 60))  # 2,4,8,16,32,→60 с
        if time.time() - last >= CHECK_INTERVAL:
            try: monitor(st)
            except Exception as e: sys.stderr.write("monitor: %s\n" % e)
            last = time.time()

if __name__ == "__main__":
    main()
