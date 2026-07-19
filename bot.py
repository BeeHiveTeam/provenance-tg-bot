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
import json, os, re, ssl, subprocess, sys, time, urllib.parse, urllib.request

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
MISSED_CRIT    = int(CFG.get("MISSED_CRIT", "1500"))
PEERS_MIN      = int(CFG.get("PEERS_MIN", "3"))
LAG_WARN       = int(CFG.get("BLOCK_LAG_WARN_SEC", "30"))
API = "https://api.telegram.org/bot%s/" % TOKEN
SSLCTX = ssl.create_default_context()

# ---------- telegram ----------
def tg(method, params=None, timeout=35):
    data = urllib.parse.urlencode(params or {}).encode()
    req = urllib.request.Request(API + method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSLCTX) as r:
            return json.load(r)
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
            st.setdefault("pending_alerts", []).append({"cid": cid, "text": text})
            sys.stderr.write("alert QUEUED (send failed) for %s\n" % cid)

def retry_pending(st):
    pend = st.get("pending_alerts") or []
    if not pend:
        return
    left = []
    for a in pend[:20]:
        if not send(a["cid"], "(повтор) " + a["text"]):
            left.append(a)
    st["pending_alerts"] = left + pend[20:]

# ---------- helpers ----------
def sh(cmd, timeout=15):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""

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
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", ts or "")
    if m:
        try:
            bt = time.mktime(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")) - time.timezone
            lag = int(time.time()) - int(bt)
        except Exception:
            lag = None
    return {"height": int(h) if h else None,
            "catching_up": bool(si.get("catching_up")),
            "vp": int(vi.get("voting_power") or 0),
            "version": ni.get("version", "?"),
            "network": ni.get("network", "?"),
            "lag": lag}

def get_signing():
    if not VALCONS:
        return None
    out = sh("provenanced query slashing signing-info %s --home %s --node %s -o json"
             % (VALCONS, HOME_DIR, RPC))
    try:
        i = json.loads(out)["val_signing_info"]
        ju = i.get("jailed_until", "1970-01-01T00:00:00Z")
        jailed = not ju.startswith("1970")
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
        L.append("Missed blocks: %d / окно 34560 (джейл при >1728)" % sg["missed"])
    p = get_peers()
    if p is not None: L.append("Пиры: %d" % p)
    d = get_disk()
    if d["pct"] is not None:
        L.append("Диск /: %s %d%% занято, %s ГБ" % (
            "✅" if d["pct"] < DISK_WARN_PCT else "🟡", d["pct"], d["avail_gb"]))
    return "\n".join(L)

def fmt_val():
    sg = get_signing(); s = get_status()
    if not sg: return "signing-info недоступна (проверь VALCONS/ноду)"
    return ("Валидатор pio-mainnet-1\nJailed: %s\njailed_until: %s\nTombstoned: %s\n"
            "Missed blocks: %d / 34560 (порог джейла >1728)\nVoting power: %s"
            % ("🔴 ДА" if sg["jailed"] else "✅ нет", sg["jailed_until"],
               sg["tombstoned"], sg["missed"], s["vp"] if s else "?"))

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
        # block stall (height not advancing)
        ph = st.get("height")
        if ph is not None and s["height"] is not None and s["height"] == ph and not rpc_dead:
            if not st.get("stalled"): A.append("🔴 БЛОКИ НЕ РАСТУТ: высота застряла на %s" % s["height"])
            st["stalled"] = True
        else:
            st["stalled"] = False
        st["height"] = s["height"]
        # voting power drop
        pvp = st.get("vp")
        if pvp and s["vp"] and s["vp"] < pvp * 0.9:
            A.append("⚠️ VOTING POWER упал: %s → %s" % (pvp, s["vp"]))
        if s["vp"] == 0 and pvp:
            A.append("🔴 VOTING POWER = 0 (выпали из активного сета / джейл?)")
        st["vp"] = s["vp"]
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
            A.append("🔴 MISSED BLOCKS = %d (>%d, близко к джейлу 1728!)" % (m, MISSED_CRIT))
        elif m >= MISSED_WARN and (pm is None or pm < MISSED_WARN):
            A.append("🟡 MISSED BLOCKS = %d (>%d)" % (m, MISSED_WARN))
        # actively missing right now (rose noticeably this tick)
        if pm is not None and m - pm >= 10:
            A.append("🟡 Активно пропускает блоки: +%d за цикл (всего %d)" % (m - pm, m))
        st["missed"] = m
    # peers
    p = get_peers()
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
    cid = str(cb.get("message", {}).get("chat", {}).get("id", ""))
    r = tg("answerCallbackQuery", {"callback_query_id": cb.get("id", "")}, timeout=10)
    if not (r and r.get("ok")):
        # колбэк протух (Telegram принимает ответ ~15-30с после нажатия):
        # юзер жал давно/серией — не шлём запоздалый ответ, чтобы не спамить чат
        return
    if cid not in ALLOWED:
        send(cid, "⛔ Не авторизован. Твой chat_id: %s" % cid); return
    dispatch(cid, (cb.get("data") or "").strip().lower())

def main():
    if not TOKEN:
        sys.stderr.write("BOT_TOKEN не задан\n"); sys.exit(1)
    st = load_state(); offset = st.get("offset", 0)
    monitor(st)
    broadcast("🟢 provenance-tg-bot запущен на %s. /help — команды." % HOST)
    last = time.time()
    while True:
        upd = tg("getUpdates", {"offset": offset, "timeout": 20}, timeout=35)
        if upd and upd.get("ok"):
            for u in upd["result"]:
                offset = u["update_id"] + 1; st["offset"] = offset
                m = u.get("message") or u.get("edited_message")
                if m:
                    try: handle(m)
                    except Exception as e: sys.stderr.write("handle: %s\n" % e)
            save_state(st)
        if time.time() - last >= CHECK_INTERVAL:
            try: monitor(st)
            except Exception as e: sys.stderr.write("monitor: %s\n" % e)
            last = time.time()

if __name__ == "__main__":
    main()
