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

# ── i18n ──────────────────────────────────────────────────────────────────────
# One bot, one operator chat, so language is a single setting. Default English; LANG=en|ru|de
# in config.env sets it, the 🌐 button and /lang cycle at runtime. Strings keep %s formatting.
_cfg_lang = CFG.get("LANG", "en").strip().lower()
DEFAULT_LANG = _cfg_lang if _cfg_lang in ("en", "ru", "de") else "en"
_lang = DEFAULT_LANG

T = {
  "b_status": {"en": "📟 Status",    "ru": "📟 Статус",     "de": "📟 Status"},
  "b_val":    {"en": "🛡 Validator", "ru": "🛡 Валидатор",  "de": "🛡 Validator"},
  "b_sync":   {"en": "🔄 Sync",      "ru": "🔄 Синк",       "de": "🔄 Sync"},
  "b_peers":  {"en": "🌐 Peers",     "ru": "🌐 Пиры",       "de": "🌐 Peers"},
  "b_disk":   {"en": "💾 Disk",      "ru": "💾 Диск",       "de": "💾 Platte"},
  "b_help":   {"en": "❓ Help",       "ru": "❓ Помощь",     "de": "❓ Hilfe"},
  "b_lang":   {"en": "🌐 EN",        "ru": "🌐 RU",         "de": "🌐 DE"},

  "y_no":     {"en": "✅ no",  "ru": "✅ нет", "de": "✅ nein"},
  "y_yes":    {"en": "🔴 YES", "ru": "🔴 ДА",  "de": "🔴 JA"},
  "svc":      {"en": "Service: ", "ru": "Сервис: ", "de": "Dienst: "},
  "svc_bad":  {"en": "🔴 NOT active", "ru": "🔴 НЕ active", "de": "🔴 NICHT aktiv"},

  "s_nolag":  {"en": "❔ lag not measured", "ru": "❔ lag не измерен", "de": "❔ Lag nicht messbar"},
  "s_behind": {"en": "🔴 BEHIND", "ru": "🔴 ОТСТАЁТ", "de": "🔴 ZURÜCK"},
  "s_ok":     {"en": "✅ in sync", "ru": "✅ в синке", "de": "✅ synchron"},

  "st_net":   {"en": "Network: %s  provenanced %s (comet %s)", "ru": "Сеть: %s  provenanced %s (comet %s)", "de": "Netz: %s  provenanced %s (comet %s)"},
  "st_sync":  {"en": "Sync: %s  block %s  lag %s", "ru": "Синк: %s  блок %s  lag %s", "de": "Sync: %s  Block %s  Lag %s"},
  "st_norpc": {"en": "Sync: 🔴 RPC :26657 not responding", "ru": "Синк: 🔴 RPC :26657 не отвечает", "de": "Sync: 🔴 RPC :26657 antwortet nicht"},
  "st_jail_unk": {"en": "Jailed: ⚠️ NOT CHECKED — signing-info unavailable", "ru": "Jailed: ⚠️ НЕ ПРОВЕРЕНО — signing-info недоступна", "de": "Jailed: ⚠️ NICHT GEPRÜFT — signing-info nicht verfügbar"},
  "st_missed_unk": {"en": "Missed blocks: ⚠️ NOT CHECKED", "ru": "Missed blocks: ⚠️ НЕ ПРОВЕРЕНО", "de": "Missed blocks: ⚠️ NICHT GEPRÜFT"},
  "st_missed": {"en": "Missed blocks: %d / %d (jail threshold >%d)\nVoting power: %s", "ru": "Missed blocks: %d / %d (порог джейла >%d)\nVoting power: %s", "de": "Missed blocks: %d / %d (Jail-Schwelle >%d)\nVoting power: %s"},
  "st_peers": {"en": "Peers: %d", "ru": "Пиры: %d", "de": "Peers: %d"},
  "st_peers_unk": {"en": "Peers: ⚠️ NOT CHECKED (/net_info unavailable)", "ru": "Пиры: ⚠️ НЕ ПРОВЕРЕНО (/net_info недоступен)", "de": "Peers: ⚠️ NICHT GEPRÜFT (/net_info nicht verfügbar)"},
  "st_disk":  {"en": "Disk /: %s %d%% used, %s GB", "ru": "Диск /: %s %d%% занято, %s ГБ", "de": "Platte /: %s %d%% belegt, %s GB"},
  "st_disk_unk": {"en": "Disk /: ⚠️ NOT CHECKED (df gave no parsable output)", "ru": "Диск /: ⚠️ НЕ ПРОВЕРЕНО (df не дал разбираемый вывод)", "de": "Platte /: ⚠️ NICHT GEPRÜFT (df lieferte keine auswertbare Ausgabe)"},
  "st_unchecked": {"en": "NOT CURRENTLY CHECKED (RPC :26657 / provenanced / VALCONS)", "ru": "СЕЙЧАС НЕ ПРОВЕРЯЮТСЯ (RPC :26657 / provenanced / VALCONS)", "de": "DERZEIT NICHT GEPRÜFT (RPC :26657 / provenanced / VALCONS)"},

  "v_body":   {"en": "Validator pio-mainnet-1\nJailed: %s\njailed_until: %s\nTombstoned: %s\n", "ru": "Валидатор pio-mainnet-1\nJailed: %s\njailed_until: %s\nTombstoned: %s\n", "de": "Validator pio-mainnet-1\nJailed: %s\njailed_until: %s\nTombstoned: %s\n"},
  "v_missed": {"en": "Missed blocks: %d / window %d (jail at >%d)", "ru": "Missed blocks: %d / окно %d (джейл при >%d)", "de": "Missed blocks: %d / Fenster %d (Jail bei >%d)"},
  "v_nosign": {"en": "signing-info unavailable (check VALCONS/node)", "ru": "signing-info недоступна (проверь VALCONS/ноду)", "de": "signing-info nicht verfügbar (VALCONS/Node prüfen)"},
  "sy_body":  {"en": "Sync %s\nblock: %s\nlag: %s\ncatching_up: %s", "ru": "Синк %s\nблок: %s\nlag: %s\ncatching_up: %s", "de": "Sync %s\nBlock: %s\nLag: %s\ncatching_up: %s"},
  "sy_norpc": {"en": "🔴 RPC :26657 not responding", "ru": "🔴 RPC :26657 не отвечает", "de": "🔴 RPC :26657 antwortet nicht"},
  "pe_body":  {"en": "Peers: %s", "ru": "Пиры: %s", "de": "Peers: %s"},
  "dk_body":  {"en": "Disk /: %s\n%s", "ru": "Диск /: %s\n%s", "de": "Platte /: %s\n%s"},
  "dk_used":  {"en": "%d%% used, %s GB free", "ru": "%d%% занято, %s ГБ свободно", "de": "%d%% belegt, %s GB frei"},

  "a_jail":   {"en": "🔴🔴 VALIDATOR IS JAILED! jailed_until %s", "ru": "🔴🔴 ВАЛИДАТОР В ДЖЕЙЛЕ! jailed_until %s", "de": "🔴🔴 VALIDATOR IST GEJAILT! jailed_until %s"},
  "a_jail_still": {"en": "🔴🔴 VALIDATOR STILL JAILED", "ru": "🔴🔴 ВАЛИДАТОР ВСЁ ЕЩЁ В ДЖЕЙЛЕ", "de": "🔴🔴 VALIDATOR WEITERHIN GEJAILT"},
  "a_unjail": {"en": "✅ Validator is out of jail", "ru": "✅ Валидатор вышел из джейла", "de": "✅ Validator ist aus dem Jail"},
  "a_tomb":   {"en": "💀 TOMBSTONED — the validator is permanently removed!", "ru": "💀 TOMBSTONED — валидатор перманентно выведен!", "de": "💀 TOMBSTONED — der Validator ist dauerhaft entfernt!"},
  "a_missed": {"en": "🔴 MISSED BLOCKS = %d (>%d, close to jail at %d!)", "ru": "🔴 MISSED BLOCKS = %d (>%d, близко к джейлу %d!)", "de": "🔴 MISSED BLOCKS = %d (>%d, nahe am Jail bei %d!)"},
  "a_missed_still": {"en": "🔴 MISSED BLOCKS still %d (jail threshold %d)", "ru": "🔴 MISSED BLOCKS всё ещё %d (порог джейла %d)", "de": "🔴 MISSED BLOCKS weiterhin %d (Jail-Schwelle %d)"},
  "a_missing": {"en": "🟡 Actively missing blocks: +%d this cycle (%d total)", "ru": "🟡 Активно пропускает блоки: +%d за цикл (всего %d)", "de": "🟡 Verpasst aktiv Blöcke: +%d in diesem Zyklus (%d gesamt)"},
  "a_vp_zero": {"en": "🔴 VOTING POWER = 0 (dropped from the active set / jailed?)", "ru": "🔴 VOTING POWER = 0 (выпали из активного сета / джейл?)", "de": "🔴 VOTING POWER = 0 (aus dem aktiven Set gefallen / gejailt?)"},
  "a_vp_zero_still": {"en": "🔴 VOTING POWER still 0 (outside the active set?)", "ru": "🔴 VOTING POWER всё ещё 0 (вне активного сета?)", "de": "🔴 VOTING POWER weiterhin 0 (außerhalb des aktiven Sets?)"},
  "a_vp_drop": {"en": "⚠️ VOTING POWER dropped: %s → %s", "ru": "⚠️ VOTING POWER упал: %s → %s", "de": "⚠️ VOTING POWER gefallen: %s → %s"},
  "a_vp_ok":  {"en": "✅ VOTING POWER restored: %s", "ru": "✅ VOTING POWER восстановлен: %s", "de": "✅ VOTING POWER wiederhergestellt: %s"},
  "a_svc_down": {"en": "🔴 SERVICE DOWN: provenanced is not active!", "ru": "🔴 СЕРВИС УПАЛ: provenanced неактивен!", "de": "🔴 DIENST AUSGEFALLEN: provenanced ist nicht aktiv!"},
  "a_svc_still": {"en": "🔴 provenanced still down", "ru": "🔴 provenanced всё ещё down", "de": "🔴 provenanced weiterhin ausgefallen"},
  "a_svc_up": {"en": "✅ provenanced is active again", "ru": "✅ provenanced снова active", "de": "✅ provenanced ist wieder aktiv"},
  "a_restart": {"en": "🔄 RESTART: provenanced restarted\nstarted: %s", "ru": "🔄 РЕСТАРТ: provenanced перезапущен\nстарт: %s", "de": "🔄 NEUSTART: provenanced neu gestartet\nStart: %s"},
  "a_rpc_down": {"en": "🔴 RPC :26657 not responding", "ru": "🔴 RPC :26657 не отвечает", "de": "🔴 RPC :26657 antwortet nicht"},
  "a_rpc_still": {"en": "🔴 RPC :26657 still not responding", "ru": "🔴 RPC :26657 всё ещё не отвечает", "de": "🔴 RPC :26657 antwortet weiterhin nicht"},
  "a_rpc_up": {"en": "✅ RPC :26657 responding again", "ru": "✅ RPC :26657 снова отвечает", "de": "✅ RPC :26657 antwortet wieder"},
  "a_stuck":  {"en": "🔴 BLOCKS NOT ADVANCING: height stuck at %s (~%d min)", "ru": "🔴 БЛОКИ НЕ РАСТУТ: высота застряла на %s (~%d мин)", "de": "🔴 BLÖCKE STEHEN: Höhe bei %s festgefahren (~%d Min)"},
  "a_stuck_still": {"en": "🔴 Blocks still not advancing (%s)", "ru": "🔴 Блоки всё ещё не растут (%s)", "de": "🔴 Blöcke wachsen weiterhin nicht (%s)"},
  "a_stuck_ok": {"en": "✅ Blocks advancing again: %s", "ru": "✅ Блоки снова растут: %s", "de": "✅ Blöcke wachsen wieder: %s"},
  "a_catching": {"en": "🟡 NODE BEHIND: catching_up=true (block %s)", "ru": "🟡 НОДА ОТСТАЁТ: catching_up=true (блок %s)", "de": "🟡 NODE ZURÜCK: catching_up=true (Block %s)"},
  "a_sync_ok": {"en": "✅ Sync recovered (block %s)", "ru": "✅ Синк восстановлен (блок %s)", "de": "✅ Sync wiederhergestellt (Block %s)"},
  "a_lag":    {"en": "🟡 Block lag: %ds", "ru": "🟡 Отставание блока: lag %ds", "de": "🟡 Block-Rückstand: %ds"},
  "a_lag_ok": {"en": "✅ lag is normal (%ds)", "ru": "✅ lag в норме (%ds)", "de": "✅ Lag normal (%ds)"},
  "a_peers_low": {"en": "🟡 Few peers: %d (<%d)", "ru": "🟡 Мало пиров: %d (<%d)", "de": "🟡 Wenige Peers: %d (<%d)"},
  "a_peers_ok": {"en": "✅ Peers normal: %d", "ru": "✅ Пиры в норме: %d", "de": "✅ Peers normal: %d"},
  "a_disk":   {"en": "🟡 DISK /: %d%% (%s GB free)", "ru": "🟡 ДИСК /: %d%% (%s ГБ свободно)", "de": "🟡 PLATTE /: %d%% (%s GB frei)"},
  "a_disk_ok": {"en": "✅ Disk ok: %d%%", "ru": "✅ Диск ок: %d%%", "de": "✅ Platte ok: %d%%"},
  "a_nosign": {"en": "⚠️ signing-info unavailable for %d cycles — jail and missed blocks ", "ru": "⚠️ signing-info недоступна %d циклов подряд — джейл и пропущенные блоки ", "de": "⚠️ signing-info seit %d Zyklen nicht verfügbar — Jail und verpasste Blöcke "},
  "a_nonet":  {"en": "⚠️ /net_info unavailable for %d cycles — peer count is NOT being checked", "ru": "⚠️ /net_info недоступен %d циклов — число пиров НЕ проверяется", "de": "⚠️ /net_info seit %d Zyklen nicht verfügbar — Peer-Anzahl wird NICHT geprüft"},
  "a_repeat": {"en": "(repeat) ", "ru": "(повтор) ", "de": "(Wiederholung) "},
  "a_reminder": {"en": "⏰ REMINDER (repeats every 30 min):\n", "ru": "⏰ НАПОМИНАНИЕ (повтор каждые 30 мин):\n", "de": "⏰ ERINNERUNG (alle 30 Min):\n"},

  "m_started": {"en": "🟢 provenance-tg-bot started on %s. /help for commands.", "ru": "🟢 provenance-tg-bot запущен на %s. /help — команды.", "de": "🟢 provenance-tg-bot gestartet auf %s. /help für Befehle."},
  "m_unauth": {"en": "⛔ Not authorised. Your chat_id: %s", "ru": "⛔ Не авторизован. Твой chat_id: %s", "de": "⛔ Nicht autorisiert. Deine chat_id: %s"},
  "m_chatid": {"en": "chat_id: %s\nAdd it to ALLOWED_CHAT_IDS and restart the service.\n\n%s", "ru": "chat_id: %s\nДобавь в ALLOWED_CHAT_IDS и перезапусти сервис.\n\n%s", "de": "chat_id: %s\nTrage sie in ALLOWED_CHAT_IDS ein und starte den Dienst neu.\n\n%s"},
  "m_unknown": {"en": "Unknown command. /help", "ru": "Неизвестная команда. /help", "de": "Unbekannter Befehl. /help"},
  "m_lang":   {"en": "Language: English. Tap 🌐 or /lang to cycle.", "ru": "Язык: русский. Нажмите 🌐 или /lang для смены.", "de": "Sprache: Deutsch. 🌐 oder /lang zum Wechseln."},
  "help":     {"en": ("Provenance validator bot — %s\n\n"
                      "/status — overview\n/val — validator (jailed/missed/power)\n"
                      "/sync — sync\n/peers — peers\n/disk — disk\n"
                      "/id — chat id\n/lang — switch language\n/help — this message"),
               "ru": ("Provenance validator bot — %s\n\n"
                      "/status — общая сводка\n/val — валидатор (jailed/missed/power)\n"
                      "/sync — синхронизация\n/peers — пиры\n/disk — диск\n"
                      "/id — chat id\n/lang — сменить язык\n/help — помощь"),
               "de": ("Provenance validator bot — %s\n\n"
                      "/status — Übersicht\n/val — Validator (jailed/missed/power)\n"
                      "/sync — Sync\n/peers — Peers\n/disk — Platte\n"
                      "/id — chat id\n/lang — Sprache wechseln\n/help — diese Nachricht")},
}


def tr(key):
    return T[key].get(_lang, T[key]["en"])


def keyboard():
    """Inline keyboard in the current language, with a language toggle."""
    return json.dumps({"inline_keyboard": [
        [{"text": tr("b_status"), "callback_data": "status"}, {"text": tr("b_val"), "callback_data": "val"}],
        [{"text": tr("b_sync"), "callback_data": "sync"}, {"text": tr("b_peers"), "callback_data": "peers"}],
        [{"text": tr("b_disk"), "callback_data": "disk"}, {"text": tr("b_help"), "callback_data": "help"}],
        [{"text": tr("b_lang"), "callback_data": "lang"}],
    ]})

def send(chat_id, text, kb=False):
    # kb=True — прикрепить инлайн-кнопки к последней части
    ok = True
    chunks = [text[i:i+3900] for i in range(0, len(text), 3900)]
    for n, chunk in enumerate(chunks):
        params = {"chat_id": chat_id, "text": chunk,
                  "disable_web_page_preview": "true"}
        if kb and n == len(chunks) - 1:
            params["reply_markup"] = keyboard()
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
        if not send(a["cid"], tr("a_repeat") + a["text"], kb=True):
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
def sync_symbol(s):
    """
    Состояние синхронизации по ВОЗРАСТУ БЛОКА, а не по флагу catching_up.

    catching_up=false у CometBFT значит «догоняющая синхронизация не идёт» — это же
    возвращает и остановившаяся нода: процесса нет, значит false, значит зелёно. Возраст
    последнего блока — единственный признак, который врать не умеет. Три состояния, а не
    два: измерили и норма, измерили и отстаём, измерить не смогли.

    Тот же баг был в monad-tg-bot и проявился 2026-08-07: нода стояла на одном блоке,
    отставая на тысячи, а /status рисовал ✅. Здесь детект в monitor() работает правильно
    и без этой правки — сломан был только показываемый значок.
    """
    if s["lag"] is None:
        return tr("s_nolag")
    if s["lag"] > LAG_WARN:
        return tr("s_behind")
    if s["catching_up"]:
        return "🟡 catching_up"
    return tr("s_ok")


def fmt_status():
    L = ["🔷 Provenance — %s" % HOST]
    L.append(tr("svc") + ("✅ active" if svc_active() else tr("svc_bad")))
    s = get_status()
    if s:
        L.append(tr("st_net") % (s["network"], app_version(), s["version"]))
        L.append(tr("st_sync") % (sync_symbol(s), s["height"],
                 "?" if s["lag"] is None else "%ds" % s["lag"]))
        L.append("Voting power: %s" % s["vp"])
    else:
        L.append(tr("st_norpc"))
    sg = get_signing()
    if sg:
        jl = tr("y_yes") if sg["jailed"] else tr("y_no")
        tb = " 💀tombstoned" if sg["tombstoned"] else ""
        L.append("Jailed: %s%s" % (jl, tb))
        L.append(tr("v_missed") % (sg["missed"], SLASH_WINDOW, JAIL_THRESHOLD))
    else:
        # Раньше эти строки просто ПРОПАДАЛИ из сводки. Отчёт выглядел здоровым — без единого
        # признака, что джейл и пропущенные блоки не проверялись вообще: не отвечает RPC, нет
        # provenanced, не задан VALCONS. Молчание читается как «всё хорошо», а это худший из
        # возможных ответов для проверки, ради которой бот и существует.
        L.append(tr("st_jail_unk"))
        L.append(tr("st_missed_unk"))
    p = get_peers()
    L.append(tr("st_peers") % p if p is not None else tr("st_peers_unk"))
    d = get_disk()
    if d["pct"] is not None:
        L.append(tr("st_disk") % (
            "✅" if d["pct"] < DISK_WARN_PCT else "🟡", d["pct"], d["avail_gb"]))
    else:
        L.append(tr("st_disk_unk"))
    return "\n".join(L)

def fmt_val():
    sg = get_signing(); s = get_status()
    if not sg: return tr("v_nosign")
    # v_body and st_missed were one implicitly-concatenated literal; keep them joined so the
    # combined format string still consumes all seven arguments in order.
    return ((tr("v_body") + tr("st_missed"))
            % (tr("y_yes") if sg["jailed"] else tr("y_no"), sg["jailed_until"],
               sg["tombstoned"], sg["missed"], SLASH_WINDOW, JAIL_THRESHOLD,
               s["vp"] if s else "?"))

def fmt_sync():
    s = get_status()
    if not s: return tr("a_rpc_down")
    return (tr("sy_body")
            % (sync_symbol(s),
               s["height"], "?" if s["lag"] is None else "%ds" % s["lag"], s["catching_up"]))

def fmt_peers():
    p = get_peers(); return tr("pe_body") % ("?" if p is None else p)

def fmt_disk():
    d = get_disk(); return tr("dk_body") % (
        "—" if d["pct"] is None else tr("dk_used") % (d["pct"], d["avail_gb"]),
        sh("df -h / | tail -1"))

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
    if st.get("active") is True and not active: A.append(tr("a_svc_down"))
    elif st.get("active") is False and active:  A.append(tr("a_svc_up"))
    if st.get("start") and start and start != st["start"] and active:
        A.append(tr("a_restart") % start)
    st["active"], st["start"] = active, start
    # rpc / sync
    s = get_status()
    rpc_dead = s is None
    if rpc_dead and not st.get("rpc_dead"): A.append(tr("a_rpc_down"))
    elif not rpc_dead and st.get("rpc_dead"): A.append(tr("a_rpc_up"))
    st["rpc_dead"] = rpc_dead
    if s:
        if s["catching_up"] and not st.get("catching_up"):
            A.append(tr("a_catching") % s["height"])
        elif not s["catching_up"] and st.get("catching_up"):
            A.append(tr("a_sync_ok") % s["height"])
        st["catching_up"] = s["catching_up"]
        if s["lag"] is not None:
            behind = s["lag"] > LAG_WARN
            if behind and not st.get("behind"): A.append(tr("a_lag") % s["lag"])
            elif not behind and st.get("behind"): A.append(tr("a_lag_ok") % s["lag"])
            st["behind"] = behind
        # block stall (height not advancing) — STALL_TICKS тиков подряд, не с одного
        # замера: одиночное совпадение высот ложнит при рестарте бота (первый тик
        # нового процесса стартует через секунды после последнего тика старого)
        ph = st.get("height")
        if ph is not None and s["height"] is not None and s["height"] == ph and not rpc_dead:
            st["stall_ticks"] = st.get("stall_ticks", 0) + 1
            if st["stall_ticks"] >= STALL_TICKS and not st.get("stalled"):
                A.append(tr("a_stuck")
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
                A.append(tr("a_stuck_ok") % s["height"])
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
                A.append(tr("a_vp_drop") % (pvp, vp))
            if vp == 0 and pvp != 0:
                A.append(tr("a_vp_zero"))
            elif vp > 0 and pvp == 0:
                A.append(tr("a_vp_ok") % vp)
            st["vp"] = vp
    # validator signing-info
    sg = get_signing()
    if sg:
        if sg["jailed"] and not st.get("jailed"):
            A.append(tr("a_jail") % sg["jailed_until"])
        elif not sg["jailed"] and st.get("jailed"):
            A.append(tr("a_unjail"))
        st["jailed"] = sg["jailed"]
        if sg["tombstoned"] and not st.get("tombstoned"):
            A.append(tr("a_tomb"))
        st["tombstoned"] = sg["tombstoned"]
        m = sg["missed"]; pm = st.get("missed")
        # threshold crossings
        if m >= MISSED_CRIT and (pm is None or pm < MISSED_CRIT):
            A.append(tr("a_missed") % (m, MISSED_CRIT, JAIL_THRESHOLD))
        elif m >= MISSED_WARN and (pm is None or pm < MISSED_WARN):
            A.append("🟡 MISSED BLOCKS = %d (>%d)" % (m, MISSED_WARN))
        # Активный пропуск блоков. Рейт-лимит обязателен: при блоке ~6с валидатор, который не
        # подписывает, набирает ~10 промахов в минуту, и это условие срабатывало КАЖДЫЙ тик —
        # 60 сообщений в час, которыми затирается всё остальное, включая джейл-алерт.
        if pm is not None and m - pm >= 10:
            now = time.time()
            if now - float(st.get("missed_rate_alert_ts") or 0) >= MISSED_ALERT_MIN_GAP:
                A.append(tr("a_missing") % (m - pm, m))
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
            # Same implicit concatenation as fmt_val: a_nosign carries the %d, st_unchecked
            # names what stops being checked.
            A.append((tr("a_nosign") + tr("st_unchecked")) % fails)
    # peers
    p = get_peers()
    if p is None:
        # Тот же класс, что PB-2, ставки ниже: /net_info недоступен → проверка пиров молча
        # пропускается. Раз подряд — не событие, но постоянная слепота должна быть слышна.
        _pf = int(st.get("peers_fail_ticks") or 0) + 1
        st["peers_fail_ticks"] = _pf
        if _pf == PEERS_FAIL_ALERT_TICKS:
            A.append(tr("a_nonet") % _pf)
    else:
        st["peers_fail_ticks"] = 0
    if p is not None:
        low = p < PEERS_MIN
        if low and not st.get("peers_low"): A.append(tr("a_peers_low") % (p, PEERS_MIN))
        elif not low and st.get("peers_low"): A.append(tr("a_peers_ok") % p)
        st["peers_low"] = low
    # disk
    d = get_disk()
    if d["pct"] is not None:
        warn = d["pct"] >= DISK_WARN_PCT
        if warn and not st.get("disk_warn"): A.append(tr("a_disk") % (d["pct"], d["avail_gb"]))
        elif not warn and st.get("disk_warn"): A.append(tr("a_disk_ok") % d["pct"])
        st["disk_warn"] = warn
    # РЕ-АЛЕРТ критических состояний каждые 30 мин (урок инцидента 2026-07-19)
    now = time.time()
    crit = []
    if st.get("jailed"):     crit.append(tr("a_jail_still"))
    if st.get("tombstoned"): crit.append("💀 TOMBSTONED")
    if st.get("stalled"):    crit.append(tr("a_stuck_still") % st.get("height"))
    if st.get("rpc_dead"):   crit.append(tr("a_rpc_still"))
    # missed, застрявший у порога джейла (1728), раньше давал ОДИН алерт и дальше тишину —
    # в crit-список он не входил, хотя это именно то состояние, о котором надо напоминать.
    if (st.get("missed") or 0) >= MISSED_CRIT:
        crit.append(tr("a_missed_still") % (st["missed"], JAIL_THRESHOLD))
    if st.get("vp") == 0:
        crit.append(tr("a_vp_zero_still"))
    if st.get("active") is False: crit.append(tr("a_svc_still"))
    if crit:
        if now - st.get("last_realert", 0) >= 1800:
            A.append(tr("a_reminder") + "\n".join(crit))
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
    elif cmd == "help":   send(cid, tr("help") % HOST, kb=True)
    elif cmd == "lang":
        # Cycle EN -> RU -> DE and reply with the full help: Telegram cannot re-render earlier
        # messages, so a bare confirmation would look like nothing happened.
        global _lang
        order = ["en", "ru", "de"]
        _lang = order[(order.index(_lang) + 1) % len(order)] if _lang in order else "en"
        st = load_state(); st["lang"] = _lang; save_state(st)
        send(cid, tr("m_lang") + "\n\n" + tr("help") % HOST, kb=True)
    else: send(cid, tr("m_unknown"), kb=True)

def handle(msg):
    cid = str(msg.get("chat", {}).get("id", ""))
    text = (msg.get("text") or "").strip()
    if not text.startswith("/"): return
    cmd = text.split()[0].lstrip("/").split("@")[0].lower()
    if cmd in ("id", "start"):
        send(cid, tr("m_chatid")
                  % (cid, tr("help") % HOST if cid in ALLOWED else ""), kb=cid in ALLOWED); return
    if cid not in ALLOWED:
        send(cid, tr("m_unauth") % cid); return
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
        send(cid, tr("m_unauth") % cid); return
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
        sys.stderr.write("BOT_TOKEN is not set\n"); sys.exit(1)
    st = load_state()
    # Restore the language chosen with /lang across restarts; config LANG is the fallback.
    global _lang
    _lang = st.get("lang", DEFAULT_LANG)
    offset = st.get("offset", 0)
    monitor(st)
    broadcast(tr("m_started") % HOST)
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
