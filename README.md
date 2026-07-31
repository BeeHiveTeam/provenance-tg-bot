# provenance-tg-bot

A tiny, dependency-free Telegram bot for monitoring a
[Provenance](https://provenance.io) (Cosmos-SDK) **validator**: push alerts on
incidents + on-demand status commands. Pure Python stdlib
(`urllib`/`json`/`subprocess`), one file, runs as a systemd service.

Validator-aware — it tracks jail status, missed blocks against the slashing
window, voting power, sync, peers, the `provenanced` service, and disk.

Companion to [monad-tg-bot](https://github.com/BeeHiveTeam/monad-tg-bot).

## Features

**Push alerts** (sent only on state change, no spam):
- 🔴🔴 validator **jailed** / 💀 **tombstoned**
- 🔴 / 🟡 **missed blocks** crossing warn/crit thresholds, and "actively missing now"
- ⚠️ **voting power** drop / dropped to 0 (fell out of the active set)
- 🔴 `provenanced` service down / restarted
- 🔴 RPC unreachable, 🟡 `catching_up` / block lag, 🔴 height not advancing
- 🟡 low peers, 🟡 disk `/` usage over threshold

**Commands** (authorized chat IDs only):

| Command | What |
|---|---|
| `/status` | summary: service, sync, height, voting power, jailed, missed, peers, disk |
| `/val` | validator detail: jailed, jailed_until, tombstoned, missed/window, voting power |
| `/sync` | sync status, height, block lag |
| `/peers` | peer count |
| `/disk` | disk usage of `/` |
| `/id` | reply with your chat id (for first-time setup) |
| `/help` | command list |

Every reply and alert comes with inline buttons for the same commands — tap instead of typing.

## Requirements

- Python 3.8+
- A Provenance node with CometBFT RPC on `http://localhost:26657`
- `provenanced` binary in `PATH` (used read-only for `query slashing signing-info`)
- systemd, `systemctl` / `journalctl` / `df`
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

Runs as **root** (reads systemd state, the journal, runs `provenanced query`).
It is **read-only** — it never signs, restarts, or modifies the node.

## Install

```bash
sudo mkdir -p /opt/provenance-tg-bot
sudo install -m 0755 bot.py                     /opt/provenance-tg-bot/bot.py
sudo install -m 0644 provenance-tg-bot.service  /etc/systemd/system/provenance-tg-bot.service
sudo install -m 0600 config.env.example         /opt/provenance-tg-bot/config.env   # then edit

# fill in BOT_TOKEN and VALCONS (and ALLOWED_CHAT_IDS after /id):
sudo nano /opt/provenance-tg-bot/config.env

sudo systemctl daemon-reload
sudo systemctl enable --now provenance-tg-bot
```

Find your `VALCONS` from the hex address in `curl localhost:26657/status`
(`result.validator_info.address`):

```bash
provenanced keys parse <HEX_ADDRESS>     # → pbvalcons1...
```

## Configuration (`config.env`)

| Key | Default | Meaning |
|---|---|---|
| `BOT_TOKEN` | — | bot token from @BotFather |
| `ALLOWED_CHAT_IDS` | — | comma-separated authorized chat ids |
| `RPC_URL` | `http://localhost:26657` | CometBFT RPC |
| `HOME_DIR` | `/home/provenance/.provenanced` | node home for `provenanced query` |
| `VALCONS` | — | validator consensus (valcons) address |
| `CHECK_INTERVAL` | `60` | background check interval, seconds |
| `MISSED_WARN` / `MISSED_CRIT` | `500` / `1500` | missed-blocks alert thresholds |
| `PEERS_MIN` | `3` | low-peers warning threshold |
| `BLOCK_LAG_WARN_SEC` | `30` | block-lag warning threshold |
| `DISK_WARN_PCT` | `85` | disk `/` usage warning threshold |

State (Telegram offset + alert de-dup baseline) lives in `/opt/provenance-tg-bot/state.json`.

## Security notes

- `config.env` holds the bot token — `chmod 600` and **gitignored**. Never commit it.
- Only `ALLOWED_CHAT_IDS` get data; others get only their own chat id.
- Only one process may long-poll a bot token (a manual `getUpdates` returns 409 and disrupts the bot).
- Read-only: the bot never signs or restarts the validator.

> Note: this bot runs on the same host as the node, so it cannot alert if the
> whole server goes down. Pair it with an external/off-host check for full coverage.

## License

MIT

### Дополнительные ключи конфигурации

Читаются кодом, ранее нигде не были описаны — оператор не мог узнать об их существовании, кроме как из исходника.

| Ключ | Назначение |
|---|---|
| `JAIL_THRESHOLD` | см. `config.env.example` |
| `MISSED_ALERT_MIN_GAP` | см. `config.env.example` |
| `PEERS_FAIL_ALERT_TICKS` | см. `config.env.example` |
| `PENDING_MAX` | см. `config.env.example` |
| `PENDING_TTL_SEC` | см. `config.env.example` |
| `SIGNING_FAIL_ALERT_TICKS` | см. `config.env.example` |
| `SLASH_WINDOW` | см. `config.env.example` |
| `STALL_TICKS` | см. `config.env.example` |
