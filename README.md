# 🐍 Nagini Protocol

> **Geographic Secret Distribution for Cryptographic Key Recovery**

Split a master secret into N encrypted shards. Each shard is locked to a GPS location. Recovery requires physical presence at K of N locations. Coordinates never leave your head.

```
Secret → Shamir SSS → N shards → AES-256-GCM (keyed by GPS) → stored publicly
Recovery → visit K locations → decrypt shards → reconstruct secret
```

> ⚠️ **PROTOTYPE — NOT SECURITY AUDITED. Do not use for real assets yet.**

---

## How it works

| Concept | Description |
|---|---|
| **Shamir Secret Sharing** | Secret split into N shards over GF(2⁸). K shards needed to reconstruct. |
| **Geo-key derivation** | Each shard encrypted with `AES-256-GCM(HKDF(SHA3-256(lat\|\|lon)))` |
| **Fuzzy Extractor** | Tolerates ~200m GPS drift. Checks 9 tile candidates automatically. |
| **Zero geo data in blobs** | Encrypted blobs contain no coordinates. Safe to store publicly. |
| **Canary shard** | One shard is a trap. Visiting it returns a fake secret + fires a silent alert. |

---

## Features

- 🔐 AES-256-GCM + HKDF + SHA3-256 + GF(2⁸) Shamir SSS
- 📍 Fuzzy GPS matching (~200m tolerance)
- 🪤 Canary shard with Telegram / webhook alerts
- 🆘 SOS Protocol: Dead Man's Switch, Duress PIN, emergency broadcast
- 🌐 REST API (Flask) — integrates with any service
- 📱 Mobile PWA — field-ready, installable, GPS capture
- 💻 Web UI — dark, runs locally at `localhost:5000`
- 🖥️ CLI interface
- 🔗 **Native LAC integration** — embedded in [LightAnonChain](https://github.com/epidemiaya/LightAnonChain-)

---

## Quick start

**Requirements:** Python 3.10+

```bash
git clone https://github.com/epidemiaya/nagini-protocol.git
cd nagini-protocol
pip install flask cryptography
python app.py
```

- Desktop UI: **http://localhost:5000**
- Mobile PWA: **http://localhost:5000/mobile**

### CLI

```bash
python nagini.py setup                    # create bundle
python nagini.py recover --id <id>        # recover secret
python nagini.py list                     # list bundles
```

---

## REST API

```
GET  /api/status                     — health check
POST /api/setup                      — create bundle
POST /api/recover/shard              — decrypt one shard
POST /api/recover/reconstruct        — reconstruct secret
GET  /api/bundles                    — list bundles
GET  /api/bundle/<id>                — bundle info

POST /api/sos/config                 — create SOS profile
POST /api/sos/checkin                — Dead Man's Switch check-in
POST /api/sos/trigger                — manual SOS alert
POST /api/sos/pin                    — verify PIN (duress detection)
GET  /api/sos/status/<profile_id>    — DMS status

POST /api/telegram/find_chat_id      — find Telegram chat_id by bot token
POST /api/telegram/test              — send test Telegram message
```

### Example: create bundle

```bash
curl -X POST http://localhost:5000/api/setup \
  -H "Content-Type: application/json" \
  -d '{
    "passphrase": "my secret",
    "locations": [[50.4501, 30.5234], [48.9226, 24.7111], [46.4825, 30.7233]],
    "threshold": 2
  }'
```

---

## SOS Protocol

Three duress mechanisms, all firing silently:

**Canary shard** — attacker visits a specific location → gets fake secret → alert fires in background

**Duress PIN** — enter a special PIN under coercion → API returns "valid" → SOS sent to contacts

**Dead Man's Switch** — if owner doesn't check in within N hours → escalating alerts fire automatically (Level 1 → 2 → 3)

Alert channels: **LAC messenger**, **Telegram bot**, **HTTP webhook**, **local log**

---

## Telegram — Find Chat ID

No need to look up chat IDs manually:

1. Create a bot via [@BotFather](https://t.me/BotFather), copy the token
2. Send `/start` to your bot
3. In the web UI → **SOS Config → Contact → 🔍 Find Chat ID**
4. Chat ID fills automatically. Hit **✉ Test** to verify.

---

## LAC Integration

Nagini is natively integrated into [LightAnonChain](https://github.com/epidemiaya/LightAnonChain-) — a privacy-first blockchain messenger.

- No separate server needed — runs embedded in `lac_node.py`
- Auth via `X-Seed` header (same as all LAC API calls)
- Canary and DMS alerts arrive as system messages in your LAC wallet
- Bundles stored per LAC address on the node

---

## Project structure

```
nagini-protocol/
  nagini_core.py      — GF(2⁸) SSS + AES-256-GCM + Fuzzy Extractor
  nagini_canary.py    — canary shard + silent alert
  nagini_sos.py       — SOS protocol (DMS, Duress PIN, broadcast)
  nagini_storage.py   — local JSON blob storage
  nagini.py           — CLI
  app.py              — Flask REST API
  static/
    index.html        — desktop web UI
    mobile.html       — mobile PWA (field testing)
  test_nagini.py      — 30 unit tests
  WHITEPAPER.pdf      — cryptographic specification
```

---

## Security notes

- Blobs in `~/.nagini/blobs/` — contain **zero** geographic data
- SOS configs in `~/.nagini/sos/` — AES-256-GCM + PBKDF2 (260k iterations)
- Canary configs in `~/.nagini/canary/` — separate passphrase, separate encryption
- Not formally audited. Contributions and reviews welcome.

---

## Roadmap

- [x] Core protocol — Shamir SSS + AES-256-GCM + Fuzzy Extractor
- [x] Canary shard + silent alerts
- [x] SOS Protocol — Dead Man's Switch, Duress PIN
- [x] REST API (Flask)
- [x] Web UI (desktop)
- [x] Mobile PWA — GPS capture, field-ready
- [x] Telegram Find Chat ID helper
- [x] **LAC messenger integration** — [LightAnonChain](https://github.com/epidemiaya/LightAnonChain-)
- [ ] Formal security audit
- [ ] Multi-device sync

---

## License

MIT — use freely, audit carefully.

---

*Built as part of the [LightAnonChain](https://lac-beta.uk) ecosystem.*
