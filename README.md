# FF Bio Changer — KAWSAR_CODEX Edition

## Project Structure
```
bioapp/
├── app.py              ← Flask backend (all API routes)
├── requirements.txt    ← Python dependencies
└── templates/
    └── index.html      ← Full frontend (bio editor + auth)
```

## Setup & Run

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run locally
python app.py

# 3. Open in browser
http://localhost:5000
```

## Deploy to Render / Railway / Koyeb
- Set start command: `gunicorn app:app`
- Python 3.10+

## API Endpoints
| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Main web page |
| `/api/get-jwt` | POST | Get JWT from UID+Password |
| `/api/eat-to-access` | POST | Convert EAT → Access Token |
| `/api/update-bio/jwt` | POST | Update bio using JWT |
| `/api/update-bio/access` | POST | Update bio using Access Token |

## Features
- 🌈 16 color picker
- 🌸 Flowers, 📦 Box Frames, ➖ Lines, ⭐ Stars, 🔥 Special Symbols, 🏹 Arrows
- 👁 Live bio preview (exactly like in-game)
- 🔑 4 Authentication methods: JWT, UID+Password, Access Token, EAT Token
- 🚀 Auto token conversion pipeline

**Developed by KAWSAR_CODEX**
