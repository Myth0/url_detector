# PhishGuard — Phishing URL Detection System

A beginner-friendly defensive cybersecurity project built with Python, Flask, HTML/CSS, and SQLite.

## Features
- URL validation (HTTP/HTTPS only)
- Explainable rule-based scoring
- HTTPS, IP host, `@` character, URL length, subdomain count, punycode, keywords, shortening service, TLD, and hyphen checks
- Dashboard summary cards
- Scan history stored in local SQLite
- Clear history action

## Important limitations
This is an educational heuristic checker, not a machine-learning model or a definitive phishing verdict. It does not fetch or open URLs. A low score does not guarantee safety, and HTTPS alone does not make a site trustworthy. Test only with sample URLs or links you are authorized to examine.

## Setup (Windows)
1. Install Python 3.10 or newer from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Extract this folder.
3. Open Command Prompt in the project folder.
4. Create a virtual environment:
   ```bat
   py -m venv .venv
   .venv\Scripts\activate
   ```
5. Install dependencies:
   ```bat
   pip install -r requirements.txt
   ```
6. Run:
   ```bat
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser.

## Setup (Linux / Kali Linux / macOS)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Safe test inputs
- `https://example.com`
- `http://example.com/login-verify`
- `http://192.0.2.10/account`

`example.com` is reserved for examples. `192.0.2.10` is a documentation-only example IP. Do not open suspicious URLs to test them; paste them into the scanner only.

## Project structure
```text
phishing_url_detector/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── scans.db             # created automatically after first run
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── history.html
│   └── 404.html
└── static/
    └── style.css
```

## Risk score rules
Rules add points; the score is capped at 100:
- HTTP instead of HTTPS: +10
- IP address host: +25
- `@` in network location: +25
- URL longer than 100 characters: +10
- 5 or more hostname labels: +10
- punycode hostname label: +15
- sensitive keywords: +5 plus 3 per additional match, capped at +20
- known URL shortener: +15
- selected TLDs: +10
- two or more hyphens in hostname: +5

Category thresholds:
- 0–24: Lower Risk
- 25–49: Suspicious
- 50–100: High Risk

These weights are illustrative and are not calibrated against a real phishing dataset.
