# 🎣 PhishTriage

A lightweight Python tool that performs first-pass triage of suspicious raw email files (`.eml`) — the kind of check a Tier-1 SOC Analyst runs when a user reports a phishing email.

## 📋 Project Overview

When a suspicious email is reported, an analyst needs to quickly pull out the key indicators **without opening links or attachments**. PhishTriage parses the raw email and prints the headers, defanged URLs, and attachment names in a clean report, ready to paste into a ticket or check against threat-intel tools (VirusTotal, URLScan, etc.).

## ✨ Features

- **Header extraction** – Subject, From, To, and Return-Path (a From/Return-Path mismatch is a classic spoofing clue).
- **URL extraction & defanging** – Finds links in plain-text and HTML bodies and makes them safe to share (`http://evil.com` → `hxxp://evil[.]com`).
- **Domain identification** – Shows the domain for each link to speed up reputation lookups.
- **Attachment listing** – Lists file names without opening them, which helps spot tricks like `Invoice.pdf.exe`.
- **Zero dependencies** – Uses only Python built-in libraries (`email`, `re`, `sys`, `urllib.parse`).

## ⚙️ Setup & Run

Requires **Python 3.8+**. Nothing to install.

```bash
git clone https://github.com/<your-username>/PhishTriage.git
cd PhishTriage
python phish_triage.py sample_phish.eml
```

## 🖥️ Example Output

```text
=== HEADERS ===
Subject:      URGENT: Your account has been suspended
From:         PayPal Security <service@paypal.com>
To:           victim@company.example
Return-Path:  <bounce@paypa1-alerts.example>

=== LINKS (defanged) ===
- hxxp://paypa1-verify[.]example/login?id=8842  (domain: paypa1-verify[.]example)
- hxxps://secure-update[.]example[.]net/account  (domain: secure-update[.]example[.]net)

=== ATTACHMENTS ===
- Invoice_8842.pdf.exe
```

**Analyst notes on this sample:**
- 🚩 `From` says `paypal.com`, but `Return-Path` points to the look-alike domain `paypa1-alerts.example`.
- 🚩 The links use a typosquatted domain (`paypa1` with the number 1 instead of the letter l).
- 🚩 The attachment has a double extension (`.pdf.exe`), so it is an executable pretending to be a document.
- 🚩 The subject uses urgent, threatening language ("suspended", "24 hours").

## 💼 CV Bullet Point

> Developed **PhishTriage**, a dependency-free Python tool that parses raw `.eml` files to extract sender headers, defanged IOCs (URLs/domains) and attachment names, so suspicious emails can be triaged safely and quickly in a SOC workflow.

## ⚠️ Disclaimer

The included `sample_phish.eml` is fake and harmless, and all domains use reserved `.example` names. Always analyse real suspicious emails inside an isolated environment.

## 📄 License

MIT
