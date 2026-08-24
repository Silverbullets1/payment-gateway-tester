# ⌬ Archive Burp — Payment Gateway Vulnerability Tester v3.0

[![Vercel](https://img.shields.io/badge/deployed%20on-Vercel-black)](https://vercel.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **2 bug tests — Price Tamper + Cancel→Success — on ANY payment gateway.**
> Paste URL → Run test → Know if site is vulnerable → Manual verify with BurpSuite.

## 🔬 The 2 Tests

### 1️⃣ Price Tamper (₹1)
Kisi bhi amount ko **₹1 / ₹0.01** me change karo — agar gateway ₹1 ka order accept kare → **VULNERABLE!**

**Flow:**
1. Paste payment link → Load
2. Click **"Test Price Tamper (₹1)"**
3. Tool rewrites amount → probes gateway
4. Result: ⚠️ VULN or ✅ Safe
5. Agar VULN → BurpSuite se manually ₹1 order karo

### 2️⃣ Cancel → Success (C2S)
Payment page pe **Cancel/Back** dabao → us cancel ko **SUCCESS** forge karo → agar order success ho jaye → **VULNERABLE!**

**Flow:**
1. Load payment URL in iframe
2. **Cancel** the payment (click cancel/back on gateway page)
3. Click **"Capture Cancel URL"** → forge success
4. Result: ⚠️ VULN or ✅ Safe
5. Agar VULN → BurpSuite se manually verify karo

## 🚀 Quick Start

```bash
git clone https://github.com/Silverbullets1/payment-gateway-tester.git
cd payment-gateway-tester

# Option 1: Static server (frontend only)
npx serve .

# Option 2: Full proxy server (recommended — enables C2S test)
npm install
npm start
```

## 🌐 Deploy on Vercel

```bash
npm i -g vercel
vercel --prod
```

## 📁 Project Structure

```
payment-gateway-tester/
├── index.html              # Main UI
├── css/styles.css          # Dark Burp-style theme
├── js/
│   ├── gateways.js         # 16+ gateway detection DB
│   ├── scanner.js          # Price Tamper + Cancel→Success engine
│   ├── batch.js            # Batch URL import + queue
│   ├── report.js           # JSON / Markdown / CSV export
│   └── app.js              # UI controller
├── proxy-server.js         # Secure proxy (+ /api/probe endpoint)
├── server/
│   └── webhook.js          # Callback receiver for gateway webhooks
├── package.json
├── vercel.json
└── README.md
```

## 🛡️ Security

- SSRF protection: domain allowlist (gateway domains only)
- XSS: HTML escaping on all user input
- IP blocklist: private, loopback, metadata IPs blocked
- CSP: frame-ancestors restricted to same-origin

## ⚙️ API Endpoints

| Endpoint | Method | Kya karta hai |
|----------|--------|---------------|
| `/proxy?url=...` | GET | Proxy HTML (strips frame blockers) |
| `/api/probe` | POST | Send forged request to gateway (real C2S detection) |
| `/api/log` | GET | View proxy request log |
| `/api/webhook/capture` | POST | Capture gateway callbacks |
| `/api/webhook/latest` | GET | View captured callbacks |
| `/health` | GET | Health check |

## 💡 Manual Workflow (C2S Test)

```
1. Load URL in tool
2. Payment page opens in iframe
3. Click Cancel/Back on gateway page
4. Click "Capture Cancel URL" button
5. Click "Forge Cancel → SUCCESS"
6. Tool sends forged callback to gateway
7. ⚠️ VULN = server accepted → order flips to success
```

## 📄 License

MIT License