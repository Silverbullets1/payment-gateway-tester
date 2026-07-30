# ⌬ Archive Burp — Real-time Payment Gateway Tester

[![Vercel](https://img.shields.io/badge/deployed%20on-Vercel-black)](https://vercel.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Burp-style payment gateway testing with real-time browser, manual OTP/phone injection, and automated bug detection.

## Features

- 🖥️ **Real-time Browser** — embedded iframe shows the gateway page
- 🔍 **Auto Parameter Detection** — extracts all URL parameters
- 🐛 **Bug Scanner** — C2S vulnerability, price tampering, full scan
- ✍️ **Manual Injection** — OTP, phone number, custom params
- 💳 **Payment Method Selector** — UPI, Card, NetBanking, Wallet
- 📱 **QR/UPI Display** — shows UPI QR code or UPI ID
- 🚀 **Deploy-ready** — Vercel, Netlify, or any static host

## Supported Gateways

| Region | Gateways |
|--------|----------|
| **India** | Razorpay, PayU, CCAvenue, Instamojo, PhonePe, Google Pay, Paytm, Cashfree, Juspay, Easebuzz, Pine Labs, BillDesk |
| **International** | Stripe, PayPal, Braintree, Adyen, Worldpay, 2Checkout, Square, Klarna, Afterpay, BlueSnap |

## Quick Start

```bash
git clone https://github.com/yourusername/payment-gateway-tester.git
cd payment-gateway-tester
npx serve .
