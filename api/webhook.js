/**
 * ⌬ Archive Burp — Vercel Serverless Webhook Function
 * Self-contained. Routes: /api/webhook/*
 */

/**
 * ⌬ Archive Burp — Webhook Receiver
 * ================================
 * Captures payment gateway callbacks (webhooks) so you can
 * replay/cancel-to-success test the order status flow.
 *
 * Run: node server/webhook.js
 * Deploy: vercel (route /api/webhook/*)
 *
 * Usage:
 *  - Point gateway webhook URL to: https://YOUR_DEPLOY/api/webhook/capture
 *  - All callbacks are logged and stored in memory
 *  - GET /api/webhook/latest — view latest captured callbacks
 */

const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// In-memory callback store (last 100)
const callbacks = [];

// Capture endpoint — accepts any method (GET/POST/PUT)
app.all('/api/webhook/capture', (req, res) => {
    const entry = {
        ts: new Date().toISOString(),
        method: req.method,
        query: req.query,
        headers: req.headers,
        body: req.body
    };
    callbacks.unshift(entry);
    if (callbacks.length > 100) callbacks.pop();
    console.log('⌬ Webhook captured:', req.method, JSON.stringify(req.body || req.query).substring(0, 200));
    res.json({ ok: true, captured: entry.ts });
});

// View latest callbacks
app.get('/api/webhook/latest', (req, res) => {
    res.json(callbacks);
});

// Clear callbacks
app.delete('/api/webhook/clear', (req, res) => {
    callbacks.length = 0;
    res.json({ ok: true, cleared: true });
});

module.exports = app;
