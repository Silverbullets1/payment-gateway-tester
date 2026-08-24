/**
 * ⌬ Archive Burp — Webhook Vercel Serverless Entry
 * Routes /api/webhook/* to the webhook receiver.
 */

const app = require('../server/webhook');

module.exports = app;