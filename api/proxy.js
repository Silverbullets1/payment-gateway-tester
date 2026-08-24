/**
 * ⌬ Archive Burp — Vercel Serverless Entry
 * Routes /api/probe, /proxy, /health to the main proxy app.
 */

const app = require('../proxy-server');

module.exports = app;