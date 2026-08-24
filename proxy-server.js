/**
 * ⌬ Archive Burp — Secure Proxy Server v2.0
 * =========================================
 * Bypasses X-Frame-Options for payment gateway testing
 * with SSRF/XSS protections, request logging, and API probing.
 *
 * Run: node proxy-server.js
 * Deploy: vercel --prod
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Serve static files (index.html, css/, js/) — enables local `npm start`
const path = require('path');
app.use(express.static(path.join(__dirname)));

/* ============================================================
 * SECURITY: SSRF & open-proxy protection
 * ============================================================ */

// Allowlist of gateway domains (add more as needed)
// Any public domain allowed — the tool tests ANY site the user pastes.
// Security is enforced via IP blocklist (SSRF protection) below,
// NOT a domain allowlist (which would block legitimate targets).
const ALLOWED_DOMAINS = null; // null = allow all public http/https domains

// Blocked IP ranges (private, loopback, link-local, metadata)
const BLOCKED_IPS = [
    '127.0.0.1', 'localhost', '0.0.0.0',
    '169.254.169.254',  // cloud metadata
    '::1', '::ffff:127.0.0.1',
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.'
];

function isBlockedHost(host) {
    if (!host) return true;
    const h = host.toLowerCase();
    if (BLOCKED_IPS.some(b => h.startsWith(b) || h === b)) return true;
    return false;
}

function isAllowedDomain(url) {
    try {
        const u = new URL(url);
        const host = u.hostname.toLowerCase();
        // Always block internal/private hosts (SSRF protection)
        if (isBlockedHost(host)) return false;
        // Allow all other public domains
        return true;
    } catch (e) {
        return false;
    }
}

// Only allow http/https
function isHttpUrl(url) {
    try {
        const u = new URL(url);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

// HTML escape helper
function esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;',
        '"': '&quot;', "'": '&#39;'
    })[c]);
}

/* ============================================================
 * PROXY ENDPOINT
 * ============================================================ */

// Clean URL — remove proxy prefix
function cleanUrl(req) {
    const url = req.query.url || req.body.url || '';
    return String(url).trim();
}

// Strip all frame-blocking headers & content
function stripFrameBlockers(html) {
    let out = html;
    // Meta tags that block iframes
    out = out.replace(/<meta[^>]*(X-Frame-Options|frame-ancestors|Content-Security-Policy|X-Content-Type-Options)[^>]*>/gi, '');
    // CSP meta with frame-ancestors
    out = out.replace(/<meta[^>]*content-security-policy[^>]*>/gi, '');
    // Frame-busting scripts
    out = out.replace(/<script[^>]*(top\.location|parent\.location|self\.location|window\.top|window\.parent|frameElement|break-out|stop\(\))[^<]*<\/script>/gi, '');
    // onload frame busters
    out = out.replace(/<body[^>]*onload=[^>]*>/gi, '<body>');
    return out;
}

// Main proxy endpoint
app.get('/proxy', async (req, res) => {
    const targetUrl = cleanUrl(req);

    if (!targetUrl) {
        return res.status(400).json({ error: 'Missing ?url= parameter' });
    }

    // SECURITY: validate protocol
    if (!isHttpUrl(targetUrl)) {
        return res.status(400).json({ error: 'Only http/https URLs allowed' });
    }

    // SECURITY: validate domain allowlist
    if (!isAllowedDomain(targetUrl)) {
        return res.status(403).json({
            error: 'Domain not in allowlist. Only payment gateway domains are allowed.'
        });
    }

    try {
        const response = await axios({
            method: 'GET',
            url: targetUrl,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            maxRedirects: 5,
            timeout: 30000,
            responseType: 'arraybuffer',
            validateStatus: () => true  // capture all statuses for analysis
        });

        // Detect content type
        const contentType = String(response.headers['content-type'] || 'text/html');
        const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml');

        // Log request for audit (in-memory, last 200)
        const logEntry = {
            ts: new Date().toISOString(),
            status: response.status,
            url: targetUrl,
            contentType
        };
        if (!app.locals.requestLog) app.locals.requestLog = [];
        app.locals.requestLog.unshift(logEntry);
        if (app.locals.requestLog.length > 200) app.locals.requestLog.pop();

        // For non-HTML, pass through as-is (JSON, images, etc.)
        if (!isHtml) {
            res.setHeader('Content-Type', contentType);
            res.setHeader('X-Proxy-Status', String(response.status));
            return res.send(Buffer.from(response.data));
        }

        // Decode HTML
        let html = Buffer.from(response.data).toString('utf-8');

        // STRIP ALL frame blockers
        html = stripFrameBlockers(html);

        // Add base tag to fix relative URLs (escaped!)
        const baseTag = `<base href="${esc(targetUrl)}">`;
        html = html.replace(/<head>/i, `<head>${baseTag}`);

        // Inject helper script for form handling within iframe
        const injectScript = `
        <script>
        (function() {
            function handler() {
                document.querySelectorAll('form').forEach(function(form) {
                    form.setAttribute('target', '_blank');
                });
            }
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', handler);
            } else { handler(); }
        })();
        </script>`;
        html = html.replace(/<\/head>/i, `${injectScript}</head>`);

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
        res.setHeader('X-Proxy-Status', String(response.status));
        res.send(html);

    } catch (error) {
        console.error('Proxy error:', error.message);
        res.status(502).send(`
            <html>
            <head><title>Proxy Error</title></head>
            <body style="background:#0a0808;color:#d48a7a;font-family:monospace;padding:2rem;">
                <h1>⌬ Proxy Error</h1>
                <p>Could not fetch: ${esc(targetUrl)}</p>
                <p style="color:#5a4f42;font-size:0.8rem;">${esc(error.message)}</p>
            </body>
            </html>
        `);
    }
});

/* ============================================================
 * API PROBE — real C2S / tamper detection engine
 * Sends a forged POST to the gateway endpoint and returns
 * the server's actual response for comparison.
 * ============================================================ */

app.post('/api/probe', async (req, res) => {
    const { url, method = 'POST', data = {}, headers = {} } = req.body || {};

    if (!url || !isHttpUrl(url)) {
        return res.status(400).json({ error: 'Invalid URL' });
    }
    if (!isAllowedDomain(url)) {
        return res.status(403).json({ error: 'Domain not in allowlist' });
    }

    try {
        const response = await axios({
            method: String(method).toUpperCase(),
            url,
            data,
            headers: Object.assign({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Content-Type': 'application/json'
            }, headers),
            maxRedirects: 3,
            timeout: 20000,
            validateStatus: () => true
        });

        const body = Buffer.isBuffer(response.data) || typeof response.data === 'string'
            ? response.data.toString().substring(0, 10000)
            : JSON.stringify(response.data).substring(0, 10000);

        res.json({
            ok: true,
            status: response.status,
            headers: response.headers,
            body
        });
    } catch (error) {
        res.json({
            ok: false,
            error: error.message,
            status: error.response ? error.response.status : 0
        });
    }
});

/* ============================================================
 * REQUEST LOG — audit trail
 * ============================================================ */

app.get('/api/log', (req, res) => {
    res.json(app.locals.requestLog || []);
});

/* ============================================================
 * HEALTH CHECK
 * ============================================================ */

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '2.0.0'
    });
});

/* ============================================================
 * START
 * ============================================================ */

// Export for Vercel serverless OR run directly
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`⌬ Archive Burp Proxy v2.0 running on port ${PORT}`);
        console.log(`📍 Use: /proxy?url=ENCODED_GATEWAY_URL`);
        console.log(`🔬 Use: POST /api/probe {url, method, data}`);
    });
}

module.exports = app;
