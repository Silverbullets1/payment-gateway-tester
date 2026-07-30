/**
 * PROXY SERVER — Bypasses X-Frame-Options for Payment Gateways
 * Run: node proxy-server.js
 * Deploy: vercel --prod (with serverless function config)
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Clean URL — remove proxy prefix
function cleanUrl(req) {
    const url = req.query.url || req.body.url || '';
    return url.trim();
}

// Main proxy endpoint
app.get('/proxy', async (req, res) => {
    const targetUrl = cleanUrl(req);
    if (!targetUrl) {
        return res.status(400).json({ error: 'Missing ?url= parameter' });
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
            timeout: 30000
        });

        // Get the HTML
        let html = response.data;

        // STRIP X-FRAME-OPTIONS HEADERS
        // Remove meta tags that block iframes
        html = html.replace(/<meta[^>]*X-Frame-Options[^>]*>/gi, '');
        html = html.replace(/<meta[^>]*frame-options[^>]*>/gi, '');
        html = html.replace(/<meta[^>]*x-frame-options[^>]*>/gi, '');

        // Remove frame-busting scripts
        html = html.replace(/<script[^>]*top\.location[^<]*<\/script>/gi, '');
        html = html.replace(/<script[^>]*parent\.location[^<]*<\/script>/gi, '');
        html = html.replace(/<script[^>]*self\.location[^<]*<\/script>/gi, '');
        html = html.replace(/<script[^>]*window\.top[^<]*<\/script>/gi, '');

        // Add base tag to fix relative URLs
        const baseTag = `<base href="${targetUrl}" target="_blank">`;
        html = html.replace(/<head>/i, `<head>${baseTag}`);

        // Inject a small script to handle form submissions within iframe
        const injectScript = `
        <script>
        // Allow forms to submit within iframe
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('form').forEach(function(form) {
                form.setAttribute('target', '_blank');
            });
        });
        </script>
        `;
        html = html.replace(/<\/head>/i, `${injectScript}</head>`);

        // Send the modified HTML
        res.setHeader('Content-Type', response.headers['content-type'] || 'text/html');
        res.setHeader('X-Frame-Options', 'SAMEORIGIN'); // Allow same-origin
        res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
        res.send(html);

    } catch (error) {
        console.error('Proxy error:', error.message);
        res.status(500).send(`
            <html>
            <head><title>Proxy Error</title></head>
            <body style="background:#0a0808;color:#d48a7a;font-family:monospace;padding:2rem;">
                <h1>⌬ Proxy Error</h1>
                <p>Could not fetch: ${targetUrl}</p>
                <p style="color:#5a4f42;font-size:0.8rem;">${error.message}</p>
                <p style="color:#3a352a;font-size:0.7rem;">Try opening directly in a new tab.</p>
            </body>
            </html>
        `);
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
    console.log(`⌬ Proxy Server running on port ${PORT}`);
    console.log(`📍 Use: /proxy?url=ENCODED_GATEWAY_URL`);
});

module.exports = app;
