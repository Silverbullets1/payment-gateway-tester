// ⌬ Archive Burp — App Controller v3.0
// Wires UI to scanner, batch, and report modules.

(function() {
    'use strict';

    /* ======= DOM REFS ======= */
    var urlInput = document.getElementById('urlInput');
    var loadBtn = document.getElementById('loadBtn');
    var reloadBtn = document.getElementById('reloadBtn');
    var openNewTabBtn = document.getElementById('openNewTabBtn');
    var gatewayFrame = document.getElementById('gatewayFrame');
    var currentUrlDisplay = document.getElementById('currentUrlDisplay');
    var frameOverlay = document.getElementById('frameOverlay');
    var gatewayBadge = document.getElementById('gatewayBadge');
    var statusText = document.getElementById('statusText');
    var goBackBtn = document.getElementById('goBackBtn');
    var goForwardBtn = document.getElementById('goForwardBtn');
    var refreshFrameBtn = document.getElementById('refreshFrameBtn');
    var clearCacheBtn = document.getElementById('clearCacheBtn');

    var detectedAmount = document.getElementById('detectedAmount');
    var detectedSession = document.getElementById('detectedSession');
    var detectedGatewayName = document.getElementById('detectedGatewayName');

    var tamperOutput = document.getElementById('tamperOutput');
    var c2sOutput = document.getElementById('c2sOutput');
    var verdictBox = document.getElementById('verdictBox');

    var scanTamperBtn = document.getElementById('scanTamperBtn');
    var scanC2SBtn = document.getElementById('scanC2SBtn');
    var scanAllBtn = document.getElementById('scanAllBtn');

    // Cancel tab
    var openCancelPageBtn = document.getElementById('openCancelPageBtn');
    var captureCancelBtn = document.getElementById('captureCancelBtn');
    var openNewTabCancelBtn = document.getElementById('openNewTabCancelBtn');
    var forgeSuccessBtn = document.getElementById('forgeSuccessBtn');
    var cancelUrlViewer = document.getElementById('cancelUrlViewer');
    var cancelTestOutput = document.getElementById('cancelTestOutput');
    var cancelUrlInput = document.getElementById('cancelUrlInput');
    var usePastedCancelBtn = document.getElementById('usePastedCancelBtn');

    // Batch
    var batchInput = document.getElementById('batchInput');
    var batchStartBtn = document.getElementById('batchStartBtn');
    var batchStopBtn = document.getElementById('batchStopBtn');
    var batchClearBtn = document.getElementById('batchClearBtn');
    var batchStatus = document.getElementById('batchStatus');
    var batchOutput = document.getElementById('batchOutput');

    // Report
    var exportJsonBtn = document.getElementById('exportJsonBtn');
    var exportMdBtn = document.getElementById('exportMdBtn');
    var exportCsvBtn = document.getElementById('exportCsvBtn');
    var reportViewer = document.getElementById('reportViewer');

    var toastContainer = document.getElementById('toastContainer');

    /* ======= STATE ======= */
    var state = {
        url: '',
        sessionId: '',
        detectedGateway: null,
        originalAmount: null,
        currency: 'INR',
        cancelUrl: '',
        lastResults: null,
        batchResults: []
    };

    /* ======= HELPERS ======= */
    function showToast(msg, type) {
        type = type || 'info';
        var t = document.createElement('div');
        t.className = 'toast ' + type;
        t.innerHTML = '<span></span><button class="toast-close">&times;</button>';
        t.querySelector('span').textContent = msg;
        toastContainer.appendChild(t);
        t.querySelector('.toast-close').addEventListener('click', function() { t.remove(); });
        setTimeout(function() { if (t.parentNode) t.remove(); }, 5000);
    }

    function setStatus(text, type) {
        statusText.textContent = text;
        statusText.className = 'status-text';
        if (type === 'error') statusText.classList.add('err');
        else if (type === 'success') statusText.classList.add('ok');
    }

    function esc(s) {
        if (!s) return '';
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function getCurrentUrl() {
        try {
            var u = gatewayFrame.contentWindow.location.href;
            if (u && u !== 'about:blank') {
                // If we loaded through the proxy, decode the real URL
                var proxyIdx = u.indexOf('/proxy?url=');
                if (proxyIdx !== -1) {
                    var enc = u.substring(proxyIdx + 11);
                    try { return decodeURIComponent(enc); } catch (e) { return enc; }
                }
                return u;
            }
        } catch (e) {}
        return state.url || urlInput.value;
    }

    function updateUI() {
        var url = getCurrentUrl();
        currentUrlDisplay.textContent = url || 'https://...';

        var gw = detectGateway(url);
        state.detectedGateway = gw;
        if (gw) {
            gatewayBadge.textContent = '⬡ ' + gw.name;
            gatewayBadge.className = 'badge detected';
            detectedGatewayName.textContent = gw.name;
            state.currency = gw.currency || 'INR';
        } else {
            gatewayBadge.textContent = '⏳ unknown';
            gatewayBadge.className = 'badge';
            detectedGatewayName.textContent = '—';
        }

        var session = extractSessionId(url);
        state.sessionId = session;
        detectedSession.textContent = session || '—';

        var amount = extractAmount(url, gw);
        state.originalAmount = amount;
        detectedAmount.textContent = amount !== null ? (state.currency === 'INR' ? '₹' : '$') + ' ' + amount.toFixed(2) : '—';

        var hasContent = url && url !== 'about:blank' && url !== '';
        frameOverlay.style.display = hasContent ? 'none' : 'flex';
    }

    /* ======= URL LOADING ======= */
    function loadUrl(url) {
        if (!url) { showToast('Enter a URL', 'error'); return; }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        state.url = url;
        urlInput.value = url;
        // Load through proxy so X-Frame-Options is stripped
        // and the gateway page actually renders in the iframe.
        var proxyUrl = '/proxy?url=' + encodeURIComponent(url);
        gatewayFrame.src = proxyUrl;
        setStatus('loading (proxy)...', '');
        showToast('Loading via proxy: ' + url.substring(0, 60) + '...', 'info');
        frameOverlay.style.display = 'none';
        setTimeout(updateUI, 1000);
        setTimeout(updateUI, 3000);
    }

    function openInNewTab() {
        var url = getCurrentUrl();
        if (!url || url === 'about:blank') url = urlInput.value.trim();
        if (!url || url === 'about:blank') { showToast('No URL to open', 'error'); return; }
        window.open(url, '_blank');
        showToast('Opened in new tab', 'info');
    }

    /* ======= TAB SWITCHING ======= */
    document.querySelectorAll('.tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
            this.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(function(tc) { tc.classList.remove('active'); });
            var name = this.dataset.tab;
            document.getElementById('tab' + name.charAt(0).toUpperCase() + name.slice(1)).classList.add('active');
        });
    });

    /* ======= TEST 1: PRICE TAMPER ======= */
    function runPriceTamper() {
        var url = getCurrentUrl();
        if (!url || url === 'about:blank') {
            tamperOutput.innerHTML = '<span class="fail">⚠ Load a gateway URL first</span>';
            return;
        }
        tamperOutput.innerHTML = '<span class="info">⤷ Testing price tamper (₹1 / ₹0.01)...</span>';
        setStatus('testing tamper...', '');
        state.cancelUrl = '';

        Scanner.testPriceTamper(url, state.detectedGateway, state.originalAmount).then(function(res) {
            if (res.vulnerable) {
                tamperOutput.innerHTML =
                    '<span class="fail bold">⚠️ PRICE TAMPER VULNERABLE!</span>\n' +
                    '<span class="warn">' + esc(res.evidence) + '</span>\n' +
                    (res.tamperedUrl ? '<span style="font-size:0.4rem;color:#5a4f42;word-break:break-all;">' + esc(res.tamperedUrl) + '</span>' : '') +
                    '\n<span class="success">→ BurpSuite se manually order karke confirm karo!</span>';
                showToast('⚠ Price tamper VULNERABLE — manual verify!', 'warning');
            } else if (res.skipped) {
                tamperOutput.innerHTML = '<span class="warn">⏭ ' + esc(res.evidence) + '</span>';
            } else {
                tamperOutput.innerHTML =
                    '<span class="success">✅ No clear signal on ₹1 tamper</span>\n' +
                    '<span style="color:#5a4f42;">' + esc(res.evidence) + '</span>\n' +
                    '<span class="warn">→ Tampered URL iframe me check karo (New Tab)</span>';
                showToast('No clear tamper signal — manual verify', 'info');
            }
            updateVerdict();
        }).catch(function(err) {
            tamperOutput.innerHTML = '<span class="fail">✗ Error: ' + esc(err.message) + '</span>';
        });
    }

    /* ======= TEST 2: CANCEL → SUCCESS ======= */
    function runCancelToSuccess() {
        var url = getCurrentUrl();
        if (!url || url === 'about:blank') {
            c2sOutput.innerHTML = '<span class="fail">⚠ Load a gateway URL first</span>';
            return;
        }
        c2sOutput.innerHTML = '<span class="info">⤷ Testing Cancel→Success...</span>';
        setStatus('testing C2S...', '');

        var cancelRef = state.cancelUrl || url;
        Scanner.testCancelToSuccess(url, state.detectedGateway, state.sessionId, cancelRef).then(function(res) {
            if (res.vulnerable) {
                c2sOutput.innerHTML =
                    '<span class="fail bold">⚠️ CANCEL→SUCCESS VULNERABLE!</span>\n' +
                    '<span class="warn">' + esc(res.evidence) + '</span>\n' +
                    '<span class="success">→ Order cancel hokar bhi SUCCESS ho gaya — BurpSuite se verify karo!</span>';
                showToast('⚠ Cancel→Success VULNERABLE!', 'warning');
            } else if (res.skipped) {
                c2sOutput.innerHTML = '<span class="warn">⏭ ' + esc(res.evidence) + '</span>';
            } else {
                c2sOutput.innerHTML =
                    '<span class="success">✅ Server ne forged success reject kiya (HTTP ' + res.status + ')</span>\n' +
                    '<span style="color:#5a4f42;">' + esc(res.evidence) + '</span>';
                showToast('Cancel→Success: server rejected', 'info');
            }
            updateVerdict();
        }).catch(function(err) {
            c2sOutput.innerHTML = '<span class="fail">✗ Error: ' + esc(err.message) + '</span>';
        });
    }

    function updateVerdict() {
        // Collect current results if any
        if (state.lastResults) {
            var anyVuln = state.lastResults.tests.some(function(t) { return t && t.vulnerable; });
            if (anyVuln) {
                verdictBox.innerHTML = '⚠️ SITE VULNERABLE — Price Tamper / Cancel→Success possible!';
                verdictBox.className = 'verdict vuln';
            } else {
                verdictBox.innerHTML = '✅ No clear vulnerability signal';
                verdictBox.className = 'verdict safe';
            }
            verdictBox.style.display = 'block';
        }
    }

    /* ======= FULL SCAN ======= */
    function runFullScan() {
        var url = getCurrentUrl();
        if (!url || url === 'about:blank') {
            showToast('Load a gateway URL first', 'error');
            return;
        }
        tamperOutput.innerHTML = '<span class="info">⤷ Price tamper test running...</span>';
        c2sOutput.innerHTML = '<span class="info">⤷ Cancel→Success test running...</span>';
        setStatus('full scan...', '');
        verdictBox.style.display = 'none';

        Scanner.fullScan(url, state.detectedGateway, state.cancelUrl).then(function(results) {
            state.lastResults = results;

            // Render tamper result
            var pt = results.tests[0];
            if (pt.vulnerable) {
                tamperOutput.innerHTML = '<span class="fail bold">⚠️ PRICE TAMPER VULNERABLE!</span>\n<span class="warn">' + esc(pt.evidence) + '</span>';
            } else if (pt.skipped) {
                tamperOutput.innerHTML = '<span class="warn">⏭ ' + esc(pt.evidence) + '</span>';
            } else {
                tamperOutput.innerHTML = '<span class="success">✅ ' + esc(pt.evidence) + '</span>';
            }

            // Render C2S result
            var c2s = results.tests[1];
            if (c2s.vulnerable) {
                c2sOutput.innerHTML = '<span class="fail bold">⚠️ CANCEL→SUCCESS VULNERABLE!</span>\n<span class="warn">' + esc(c2s.evidence) + '</span>';
            } else if (c2s.skipped) {
                c2sOutput.innerHTML = '<span class="warn">⏭ ' + esc(c2s.evidence) + '</span>';
            } else {
                c2sOutput.innerHTML = '<span class="success">✅ ' + esc(c2s.evidence) + '</span>';
            }

            // Verdict
            var anyVuln = results.tests.some(function(t) { return t && t.vulnerable; });
            if (anyVuln) {
                verdictBox.innerHTML = '⚠️ SITE VULNERABLE — Price Tamper / Cancel→Success possible!';
                verdictBox.className = 'verdict vuln';
            } else {
                verdictBox.innerHTML = '✅ No clear vulnerability signal — manual verify karo';
                verdictBox.className = 'verdict safe';
            }
            verdictBox.style.display = 'block';
            setStatus('scan complete', 'success');
            showToast('Full scan complete', 'success');

            // Also show in report tab
            reportViewer.innerHTML = '<span style="color:#8ab4c4;">' + esc(results.gateway) + '</span>\n' +
                (results.vulnerable ? '<span class="fail bold">⚠️ VULNERABLE</span>' : '<span class="success">✅ No signal</span>') +
                '\n\n' + esc(ReportExporter.toMarkdown(results));
        }).catch(function(err) {
            showToast('Scan error: ' + err.message, 'error');
        });
    }

    /* ======= CANCEL FLOW ======= */
    function captureCancelUrl() {
        var url = getCurrentUrl();
        if (!url || url === 'about:blank') {
            cancelUrlViewer.innerHTML = '<span class="fail">⚠ No URL in frame — cancel pehle karo</span>';
            return;
        }
        state.cancelUrl = url;
        cancelUrlViewer.innerHTML = '<span class="param">Captured:</span> <span class="value">' + esc(url) + '</span>';
        showToast('Cancel URL captured!', 'success');
    }

    function forgeSuccess() {
        if (!state.cancelUrl && !state.url) {
            cancelTestOutput.innerHTML = '<span class="fail">⚠ Pehle cancel URL capture karo ya URL load karo</span>';
            return;
        }
        var url = state.url || state.cancelUrl;
        var cancelRef = state.cancelUrl || url;
        cancelTestOutput.innerHTML = '<span class="info">⤷ Forging cancel→success...</span>';

        Scanner.testCancelToSuccess(url, state.detectedGateway, state.sessionId, cancelRef).then(function(res) {
            if (res.vulnerable) {
                cancelTestOutput.innerHTML =
                    '<span class="fail bold">⚠️ CANCEL→SUCCESS VULNERABLE!</span>\n' +
                    '<span class="warn">' + esc(res.evidence) + '</span>\n' +
                    '<span class="success">→ Order cancel → success flip hua! BurpSuite se verify karo.</span>';
                showToast('⚠ Cancel→Success VULNERABLE!', 'warning');
            } else {
                cancelTestOutput.innerHTML =
                    '<span class="success">✅ Server rejected forged success (HTTP ' + res.status + ')</span>\n' +
                    '<span style="color:#5a4f42;">' + esc(res.evidence) + '</span>';
                showToast('Cancel→Success rejected', 'info');
            }
        }).catch(function(err) {
            cancelTestOutput.innerHTML = '<span class="fail">✗ Error: ' + esc(err.message) + '</span>';
        });
    }

    /* ======= BATCH ======= */
    function renderBatchResults() {
        var lines = [];
        state.batchResults.forEach(function(r) {
            var verdict = r.vulnerable ? '⚠️ VULN' : '✅ safe';
            lines.push('<span class="' + (r.vulnerable ? 'batch-item-vuln' : 'batch-item-done') + '">' + esc(r.label || r.url) + ' → ' + verdict + '</span>');
        });
        batchOutput.innerHTML = lines.join('\n') || '<span style="color:#5a4f42;">Batch ready</span>';
    }

    function startBatch() {
        var items = BatchProcessor.parseInput(batchInput.value);
        if (items.length === 0) {
            showToast('Koi valid URL nahi mila', 'error');
            return;
        }
        BatchProcessor.clearQueue();
        BatchProcessor.addUrls(items);
        state.batchResults = [];
        renderBatchResults();

        BatchProcessor.setCallbacks({
            onProgress: function(idx, total) {
                batchStatus.textContent = (idx + 1) + '/' + total;
            },
            onResult: function(res, idx) {
                state.batchResults.push(res);
                renderBatchResults();
                batchStatus.textContent = (idx + 1) + '/' + BatchProcessor.getQueue().length;
            },
            onComplete: function(results) {
                batchStatus.textContent = 'done (' + results.length + ')';
                state.lastResults = results.length === 1 ? results[0] : results;
                showToast('Batch complete — ' + results.length + ' URLs tested', 'success');
                // Show summary in report tab
                var vulnCount = results.filter(function(r) { return r.vulnerable; }).length;
                reportViewer.innerHTML =
                    'Batch: ' + results.length + ' URLs, ' + vulnCount + ' VULNERABLE\n\n' +
                    esc(ReportExporter.toMarkdown(results));
            }
        });
        BatchProcessor.start();
        showToast('Batch started — ' + items.length + ' URLs', 'info');
    }

    /* ======= REPORT ======= */
    function getReportData() {
        if (state.lastResults) return state.lastResults;
        return state.batchResults;
    }

    /* ======= EVENT BINDINGS ======= */
    loadBtn.addEventListener('click', function() { loadUrl(urlInput.value); });
    reloadBtn.addEventListener('click', function() { loadUrl(getCurrentUrl() || urlInput.value); });
    openNewTabBtn.addEventListener('click', openInNewTab);
    refreshFrameBtn.addEventListener('click', function() { gatewayFrame.src = gatewayFrame.src; });
    goBackBtn.addEventListener('click', function() {
        try { gatewayFrame.contentWindow.history.back(); } catch (e) { showToast('Cannot go back', 'error'); }
    });
    goForwardBtn.addEventListener('click', function() {
        try { gatewayFrame.contentWindow.history.forward(); } catch (e) { showToast('Cannot go forward', 'error'); }
    });
    clearCacheBtn.addEventListener('click', function() {
        gatewayFrame.src = 'about:blank';
        showToast('Cleared', 'info');
        setTimeout(updateUI, 200);
    });
    urlInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') loadUrl(this.value); });

    scanTamperBtn.addEventListener('click', runPriceTamper);
    scanC2SBtn.addEventListener('click', runCancelToSuccess);
    scanAllBtn.addEventListener('click', runFullScan);

    openCancelPageBtn.addEventListener('click', function() { loadUrl(state.url || urlInput.value); });
    captureCancelBtn.addEventListener('click', captureCancelUrl);
    usePastedCancelBtn.addEventListener('click', function() {
        var pasted = cancelUrlInput.value.trim();
        if (!pasted) { showToast('Cancel URL paste karo pehle', 'error'); return; }
        if (!pasted.startsWith('http')) pasted = 'https://' + pasted;
        state.cancelUrl = pasted;
        cancelUrlViewer.innerHTML = '<span class="param">Pasted:</span> <span class="value">' + esc(pasted) + '</span>';
        showToast('Cancel URL set!', 'success');
    });
    openNewTabCancelBtn.addEventListener('click', function() {
        if (state.cancelUrl) window.open(state.cancelUrl, '_blank');
        else showToast('Pehle cancel URL capture karo', 'error');
    });
    forgeSuccessBtn.addEventListener('click', forgeSuccess);

    batchStartBtn.addEventListener('click', startBatch);
    batchStopBtn.addEventListener('click', function() {
        BatchProcessor.stop();
        batchStatus.textContent = 'stopped';
        showToast('Batch stopped', 'info');
    });
    batchClearBtn.addEventListener('click', function() {
        BatchProcessor.clearQueue();
        state.batchResults = [];
        batchOutput.innerHTML = '<span style="color:#5a4f42;">Batch cleared</span>';
        batchStatus.textContent = '0/0';
    });

    exportJsonBtn.addEventListener('click', function() {
        var data = getReportData();
        if (!data || (Array.isArray(data) && data.length === 0)) { showToast('Pehle scan karo', 'error'); return; }
        ReportExporter.downloadJSON(data, 'archive-burp-' + Date.now() + '.json');
        showToast('JSON exported', 'success');
    });
    exportMdBtn.addEventListener('click', function() {
        var data = getReportData();
        if (!data || (Array.isArray(data) && data.length === 0)) { showToast('Pehle scan karo', 'error'); return; }
        ReportExporter.downloadMarkdown(data, 'archive-burp-' + Date.now() + '.md');
        showToast('Markdown exported', 'success');
    });
    exportCsvBtn.addEventListener('click', function() {
        var data = getReportData();
        if (!data || (Array.isArray(data) && data.length === 0)) { showToast('Pehle scan karo', 'error'); return; }
        ReportExporter.downloadCSV(data, 'archive-burp-' + Date.now() + '.csv');
        showToast('CSV exported', 'success');
    });

    gatewayFrame.addEventListener('load', function() {
        setTimeout(updateUI, 300);
        setStatus('loaded', 'success');
        try {
            var url = gatewayFrame.contentWindow.location.href;
            if (url && url !== 'about:blank') {
                var proxyIdx = url.indexOf('/proxy?url=');
                if (proxyIdx !== -1) {
                    try { url = decodeURIComponent(url.substring(proxyIdx + 11)); } catch (e) {}
                }
                state.url = url;
                currentUrlDisplay.textContent = url;
            }
        } catch (e) {}
        frameOverlay.style.display = 'none';
    });

    setInterval(function() {
        if (gatewayFrame.src && gatewayFrame.src !== 'about:blank') {
            try {
                var u = gatewayFrame.contentWindow.location.href;
                var real = u;
                if (u && u !== 'about:blank') {
                    var proxyIdx = u.indexOf('/proxy?url=');
                    if (proxyIdx !== -1) {
                        try { real = decodeURIComponent(u.substring(proxyIdx + 11)); } catch (e) {}
                    }
                    if (real && real !== state.url) {
                        state.url = real;
                        updateUI();
                    }
                }
            } catch (e) {}
        }
    }, 3000);

    // Init
    updateUI();
    console.log('⌬ Archive Burp v3.0 loaded — Price Tamper + Cancel→Success tests ready');
})();
