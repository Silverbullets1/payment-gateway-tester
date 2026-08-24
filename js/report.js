// ⌬ Archive Burp — Report Exporter v2.0
// JSON / Markdown / CSV export of scan results.

var ReportExporter = (function() {
    'use strict';

    function toJSON(results) {
        return JSON.stringify(results, null, 2);
    }

    function toMarkdown(results) {
        var lines = [];
        lines.push('# ⌬ Archive Burp — Vulnerability Report');
        lines.push('Generated: ' + new Date().toISOString());
        lines.push('');

        var single = Array.isArray(results) ? results : [results];
        single.forEach(function(r, idx) {
            var label = r.label || r.url || 'Test ' + (idx + 1);
            lines.push('## ' + label);
            lines.push('');
            lines.push('| Field | Value |');
            lines.push('|-------|-------|');
            lines.push('| URL | `' + (r.url || '') + '` |');
            lines.push('| Gateway | ' + (r.gateway || 'Unknown') + ' |');
            lines.push('| Session/Order | ' + (r.session || '—') + ' |');
            lines.push('| Amount | ' + (r.amount !== null && r.amount !== undefined ? r.amount : '—') + ' |');
            lines.push('| Verdict | ' + (r.vulnerable ? '⚠️ **VULNERABLE**' : '✅ Safe / No clear signal') + ' |');
            lines.push('| Summary | ' + (r.summary || r.error || '') + ' |');
            lines.push('');

            if (r.tests && r.tests.length > 0) {
                lines.push('### Test Results');
                lines.push('');
                r.tests.forEach(function(t) {
                    if (!t) return;
                    var name = t.test || 'Test';
                    var verdict = t.vulnerable ? '⚠️ **VULNERABLE**' : (t.skipped ? '⏭ Skipped' : '✅ Safe / No signal');
                    lines.push('**' + name + ':** ' + verdict);
                    lines.push('');
                    if (t.evidence) {
                        lines.push('> ' + t.evidence);
                        lines.push('');
                    }
                    if (t.status) {
                        lines.push('- HTTP status: ' + t.status);
                        lines.push('');
                    }
                    if (t.tamperedUrl) {
                        lines.push('- Tampered URL: `' + t.tamperedUrl + '`');
                        lines.push('');
                    }
                });
            }

            if (r.error) {
                lines.push('**Error:** ' + r.error);
                lines.push('');
            }
            lines.push('---');
            lines.push('');
        });
        return lines.join('\n');
    }

    function toCSV(results) {
        var lines = [];
        lines.push('URL,Gateway,Session,Amount,Verdict,PriceTamper,C2S(PT Evidence,C2S Evidence');
        var single = Array.isArray(results) ? results : [results];
        single.forEach(function(r) {
            var pt = r.tests ? r.tests.find(function(t) { return t && t.test === 'PriceTamper'; }) : null;
            var c2s = r.tests ? r.tests.find(function(t) { return t && t.test === 'CancelToSuccess'; }) : null;
            var row = [
                '"' + (r.url || '').replace(/"/g, '""') + '"',
                '"' + (r.gateway || '') + '"',
                '"' + (r.session || '') + '"',
                r.amount !== null ? r.amount : '',
                r.vulnerable ? 'VULN' : 'Safe',
                pt ? (pt.vulnerable ? 'VULN' : (pt.skipped ? 'SKIP' : 'Safe')) : '',
                c2s ? (c2s.vulnerable ? 'VULN' : (c2s.skipped ? 'SKIP' : 'Safe')) : '',
                '"' + (pt ? (pt.evidence || '').replace(/"/g, '""') : '') + '"',
                '"' + (c2s ? (c2s.evidence || '').replace(/"/g, '""') : '') + '"'
            ];
            lines.push(row.join(','));
        });
        return lines.join('\n');
    }

    function download(filename, content, mimeType) {
        var blob = new Blob([content], { type: mimeType || 'text/plain' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
    }

    function downloadJSON(results, filename) {
        download(filename || 'archive-burp-report.json', toJSON(results), 'application/json');
    }
    function downloadMarkdown(results, filename) {
        download(filename || 'archive-burp-report.md', toMarkdown(results), 'text/markdown');
    }
    function downloadCSV(results, filename) {
        download(filename || 'archive-burp-report.csv', toCSV(results), 'text/csv');
    }

    return {
        toJSON: toJSON,
        toMarkdown: toMarkdown,
        toCSV: toCSV,
        downloadJSON: downloadJSON,
        downloadMarkdown: downloadMarkdown,
        downloadCSV: downloadCSV
    };
})();