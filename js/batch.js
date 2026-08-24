// ⌬ Archive Burp — Batch Processor v2.0
// Import multiple gateway URLs, queue them, auto-scan both tests.

var BatchProcessor = (function() {
    'use strict';

    var queue = [];
    var running = false;
    var currentIndex = 0;
    var results = [];
    var callbacks = {
        onProgress: null,
        onComplete: null,
        onResult: null
    };

    function setCallbacks(cb) {
        if (cb) callbacks = cb;
    }

    function parseInput(text) {
        var lines = String(text || '').split(/\r?\n/);
        var urls = [];
        lines.forEach(function(line) {
            line = line.trim();
            if (!line) return;
            var parts = line.split(',').map(function(s) { return s.trim(); });
            var url = parts[parts.length - 1];
            if (url && url.startsWith('http')) {
                urls.push({ label: parts.length > 1 ? parts.slice(0, -1).join(',') : '', url: url });
            } else if (url && (url.includes('.') || url.includes('session_') || url.includes('order_'))) {
                if (!url.startsWith('http')) url = 'https://' + url;
                urls.push({ label: parts.length > 1 ? parts.slice(0, -1).join(',') : '', url: url });
            }
        });
        return urls;
    }

    function addUrls(items) {
        items.forEach(function(item) { queue.push(item); });
    }

    function getQueue() { return queue; }
    function clearQueue() { queue = []; results = []; currentIndex = 0; }
    function isRunning() { return running; }

    function next() {
        if (currentIndex >= queue.length) {
            running = false;
            if (callbacks.onComplete) callbacks.onComplete(results);
            return;
        }
        var item = queue[currentIndex];
        if (callbacks.onProgress) callbacks.onProgress(currentIndex, queue.length, item);

        Scanner.fullScan(item.url, detectGateway(item.url), item.cancelUrl).then(function(res) {
            res.label = item.label;
            results.push(res);
            if (callbacks.onResult) callbacks.onResult(res, currentIndex);
            currentIndex++;
            next();
        }).catch(function(err) {
            results.push({
                url: item.url, label: item.label, gateway: 'Error',
                error: err.message, tests: [], vulnerable: false
            });
            currentIndex++;
            next();
        });
    }

    function start() {
        if (running) return;
        if (queue.length === 0) { if (callbacks.onComplete) callbacks.onComplete([]); return; }
        running = true;
        currentIndex = 0;
        results = [];
        next();
    }

    function stop() { running = false; }

    return {
        parseInput: parseInput,
        addUrls: addUrls,
        getQueue: getQueue,
        clearQueue: clearQueue,
        isRunning: isRunning,
        start: start,
        stop: stop,
        setCallbacks: setCallbacks,
        getResults: function() { return results; }
    };
})();