// ⌬ Archive Burp — Gateway Database v2.0
// Comprehensive list of payment gateways with detection patterns,
// amount params, signature names, and probe endpoints.

var GATEWAYS = [{
    id: 'razorpay',
    name: 'Razorpay',
    patterns: [/razorpay\.com/i, /api\.razorpay\.com/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'razorpay@upi',
    supportsQr: true,
    probeUrl: 'https://api.razorpay.com/v1/payments/',
    signatureName: 'razorpay_signature',
    requiresHash: true
}, {
    id: 'payu',
    name: 'PayU',
    patterns: [/payu\.in/i, /payumoney\.com/i],
    amountParams: ['amount', 'txnAmount', 'purchaseQuantity', 'price'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'payu@upi',
    supportsQr: true,
    probeUrl: 'https://payu.in/_payment',
    signatureName: 'hash',
    requiresHash: true
}, {
    id: 'ccavenue',
    name: 'CCAvenue',
    patterns: [/ccavenue\.com/i, /ccavenu\.in/i],
    amountParams: ['amount', 'price', 'total', 'MerchantAmount'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'ccavenue@upi',
    supportsQr: true,
    probeUrl: 'https://ccavenue.com/transaction/',
    signatureName: 'signature',
    requiresHash: true
}, {
    id: 'instamojo',
    name: 'Instamojo',
    patterns: [/instamojo\.com/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'instamojo@upi',
    supportsQr: true,
    probeUrl: 'https://api.instamojo.com/v2/payment_requests/',
    signatureName: null,
    requiresHash: false
}, {
    id: 'phonepe',
    name: 'PhonePe',
    patterns: [/phonepe\.com/i, /pg\.phonepe\.com/i],
    amountParams: ['amount', 'txnAmount', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'phonepe@upi',
    supportsQr: true,
    probeUrl: 'https://pg.phonepe.com/transaction/',
    signatureName: 'X-VERIFY',
    requiresHash: true
}, {
    id: 'googlepay',
    name: 'Google Pay',
    patterns: [/pay\.google\.com/i, /googlepay/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'gpay@upi',
    supportsQr: true,
    probeUrl: 'https://pay.google.com/gp/p/ui/pay',
    signatureName: null,
    requiresHash: false
}, {
    id: 'paytm',
    name: 'Paytm',
    patterns: [/paytm\.com/i, /paytm\.in/i],
    amountParams: ['amount', 'txnAmount', 'total', 'price'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'paytm@upi',
    supportsQr: true,
    probeUrl: 'https://secure.paytm.in/transaction/',
    signatureName: 'CHECKSUMHASH',
    requiresHash: true
}, {
    id: 'cashfree',
    name: 'Cashfree',
    patterns: [/cashfree\.com/i, /api\.cashfree\.com/i, /session_/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'cashfree@upi',
    supportsQr: false,
    probeUrl: 'https://api.cashfree.com/pg/orders/',
    signatureName: 'x-signature',
    requiresHash: true
}, {
    id: 'stripe',
    name: 'Stripe',
    patterns: [/stripe\.com/i, /api\.stripe\.com/i],
    amountParams: ['amount', 'price', 'total', 'unit_amount'],
    currency: 'USD',
    testAmount: 0.01,
    upiMerchant: 'stripe@upi',
    supportsQr: false,
    probeUrl: 'https://api.stripe.com/v1/charges/',
    signatureName: null,
    requiresHash: false
}, {
    id: 'paypal',
    name: 'PayPal',
    patterns: [/paypal\.com/i, /api\.paypal\.com/i],
    amountParams: ['amount', 'total', 'price', 'value'],
    currency: 'USD',
    testAmount: 0.01,
    upiMerchant: 'paypal@upi',
    supportsQr: false,
    probeUrl: 'https://api.paypal.com/v2/checkout/orders/',
    signatureName: null,
    requiresHash: false
}, {
    id: 'braintree',
    name: 'Braintree',
    patterns: [/braintree\.com/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'USD',
    testAmount: 0.01,
    upiMerchant: 'braintree@upi',
    supportsQr: false,
    probeUrl: 'https://api.braintreegateway.com/merchants/',
    signatureName: null,
    requiresHash: false
}, {
    id: 'adyen',
    name: 'Adyen',
    patterns: [/adyen\.com/i],
    amountParams: ['amount', 'price', 'total', 'value'],
    currency: 'USD',
    testAmount: 0.01,
    upiMerchant: 'adyen@upi',
    supportsQr: false,
    probeUrl: 'https://checkout.adyen.com/',
    signatureName: 'hmacSignature',
    requiresHash: true
}, {
    id: 'juspay',
    name: 'Juspay',
    patterns: [/juspay\.in/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'juspay@upi',
    supportsQr: true,
    probeUrl: 'https://api.juspay.in/orders/',
    signatureName: 'signature',
    requiresHash: true
}, {
    id: 'easebuzz',
    name: 'Easebuzz',
    patterns: [/easebuzz\.in/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'easebuzz@upi',
    supportsQr: true,
    probeUrl: 'https://api.easebuzz.in/transaction/',
    signatureName: 'hash',
    requiresHash: true
}, {
    id: 'pinelabs',
    name: 'Pine Labs',
    patterns: [/pinelabs\.com/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'pinelabs@upi',
    supportsQr: false,
    probeUrl: null,
    signatureName: null,
    requiresHash: false
}, {
    id: 'billdesk',
    name: 'BillDesk',
    patterns: [/billdesk\.com/i, /billdesk\.in/i],
    amountParams: ['amount', 'price', 'total'],
    currency: 'INR',
    testAmount: 1.00,
    upiMerchant: 'billdesk@upi',
    supportsQr: false,
    probeUrl: 'https://api.billdesk.com/transactions/',
    signatureName: 'checksum',
    requiresHash: true
}];

// Helper: find gateway by URL
function detectGateway(url) {
    for (var i = 0; i < GATEWAYS.length; i++) {
        var g = GATEWAYS[i];
        for (var j = 0; j < g.patterns.length; j++) {
            if (g.patterns[j].test(url)) return g;
        }
    }
    return null;
}

// Helper: extract session ID from URL
function extractSessionId(url) {
    var patterns = [
        /session_([A-Za-z0-9_\-]+)/,
        /order_id=([A-Za-z0-9_\-]+)/,
        /payment_id=([A-Za-z0-9_\-]+)/,
        /txn_id=([A-Za-z0-9_\-]+)/
    ];
    for (var i = 0; i < patterns.length; i++) {
        var m = url.match(patterns[i]);
        if (m) return m[0];
    }
    var f = url.match(/\/(gateway|pay|payment|checkout)\/([A-Za-z0-9_\-]{10,})/);
    if (f) return f[2];
    return null;
}

// Helper: extract amount from URL
function extractAmount(url, gateway) {
    var params = gateway ? gateway.amountParams : ['amount', 'price', 'total', 'amt', 'value'];
    for (var i = 0; i < params.length; i++) {
        var r = new RegExp('[?&]' + params[i] + '=([0-9.]+)', 'i');
        var m = url.match(r);
        if (m) return parseFloat(m[1]);
    }
    var cm = url.match(/[₹$]\s*([0-9.]+)/);
    if (cm) return parseFloat(cm[1]);
    return null;
}

// Helper: extract all URL params
function extractParams(url) {
    var params = {};
    try {
        var u = new URL(url);
        u.searchParams.forEach(function(v, k) { params[k] = v; });
    } catch (e) {}
    return params;
}

// Helper: build URL with params
function buildUrl(url, params) {
    try {
        var u = new URL(url);
        for (var k in params) {
            if (params[k] !== null && params[k] !== undefined && params[k] !== '') {
                u.searchParams.set(k, params[k]);
            } else {
                u.searchParams.delete(k);
            }
        }
        return u.toString();
    } catch (e) { return url; }
}
