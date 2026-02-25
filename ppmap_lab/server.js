const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const _ = require('lodash');
const deepMerge = require('@75lb/deep-merge');
const { exec, spawn } = require('child_process');
const path = require('path');
const http = require('http');

// GraphQL imports
const { ApolloServer, gql } = require('apollo-server-express');

// WebSocket imports
const WebSocket = require('ws');
const { Server: SocketIO } = require('socket.io');

const app = express();
const PORT = 3000;

// Create HTTP server for WebSocket support
const server = http.createServer(app);

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static('public'));

// Set EJS as template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============================================
// TIER 0 - STANDARD DETECTION
// ============================================

// Home page with jQuery PP
app.get('/', (req, res) => {
    res.render('index', {
        title: 'PPMAP Vulnerable Lab',
        query: req.query
    });
});

// Lodash _.merge vulnerability (CVE-2020-8203)
app.post('/api/merge', (req, res) => {
    try {
        const defaultConfig = { role: 'user', isAdmin: false };
        const userConfig = _.merge({}, defaultConfig, req.body);

        res.json({
            success: true,
            config: userConfig,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Server-side PP with JSON response
app.post('/api/config', (req, res) => {
    const config = {};
    _.merge(config, req.body);

    res.json({
        config: config,
        isAdmin: config.isAdmin || false,
        role: config.role || 'guest'
    });
});

// ============================================
// TIER 1 - BLIND DETECTION
// ============================================

// JSON Spaces Overflow
app.post('/api/json-spaces', (req, res) => {
    const data = _.merge({}, req.body);
    res.json(data); // Will use JSON.stringify with spaces from prototype
});

// Status Code Override
app.post('/api/status', (req, res) => {
    const config = {};
    _.merge(config, req.body);
    res.status(config.statusCode || 200).json({ message: 'OK' });
});

// Function.prototype Chain
app.post('/api/function-proto', (req, res) => {
    _.merge({}, req.body);
    const testFunc = function () { };
    res.json({
        hasToString: typeof testFunc.toString === 'function',
        protoChain: Object.getPrototypeOf(testFunc)
    });
});

// ============================================
// TIER 3 - PORTSWIGGER TECHNIQUES
// ============================================

// child_process RCE vulnerability
app.post('/api/child-process', (req, res) => {
    try {
        const options = {};
        _.merge(options, req.body);

        // Vulnerable: uses polluted options
        const child = spawn('echo', ['test'], options);

        child.on('error', (err) => {
            res.status(500).json({ error: err.message });
        });

        child.on('close', (code) => {
            res.json({
                success: true,
                exitCode: code,
                options: options
            });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Object.defineProperty bypass
app.post('/api/define-property', (req, res) => {
    _.merge({}, req.body);

    const obj = {};
    Object.defineProperty(obj, 'secure', {
        value: 'protected',
        writable: false,
        configurable: false
    });

    res.json({
        obj: obj,
        prototype: Object.prototype
    });
});

// fetch() API pollution
app.post('/api/fetch-config', (req, res) => {
    const fetchConfig = {};
    _.merge(fetchConfig, req.body);

    res.json({
        fetchConfig: fetchConfig,
        credentials: fetchConfig.credentials,
        mode: fetchConfig.mode
    });
});

// ============================================
// TIER 4 - ADVANCED BYPASS
// ============================================

// Constructor-based pollution
app.post('/api/constructor', (req, res) => {
    try {
        const data = JSON.parse(JSON.stringify(req.body));

        // Vulnerable to constructor.prototype pollution
        if (data.constructor && data.constructor.prototype) {
            Object.assign(Object.prototype, data.constructor.prototype);
        }

        res.json({
            success: true,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Sanitization bypass (recursive filter evasion)
app.post('/api/sanitize', (req, res) => {
    try {
        let data = JSON.stringify(req.body);

        // Weak sanitization - can be bypassed
        data = data.replace(/__proto__/g, '');
        data = data.replace(/prototype/g, '');

        const parsed = JSON.parse(data);
        _.merge({}, parsed);

        res.json({
            sanitized: true,
            data: parsed,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Descriptor pollution
app.post('/api/descriptor', (req, res) => {
    _.merge({}, req.body);

    const config = {};
    Object.defineProperty(config, 'apiUrl', {
        configurable: false,
        writable: false
    });

    res.json({
        config: config,
        descriptor: Object.getOwnPropertyDescriptor(config, 'apiUrl')
    });
});

// Blind gadget fuzzing endpoint
app.post('/api/gadgets', (req, res) => {
    try {
        _.merge({}, req.body);

        // Simulate gadget usage
        const gadgets = {
            shell: process.env.SHELL,
            execArgv: process.execArgv,
            NODE_OPTIONS: process.env.NODE_OPTIONS
        };

        res.json({
            gadgets: gadgets,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// ============================================
// TIER 5 - RESEARCH GAP FEATURES
// ============================================

// CORS Header Pollution
app.post('/api/cors', (req, res) => {
    const corsConfig = {};
    _.merge(corsConfig, req.body);

    // Vulnerable: CORS headers from polluted prototype
    if (corsConfig.exposedHeaders) {
        res.header('Access-Control-Expose-Headers', corsConfig.exposedHeaders);
    }
    if (corsConfig.allowedHeaders) {
        res.header('Access-Control-Allow-Headers', corsConfig.allowedHeaders);
    }

    res.json({
        success: true,
        corsConfig: corsConfig
    });
});

// Third-Party Library Gadgets (Google Analytics simulation)
app.get('/analytics', (req, res) => {
    res.render('analytics', { query: req.query });
});

// Storage API pollution endpoint
app.get('/storage-test', (req, res) => {
    res.render('storage', { query: req.query });
});

// ============================================
// TIER 6 - CVE-SPECIFIC & REAL-WORLD EXPLOITS
// ============================================

// deep-merge RCE (CVE-2024-38986)
app.post('/api/deep-merge', (req, res) => {
    try {
        const result = deepMerge({}, req.body);

        res.json({
            success: true,
            result: result,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Kibana Telemetry RCE simulation (HackerOne #852613)
app.post('/api/telemetry', (req, res) => {
    try {
        const telemetryData = {};

        // Vulnerable: Lodash _.set pattern
        if (req.body.path && req.body.value) {
            _.set(telemetryData, req.body.path, req.body.value);
        }

        res.json({
            success: true,
            telemetry: telemetryData,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Blitz.js RCE Chain simulation (CVE-2022-23631)
app.post('/api/blitzjs', (req, res) => {
    try {
        // Simulate superjson deserialization
        const data = req.body;

        if (data.json && data.meta) {
            _.merge({}, data.json);
        }

        res.json({
            success: true,
            data: data,
            prototype: Object.prototype
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Elastic XSS simulation (HackerOne #998398)
app.get('/elastic', (req, res) => {
    res.render('elastic', { query: req.query });
});

// ============================================
// TIER 7 - GRAPHQL PP VULNERABILITIES
// ============================================

// GraphQL Schema with PP vulnerabilities
const typeDefs = gql`
    scalar JSON
    
    type User {
        id: ID!
        name: String
        email: String
        isAdmin: Boolean
        role: String
    }
    
    type Config {
        success: Boolean
        data: JSON
        prototype: JSON
    }
    
    input UserInput {
        name: String
        email: String
        settings: JSON
    }
    
    type Query {
        users(filter: JSON): [User]
        config: Config
        search(options: JSON): JSON
    }
    
    type Mutation {
        updateUser(input: UserInput): User
        setConfig(config: JSON): Config
        updateSettings(input: JSON): Config
    }
`;

// GraphQL Resolvers with PP vulnerabilities
const resolvers = {
    Query: {
        users: (_, { filter }) => {
            // Vulnerable: merges filter into query options
            const queryOptions = {};
            _.merge(queryOptions, filter);

            return [
                { id: 1, name: 'Admin', email: 'admin@test.com', isAdmin: queryOptions.isAdmin || false }
            ];
        },
        config: () => ({
            success: true,
            data: {},
            prototype: Object.prototype
        }),
        search: (_, { options }) => {
            const searchConfig = {};
            _.merge(searchConfig, options);
            return { results: [], config: searchConfig, prototype: Object.prototype };
        }
    },
    Mutation: {
        updateUser: (_, { input }) => {
            // Vulnerable: deep merge user input
            const userData = {};
            _.merge(userData, input);

            return {
                id: 1,
                name: userData.name || 'Guest',
                email: userData.email || '',
                isAdmin: userData.isAdmin || Object.prototype.isAdmin || false,
                role: userData.role || Object.prototype.role || 'user'
            };
        },
        setConfig: (_, { config }) => {
            // Vulnerable: directly merges config
            const appConfig = {};
            _.merge(appConfig, config);

            return {
                success: true,
                data: appConfig,
                prototype: Object.prototype
            };
        },
        updateSettings: (_, { input }) => {
            _.merge({}, input);
            return { success: true, data: input, prototype: Object.prototype };
        }
    }
};

// ============================================
// TIER 8 - WEBSOCKET PP VULNERABILITIES
// ============================================

// Native WebSocket Server
const wss = new WebSocket.Server({ server, path: '/ws' });

wss.on('connection', (ws) => {
    console.log('[WS] Client connected');

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('[WS] Received:', data);

            // VULNERABLE: Deep merge incoming data
            const config = {};
            _.merge(config, data);

            // Send response with pollution evidence
            ws.send(JSON.stringify({
                type: 'response',
                received: data,
                config: config,
                polluted: Object.prototype.polluted || false,
                isAdmin: Object.prototype.isAdmin || false,
                prototype: Object.prototype
            }));
        } catch (e) {
            ws.send(JSON.stringify({ error: e.message }));
        }
    });

    ws.send(JSON.stringify({ type: 'connected', message: 'WebSocket PP Lab Ready' }));
});

// Socket.IO Server
const io = new SocketIO(server, {
    cors: { origin: '*' }
});

io.on('connection', (socket) => {
    console.log('[Socket.IO] Client connected:', socket.id);

    socket.on('message', (data) => {
        try {
            // VULNERABLE: Merges client data
            const config = {};
            _.merge(config, data);

            socket.emit('response', {
                received: data,
                config: config,
                polluted: Object.prototype.polluted || false,
                isAdmin: Object.prototype.isAdmin || false
            });
        } catch (e) {
            socket.emit('error', { message: e.message });
        }
    });

    socket.on('update', (data) => {
        _.merge({}, data);
        socket.emit('updated', { success: true, prototype: Object.prototype });
    });

    socket.on('SET_USER', (payload) => {
        // Redux-style action - VULNERABLE
        _.merge({}, payload);
        socket.emit('USER_SET', { ...payload, prototype: Object.prototype });
    });
});

// ============================================
// JQUERY CVE TESTING ENDPOINTS (Lab Coverage)
// ============================================

// jQuery 1.11.1 page — covers CVE-2012-6708 (< 1.9.0) and CVE-2015-9251 (< 3.0.0)
// BUG FIX: CVE-2015-9251 range is < 3.0.0 (NOT < 2.2.0 as previously commented)
app.get('/jquery-old', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>jQuery Old (1.11.1) CVE Lab</title>
  <!-- CVE-2015-9251: XSS via cross-domain AJAX auto-eval - jQuery < 3.0.0 (fixed in 3.0.0) -->
  <script src="https://code.jquery.com/jquery-1.11.1.js"></script>
</head>
<body>
  <h2>jQuery 1.11.1 CVE Test Page</h2>
  <p>Covers: CVE-2015-9251 (cross-domain AJAX auto-eval XSS, jQuery &lt;3.0.0)</p>
  <p>jQuery version: <span id="ver"></span></p>
  <script>
    $('#ver').text($.fn.jquery);
    // Vulnerable: jQuery 1.11.1 converters["text script"] = globalEval — auto-eval AJAX responses
    var query = ${JSON.stringify(req.query)};
    try { $.extend(true, {}, query); } catch(e) {}
  </script>
</body>
</html>`);
});

// jQuery 1.12.4 page — PRIMARY TARGET for pentest
// Covers: CVE-2019-11358(PP), CVE-2020-11022, CVE-2020-11023, CVE-2020-23064, CVE-2015-9251
app.get('/jquery-1124', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>jQuery 1.12.4 CVE Lab — Primary Pentest Target</title>
  <!-- ALL 5 CVEs apply to jQuery 1.12.4: -->
  <!-- CVE-2019-11358: Prototype Pollution via $.extend() - jQuery < 3.4.0 -->
  <!-- CVE-2020-11022: HTML Prefilter XSS - jQuery < 3.5.0 -->
  <!-- CVE-2020-11023: <option> element XSS - jQuery < 3.5.0 -->
  <!-- CVE-2020-23064: DOM Manipulation XSS - jQuery < 3.5.0 -->
  <!-- CVE-2015-9251: Cross-domain AJAX auto-eval - jQuery < 3.0.0 -->
  <script src="https://code.jquery.com/jquery-1.12.4.js"></script>
</head>
<body>
  <h2>jQuery 1.12.4 — All 5 CVEs Active</h2>
  <p>jQuery version: <span id="ver"></span></p>
  <p>CVEs: CVE-2019-11358, CVE-2020-11022, CVE-2020-11023, CVE-2020-23064, CVE-2015-9251</p>
  <div id="pp-result"></div>
  <div id="xss-result"></div>
  <script>
    $('#ver').text($.fn.jquery);
    var query = ${JSON.stringify(req.query)};
    // CVE-2019-11358: $.extend Prototype Pollution test
    try { $.extend(true, {}, query); } catch(e) {}
    // CVE-2020-11022: htmlPrefilter bypass
    var ppResult = document.getElementById('pp-result');
    // CVE-2015-9251: converter still active in 1.12.4
    document.getElementById('xss-result').textContent =
      'text/script converter: ' + typeof $.ajaxSettings.converters['text script'];
  </script>
</body>
</html>`);
});

// jQuery 3.5.0 page — covers CVE-2020-11023 (ALREADY PATCHED in 3.5.0, use for VERIFY fix)
// BUG FIX: CVE-2020-11023 affects jQuery < 3.5.0, so jQuery 3.5.0 itself is PATCHED
// This page is useful to test that 3.5.0 is NOT vulnerable (negative test)
app.get('/jquery-350', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>jQuery 3.5.0 CVE Verification Lab (PATCHED)</title>
  <!-- jQuery 3.5.0 = PATCHED for CVE-2020-11022 and CVE-2020-11023 -->
  <!-- Still vulnerable to NO known jQuery CVEs at this version -->
  <!-- Use this page to VERIFY that patches work correctly (negative test) -->
  <!-- CVE-2019-11358 already patched in 3.4.0, so 3.5.0 is safe for PP too -->
  <script src="https://code.jquery.com/jquery-3.5.0.js"></script>
</head>
<body>
  <h2>jQuery 3.5.0 — Patched Verification Page</h2>
  <p>CVE-2020-11022, CVE-2020-11023, CVE-2020-23064: PATCHED in this version</p>
  <p>CVE-2019-11358 (PP): PATCHED since 3.4.0</p>
  <p>jQuery version: <span id="ver"></span></p>
  <script>
    $('#ver').text($.fn.jquery);
    var query = ${JSON.stringify(req.query)};
    try { $.extend(true, {}, query); } catch(e) {}
  </script>
</body>
</html>`);
});

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (req, res) => {
    res.json({
        status: 'vulnerable',
        version: '2.2.0',
        endpoints: 24,
        tiers: 8,
        detectionMethods: 32,
        cvePages: {
            'CVE-2012-6708': '/jquery-old (jQuery 1.11.1) — affected: < 1.9.0',
            'CVE-2015-9251': '/jquery-old (jQuery 1.11.1) — affected: < 3.0.0 [BUG FIXED: was < 2.2.0]',
            'CVE-2019-11358': '/jquery-1124 (jQuery 1.12.4) — affected: < 3.4.0 [BUG FIXED: was < 3.5.0]',
            'CVE-2020-11022': '/jquery-1124 (jQuery 1.12.4) — affected: < 3.5.0',
            'CVE-2020-11023': '/jquery-1124 (jQuery 1.12.4) — affected: < 3.5.0 [BUG FIXED: was == 3.5.0]',
            'CVE-2020-23064': '/jquery-1124 (jQuery 1.12.4) — affected: < 3.5.0 [NEW: was missing]',
            'CVE-2020-11022+11023+23064 PATCHED': '/jquery-350 (jQuery 3.5.0) — negative test'
        },
        bugFixes: [
            'CVE-2020-11023: range was == 3.5.0, now correctly < 3.5.0',
            'CVE-2015-9251: range was < 2.2.0, now correctly < 3.0.0',
            'CVE-2019-11358: range was < 3.5.0, now correctly < 3.4.0',
            'CVE-2020-23064: was completely missing, now added',
            'Added /jquery-1124 page for primary pentest target (jQuery 1.12.4)'
        ],
        features: {
            graphql: '/graphql',
            websocket: '/ws',
            socketio: 'port 3000'
        }
    });
});


// ============================================
// START SERVER WITH GRAPHQL
// ============================================

async function startServer() {
    // Initialize Apollo Server
    const apolloServer = new ApolloServer({
        typeDefs,
        resolvers,
        introspection: true,
        playground: true
    });

    await apolloServer.start();
    apolloServer.applyMiddleware({ app, path: '/graphql' });

    server.listen(PORT, () => {
        console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║           PPMAP VULNERABLE LAB - v2.0.0                   ║
║                                                           ║
║  ⚠️  INTENTIONALLY VULNERABLE APPLICATION ⚠️               ║
║                                                           ║
║  Server running on: http://localhost:${PORT}              ║
║                                                           ║
║  NEW FEATURES:                                            ║
║  ├── GraphQL: http://localhost:${PORT}/graphql            ║
║  ├── WebSocket: ws://localhost:${PORT}/ws                 ║
║  └── Socket.IO: http://localhost:${PORT}                  ║
║                                                           ║
║  Endpoints: 20  |  Tiers: 8  |  Methods: 32               ║
║                                                           ║
║  Test with PPMAP:                                         ║
║  python3 ppmap.py --scan http://localhost:${PORT}         ║
║                                                           ║
║  ⚠️  DO NOT DEPLOY TO PRODUCTION ⚠️                       ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
        `);
    });
}

startServer().catch(console.error);
