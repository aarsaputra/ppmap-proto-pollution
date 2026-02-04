# Common gadget properties for prototype pollution fuzzing
# Source: pp-finder, BlackFan, Yuske, refrensi.md
GADGET_PROPERTIES = [
    # RCE / Process Execution
    "shell", "exec", "command", "cmd", "code", "eval", 
    "argv0", "execArgv", "NODE_OPTIONS", "env",
    
    # Template Engines
    "template", "layout", "view", "outputFunctionName", 
    "settings", "partials", "compileDebug", "debug",
    "filename", "sourceURL", "escapeFunction",
    
    # File System / Paths
    "file", "path", "dest", "source", "cwd",
    "base", "root", "dir", "directory",
    
    # Database / Query
    "where", "query", "sql", "table", "collection",
    
    # Third-Party Library Gadgets (refrensi.md lines 69-96)
    # Google Analytics
    "hitCallback", "eventCallback", "callback",
    # Google Tag Manager
    "sequence", "event_callback", "dataLayer",
    # Adobe DTM
    "cspNonce", "bodyHiddenStyle", "nonce",
    # Vue.js
    "v-if", "v-html", "props", "render",
    # DOMPurify
    "ALLOWED_ATTR", "ALLOWED_TAGS", "documentMode",
    # BSON / Serialization
    "evalFunctions", "deserialize",
    
    # CORS / Headers
    "exposedHeaders", "allowedHeaders", "credentials",
    
    # Generic / Misc
    "options", "config", "settings", "data", "context",
    "constructor", "prototype", "__proto__"
]

