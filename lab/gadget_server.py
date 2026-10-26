#!/usr/bin/env python3
"""Lab gadget v3 — deparam manual split (nilai boleh mengandung '=') +
$.extend pollution + $.attr gadget (intigriti 0124, BlackFan)."""
PAGE = """<!doctype html><html><body>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script src="https://www.google.com/recaptcha/api.js"></script>
<div id="t"></div>
<script>
try {
  var params = {};
  location.search.slice(1).split('&').forEach(function(pair) {
    if (!pair) return;
    var eq = pair.indexOf('=');
    if (eq < 0) return;
    var k = decodeURIComponent(pair.slice(0, eq));
    var v = decodeURIComponent(pair.slice(eq + 1));
    var keys = k.replace(/]/g, '').split('[');
    var obj = params;
    for (var i = 0; i < keys.length - 1; i++) {
      var key = keys[i];
      if (!obj[key]) obj[key] = {};
      obj = obj[key];
    }
    obj[keys[keys.length - 1]] = v;
  });
  var appConfig = {};
  jQuery.extend(true, appConfig, params);
  $('#t').attr(appConfig);
} catch(e) { document.title = 'ERR:' + e; }
</script>
</body></html>"""

import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("127.0.0.1", 8903), H)
httpd.serve_forever()
