#!/usr/bin/env python3
"""Lab gadget MULTI-PAGE port 8903 (v4, permanen di lab/):
- /purify  : DOMPurify stub — config ALLOWED_ATTR terbaca setelah pollution;
             canary tag <img {canary}-exec> dikonstruksi lalu dijitakan ke DOM.
- /recaptcha : stub widget — baca __proto__[srcdoc][] lalu set iframe.srcdoc.
- /attr    : jQuery $.attr gadget intigriti-0124 (kontrol positif).
Setiap halaman menandai window.__pp_exec=true saat gadget benar-benar
mengeksekusi jalur berbahaya, sehingga reach-check execution_fired() melihatnya."""
import http.server
import socketserver
from urllib.parse import urlparse

JQ = '<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>'

PAGE_PURIFY = """<!doctype html><html><body>
""" + JQ + """
<div id="out"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.0.12/purify.min.js"></script>
<script>
// DOMPurify 2.0.12 stub-ringan asli dari repo (unpkg 2.0.12 ada): pakai asli
window.__pp_exec = false;
try {
  var params = {};
  location.search.slice(1).split('&').forEach(function(pair){
    if (!pair) return;
    var eq = pair.indexOf('='); if (eq < 0) return;
    var k = decodeURIComponent(pair.slice(0, eq));
    var v = decodeURIComponent(pair.slice(eq + 1));
    var keys = k.replace(/]/g, '').split('[');
    var obj = params;
    for (var i=0;i<keys.length-1;i++){ var kk=keys[i]; if(!obj[kk]) obj[kk]={}; obj=obj[kk]; }
    obj[keys[keys.length-1]] = v;
  });
  var cfg = {};
  jQuery.extend(true, cfg, params);           // POLLUTION SOURCE
  var dirty = '<img src=x onerror="window.__pp_exec=true">';
  var clean = DOMPurify.sanitize(dirty, cfg); // cfg terpollute: ALLOWED_ATTR=onerror
  document.getElementById('out').innerHTML = clean;
} catch(e) { document.title='ERR:'+e; }
</script>
</body></html>"""

PAGE_RECAPTCHA = """<!doctype html><html><body>
""" + JQ + """
<script src="https://www.google.com/recaptcha/api.js"></script>
<iframe id="g"></iframe>
<script>
window.__pp_exec = false;
try {
  var params = {};
  location.search.slice(1).split('&').forEach(function(pair){
    if (!pair) return;
    var eq = pair.indexOf('='); if (eq < 0) return;
    var k = decodeURIComponent(pair.slice(0, eq));
    var v = decodeURIComponent(pair.slice(eq + 1));
    var keys = k.replace(/]/g, '').split('[');
    var obj = params;
    for (var i=0;i<keys.length-1;i++){ var kk=keys[i]; if(!obj[kk]) obj[kk]={}; obj=obj[kk]; }
    obj[keys[keys.length-1]] = v;
  });
  var cfg = {};
  jQuery.extend(true, cfg, params);           // __proto__[srcdoc][]=...
  // gadget: widget membaca konfigurasi terpollute utk set iframe srcdoc
  var sd = (cfg.srcdoc && (cfg.srcdoc[0] || cfg.srcdoc)) || null;
  if (sd) {
    document.getElementById('g').setAttribute('srcdoc', String(sd).replace('__EXEC__', 'window.__pp_exec=true'));
    window.__pp_exec = true;
  }
} catch(e) { document.title='ERR:'+e; }
</script>
</body></html>"""

PAGE_ATTR = """<!doctype html><html><body>
""" + JQ + """
<div id="t"></div>
<script>
window.__pp_exec = false;
try {
  var params = {};
  location.search.slice(1).split('&').forEach(function(pair){
    if (!pair) return;
    var eq = pair.indexOf('='); if (eq < 0) return;
    var k = decodeURIComponent(pair.slice(0, eq));
    var v = decodeURIComponent(pair.slice(eq + 1));
    var keys = k.replace(/]/g, '').split('[');
    var obj = params;
    for (var i=0;i<keys.length-1;i++){ var kk=keys[i]; if(!obj[kk]) obj[kk]={}; obj=obj[kk]; }
    obj[keys[keys.length-1]] = v;
  });
  var appConfig = {};
  jQuery.extend(true, appConfig, params);
  $('#t').attr(appConfig);
  // gadget terpicu bila atribut event masuk
  if (document.getElementById('t').getAttribute('onerror') ||
      document.getElementById('t').getAttribute('OnError')) {
    window.__pp_exec = true;
    try {
      var im = document.createElement('img');
      im.src = 'x';
      im.setAttribute('onerror', 'window.__pp_exec=true');
      document.body.appendChild(im);
    } catch(e){}
  }
} catch(e) { document.title='ERR:'+e; }
</script>
</body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt=None, *args):  # sesuaikan signature
        pass

    def do_GET(self):
        p = urlparse(self.path).path
        page = {"/purify": PAGE_PURIFY,
                "/recaptcha": PAGE_RECAPTCHA,
                "/attr": PAGE_ATTR,
                "/gadget": PAGE_ATTR}.get(p, PAGE_ATTR)
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


socketserver.TCPServer.allow_reuse_address = True
httpd = socketserver.TCPServer(("127.0.0.1", 8903), H)
httpd.serve_forever()
