"""Test AUDIT-22: setiap URL vektor gadget harus benar-benar membawa payload.

Regresi yang dicegah (lolos ke lapangan, terdeteksi saat audit URL mentah):

a) Token tidak tersubstitusi — substitusi dulu baru encoding membuat `{xs}`
   berubah jadi `%7Bxs%7D`, sehingga URL berisi literal token dan payload
   mentah (spasi) yang tidak pernah terkirim.
b) Notasi bracket datar rusak — karakter `=`/`&` pada KEY tidak di-encode,
   jadi key `...[callback][=21]` pecah jadi parameter lain.
c) CR/LF hilang — `urllib.parse` membuang `\\r\\n` (WHATWG), jadi payload
   multi-baris lodash tiba sebagai `x}` bukan `x\\n}`.
d) Canary tidak ikut — canary produksi (`make_canary()`) adalah string mentah
   tanpa `window['...']=1`; vektor bertipe string (alert/javascript:/onerror)
   tidak pernah membawanya sehingga `execution_fired()` mustahil True.
"""
from urllib.parse import parse_qsl, urlsplit

import pytest

from ppmap.payloads.gadget_library import GADGET_VECTORS, build_gadget_urls
from ppmap.scanner.reach_check import EXEC_MARKER_JS, build_reach_urls, make_canary

BASE = "http://127.0.0.1:8903/gadget"
CANARY = make_canary("audit22")


@pytest.fixture(scope="module")
def urls():
    return build_gadget_urls(BASE, CANARY)


def test_every_gadget_vector_is_built(urls):
    assert len(urls) == len(GADGET_VECTORS)


@pytest.mark.parametrize("needle", ["{xs}", "{xs_enc}", "{xs_enc2}", "{x_k}"])
def test_no_leftover_token_in_any_url(urls, needle):
    offenders = [u["label"] for u in urls if needle in u["url"]]
    assert offenders == [], f"token {needle} tidak tersubstitusi: {offenders}"


def test_no_raw_url_breaking_chars(urls):
    for u in urls:
        assert " " not in u["url"], f"{u['label']}: spasi mentah"
        assert "<" not in u["url"] and ">" not in u["url"], f"{u['label']}: < > mentah"
        assert "\n" not in u["url"] and "\r" not in u["url"], f"{u['label']}: CRLF mentah"


def test_query_parses_into_clean_pairs(urls):
    """Setelah di-parse, tidak boleh ada key yang memuat token."""
    for u in urls:
        pairs = parse_qsl(urlsplit(u["url"]).query, keep_blank_values=True)
        assert pairs, f"{u['label']}: query kosong"
        bad = [k for k, _ in pairs if "{" in k or "}" in k]
        assert bad == [], f"{u['label']}: key ber-token {bad}"


def test_canary_and_exec_marker_present_in_every_vector(urls):
    for u in urls:
        assert CANARY in u["url"], f"{u['label']}: canary hilang"
        assert EXEC_MARKER_JS.split(".")[-1] in u["url"], f"{u['label']}: marker hilang"


def test_no_double_window_prefix(urls):
    for u in urls:
        assert "window.window" not in u["url"], f"{u['label']}: window.window"


def test_lodash_payload_keeps_newline(urls):
    """CR/LF harus sampai utuh (ter-encode %0A) setelah decode."""
    url = next(u["url"] for u in urls if u["label"] == "lodash_merge_client")
    assert "%0A" in url
    decoded = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    assert decoded["__proto__[sourceURL]"] == "x\n}"


def test_jquery_attr_vector_carries_exec_payload(urls):
    """Vektor yang dulu paling parah: {xs} mentah + payload tanpa canary."""
    url = next(u["url"] for u in urls if u["label"] == "jquery_attr_upper")
    decoded = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    on_error = decoded["__proto__[OnError]"]
    assert CANARY in on_error
    assert on_error.startswith("<img src=x onerror=")


def test_reach_urls_also_carry_canary():
    for v in build_reach_urls(BASE, CANARY):
        assert CANARY in v["url"], f"{v['label']}: canary hilang"
        assert " " not in v["url"], f"{v['label']}: spasi mentah"
