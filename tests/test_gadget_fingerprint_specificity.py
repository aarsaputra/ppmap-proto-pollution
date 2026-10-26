"""Test AUDIT-21: fingerprint gadget library harus spesifik (anti false-positive).

Regresi yang dicegah: marker generik (".attr(", ".on(", "jquery") menyalakan
deteksi di halaman mana pun -> reach-check menambah vektor gadget untuk library
yang sebenarnya tidak ada, dan laporan bisa menyiratkan gadget tersedia.
"""
from ppmap.payloads.gadget_library import (
    FINGERPRINT_OVERRIDES,
    GADGET_TO_LIBRARY,
    LIBRARY_FINGERPRINTS,
    build_gadget_urls,
    detect_libraries,
)

GENERIC_IDIOM_PAGE = (
    "<!doctype html><html><head><title>jquery tutorial</title></head><body>"
    "<script>// $('a').attr('href'); el.on('click', f); $('.x').off();</script>"
    "</body></html>"
)

LAB_JQUERY_142_PAGE = (
    "<!doctype html><html><body>"
    '<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js">'
    "</script><script>$('#t').attr({});</script></body></html>"
)


class TestFingerprintSpecificity:
    def test_generic_idioms_do_not_detect_jquery_gadgets(self):
        found = detect_libraries(GENERIC_IDIOM_PAGE)
        for lib in ("jquery_attr", "jquery_on", "jquery_off", "jquery_get"):
            assert lib not in found, f"{lib} false-positive pada halaman generik: {found}"

    def test_real_jquery_page_still_detected(self):
        found = detect_libraries(LAB_JQUERY_142_PAGE)
        for lib in ("jquery_attr", "jquery_on", "jquery_off"):
            assert lib in found, f"{lib} hilang (regresi): {found}"

    def test_specific_libraries_detected(self):
        src = (
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/2.0.12/purify.min.js"></script>'
            '<script src="https://www.google.com/recaptcha/api.js"></script>'
        )
        found = detect_libraries(src)
        assert "dompurify" in found
        assert "recaptcha" in found

    def test_overrides_stay_subset_of_known_libraries(self):
        assert set(FINGERPRINT_OVERRIDES) <= set(LIBRARY_FINGERPRINTS)

    def test_override_markers_are_not_bare_generic_tokens(self):
        banned = {".attr(", "attr({", ".on(", ".submit(", "jquery", ".off(", "unbind("}
        for lib, markers in FINGERPRINT_OVERRIDES.items():
            for mk in markers:
                assert mk.lower() not in banned, f"{lib}: marker generik {mk!r}"

    def test_empty_source(self):
        assert detect_libraries("") == []


class TestGadgetVectorConsistency:
    def test_every_vector_maps_to_a_library(self):
        labels = {v["label"] for v in build_gadget_urls("http://127.0.0.1:8903/gadget", "canary")}
        missing = labels - set(GADGET_TO_LIBRARY)
        assert not missing, f"vektor tanpa mapping library: {sorted(missing)}"

    def test_every_mapping_target_is_known_library(self):
        unknown = set(GADGET_TO_LIBRARY.values()) - set(LIBRARY_FINGERPRINTS)
        assert not unknown, f"mapping ke library tak dikenal: {sorted(unknown)}"
