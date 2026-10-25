"""Runner reachability: kombinasi Selenium + instrumentasi pra-navigasi.

Dipakai dari scanner/core.py atau CLI `--reach-check`. Non-destructive:
hanya GET dengan payload di URL, tidak ada form submit/POST.
"""
import json
import time
from typing import Any, Dict, List, Optional

from ppmap.scanner.reach_check import (
    build_instrumentation,
    build_reach_urls,
    collect_hits,
    execution_fired,
    make_canary,
    reach_verdict,
)


def run_reach_check(base_url: str, driver=None, canary: Optional[str] = None,
                    settle_seconds: float = 3.0) -> Dict[str, Any]:
    """Jalankan 8 vektor URL di halaman target dgn sink ter-instrumentasi.

    Args:
        base_url: URL halaman (dengan query bila ada).
        driver: Selenium WebDriver (Chrome). Bila None, dibuat di sini.
        canary: canary kustom; default auto.
        settle_seconds: jeda tunggu halaman+JS selesai tiap vektor.

    Returns:
        dict verdict lengkap + bukti per vektor.
    """
    canary = canary or make_canary()
    instrumented = False
    local_driver = False

    if driver is None:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            for a in ("--headless=new", "--no-sandbox", "--disable-gpu",
                      "--disable-dev-shm-usage", "--window-size=1400,900"):
                opts.add_argument(a)
            import tempfile
            opts.add_argument(f"--user-data-dir={tempfile.mkdtemp(prefix='ppmap_rc_')}")
            driver = webdriver.Chrome(options=opts)
            local_driver = True
        except Exception as e:
            return {"verdict": "UNAVAILABLE", "reason": f"no driver: {e}", "canary": canary}

    try:
        # 1. pasang instrumentasi pra-navigasi
        try:
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {"source": build_instrumentation(canary)},
            )
            instrumented = True
        except Exception:
            # fallback Selenium biasa (berlaku utk navigasi pertama saja)
            pass

        # 2. baseline dulu (tanpa payload) — hitam-putihkan perilaku halaman normal
        vector_results = []
        try:
            driver.get(base_url)
            time.sleep(settle_seconds)
        except Exception:
            pass
        baseline_hits = collect_hits(driver)

        # 3. jalankan tiap vektor
        urls = build_reach_urls(base_url, canary)
        for v in urls:
            try:
                driver.get(v["url"])
                time.sleep(settle_seconds)
            except Exception:
                pass
            hits = collect_hits(driver)
            executed = execution_fired(driver, canary)
            # pollution nyata? cek Object.prototype
            try:
                polluted = bool(driver.execute_script(
                    f"return (function(){{var o={{}}; return ('{canary}' in o);}})();"
                ))
            except Exception:
                polluted = False
            vector_results.append({
                "label": v["label"],
                "url": v["url"][:200],
                "desc": v["desc"],
                "sink_calls": len(hits),
                "canary_in_sink": any(canary in json.dumps(h, default=str) for h in hits),
                "object_prototype_polluted": polluted,
                "executed": executed,
            })

        any_canary = any(r["canary_in_sink"] or r["object_prototype_polluted"] for r in vector_results)
        any_exec = any(r["executed"] for r in vector_results)
        all_hits = baseline_hits  # pakai baseline utk verdict (hits per-vektor dicatat detail)
        verdict = reach_verdict(
            [{"sink": "aggregated", "data": canary}] if any_canary else all_hits,
            canary, any_exec,
        )
        verdict["vector_results"] = vector_results
        verdict["instrumented_cdp"] = instrumented
        verdict["base_url"] = base_url
        return verdict
    finally:
        if local_driver:
            try:
                driver.quit()
            except Exception:
                pass
