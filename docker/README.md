QuickPoC Docker Runner
======================

This Dockerfile builds an environment with Playwright and Python to run
`tools/quickpoc_local.py` reproducibly without ChromeDriver mismatches.

Build:

```bash
docker build -t ppmap-quickpoc -f docker/Dockerfile.quickpoc .
```

Run (example):

```bash
docker run --rm ppmap-quickpoc --target https://example.com --headless
```

Notes:
- The image is based on Playwright's official Python image which bundles browsers.
- If you prefer Selenium+ChromeDriver instead, run the script on your host machine
  where Chrome and ChromeDriver versions match, or adapt the Dockerfile to
  install a specific ChromeDriver version.
