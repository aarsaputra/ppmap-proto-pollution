# PPMAP LAB (permanen di repo, port 8901-8903 — milik AGENT-B)

Server lab mini untuk menguji fitur ppmap tanpa menyentuh target eksternal.
Jalankan dari root repo:

    /home/lota1337/myenv/bin/python lab/gql_server.py &      # 8901 GraphQL (introspection + echo vars)
    /home/lota1337/myenv/bin/python lab/ws_server.py &       # 8902 WebSocket echo RFC6455
    /home/lota1337/myenv/bin/python lab/gadget_server.py &   # 8903 jQuery $.attr gadget (query-string deparam)

Uji cepat:

    ppmap.py --reach-check http://127.0.0.1:8903/gadget     # harap tier 2 REACHABLE, gadget jquery_*
    ppmap.py --scan http://127.0.0.1:8901/graphql          # graphql findings (echo vars)
    python -c "from ppmap.websocket import scan_websocket; print(scan_websocket('http://127.0.0.1:8902/'))"

Catatan:
- vvLab sengaja TIDAK memakai hash; gadget page menerima payload lewat query-string
  `?__proto__[...]=...` (pola gadget dunia nyata), lalu `$.extend(true, appConfig, params)`
  + `$('#t').attr(appConfig)` — celah intigriti-0124/BlackFan.
- Bila lab mati setelah reboot: jalankan 3 baris di atas lagi.
