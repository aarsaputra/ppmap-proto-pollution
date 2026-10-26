#!/usr/bin/env python3
"""Lab WebSocket PP echo — RFC6455 handshake + echo semua text frame.
Untuk uji ppmap.websocket.scan_websocket() (7 payload PP)."""
import base64
import hashlib
import socket
import threading

def handler(conn):
    data = conn.recv(4096).decode("utf-8", "ignore")
    key = ""
    for line in data.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
    ).decode()
    conn.sendall((
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    ).encode())
    while True:
        hdr = conn.recv(2)
        if len(hdr) < 2:
            break
        ln = hdr[1] & 0x7F
        mask = hdr[1] & 0x80
        if ln == 126:
            ln = int.from_bytes(conn.recv(2), "big")
        elif ln == 127:
            ln = int.from_bytes(conn.recv(8), "big")
        maskkey = conn.recv(4) if mask else None
        payload = conn.recv(ln) if ln else b""
        if maskkey:
            payload = bytes(b ^ maskkey[i % 4] for i, b in enumerate(payload))
        frame = bytearray([0x81])
        n = len(payload)
        if n < 126:
            frame.append(n)
        elif n < 65536:
            frame += bytes([126]) + n.to_bytes(2, "big")
        else:
            frame += bytes([127]) + n.to_bytes(8, "big")
        frame += payload
        try:
            conn.sendall(bytes(frame))
        except Exception:
            break

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8902))
srv.listen(5)
print("WS lab di 8902", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=handler, args=(c,), daemon=True).start()
