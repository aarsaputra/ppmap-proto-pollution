#!/usr/bin/env python3
"""Lab GraphQL: introspection + endpoint detection target ppmap.graphql."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

INTROSPECTION_RESULT = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                {"name": "user", "args": [], "type": {"kind": "OBJECT", "name": "User"}}]},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "ID"}},
                {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String"}}]},
        ]}}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/graphql"):
            self._json(200, {"data": {"__typename": "Query"}})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            payload = {}
        q = str(payload.get("query", ""))
        if "__schema" in q:
            self._json(200, INTROSPECTION_RESULT)
        else:
            # echo vars mentah -> indikator PP balik di errors.message
            self._json(200, {"errors": [{"message": "bad filter: " + json.dumps(payload)}]})


HTTPServer(("127.0.0.1", 8901), H).serve_forever()
