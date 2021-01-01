#!/usr/bin/env python3

import gpg
import json
import os
import re
from gpg.gpgme import GPG_ERR_NO_ERROR, GPGME_DELETE_FORCE, gpgme_op_delete_ext 
from http.server import BaseHTTPRequestHandler, HTTPServer
from secrets import token_urlsafe
from sys import argv, exit as sysexit
from tempfile import TemporaryDirectory

import websocket
from database import DataBase

NONCE_BYTES = 128
ADMIN_ACCESS = 100

class JsonMissingFieldException(Exception):
    def __init__(self, missing):
        self.missing = missing
        

class RequestHandler(BaseHTTPRequestHandler):
    _RE_FILES = re.compile(r"^(/|/admin\.html|/config\.js|/registered\.js|/openpgp\.min\.js)$")
    _RE_KEY_FINGERPRINT = re.compile(r"^/key/([0-9a-fA-F]{40})$")
    _RE_PGP_JSON_REQUEST_FIELD = re.compile(r"^[0-9a-zA-Z_/]{3,100}$")
    _VALID_CONTENT_SUBTYPES = {"html", "javascript", "json", "plain"}

    def _api_get_user_key(self, fingerprints=None):
        keys = list()
        if fingerprints == None:
            for user in self.server.db.getUser():
                keys.append({ "fingerprint": user["fingerprint"],
                              "armored_key": (self.gpg_context.key_export(user["fingerprint"])).decode()})
        else:
            for fpr in fingerprints:
                if self.server.db.getUser(fpr) is not None:
                    keys.append({ "fingerprint": fpr,
                                  "armored_key": (self.gpg_context.key_export(fpr)).decode()})
                else:
                    websocket.close(self.wfile, 1008, "Asking for an unknown key.")
                    self.websocket_connected = False
                    return
        request_answer = websocket.encrypt_pgp_json({
            "request": self.websocket_pending_request,
            "payload": keys
        }, [self.websocket_client_key], self.gpg_context)
        websocket.send_message(self.wfile, request_answer)
        websocket.close(self.wfile)
        self.websocket_connected = False

    def _api_register_user(self):
        try:
            req = self._read_json(["pubKey"])
        except JsonMissingFieldException:
            self._api_register_user_answer(400, f"Missing {missingField.missing}.")
            return
        results = self.server.gpg_context.key_import(req["pubKey"].encode())
        if results == "IMPORT_PROBLEM" or not results.considered:
            self._api_register_user_answer(400, "Invalid pubKey.")
        elif results.imported:
            access_level = ADMIN_ACCESS if len(self.server.db.getUser()) == 0 else 0 # first user get admin access level
            self.server.db.addUser(results.imports[0].fpr, access_level)
            print(f"Imported key {results.imports[0].fpr}.")
            self._api_register_user_answer(201, "Key registered.")
        elif results.unchanged:
            self._api_register_user_answer(200, "Key already on server.")
        else:
            self._api_register_user_answer(418, "What happened?")
            print(f"Tried to add following pubKey and got strange results:\n{req[pubKey]}\n\n{results}")

    def _api_register_user_answer(self, code: int, message: str):
        self.send_response(code)
        self._set_content_type("json")
        self.end_headers()
        self.wfile.write(json.dumps({ "message": message }).encode())

    def _api_unregister_user(self):
        result = gpgme_op_delete_ext(self.server.gpg_context.wrapped, self.websocket_client_key, GPGME_DELETE_FORCE)
        if result == GPG_ERR_NO_ERROR:
            self.server.db.deleteUser(self.websocket_client_key.fpr)
            print(f"Key {self.websocket_client_key.fpr} deleted.")
            websocket.close(self.wfile)
        else:
            print(f"Failed to delete key {self.websocket_client_key.fpr}, status code: {result}.")
            websocket.close(self.wfile, 1011)
        self.websocket_connected = False

    def _handle_api_request(self, message: websocket.WebSocketMessage):
        signatures_keys = [self.websocket_client_key] if self.websocket_client_key is not None else None
        json_, signatures = websocket.decrypt_pgp_json(self.wfile, self.gpg_context,
                                                       message, signatures_keys)

        if len(signatures) != 1:
            websocket.close(self.wfile, 1002, "Multi-signatures message not implemented.")
            self.websocket_connected = False
        elif "request" not in json_ or not re.match(self._RE_PGP_JSON_REQUEST_FIELD, json_["request"]):
            websocket.close(self.wfile, 1002, "Missing or invalid request field.")
            self.websocket_connected = False

        elif self.websocket_nonce is None:
            self.websocket_pending_request = json_["request"]
            self.websocket_client_key = self.gpg_context.get_key(signatures[0].fpr)
            self._request_signature()
        elif "nonce" not in json_ or json_["nonce"] != self.websocket_nonce:
            websocket.close(self.wfile, 1002, "Authentication failed.")
            self.websocket_connected = False

        # API "routes"
        elif self.websocket_pending_request == "key/delete":
            if self.server.db.getUser(self.websocket_client_key.fpr)["access_level"] == ADMIN_ACCESS:
                websocket.close(self.wfile, 1008, "Cannot delete admin account.")
                self.websocket_connected = False
                return
            self._api_unregister_user()
        elif self.websocket_pending_request == "key/all":
            if self.server.db.getUser(self.websocket_client_key.fpr)["access_level"] == ADMIN_ACCESS:
                self._api_get_user_key()
            else:
                websocket.close(self.wfile, 1008, "API function reserved to admins.")
                self.websocket_connected = False
        else:
            websocket.close(self.wfile, 1002, "API function undefined.")
            self.websocket_connected = False

    def _handle_websocket_request(self):
        self.websocket_client_key = None
        self.websocket_nonce = None
        self.websocket_pending_request = None
        self.gpg_context = gpg.Context(armor=True,
                                       home_dir=self.server.gpg_context.home_dir,
                                       offline=True,
                                       signers=[self.server.key])
        
        try:
            proto = websocket.handshake(self, ["pgp-json"])
            if proto is None:
                websocket.close(self.wfile, 1002, "I only speak pgp-json")
                return
            self.websocket_connected = True
            print(f"WebSocket connection with {self.client_address[0]}:{self.client_address[1]}")
        except websocket.HandshakeError as error:
            print(f"WebSocket handshake failed. {error.get_reason(error.why)}: {error.what}={error.value}")
            return

        try:
            while self.websocket_connected:
                message = websocket.read_next_message(self.rfile, self.wfile)
                self._handle_api_request(message)
        except websocket.WebSocketCloseException as close:
            print(f"WebSocket closed with code {close.code}, reason {close.reason}")

    def _read(self):
        if not self.headers["Content-Length"]:
            return ""
        length = int(self.headers["Content-Length"])
        return self.rfile.read(length)

    # implement type check for fields
    def _read_json(self, required_fields=list()):
        try:
            data = json.loads(self._read())
        except json.decoder.JSONDecodeError:
            data = {}
        for f in required_fields:
            if not f in data:
                raise JsonMissingFieldException(missing=f)
        return data

    def _request_signature(self):
        self.websocket_nonce = token_urlsafe(NONCE_BYTES)
        signature_request = websocket.encrypt_pgp_json({
            "nonce": self.websocket_nonce,
            "request": self.websocket_pending_request
        }, [self.websocket_client_key], self.gpg_context)
        websocket.send_message(self.wfile, signature_request)

    def _serve_err404(self):
        self.send_response(404)
        self._set_content_type("plain")
        self.end_headers()
        self.wfile.write("Not found".encode())

    def _serve_file(self, filepath):
        if filepath == "/":
            filepath = "register.html"
        else:
            filepath = filepath[1:]
        self.send_response(200)
        if filepath.endswith("html"):
            self._set_content_type("html")
        else:
            self._set_content_type("javascript")
        self.end_headers()
        # assume files are utf-8 encoded
        with open(filepath, "rb") as f:
            output = f.read()
            self.wfile.write(output)

    def _set_content_type(self, subtype):
        if subtype not in self._VALID_CONTENT_SUBTYPES:
            raise ValueError(f"RequestHandler._set_content_type: _type must be one of {self._VALID_CONTENT_SUBTYPES}.")
        _type = "text"
        if subtype == "json":
            _type = "application"
        self.send_header("Content-Type", f"{_type}/{subtype}; charset=utf-8")

    def do_GET(self):
        filepath = re.match(self._RE_FILES, self.path)
        key_fingerprint = re.match(self._RE_KEY_FINGERPRINT, self.path)
        if self.headers.get("Upgrade") == "websocket":
            self._handle_websocket_request()
        elif key_fingerprint:
            key = self.server.gpg_context.key_export(key_fingerprint.group(1))
            key = key if key is not None else b"Unknown"
            self.send_response(200)
            self._set_content_type("plain")
            self.end_headers()
            self.wfile.write(key)
        elif self.path == "/key/srv":
            # May raise GPGMEerror
            key = self.server.gpg_context.key_export(self.server.db.getConfig("server_key"))
            self.send_response(200)
            self._set_content_type("plain")
            self.end_headers()
            self.wfile.write(key)
        elif filepath:
            self._serve_file(filepath.group(1))
        else:
            self._serve_err404()

    def do_POST(self):
        if self.path == "/key/add":
            self._api_register_user()

class Server(HTTPServer):
    def __init__(self, listen_to, gpg_home, db):
        self.gpg_context = gpg.Context(armor=True, home_dir=gpg_home, offline=True)
        self.db = DataBase(db)
        self.initSrvKeys()
        super().__init__(listen_to, RequestHandler)

    def initSrvKeys(self):
        fingerprint = self.db.getConfig("server_key")
        if not fingerprint:
            try:
                result = self.gpg_context.create_key(userid="PoC server", algorithm="ed25519",
                    expires=False, sign=True)
                fingerprint = result.fpr
                result = self.gpg_context.create_subkey(key=self.gpg_context.get_key(fingerprint),
                    algorithm="cv25519", expires=False, encrypt=True)
                self.db.setConfig("server_key", fingerprint)
                self.key = self.gpg_context.get_key(fingerprint)
            except gpg.errors.GPGMEError as error:
                print("Failed to create server key.")
                sysexit(error)
            except gpg.errors.KeyError as error:
                print("Can't find the key I just created... wtf?")
                sysexit(error)
        else:
            try:
                self.key = self.gpg_context.get_key(fingerprint)
            except gpg.errors.KeyError as error:
                print(f"Cannot find server key {fingerprint}.")
                sysexit(error)
        print(f"Loaded server key {fingerprint}.")

if __name__ == "__main__":

    def run(listen_to, gpg_home, db):
        httpd = Server(listen_to, gpg_home, db)
        try:
            print(f"Starting server… listening to {listen_to[0]}:{listen_to[1]} with datadir {gpg_home}, db {db}")
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        print("Stopping server")
        httpd.server_close()

    datadir = None
    host = "127.0.0.1"
    port = 8000
    if len(argv) > 3:
        datadir = argv[3]
    if len(argv) > 2:
        host = argv[2]
    if len(argv) > 1:
        port = int(argv[1])

    if not datadir:
        with TemporaryDirectory(prefix="websocket-pgp-json") as tempdir:
            run((host, port), tempdir, ":memory:")
    else:
        gpg_home = os.path.join(datadir, "gpg")
        db = os.path.join(datadir, "sqlite.db")
        try:
            os.mkdir(gpg_home)
        except FileExistsError:
            print("Using existing GPG home dir.")
        run((host, port), gpg_home, db)
