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
    _RE_FILES = re.compile(r"^(/|/admin\.html|/data\.html|/forms\.html|/config\.js|/public\.js|/registered\.js|/openpgp\.min\.js)$")
    _RE_FORM_NAME = re.compile(r"^([-_0-9a-zA-Z]{1,64})$")
    _RE_KEY_FINGERPRINT = re.compile(r"^([0-9a-fA-F]{40})$")
    _RE_PGP_JSON_REQUEST_FIELD = re.compile(r"^[0-9a-zA-Z_/]{3,100}$")
    _VALID_CONTENT_SUBTYPES = {"html", "javascript", "json", "plain"}

    def _api_answer_pgp_json(self, payload):
        request_answer = websocket.encrypt_pgp_json({
            "request": self._pgpjson_pending_request,
            "payload": payload
        }, self._pgpjson_client_key, self._gpg_context)
        websocket.send_message(self.wfile, request_answer)
        self._close_websocket()

    def _api_collect_data(self):
        form_name = re.match(self._RE_FORM_NAME, self.path.replace("/post/", ""))
        if form_name:
            secret = self._read().decode()
            self.server.db.store_form_data(form_name.group(1), secret)
            self.send_response(200)
            self.end_headers()

    def _api_get_collected_data(self):
        form_name = re.match(self._RE_FORM_NAME, self._pgpjson_pending_request.replace("data/get/", ""))
        if form_name:
            form_name = form_name.group(1)
            form_users = self.server.db.get_form_keys_fingerprints(form_name)
            if self._pgpjson_user["fingerprint"] not in form_users["fingerprints"]:
                self._close_websocket(1008, "Access denied.")
            else:
                collected_data = self.server.db.get_collected_data(form_name)
                self._api_answer_pgp_json(collected_data)
        else:
            self._close_websocket(1002, "Invalid form name.")

    def _api_get_form_keys_fingerprints(self):
        if self._pgpjson_user["access_level"] != ADMIN_ACCESS:
            self._close_websocket(1008, "Access denied.")
            return

        form_name = re.match(self._RE_FORM_NAME, self._pgpjson_pending_request.replace("form/get/", ""))
        if form_name:
            form_key_list = self.server.db.get_form_keys_fingerprints(form_name.group(1))
            self._api_answer_pgp_json(form_key_list)
        else:
            self._close_websocket(1002, "Invalid form name.")

    def _api_get_user(self):
        user_fingerprint = re.match(self._RE_KEY_FINGERPRINT, self._pgpjson_pending_request.replace("user/", ""))
        if user_fingerprint:
            fpr = user_fingerprint.group(1)
            if self._pgpjson_user["access_level"] == ADMIN_ACCESS or self._pgpjson_user["fingerprint"] == fpr:
                user = self.server.db.get_user(fpr)
                self._api_answer_pgp_json(user)
            else:
                self._close_websocket(1008, "Access denied.")
        elif self._pgpjson_pending_request == "user/all":
            if self._pgpjson_user["access_level"] == ADMIN_ACCESS:
                users = self.server.db.get_user()
                self._api_answer_pgp_json(users)
            else:
                self._close_websocket(1008, "Access denied.")
        else:
            self._close_websocket(1002, "Invalid user fingerprint.")

    def _api_get_user_key(self, fingerprints=None):
        keys = list()
        if fingerprints == None:
            for user in self.server.db.get_user():
                keys.append({ "fingerprint": user["fingerprint"],
                              "armored_key": (self._gpg_context.key_export(user["fingerprint"])).decode()})
        else:
            for fpr in fingerprints:
                if self.server.db.get_user(fpr) is not None:
                    keys.append({ "fingerprint": fpr,
                                  "armored_key": (self._gpg_context.key_export(fpr)).decode()})
                else:
                    self._close_websocket(1008, "Asking for an unknown key.")
                    return
        self._api_answer_pgp_json(keys)

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
            access_level = ADMIN_ACCESS if len(self.server.db.get_user()) == 0 else 0 # first user get admin access level
            self.server.db.add_user(results.imports[0].fpr, access_level)
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

    def _api_set_collected_data(self):
        if self._pgpjson_user["access_level"] != ADMIN_ACCESS:
            self._close_websocket(1008, "Access denied.")
            return

        form_name = re.match(self._RE_FORM_NAME, self._pgpjson_pending_request.replace("data/set/", ""))
        if form_name:
            if self._pgpjson_payload is None:
                self._close_websocket(1002, "Missing payload.")
                return
            for data in self._pgpjson_payload:
                if "secret" not in data or "id" not in data:
                    self._close_websocket(1002, "Invalid payload")
                    return
                elif not data["secret"].startswith("-----BEGIN PGP MESSAGE-----"):
                    self._close_websocket(1002, "Invalid PGP message")
                    return
            self.server.db.set_collected_data(form_name.group(1), self._pgpjson_payload)
            self._close_websocket()
        else:
            self._close_websocket(1002, "Invalid form name.")

    def _api_set_form_keys_fingerprints(self):
        if self._pgpjson_user["access_level"] != ADMIN_ACCESS:
            self._close_websocket(1008, "Access denied.")
            return

        form_name = re.match(self._RE_FORM_NAME, self._pgpjson_pending_request.replace("form/set/", ""))
        if form_name:
            if self._pgpjson_payload is not None and "fingerprints" in self._pgpjson_payload and isinstance(self._pgpjson_payload["fingerprints"], list):
                self.server.db.set_form_keys_fingerprints(form_name.group(1), self._pgpjson_payload["fingerprints"])
                self._close_websocket()
            else:
                self._close_websocket(1002, "Invalid request payload.")
        else:
            self._close_websocket(1002, "Invalid form name.")

    def _api_unregister_user(self):
        if self._pgpjson_user["access_level"] == ADMIN_ACCESS:
            self._close_websocket(1008, "Cannot delete admin account.")
            return
        result = gpgme_op_delete_ext(self._gpg_context.wrapped, self._pgpjson_client_key, GPGME_DELETE_FORCE)
        if result == GPG_ERR_NO_ERROR:
            self.server.db.delete_user(self._pgpjson_client_key.fpr)
            print(f"Key {self._pgpjson_client_key.fpr} deleted.")
            self._close_websocket()
        else:
            print(f"Failed to delete key {self._pgpjson_client_key.fpr}, status code: {result}.")
            self._close_websocket(1011, "Failed to delete key.")

    def _close_websocket(self, code=1000, reason=None):
        websocket.close(self.wfile, code, reason)
        self._websocket_connected = False
        print(f"Closed WebSocket connection with {self.client_address[0]}:{self.client_address[1]}")
        if code != 1000:
            print(f"Code: {code} reason: {reason}")


    def _handle_api_request(self, message: websocket.WebSocketMessage):
        signature_key = self._pgpjson_client_key if self._pgpjson_client_key is not None else None
        json_, signature = websocket.decrypt_pgp_json(self.wfile, self._gpg_context,
                                                       message, signature_key)

        if "request" not in json_ or not re.match(self._RE_PGP_JSON_REQUEST_FIELD, json_["request"]):
            self._close_websocket(1002, "Missing or invalid request field.")
            return

        elif self._pgpjson_nonce is None:
            self._pgpjson_pending_request = json_["request"]
            if "payload" in json_:
                self._pgpjson_payload = json_["payload"]
            self._pgpjson_client_key = self._gpg_context.get_key(signature[0].fpr)
            self._request_signature()
            return
        elif "nonce" not in json_ or json_["nonce"] != self._pgpjson_nonce:
            self._close_websocket(1002, "Authentication failed.")
            return

        self._pgpjson_user = self.server.db.get_user(self._pgpjson_client_key.fpr)

        # API "routes"
        if self._pgpjson_pending_request.startswith("data/get/"):
            self._api_get_collected_data()
        elif self._pgpjson_pending_request.startswith("data/set/"):
            self._api_set_collected_data()
        elif self._pgpjson_pending_request.startswith("form/get/"):
            self._api_get_form_keys_fingerprints()
        elif self._pgpjson_pending_request.startswith("form/set/"):
            self._api_set_form_keys_fingerprints()
        elif self._pgpjson_pending_request == "key/delete":
            self._api_unregister_user()
        elif self._pgpjson_pending_request.startswith("user/"):
            self._api_get_user()
        else:
            print(self._pgpjson_pending_request)
            self._close_websocket(1002, "API function undefined.")

    def _handle_websocket_request(self):
        self._pgpjson_client_key = None
        self._pgpjson_nonce = None
        self._pgpjson_pending_request = None
        self._pgpjson_payload = None
        self._pgpjson_user = None
        self._gpg_context = gpg.Context(armor=True,
                                       home_dir=self.server.gpg_context.home_dir,
                                       offline=True,
                                       signers=[self.server.key])
        
        try:
            proto = websocket.handshake(self, ["pgp-json"])
            if proto is None:
                self._close_websocket(1002, "I only speak pgp-json")
                return
            self._websocket_connected = True
            print(f"WebSocket connection with {self.client_address[0]}:{self.client_address[1]}")
        except websocket.HandshakeError as error:
            print(f"WebSocket handshake failed. {error.get_reason(error.why)}: {error.what}={error.value}")
            return

        try:
            while self._websocket_connected:
                message = websocket.read_next_message(self.rfile, self.wfile)
                self._handle_api_request(message)
        except websocket.WebSocketCloseException as close:
            print(f"WebSocket closed with code {close.code}, reason {close.reason}")

    def _read(self):
        if not self.headers["Content-Length"]:
            return ""
        length = int(self.headers["Content-Length"])
        return self.rfile.read(length)

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
        self._pgpjson_nonce = token_urlsafe(NONCE_BYTES)
        signature_request = websocket.encrypt_pgp_json({
            "nonce": self._pgpjson_nonce,
            "request": self._pgpjson_pending_request
        }, self._pgpjson_client_key, self._gpg_context)
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

    def _serve_form_keys(self):
        form_name = re.match(self._RE_FORM_NAME, self.path.replace("/formkeys/", ""))
        if form_name:
            form_name = form_name.group(1)
            keys = []
            keylist = self.server.db.get_form_keys_fingerprints(form_name)
            for fpr in keylist["fingerprints"]:
                keys.append(self.server.gpg_context.key_export(fpr).decode())
            self.send_response(200)
            self._set_cors()
            self._set_content_type("json")
            self.end_headers()
            self.wfile.write(json.dumps({ "form": form_name, "keys": keys }).encode())
        else:
            self._serve_err404()

    def _set_content_type(self, subtype):
        if subtype not in self._VALID_CONTENT_SUBTYPES:
            raise ValueError(f"RequestHandler._set_content_type: _type must be one of {self._VALID_CONTENT_SUBTYPES}.")
        _type = "text"
        if subtype == "json":
            _type = "application"
        self.send_header("Content-Type", f"{_type}/{subtype}; charset=utf-8")

    def _set_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")

    def do_GET(self):
        filepath = re.match(self._RE_FILES, self.path)
        if self.headers.get("Upgrade") == "websocket":
            self._handle_websocket_request()
        elif self.path.startswith("/formkeys/"):
            self._serve_form_keys()
        elif self.path == "/key/srv":
            # May raise GPGMEerror
            key = self.server.gpg_context.key_export(self.server.db.get_config("server_key"))
            self.send_response(200)
            self._set_cors()
            self._set_content_type("plain")
            self.end_headers()
            self.wfile.write(key)
        elif self.path.startswith("/key/"):
            key_fingerprint = re.match(self._RE_KEY_FINGERPRINT, self.path.replace("/key/", ""))
            key = self.server.gpg_context.key_export(key_fingerprint.group(1))
            key = key if key is not None else b"Unknown"
            self.send_response(200)
            self._set_cors()
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
        elif self.path.startswith("/post/"):
            self._api_collect_data()
        else:
            self.send_response(404)
            self.end_headers()

class Server(HTTPServer):
    def __init__(self, listen_to, gpg_home, db):
        self.gpg_context = gpg.Context(armor=True, home_dir=gpg_home, offline=True)
        self.db = DataBase(db)
        self.initSrvKeys()
        super().__init__(listen_to, RequestHandler)

    def initSrvKeys(self):
        fingerprint = self.db.get_config("server_key")
        if not fingerprint:
            try:
                result = self.gpg_context.create_key(userid="PoC server", algorithm="ed25519",
                    expires=False, sign=True)
                fingerprint = result.fpr
                result = self.gpg_context.create_subkey(key=self.gpg_context.get_key(fingerprint),
                    algorithm="cv25519", expires=False, encrypt=True)
                self.db.set_config("server_key", fingerprint)
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
            print(f"Starting server… listening to {listen_to[0]}:{listen_to[1]} with keystore {gpg_home}, db {db}")
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
