# References from
# https://tools.ietf.org/html/rfc6455
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
# https://gist.github.com/SevenW/47be2f9ab74cac26bf21/ (SevenW/HTTPWebSocketsHandler.py)

from base64 import b64decode, b64encode
import json
from gpg import Context as GPGContext
from gpg.errors import GPGMEError
from hashlib import sha1
from binascii import Error as BinasciiError
from http.server import BaseHTTPRequestHandler
from io import BufferedIOBase
from time import time

_WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OPCODE = { "continueation": 0x0,
            "text": 0x1,
            "binary": 0x2,
            "close": 0x8,
            "ping": 0x9,
            "pong": 0xa }
CONTROL_OPCODES = [OPCODE["close"], OPCODE["ping"], OPCODE["pong"]]
NONCONTROL_OPCODES = [OPCODE["continueation"], OPCODE["text"], OPCODE["binary"]]
PROTOCOL_VERSION = 13
HTTP_VERSION = "HTTP/1.1"

PGP_JSON_SIGNATURE_VALIDITY = 60

class WebSocketException(Exception):
    pass

class FrameError(WebSocketException):
    def __init__(message: str, frame: dict):
        assert "FIN" in frame and frame["FIN"] is not None
        assert "RSV1" in frame and frame["RSV1"] is not None
        assert "RSV2" in frame and frame["RSV2"] is not None
        assert "RSV3" in frame and frame["RSV3"] is not None
        assert "opcode" in frame and frame["opcode"] is not None
        self.message = message
        self.frame = frame

class HandshakeError(WebSocketException):
    reason = { "invalid_header": 0,
               "missing_header": 1,
               "incompatible_version": 2 }

    def __init__(self, what: str, value: str, why: int):
        assert why in self.reason.values()
        self.what = what
        self.value = value
        self.why = why

    def get_reason(self, code: int):
        for k, v in self.reason.items():
            if v == code:
                return k

class InvalidLengthError(FrameError):
    def __init__(length: int):
        self.length = length

class WebSocketCloseException(WebSocketException):
    def __init__(self, code: int, reason: str):
        self.code = code
        self.reason = reason

class WebSocketMessage():
    def __add__(self, other):
        assert isinstance(other, WebSocketMessage)
        assert other["opcode"] == OPCODE["continueation"]
        if opcode == OPCODE["text"]:
            # may raise UnicodeError
            self.payload += other.payload.decode()
        else:
            self.payload += other.payload

    def __init__(self, opcode, payload):
        self.opcode = opcode
        if opcode == OPCODE["text"]:
            # may raise UnicodeError
            self.payload = payload.decode()
        else:
            self.payload = payload

    def __str__(self):
        return f"WebSocket Message opcode:0x{self.opcode:x} payload:{self.payload}"

def _check_required_headers(request_handler: BaseHTTPRequestHandler):
    if request_handler.request_version != HTTP_VERSION:
        request_handler.send_response(400)
        request_handler.end_headers()
        raise HandshakeError("HTTP", request_handler.request_version,
                             HandshakeError.reason["incompatible_version"])

    for header in [["Host", None],
                  ["Upgrade", "websocket"],
                  ["Connection", "upgrade"],
                  ["Sec-WebSocket-Key", None],
                  ["Sec-WebSocket-Version", None]]:
        value = request_handler.headers.get(header[0])
        requisite = header[1] in value.lower().split(", ") if header[1] is not None else value is not None
        reason = HandshakeError.reason["invalid_header"] if value is not None else HandshakeError.reason["missing_header"]
        if requisite is False:
            request_handler.send_response(400)
            request_handler.end_headers()
            raise HandshakeError(header[0], value, reason)

    ws_key = request_handler.headers.get("Sec-WebSocket-Key")
    if ws_key is None:
        request_handler.send_response(400)
        request_handler.end_headers()
        raise HandshakeError("Sec-WebSocket-Key", None, HandshakeError.reason["missing_header"])
    try:
        invalid_key_error = HandshakeError("Sec-WebSocket-Key", ws_key, HandshakeError.reason["invalid_header"])
        decoded = b64decode(s=ws_key, altchars=None, validate=True)
        if len(decoded) != 16:
            request_handler.send_response(400)
            request_handler.end_headers()
            raise invalid_key_error
    except BinasciiError:
        request_handler.send_response(400)
        request_handler.end_headers()
        raise invalid_key_error

def _decode_payload(masking_key: bytes, encoded_payload: bytes):
    decoded_payload = bytearray()
    for byte in encoded_payload:
        decoded_payload += bytes([byte ^ masking_key[len(decoded_payload) % 4]])
    return decoded_payload

def _encode_data_frame(fin: int, opcode: int, rsv1: int, rsv2: int, rsv3: int, payload: bytes):
    assert isinstance(payload, bytes)
    if not opcode in OPCODE.values():
        raise ValueError(f"Unsupported opcode {opcode}. Valid values {list(OPCODE.values())}.")
    if fin == 0 and opcode in CONTROL_OPCODES:
        raise ValueError(f"Control frames cannot be fragmented")
    if opcode in CONTROL_OPCODES and len(payload) > 125:
        raise ValueError("Control frame cannot have a payload bigger than 125 bytes.")
    payload_length = len(payload)
    length_bits = 7
    if payload_length > 0x7fffffffffffffff:
        raise ValueError(f"Payload maximal size exceeded (provided {payload_length} bytes).")
    elif payload_length > 0xffff:
        length_bits = 7 + 64
    elif payload_length > 125:
        length_bits = 7 + 16
    frame_size = int(1 + (1 + length_bits) / 8 + payload_length)
    frame = bytearray(frame_size)
    frame[0] = (fin << 7) + (rsv1 << 6) + (rsv2 << 5) + (rsv3 << 4) + opcode
    if length_bits == 7:
        frame[1] = payload_length
        frame[2:] = payload
    elif length_bits == 7 + 16:
        frame[1] = 126
        frame[2:2] = payload_length.to_bytes(2, byteorder="big")
        frame[4:] = payload
    else:
        frame[1] = 127
        frame[2:8] = payload_length.to_bytes(8, byteorder="big")
        frame[11:] = payload

    return frame

def _handle_control_frame(wfile: BufferedIOBase, frame: dict):
    if frame["opcode"] == OPCODE["close"]:
        code = frame["status_code"] if "status_code" in frame else None
        payload = code.to_bytes(2, byteorder="big") if code is not None else b""
        reason = frame["close_reason"] if "close_reason" in frame else "-"
        send_message(wfile, OPCODE["close"], payload)
        raise WebSocketCloseException(code, reason)
    elif frame["opcode"] == OPCODE["ping"]:
        payload = frame["payload"] if "payload" in frame else b""
        send_message(wfile, OPCODE["pong"], payload)

def _read_data_frame(rfile: BufferedIOBase):
    frame = {}
    #char = rfile.read(1)
    #if len(char) == 0:
    #    return
    net_bytes = ord(rfile.read(1))
    frame["FIN"] = net_bytes >> 7
    frame["RSV1"] = (net_bytes & 0x40) >> 6
    frame["RSV2"] = (net_bytes & 0x20) >> 5
    frame["RSV3"] = (net_bytes & 0x10) >> 4
    frame["opcode"] = net_bytes & 0x0f

    if frame["RSV1"] != 0 or frame["RSV2"] != 0 or frame["RSV3"] != 0:
        raise FrameError("Unsupported feature. RSV1, RSV2 or RSV3 has a non-zero value.", frame)

    if not frame["opcode"] in OPCODE.values():
        raise FrameError("Unsupported opcode value.", frame)

    if frame["FIN"] == 0 and frame["opcode"] != OPCODE["continueation"]:
        raise FrameError("FIN bit not set for a non-continueation frame.", frame)

    if frame["opcode"] in CONTROL_OPCODES and frame["FIN"] == 0:
        raise FrameError("FIN bit not set for a control frame.", frame)

    net_bytes = ord(rfile.read(1))
    mask_bit = net_bytes >> 7

    if mask_bit == 0:
        raise FrameError("Unmasked frame from client.", frame)

    length1 = net_bytes & 0x7f

    if frame["opcode"] in CONTROL_OPCODES and length1 > 125:
        raise FrameError("Control frame with invalid payload length.", frame)

    try:
        length = _read_payload_length(length1, rfile)
    except InvalidLengthError as error:
        raise FrameError(f"Invalid payload length of {error.length} bytes.", frame)

    masking_key = rfile.read(4)
    encoded_payload = rfile.read(length)
    frame["payload"] = _decode_payload(masking_key, encoded_payload)

    if frame["opcode"] == OPCODE["close"] and frame["payload"]:
        frame["status_code"] = int.from_bytes(frame["payload"][0:2], byteorder="big")
        if length > 2:
            # /!\ may raise UnicodeError /!\
            frame["close_reason"] = frame["payload"][2:].decode()

    return frame

def _read_payload_length(payload_length1: int, rfile: BufferedIOBase):
    final_length = payload_length1
    if payload_length1 == 126:
        final_length = int.from_bytes(rfile.read(2), byteorder="big")
    elif payload_length1 == 127:
        final_length = int.from_bytes(rfile.read(8), byteorder="big")
        if final_length >> 63 == 1:
            raise InvalidLengthError(final_length)
    return final_length

def close(wfile: BufferedIOBase, code=1000, reason=None):
    code_bytes = code.to_bytes(2, byteorder="big")
    payload = code_bytes if reason is None else code_bytes + reason.encode()
    frame = _encode_data_frame(1, OPCODE["close"], 0, 0, 0, payload)
    wfile.write(frame)

def decrypt_pgp_json(wfile: BufferedIOBase, gpg_context: GPGContext, message: WebSocketMessage, signature_key=None):
    if message.opcode != OPCODE["text"]:
        close(wfile, 1003, "Only text datatype is allowed.")
        raise WebSocketCloseException(1003, "Received no-text datatype.")
    try:
        plaintext, result, verify_result = gpg_context.decrypt(message.payload.encode())
    except GPGMEError as error:
        close(wfile, 1002, f"Failed to decrypt message.")
        raise WebSocketCloseException(1002, f"Failed to decrypt websocket message: {error}.")

    if len(verify_result.signatures) == 0:
        close(wfile, 1008, "No signature recognized.")
        raise WebSocketCloseException(1008, "Message with missing or unknown signature.")
    if signature_key is not None and signature_key.fpr != verify_result.signatures[0].fpr:
        close(wfile, 1008, "Message signature check failed.")
        raise WebSocketCloseException(1008, "Signing keys doesn't match.")

    signature_age = int(time()) - verify_result.signatures[0].timestamp
    if signature_age > PGP_JSON_SIGNATURE_VALIDITY:
        close(wfile, 1008, "Signature too old.")
        raise WebSocketCloseException(1008, f"Message with a {signature_age}s old signature.")

    try:
        json_ = json.loads(plaintext)
    except json.JSONDecodeError:
        close(wfile, 1002, "Invalid JSON data.")
        raise WebSocketCloseException(1002, "Invalid JSON data.")

    return json_, verify_result.signatures

def encrypt_pgp_json(obj: dict, recipient, gpg_context: GPGContext):
    json_ = json.dumps(obj).encode()
    ciphertext, result, sign_result = gpg_context.encrypt(json_,
        recipients=[recipient],
        sign=True,
        always_trust=True)
    return ciphertext

def handshake(request_handler: BaseHTTPRequestHandler, subprotocols=[]):
    request_handler.protocol_version = HTTP_VERSION
    _check_required_headers(request_handler)
    websocket_key = request_handler.headers.get("Sec-WebSocket-Key")
    digest = b64encode(sha1((websocket_key + _WEBSOCKET_GUID).encode()).digest())
    websocket_version = request_handler.headers.get("Sec-WebSocket-Version")
    if int(websocket_version) != PROTOCOL_VERSION:
        request_handler.send_response(400)
        request_handler.send_header("Sec-WebSocket-Version", PROTOCOL_VERSION)
        request_handler.end_headers()
        raise HandshakeError("Sec-WebSocket-Version", websocket_version, HandshakeError.reason["incompatible_version"])
    selected_subprotocol = None
    requested_subprotocols = request_handler.headers.get("Sec-WebSocket-Protocol")
    if requested_subprotocols:
        requested_subprotocols = requested_subprotocols.split(",")
        for proto in requested_subprotocols:
            for serv_proto in subprotocols:
                if proto == serv_proto:
                    selected_subprotocol = proto

    request_handler.send_response(101)
    request_handler.send_header("Upgrade", "websocket")
    request_handler.send_header("Connection", "Upgrade")
    request_handler.send_header("Sec-WebSocket-Accept", digest.decode())
    if requested_subprotocols and selected_subprotocol is not None:
        request_handler.send_header("Sec-WebSocket-Protocol", selected_subprotocol)
    request_handler.end_headers()

    return selected_subprotocol

def read_next_message(rfile: BufferedIOBase, wfile: BufferedIOBase):
    frame = _read_data_frame(rfile)
    message = WebSocketMessage(frame["opcode"], frame["payload"])
    if frame["FIN"] == 1:
        if frame["opcode"] in NONCONTROL_OPCODES:
            return message
        else:
            _handle_control_frame(wfile, frame)
            return read_next_message(rfile, wfile)
    else:
        return message + read_next_message(rfile)

def send_message(wfile: BufferedIOBase, payload: bytes, opcode=OPCODE["text"], rsv1=0, rsv2=0, rsv3=0):
    if len(payload) > 0x7fffffffffffffff:
        raise ValueError(f"Payload to big. Sending fragmented messages not implemented.")
    frame = _encode_data_frame(1, opcode, rsv1, rsv2, rsv3, payload)
    wfile.write(frame)
