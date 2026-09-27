import hashlib
import hmac
import json
import socket
import ssl
import struct
import sys
from pathlib import Path


MAGIC = b"NJ"


def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def pack_frame(command: int, sequence: int, payload: bytes) -> bytes:
    frame = MAGIC + bytes((command, sequence)) + struct.pack("<H", len(payload)) + payload
    return frame + struct.pack("<H", crc16_ccitt(frame))


def unpack_frame(frame: bytes):
    if len(frame) < 8 or frame[:2] != MAGIC:
        raise ValueError("invalid frame header")
    command, sequence, length = frame[2], frame[3], struct.unpack_from("<H", frame, 4)[0]
    if len(frame) != length + 8:
        raise ValueError(f"invalid frame length: header={length}, actual={len(frame) - 8}")
    expected = struct.unpack_from("<H", frame, len(frame) - 2)[0]
    actual = crc16_ccitt(frame[:-2])
    if actual != expected:
        raise ValueError(f"invalid frame CRC: expected={expected:04x}, actual={actual:04x}")
    return command, sequence, frame[6:-2]


class MaintenanceClient:
    def __init__(self, credential: bytes, greeting: bytes):
        if len(credential) != 32:
            raise ValueError("maintenance credential must be 32 bytes")
        command, sequence, payload = unpack_frame(greeting)
        if (command, sequence, len(payload)) != (0x80, 0, 28):
            raise ValueError("unexpected greeting")
        self.session_id = payload[:4]
        self.nonce = payload[4:12]
        self.challenge = payload[12:28]
        self.credential = credential
        self.sequence = 1
        self.transcript = bytearray()
        self.open_generation = None
        self.current_cursor = None
        self.journal_cursor = None
        self.device_key = None

    def request(self, command: int, body: bytes = b"") -> bytes:
        message = self.session_id + self.challenge + bytes((command, self.sequence)) + body
        mac = hmac.new(self.credential, message, hashlib.sha256).digest()
        return pack_frame(command, self.sequence, body + mac)

    def accept(self, command: int, body: bytes, response: bytes):
        response_command, sequence, payload = unpack_frame(response)
        if response_command != (command | 0x80) or sequence != self.sequence or len(payload) < 16:
            raise ValueError("response does not match request")
        self.challenge = payload[:16]
        data = payload[16:]
        if data.startswith(b"ERR"):
            raise RuntimeError(data.decode("utf-8", "replace"))

        self.transcript.extend(bytes((command, self.sequence)))
        self.transcript.extend(body)
        self.transcript.extend(data)
        self.sequence = (self.sequence + 1) & 0xFF

        if command == 0x10:
            if len(data) != 24 or not data.startswith(b"OPEN"):
                raise ValueError("invalid OPEN response")
            self.open_generation = struct.unpack_from("<I", data, 4)[0]
        elif command == 0x21:
            if len(data) < 24 or not data.startswith(b"SCAN"):
                raise ValueError("invalid SCAN response")
            self.current_cursor = data[4:24]
        elif command == 0x22:
            if len(data) < 8 or not data.startswith(b"SUSPEND"):
                raise ValueError("invalid SUSPEND response")
            count = data[7]
            if len(data) != 8 + 21 * count:
                raise ValueError("invalid SUSPEND journal length")
            entries = [(data[8 + index * 21:28 + index * 21], data[28 + index * 21]) for index in range(count)]
            matches = [cursor for cursor, state in entries if state == 3]
            if len(matches) != 1:
                raise ValueError(f"expected one retained journal checkpoint, found {len(matches)}")
            self.journal_cursor = matches[0]
        elif command == 0x23:
            if len(data) != 50 or not data.startswith(b"EXPORT"):
                raise ValueError("invalid EXPORT response")
            self.device_key = data[18:50]
        return data

    def body_for(self, command: int) -> bytes:
        if command in (0x10, 0x21, 0x22):
            return b""
        if command == 0x20:
            if self.open_generation is None:
                raise ValueError("OPEN generation unavailable")
            return struct.pack("<II", self.open_generation, 1)
        if command == 0x23:
            if self.journal_cursor is None:
                raise ValueError("journal cursor unavailable")
            # A retained cursor preserves its historical object reference, but the
            # continuation envelope and embedded generation must be rebound to the
            # current live generation. This is the difference exposed by comparing
            # the failed journal capture with the ordinary current snapshot.
            rebound_cursor = self.journal_cursor[:8] + struct.pack("<I", self.open_generation) + self.journal_cursor[12:]
            return struct.pack("<II", self.open_generation, 1) + rebound_cursor
        if command == 0x24:
            if self.device_key is None:
                raise ValueError("device key unavailable")
            digest = hashlib.sha256(self.transcript).digest()
            finish_message = self.session_id + self.nonce + digest
            return hmac.new(self.device_key, finish_message, hashlib.sha256).digest()
        raise ValueError(f"unsupported command {command:02x}")


def solve_live():
    bootstrap = json.loads(Path("assets/tunnel-bootstrap.json").read_text())
    field = bootstrap["/api/fieldtoken"]["body"]
    state = bootstrap["/api/state"]["body"]
    receipt = bootstrap["/api/handover/insider"]["body"]["receipt"]
    host = state["connections"]["host"]
    port = state["connections"]["tunnel"]
    server_name = state["connections"]["server_name"]

    context = ssl.create_default_context()

    def read_network_frame(channel):
        header = channel.read(6)
        if len(header) != 6:
            raise RuntimeError("server closed during frame header")
        length = struct.unpack_from("<H", header, 4)[0]
        tail = channel.read(length + 2)
        if len(tail) != length + 2:
            raise RuntimeError("server closed during frame payload")
        return header + tail

    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as tls:
            channel = tls.makefile("rwb", buffering=0)
            channel.write(f"{field['player']}:{field['field_token']}\n".encode())
            greeting = read_network_frame(channel)
            client = MaintenanceClient(bytes.fromhex(receipt), greeting)
            result = None
            for command in (0x10, 0x20, 0x21, 0x22, 0x23, 0x24):
                body = client.body_for(command)
                request = client.request(command, body)
                channel.write(request)
                response = read_network_frame(channel)
                result = client.accept(command, body, response)
                print(f"command={command:02x} response={result.hex()}")
            print(result.decode("utf-8", "replace"))


def verify_sample(path: Path, credential_hex: str, journal_mode: bool):
    lines = [line.split(" ", 1) for line in path.read_text().splitlines() if line.startswith(("S ", "C "))]
    greeting = bytes.fromhex(lines[0][1])
    client = MaintenanceClient(bytes.fromhex(credential_hex), greeting)
    index = 1
    for command in (0x10, 0x20, 0x21, 0x22, 0x23):
        body = client.body_for(command)
        if command == 0x23 and not journal_mode:
            body = struct.pack("<II", client.open_generation, 1) + client.current_cursor
        if command == 0x23 and journal_mode:
            body = struct.pack("<II", client.open_generation, 1) + client.journal_cursor
        generated = client.request(command, body).hex()
        recorded = lines[index][1]
        if generated != recorded:
            raise AssertionError(f"command {command:02x} mismatch\ngenerated={generated}\nrecorded ={recorded}")
        response = bytes.fromhex(lines[index + 1][1])
        try:
            client.accept(command, body, response)
        except RuntimeError:
            if command != 0x23:
                raise
        index += 2
    print(f"verified {path} ({'journal failure' if journal_mode else 'current snapshot'})")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        sample = Path("assets/tunnel-sample.hex").read_text().split("ACQUISITION CURRENT SNAPSHOT")
        failed_path = Path("assets/tunnel-failed.hex")
        current_path = Path("assets/tunnel-current.hex")
        failed_path.write_text(sample[0])
        current_path.write_text("ACQUISITION CURRENT SNAPSHOT" + sample[1])
        credential = "94be60d5db400f3fcaa827b436951e77665b8c680256b00ae4ca556197f753ba"
        verify_sample(failed_path, credential, True)
        verify_sample(current_path, credential, False)
    else:
        solve_live()
