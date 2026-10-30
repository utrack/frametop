"""Small, dependency-free parts of the experimental window protocol."""
import math
import struct

HEADER = struct.Struct("!cI")
MAX_CONTROL = 4096


def packet(kind, payload):
    return HEADER.pack(kind, len(payload)) + payload


def read_packet(sock):
    def exact(size):
        result = bytearray()
        while len(result) < size:
            part = sock.recv(size - len(result))
            if not part:
                raise EOFError("Client disconnected")
            result.extend(part)
        return bytes(result)

    kind, size = HEADER.unpack(exact(HEADER.size))
    if size > MAX_CONTROL:
        raise ValueError("Control message too large")
    return kind, exact(size)


def absolute_position(window, desktop, video_size, x, y):
    if not all(math.isfinite(v) for v in (x, y)):
        raise ValueError("Non-finite pointer coordinate")
    width, height = video_size
    if min(width, height, window["width"], window["height"], desktop["width"], desktop["height"]) <= 0:
        raise ValueError("Invalid coordinate space")
    px = window["x"] + min(max(x / width, 0), 1 - 1 / window["width"]) * window["width"]
    py = window["y"] + min(max(y / height, 0), 1 - 1 / window["height"]) * window["height"]
    # Refuse coordinates outside the actual desktop rather than clicking an edge.
    if not (desktop["x"] <= px < desktop["x"] + desktop["width"] and
            desktop["y"] <= py < desktop["y"] + desktop["height"]):
        raise ValueError("The selected part of the window is outside the desktop")
    return (round((px - desktop["x"]) / desktop["width"] * 65535),
            round((py - desktop["y"]) / desktop["height"] * 65535))
