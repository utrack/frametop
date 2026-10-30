#!/usr/bin/env python3
"""Experimental existing-window exporter. See README.md for setup and limits.

TLS authenticates certificates already paired with Sunshine; the server presents
Sunshine's existing certificate, whose public key Frametop pinned during pairing.
Only explicitly selected window UUIDs are available. No SSH transport is used.
"""
import argparse
import json
import math
import select
import signal
import socket
import ssl
import threading
import time
from pathlib import Path

import evdev
from gi.repository import GLib

from capture import Capture, CapturePermission
from kwin import KWin
from protocol import ResizeTracker, absolute_position, packet, read_packet, window_size

E = evdev.ecodes


class WindowInput:
    """One connection owns its pressed keys/buttons, released on blur or disconnect."""
    def __init__(self, kwin, window_id, size):
        self.kwin, self.window_id, self.size = kwin, window_id, size
        self.buttons = {E.BTN_LEFT, E.BTN_RIGHT, E.BTN_MIDDLE, E.BTN_SIDE, E.BTN_EXTRA}
        self.keys = {v for k, v in vars(E).items()
                     if k.startswith("KEY_") and isinstance(v, int) and 0 < v < E.KEY_MAX}
        self.held_keys, self.held_buttons = set(), set()
        self.scroll_remainder = [0.0, 0.0]
        self.mouse = self.keyboard = None
        try:
            # The same absolute-mouse capabilities as Sunshine/libvirtualhid.
            self.mouse = evdev.UInput({
                E.EV_KEY: sorted(self.buttons),
                E.EV_ABS: [(E.ABS_X, evdev.AbsInfo(0, 0, 65535, 0, 0, 0)),
                           (E.ABS_Y, evdev.AbsInfo(0, 0, 65535, 0, 0, 0))],
                E.EV_REL: [E.REL_WHEEL, E.REL_HWHEEL, E.REL_WHEEL_HI_RES, E.REL_HWHEEL_HI_RES],
            }, name="Frametop window mouse", input_props=[E.INPUT_PROP_DIRECT])
            self.keyboard = evdev.UInput({E.EV_KEY: sorted(self.keys)}, name="Frametop window keyboard")
        except BaseException:
            self.close()
            raise
        time.sleep(0.2)  # Allow udev/libinput to discover the two devices.

    def focus(self):
        with self.kwin.lock:
            active = self.kwin.active
        window = self.kwin.snapshot(self.window_id)
        if active != self.window_id or not window["active"] or window["minimized"]:
            window = self.kwin.activate(self.window_id)
        if not window["active"]:
            raise RuntimeError("KWin could not activate the selected window")
        return window

    def handle(self, message):
        words = message.split()
        if not words:
            return
        action = words[0]
        if action == "blur":
            self.release()
        elif action == "move" and len(words) == 3:
            window = self.focus()
            with self.kwin.lock:
                desktop = dict(self.kwin.desktop)
            x, y = absolute_position(window, desktop, self.size, float(words[1]), float(words[2]))
            self.mouse.write(E.EV_ABS, E.ABS_X, x)
            self.mouse.write(E.EV_ABS, E.ABS_Y, y)
            self.mouse.syn()
        elif action in ("button", "key") and len(words) == 3:
            code, down = int(words[1]), int(words[2])
            if down not in (0, 1):
                raise ValueError("Invalid key state")
            valid = self.buttons if action == "button" else self.keys
            if code not in valid:
                raise ValueError("Invalid input code")
            held = self.held_buttons if action == "button" else self.held_keys
            device = self.mouse if action == "button" else self.keyboard
            if down:
                self.focus()
                held.add(code)
            elif code not in held:
                return
            else:
                held.remove(code)
            device.write(E.EV_KEY, code, down)
            device.syn()
        elif action == "scroll" and len(words) == 3:
            self.focus()
            for axis, value in enumerate((float(words[1]), -float(words[2]))):
                if not math.isfinite(value) or abs(value) > 100:
                    raise ValueError("Invalid scroll amount")
                high = E.REL_HWHEEL_HI_RES if axis == 0 else E.REL_WHEEL_HI_RES
                low = E.REL_HWHEEL if axis == 0 else E.REL_WHEEL
                self.mouse.write(E.EV_REL, high, round(value * 120))
                self.scroll_remainder[axis] += value
                whole = math.trunc(self.scroll_remainder[axis])
                if whole:
                    self.mouse.write(E.EV_REL, low, whole)
                    self.scroll_remainder[axis] -= whole
            self.mouse.syn()
        else:
            raise ValueError("Unknown window input command")

    def release(self):
        for device, held in ((self.keyboard, self.held_keys), (self.mouse, self.held_buttons)):
            if device:
                for code in held:
                    device.write(E.EV_KEY, code, 0)
                if held:
                    device.syn()
            held.clear()

    def close(self):
        try:
            self.release()
        finally:
            if self.mouse:
                self.mouse.close()
            if self.keyboard:
                self.keyboard.close()


def sunshine_paths(config):
    values = {}
    for line in config.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.lstrip().startswith("#"):
            values[key.strip()] = value.strip()
    required = ("cert", "pkey", "file_state")
    if any(not values.get(key) for key in required):
        raise ValueError("Set cert, pkey and file_state explicitly in the Sunshine configuration")
    return {key: Path(values[key]).expanduser() for key in required}


def tls_context(paths):
    state = json.loads(paths["file_state"].read_text())
    certificates = [device["cert"] for device in state["root"]["named_devices"]
                    if str(device.get("enabled", "true")).lower() in ("true", "1")]
    if not certificates:
        raise ValueError("Pair a Frametop client with Sunshine first")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(paths["cert"], paths["pkey"])
    context.load_verify_locations(cadata="\n".join(certificates))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class Server:
    def __init__(self, kwin, args):
        self.kwin, self.args = kwin, args
        self.paths = sunshine_paths(Path(args.sunshine_config))
        tls_context(self.paths)  # Check credentials before opening a listener.
        self.stop = threading.Event()
        self.capacity = threading.BoundedSemaphore(4)
        self.connections, self.workers = set(), []
        self.lock = threading.Lock()
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((args.listen, args.port))
        self.listener.listen(4)
        self.listener.settimeout(1)

    def run(self):
        print(f"Window exporter listening on {self.args.listen}:{self.args.port}", flush=True)
        while not self.stop.is_set():
            try:
                raw, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.capacity.acquire(blocking=False):
                raw.close()
                continue
            worker = threading.Thread(target=self.connection, args=(raw, peer), daemon=True)
            self.workers = [w for w in self.workers if w.is_alive()]
            self.workers.append(worker)
            worker.start()

    def connection(self, raw, peer):
        capture = inputs = sock = None
        try:
            raw.settimeout(5)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # Re-read Sunshine's paired devices for each connection, including revocations.
            sock = tls_context(self.paths).wrap_socket(raw, server_side=True)
            with self.lock:
                self.connections.add(sock)
            kind, payload = read_packet(sock)
            if kind != b"J":
                raise ValueError("Expected stream request")
            request = json.loads(payload)
            if not isinstance(request, dict):
                raise ValueError("Expected a JSON stream request")
            if request.get("version") != 1:
                raise ValueError("Unsupported window protocol version")
            window_id = request["window"]
            if window_id not in self.args.window:
                raise ValueError("This window has not been selected for sharing")
            window = self.kwin.snapshot(window_id)
            follow = request.get("follow_window") is True
            input_size = (int(request["width"]), int(request["height"]))
            size = window_size(window) if follow else input_size
            resize = ResizeTracker(window)
            capture = Capture(window_id, *size, int(request["fps"]), int(request["bitrate"]))
            sock.settimeout(2)
            sock.sendall(packet(b"J", json.dumps({"version": 1, "codec": "hevc", "window": window,
                                                "width": size[0], "height": size[1]}).encode()))
            print(f"Streaming window {window_id} to {peer[0]} at {size[0]}x{size[1]}", flush=True)
            start, count, total = time.monotonic(), 0, 0
            while not self.stop.is_set():
                if sock.pending() or select.select([sock], [], [], 0)[0]:
                    kind, payload = read_packet(sock)
                    if kind != b"C":
                        raise ValueError("Expected window input")
                    message = payload.decode("utf-8")
                    if message == "quit":
                        break
                    if message.startswith("attention "):
                        continue  # v1: damage driven, but visibility does not yet reduce host fps.
                    if message.startswith("size ") and follow:
                        acknowledged = tuple(map(int, message.split()[1:]))
                        if acknowledged == size:
                            input_size = size
                            if inputs:
                                inputs.size = size
                        continue
                    if message == "blur" and inputs is None:
                        continue
                    if inputs is None:
                        inputs = WindowInput(self.kwin, window_id, input_size)
                    inputs.handle(message)
                window = self.kwin.snapshot(window_id)
                if follow and resize.changed(window, time.monotonic()):
                    # A new PipeWire stream also recovers a source whose buffers/timestamps
                    # stopped updating when KWin moved it between virtual desktops.
                    capture.close()
                    capture = None
                    size = window_size(window)
                    capture = Capture(window_id, *size, int(request["fps"]), int(request["bitrate"]))
                    sock.sendall(packet(b"J", json.dumps({"version": 1, "codec": "hevc", "window": window,
                                                        "width": size[0], "height": size[1]}).encode()))
                    print(f"Window capture renewed at {size[0]}x{size[1]}", flush=True)
                frame = capture.frame()
                if frame is not None:
                    sock.sendall(packet(b"V", frame))
                    count += 1
                    total += len(frame)
                now = time.monotonic()
                if now - start >= 10:
                    print(f"{window_id}: {count / (now - start):.1f} fps, "
                          f"{total * 8 / (now - start) / 1e6:.2f} Mbit/s", flush=True)
                    start, count, total = now, 0, 0
        except (OSError, ValueError, KeyError, RuntimeError, EOFError, GLib.Error) as error:
            print(f"Window connection {peer[0]}: {error}", flush=True)
            if sock:
                try:
                    sock.sendall(packet(b"J", json.dumps({"error": str(error)}).encode()))
                except OSError:
                    pass
        finally:
            # Release input first, even if stopping the media pipeline takes time.
            for resource in (inputs, capture):
                if resource:
                    try:
                        resource.close()
                    except Exception as error:
                        print(f"Window cleanup: {error}", flush=True)
            if sock:
                with self.lock:
                    self.connections.discard(sock)
                sock.close()
            raw.close()
            self.capacity.release()

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            for sock in self.connections:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        for worker in self.workers:
            worker.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sunshine-config", required=True)
    parser.add_argument("--window", action="append", required=True, help="KWin UUID; repeat to share more windows")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=14501)
    args = parser.parse_args()
    permission = CapturePermission()
    kwin = server = None
    loop = GLib.MainLoop()
    try:
        kwin = KWin()
        kwin.start()
        server = Server(kwin, args)
        threading.Thread(target=server.run, daemon=True).start()
        for sig in (signal.SIGINT, signal.SIGTERM):
            GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, sig, lambda: (loop.quit(), False)[1])
        loop.run()
    finally:
        if server:
            server.close()
        if kwin:
            kwin.close()
        permission.close()


if __name__ == "__main__":
    main()
