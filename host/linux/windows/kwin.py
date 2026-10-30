"""Metadata and activation in the existing KWin session. No nested compositor."""
import json
from pathlib import Path
import threading

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

SERVICE = "org.frametop.Windows"
PATH = "/org/frametop/Windows"
SCRIPT = "frametop-window-stream"
HERE = Path(__file__).resolve().parent


class KWin(dbus.service.Object):
    def __init__(self):
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        self.bus = dbus.SessionBus()
        name = dbus.service.BusName(SERVICE, self.bus, do_not_queue=True)
        super().__init__(name, PATH)
        self.owner = str(self.bus.get_name_owner("org.kde.KWin"))
        self.scripting = dbus.Interface(self.bus.get_object("org.kde.KWin", "/Scripting"),
                                       "org.kde.kwin.Scripting")
        self.windows = {}
        self.active = ""
        self.desktop = {}
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.pending = []
        self.waiter = None
        self.seq = 0
        self.commands = {}
        self.error = ""

    def start(self):
        if self.scripting.isScriptLoaded(SCRIPT):
            self.scripting.unloadScript(SCRIPT)
        sid = int(self.scripting.loadScript(str(HERE / "frametop-windows.js"), SCRIPT, signature="ss"))
        if sid < 0:
            raise RuntimeError("KWin refused the window metadata script")
        self.scripting.start()

    def close(self):
        if self.waiter:
            reply, source = self.waiter
            self.waiter = None
            GLib.source_remove(source)
            reply("")
        self.scripting.unloadScript(SCRIPT)
        self.remove_from_connection()

    @dbus.service.method(SERVICE, in_signature="s", out_signature="", sender_keyword="sender")
    def Event(self, text, sender=None):
        if sender != self.owner:
            raise dbus.exceptions.DBusException("Only KWin may report window metadata")
        message = json.loads(text)
        kind = message.get("type")
        with self.lock:
            if kind == "window":
                w = message["window"]
                self.windows[w["id"]] = w
                if w["active"]:
                    self.active = w["id"]
            elif kind == "removed":
                self.windows.pop(message["id"], None)
            elif kind == "active":
                self.active = message["id"]
            elif kind == "desktop":
                self.desktop = message
            elif kind == "ready":
                self.ready.set()
            elif kind == "error":
                self.error = message.get("error", "KWin script failed")
        if kind == "done":
            waiting = self.commands.pop(message["seq"], None)
            if waiting:
                result, done = waiting
                result.update(message)
                done.set()

    @dbus.service.method(SERVICE, in_signature="", out_signature="s",
                         async_callbacks=("reply", "error"), sender_keyword="sender")
    def NextCommand(self, reply, error, sender=None):
        if sender != self.owner:
            error(dbus.exceptions.DBusException("Only KWin may read window commands"))
            return
        if self.waiter:
            previous, source = self.waiter
            GLib.source_remove(source)
            previous("")

        def timeout():
            if self.waiter and self.waiter[0] is reply:
                self.waiter = None
                reply("")
            return False

        self.waiter = (reply, GLib.timeout_add_seconds(20, timeout))
        self._flush()

    @dbus.service.method(SERVICE, in_signature="", out_signature="s")
    def ListWindows(self):
        return json.dumps(self.snapshot())

    def _flush(self):
        if self.waiter and self.pending:
            reply, source = self.waiter
            self.waiter = None
            GLib.source_remove(source)
            reply(json.dumps(self.pending.pop(0)))

    def snapshot(self, window_id=None):
        with self.lock:
            if window_id is not None:
                window = self.windows.get(window_id)
                if window is None:
                    raise ValueError("The selected window has closed")
                return dict(window)
            return [dict(w) for w in self.windows.values() if w["normal"] or w["dialog"]]

    def activate(self, window_id):
        """Worker thread: wait for KWin's activation acknowledgement before input."""
        result, done = {}, threading.Event()

        def send():
            self.seq += 1
            seq = self.seq
            self.commands[seq] = (result, done)
            self.pending.append({"type": "activate", "id": window_id, "seq": seq})
            self._flush()

            def expire():
                if self.commands.pop(seq, None):
                    result["error"] = "KWin activation timed out"
                    done.set()
                return False

            GLib.timeout_add_seconds(3, expire)
            return False

        GLib.idle_add(send)
        if not done.wait(4):
            raise RuntimeError("KWin activation timed out")
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["window"]


def list_windows():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    if bus.name_has_owner(SERVICE):
        service = dbus.Interface(bus.get_object(SERVICE, PATH), SERVICE)
        print(json.dumps(json.loads(service.ListWindows()), indent=2))
        return
    kwin = KWin()
    loop = GLib.MainLoop()
    kwin.start()
    checks = 0

    def check():
        nonlocal checks
        checks += 1
        if kwin.ready.is_set() or checks >= 50:
            loop.quit()
            return False
        return True

    GLib.timeout_add(100, check)
    try:
        loop.run()
        if not kwin.ready.is_set():
            raise RuntimeError("KWin did not report its windows")
        print(json.dumps(kwin.snapshot(), indent=2))
    finally:
        kwin.close()


if __name__ == "__main__":
    list_windows()
