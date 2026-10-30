// Runs inside the host's existing KWin. Report metadata and activate a selected
// window; capture itself is stream_window(), never an output or a desktop crop.
const SERVICE = "org.frametop.Windows";
const PATH = "/org/frametop/Windows";
const IFACE = "org.frametop.Windows";

function event(value) {
    callDBus(SERVICE, PATH, IFACE, "Event", JSON.stringify(value));
}

function info(w) {
    const r = w.frameGeometry;
    return {
        id: String(w.internalId), title: String(w.caption), app: String(w.desktopFileName),
        x: r.x, y: r.y, width: r.width, height: r.height,
        normal: w.normalWindow, dialog: w.dialog, popup: w.popupWindow,
        parent: w.transientFor ? String(w.transientFor.internalId) : "",
        minimized: w.minimized, active: workspace.activeWindow === w
    };
}

function report(w) {
    if (!w.deleted) event({type: "window", window: info(w)});
}

function watch(w) {
    report(w);
    w.frameGeometryChanged.connect(() => report(w));
    w.captionChanged.connect(() => report(w));
    w.minimizedChanged.connect(() => report(w));
}

function desktop() {
    const outputs = workspace.screens.map(o => o.geometry);
    if (!outputs.length) return;
    const x = Math.min(...outputs.map(r => r.x));
    const y = Math.min(...outputs.map(r => r.y));
    event({type: "desktop", x: x, y: y,
        width: Math.max(...outputs.map(r => r.x + r.width)) - x,
        height: Math.max(...outputs.map(r => r.y + r.height)) - y});
}
workspace.screensChanged.connect(desktop);
desktop();
workspace.windowAdded.connect(watch);
workspace.windowRemoved.connect(w => event({type: "removed", id: String(w.internalId)}));
workspace.windowActivated.connect(w => {
    event({type: "active", id: w ? String(w.internalId) : ""});
    if (w) report(w);
});
workspace.windowList().forEach(watch);
event({type: "ready"});

function command(cmd) {
    if (!cmd || !cmd.type) return;
    const w = workspace.windowList().find(w => String(w.internalId) === cmd.id);
    if (!w || w.deleted) {
        event({type: "done", seq: cmd.seq, error: "Window closed"});
        return;
    }
    if (cmd.type === "activate") {
        w.minimized = false;
        workspace.activeWindow = w;
    } else {
        event({type: "done", seq: cmd.seq, error: "Unknown window command"});
        return;
    }
    event({type: "done", seq: cmd.seq, window: info(w)});
}

// As in frametop-float: a long poll, answered within KWin's 25-second timeout.
// Re-arm after a lost D-Bus reply, without allowing two polling loops.
let generation = 0;
const watchdog = new QTimer();
watchdog.singleShot = true;
watchdog.interval = 30000;
function poll() {
    const mine = ++generation;
    watchdog.start();
    callDBus(SERVICE, PATH, IFACE, "NextCommand", function(text) {
        if (text) {
            try { command(JSON.parse(text)); }
            catch (e) { event({type: "error", error: String(e)}); }
        }
        if (mine === generation) {
            watchdog.stop();
            poll();
        }
    });
}
watchdog.timeout.connect(poll);
poll();
