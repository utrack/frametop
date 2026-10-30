# Direct KWin window streaming (experimental)

Capture an existing window from a Linux PC's normal KDE Wayland session and show it
as an independent Frametop panel. The application stays on the PC. This does not
create a virtual monitor, crop a monitor stream, or start another desktop session.

The prototype uses KWin's `stream_window` protocol, PipeWire DMA-BUF buffers,
GStreamer's VA-API HEVC encoder, TLS over TCP, and Frametop's existing Iris decoder,
GPU conversion and remote-panel machinery. It requires a working Sunshine pairing:
the window service accepts those paired client certificates and presents Sunshine's
server certificate, whose public key Frametop already pinned. Video and input use
TLS on port 14501; SSH is only a development/deployment convenience.

## Host setup

Use packages rather than building the dependencies. On Arch/CachyOS the relevant
packages are `wayland`, `plasma-wayland-protocols`, `gst-plugin-pipewire`,
`gst-plugin-va`, `gst-plugins-bad`, `python-gobject`, `python-dbus`, `python-evdev`,
`gcc` and `pkgconf`. Check that `gst-inspect-1.0 vah265enc` succeeds and the desktop
user can write `/dev/uinput`. The Frame already has the client libraries.

Copy this directory to the host and run from its existing Plasma session:

```bash
bash build.sh
python kwin.py
```

The build compiles only the small `ft-wincast` Wayland helper. The second command
prints existing windows and their KWin UUIDs. Pick a window to share.

Start the exporter with the same certificate, key and pairing state used by the
working Sunshine instance:

```bash
python ft_window_host.py \
  --sunshine-config /path/to/sunshine.conf \
  --listen HOST_LAN_IP \
  --window '{KWIN-WINDOW-UUID}'
```

The Sunshine configuration must explicitly name `cert`, `pkey` and `file_state`.
The exporter does not read the Web UI password. Repeat `--window` to allow more
windows; other windows are refused, even for paired clients. Up to four concurrent
streams are accepted. It reads the paired certificate list on each connection;
revocation prevents new connections, but does not terminate an existing stream.

The helper temporarily registers its executable with KWin's normal desktop-file
permission mechanism. It does not disable KWin's permission checks. On shutdown it
removes its permission entry, unloads its KWin script, ends the capture streams and
releases any keys or mouse buttons it holds. The original applications keep running.

## Frame setup

Build the updated `ft-stream` with `stream/build.sh`, using the repository's normal
container workflow. There is no new client-side library or background service.
For a source install, existing streams keep running their current binary; new
connections use the new build. Release installs use `scripts/fast-install`.

Find the existing Sunshine client name with:

```bash
layout/ft-layout remote list
```

Then add the window, using exactly the same host address and client name as that
pairing. For example:

```bash
layout/ft-layout remote add hal2 192.168.128.214 \
  'window:{KWIN-WINDOW-UUID}' \
  --client frametop-hal2-dp-6 \
  --size 1720x1420 --fps 60 --bitrate 15000 --label 'Editor window'
```

`window:` selects the new backend; normal `Desktop`, physical-display and virtual-
monitor streams still use Sunshine/Moonlight. The new panel has Frametop's normal
placement, size, curve, pins, keyboard and pointer controls. No VR service restart
is needed to add it.

This prototype can reuse a paired client identity. Removing a panel keeps that
pairing while another panel on the same host still uses it. Creating separate
pairings for each window is also possible through Sunshine before adding the panel.

## Current limits

- The stream follows the host window's logical size (rounded to even pixels, up to
  8192 per side). After a size or desktop change settles for 200 ms, it renews the
  KWin/PipeWire capture and hardware encoder. Frame opens a fresh decoder sequence
  and changes the panel's aspect ratio and physical width, preserving its position
  and current text density. There can be a short pause during this transition.
  Input stays connected and changes coordinate space when the new picture arrives.
- Pointer entry and typing activate/raise the original window on the host. This
  shares the host's cursor and keyboard focus, as desktop streaming does. It does
  not provide independent seats for simultaneous local and remote users.
- The first target is an ordinary, visible window on one physical monitor.
  Minimized windows, menus, transient dialogs, mixed-DPI/multiple-monitor input,
  and off-screen windows still need validation. An input point outside the physical
  desktop is refused.
- The KWin UUID lasts for the window's lifetime, not across application restarts.
  Closing the source leaves the panel disconnected; it does not select another
  window automatically.
- No audio or cross-machine clipboard is added by this backend. The desktop stream
  can continue supplying the host's audio.
- Capture is driven by damage, with a one-second keepalive. Out-of-view presentation
  is throttled on Frame, but visibility does not yet reduce host capture/encode work.
  TCP handles loss reliably; latency under congestion needs measurement.
- This is a manually selected prototype, without a window picker or persistent
  host installer. An exporter started from `/tmp` is not retained across reboots.

## Verification and update checks

`python test_windows.py` checks fragmented/bounded protocol messages and coordinate
mapping for scaling, moving windows, negative desktop origins, and off-screen input.
It uses only the standard library and runs in `just test-python`.

`python capture.py UUID --size WxH --seconds 5` probes the capture/encoder without
networking or input. `--output FILE.hevc` optionally records a local clip; it can
contain private application content and should stay out of version control.

For an end-to-end test:

1. Confirm that only the selected window appears, including when another window
   overlaps it on the host.
2. Check pointer position at all four corners, scrolling, and keyboard input in a
   scratch document. Move and resize the original window, then repeat.
3. Check menus and dialogs explicitly; do not infer their behavior from the parent.
4. Disconnect/reconnect while leaving the application open, and check that modifiers
   and mouse buttons are released.
5. Measure idle and animated-window CPU, bandwidth and latency. Check several
   simultaneous windows before drawing battery-life conclusions.

KWin's screencast and scripting interfaces are host dependencies. After a host
Plasma update, repeat the capture probe, window listing, focus and coordinate tests.
After a Frame kernel update, retest Iris HEVC decode and DMA-BUF conversion. Live
headset verification follows `.claude/skills/verify-frametop`; otherwise the wearer
must perform the visual/input checks.
