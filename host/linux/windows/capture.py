"""A KWin window -> DMA-BUF -> VA-API HEVC pipeline, using packaged GStreamer."""
import argparse
import json
import os
from pathlib import Path
import queue
import select
import subprocess
import threading
import time

import gi
gi.require_version("Gst", "1.0")
from gi.repository import Gst

HERE = Path(__file__).resolve().parent
MAX_FRAME = 4 * 1024 * 1024  # matches the Frame decoder's bitstream buffer


class CapturePermission:
    """Use KWin's normal executable permission entry; remove our entry on exit."""
    def __init__(self):
        binary = (HERE / "build/ft-wincast").resolve(strict=True)
        applications = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "applications"
        applications.mkdir(parents=True, exist_ok=True)
        self.path = applications / f"org.frametop.WindowCapture.{os.getpid()}.desktop"
        executable = str(binary).replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")
        self.path.write_text(
            "[Desktop Entry]\nType=Application\nName=Frametop Window Capture\nNoDisplay=true\n"
            f'Exec="{executable}"\nX-KDE-Wayland-Interfaces=zkde_screencast_unstable_v1\n')
        time.sleep(3)  # KWin's desktop-file watcher must see it before the helper connects.

    def close(self):
        self.path.unlink(missing_ok=True)


class Capture:
    def __init__(self, window_id, width, height, fps, bitrate):
        if not 64 <= width <= 8192 or not 64 <= height <= 8192 or width % 2 or height % 2:
            raise ValueError("Stream dimensions must be even and between 64 and 8192")
        if not 1 <= fps <= 120 or not 100 <= bitrate <= 150000:
            raise ValueError("Invalid frame rate or bitrate")
        Gst.init(None)
        self.frames = queue.Queue(maxsize=2)
        self.stopped = threading.Event()
        self.pipeline = None
        self.bus = None
        self.sink = None
        self.sample_handler = None
        self.helper = subprocess.Popen([str(HERE / "build/ft-wincast"), window_id],
                                       stdout=subprocess.PIPE, text=True)
        try:
            if not select.select([self.helper.stdout], [], [], 10)[0]:
                raise RuntimeError("KWin window capture timed out")
            line = self.helper.stdout.readline()
            if not line:
                raise RuntimeError("KWin did not create the window stream")
            source = json.loads(line)
            selector = (f"target-object={source['serial']}" if source["serial"]
                        else f"path={source['node']}")
            # No raw pixels cross Python. Only the small encoded access units do.
            pipeline = (
                f"pipewiresrc {selector} do-timestamp=true keepalive-time=1000 ! "
                "video/x-raw(memory:DMABuf),format=DMA_DRM ! "
                f"videorate drop-only=true ! video/x-raw(memory:DMABuf),framerate={fps}/1 ! "
                "vapostproc add-borders=false ! "
                f"video/x-raw(memory:VAMemory),format=NV12,width={width},height={height},colorimetry=bt709 ! "
                f"vah265enc bitrate={bitrate} key-int-max={fps} b-frames=0 aud=true ! "
                "h265parse config-interval=-1 ! video/x-h265,stream-format=byte-stream,alignment=au ! "
                "appsink name=encoded emit-signals=true sync=false max-buffers=2 drop=false"
            )
            self.pipeline = Gst.parse_launch(pipeline)
            self.sink = self.pipeline.get_by_name("encoded")
            self.sample_handler = self.sink.connect("new-sample", self._sample)
            self.bus = self.pipeline.get_bus()
            if self.pipeline.set_state(Gst.State.PLAYING) == Gst.StateChangeReturn.FAILURE:
                raise RuntimeError("Cannot start the hardware window encoder")
        except BaseException:
            self.close()
            raise

    def _sample(self, sink):
        sample = sink.emit("pull-sample")
        if sample is None:
            return Gst.FlowReturn.EOS
        buffer = sample.get_buffer()
        if buffer.get_size() > MAX_FRAME:
            self.stopped.set()
            return Gst.FlowReturn.ERROR
        data = buffer.extract_dup(0, buffer.get_size())
        while not self.stopped.is_set():
            try:
                # Backpressure rather than dropping arbitrary HEVC reference pictures.
                self.frames.put(data, timeout=0.1)
                return Gst.FlowReturn.OK
            except queue.Full:
                pass
        return Gst.FlowReturn.FLUSHING

    def frame(self, timeout=0.01):
        message = self.bus.timed_pop_filtered(0, Gst.MessageType.ERROR | Gst.MessageType.EOS)
        if message:
            if message.type == Gst.MessageType.ERROR:
                error, detail = message.parse_error()
                raise RuntimeError(f"Window capture: {error.message}; {detail}")
            raise RuntimeError("Window capture ended")
        if self.helper.poll() is not None or self.stopped.is_set():
            raise RuntimeError("KWin closed the window stream")
        try:
            return self.frames.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self.stopped.set()
        if self.pipeline is not None:
            self.pipeline.set_state(Gst.State.NULL)
            # A GObject signal's bound method keeps this Capture alive through C,
            # outside Python's cycle collector. Drop it and the bus/pipeline refs
            # so old PipeWire loops and VA-API contexts really go away on resize.
            if self.sample_handler is not None:
                self.sink.disconnect(self.sample_handler)
                self.sample_handler = None
            if self.bus is not None:
                self.bus.set_flushing(True)
            self.sink = self.bus = self.pipeline = None
        if self.helper.poll() is None:
            self.helper.terminate()
            try:
                self.helper.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.helper.kill()
                self.helper.wait()
        if self.helper.stdout:
            self.helper.stdout.close()


def probe():
    parser = argparse.ArgumentParser(description="Probe hardware capture of one existing KWin window")
    parser.add_argument("window")
    parser.add_argument("--size", default="1720x1420")
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--output", help="Optional local HEVC recording for inspection")
    args = parser.parse_args()
    width, height = map(int, args.size.split("x"))
    permission = CapturePermission()
    capture = None
    output = None
    try:
        capture = Capture(args.window, width, height, 60, 15000)
        if args.output:
            output = open(args.output, "xb")
        start = time.monotonic()
        count = total = 0
        while time.monotonic() - start < args.seconds:
            data = capture.frame()
            if data:
                count += 1
                total += len(data)
                if output:
                    output.write(data)
        print(json.dumps({"frames": count, "bytes": total, "seconds": round(time.monotonic() - start, 2),
                          "capture": "KWin stream_window", "encoder": "vah265enc", "raw_buffers": "DMA-BUF"}))
        if not count:
            raise RuntimeError("No encoded frames arrived")
    finally:
        if output:
            output.close()
        if capture:
            capture.close()
        permission.close()


if __name__ == "__main__":
    probe()
