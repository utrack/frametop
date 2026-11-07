#!/usr/bin/env python3
"""Run StreamWindow's real exit paths with a stuck decoder or audio worker.

Build in the dev container, as in just test-python. No GPU, host connection,
SteamVR or live audio: only the receiver function is copied into the harness.
"""
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path


HARNESS = r"""
#include <nlohmann/json.hpp>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <poll.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <unistd.h>
#include <vector>

std::string scenario;
volatile sig_atomic_t g_stop = 0;
constexpr unsigned kExitWatchdogS = 1;  // same path, shorter wait for this test
constexpr int kHiddenFps = 10;
constexpr unsigned DRM_FORMAT_ABGR8888 = 0;
void Stop(int) { g_stop = 1; }
int64_t MonoNs() { return 0; }
int64_t CpuNs() { return 0; }
int SSL_pending(void *) { return 0; }
void Hang() { for (;;) pause(); }

struct Client { struct { bool paired = true; } server; };
struct Viewer {
    int fd;
    bool Read(std::string *message, bool wait) const {
        *message = wait ? "modifiers" : "";
        return wait;  // ft-screens closes its end immediately after startup
    }
    bool Send(const std::string &message, const int * = nullptr, int = 0) const {
        std::puts(message.c_str());
        std::fflush(stdout);
        return true;
    }
};
struct Decoder {
    int fd = -1;
    bool toSteamVR = true;
    bool Open(const char *, int) { return true; }
    bool Events() { return false; }
    void Reclaim() {}
    bool Feed(const uint8_t *, size_t, uint64_t) { return true; }
    int Decoded(uint64_t *, bool *) { return -1; }
    void Requeue(int) {}
    void Close() {
        if (scenario.find("decoder") != std::string::npos) Hang();
    }
};
struct Converter {
    bool toSteamVR = true;
    std::vector<uint64_t> modifiers;
    struct { int fd = -1; uint64_t modifier = 0; unsigned offset = 0, stride = 0; } out[3];
    unsigned width = 1280, height = 720;
    int next = 0;
    double msSum = 0;
    bool Init() { return true; }
    bool Setup(const Decoder &) { return true; }
    void Reset() {}
    void ConvertInto(int, int) {}
};
struct WindowAudio {
    void Start(const Client &) {}
    ~WindowAudio() {
        if (scenario.find("audio") != std::string::npos) Hang();
    }
};
struct WindowPacket { char type; std::vector<uint8_t> data; };
struct WindowPeer {
    int fd = -1;
    void *tls = nullptr;
    bool readNeedsWrite = false;
    std::deque<std::string> outgoing;
    void Connect(const Client &) {
        if (scenario.rfind("error-", 0) == 0) throw std::runtime_error("host disconnected");
    }
    void Send(char, const std::string &) {}
    void Flush() {}
    void Read(std::deque<WindowPacket> &) {}
};
void WindowPanelSize(const Viewer &, const Client &, const std::string &, int, int) {}
"""

MAIN = r"""
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    scenario = argv[1];
    Client client;
    return StreamWindow(client, "test-window", -1, 1280, 720, 60, 15000);
}
"""


class WindowExitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix="window-exit-test-")
        cls.addClassCleanup(directory.cleanup)
        work = Path(directory.name)
        text = (Path(__file__).resolve().parents[1] / "window-stream.h").read_text()
        receiver = text[text.index("int StreamWindow("):]
        source = work / "receiver.cpp"
        source.write_text(HARNESS + receiver + MAIN)
        cls.program = work / "receiver"
        subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(cls.program)], check=True)

    def test_normal_shutdown_reports_lost_and_exits(self):
        result = subprocess.run([self.program, "normal"], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("state lost window disconnected", result.stdout)

    def test_cleanup_is_bounded_without_a_parent_to_kill_the_stream(self):
        for scenario in ("decoder", "audio", "error-decoder", "error-audio"):
            with self.subTest(scenario=scenario):
                result = subprocess.run([self.program, scenario], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, -signal.SIGALRM, result.stderr)
                self.assertIn("state lost ", result.stdout)


if __name__ == "__main__":
    unittest.main()
