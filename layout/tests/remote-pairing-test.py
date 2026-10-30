#!/usr/bin/env python3
"""Window panels reuse valid pairing, including identities with no remaining panel."""
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ft_layout


class WindowDiscoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.keys = Path(directory.name)
        setting = patch.object(ft_layout, "STREAM_KEYS", str(self.keys))
        setting.start()
        self.addCleanup(setting.stop)
        self.host = {"name": "hal2", "address": "hal2", "displays": []}

    def identity(self, name):
        path = self.keys / name
        path.mkdir()
        for filename in ("client.pem", "key.pem", "client.p12", "uniqueid.dat"):
            (path / filename).write_text("fixture")

    def test_saved_pairing_works_without_any_panels(self):
        self.identity("saved-frame")
        windows = [{"id": "window", "title": "Editor"}]
        with patch.object(ft_layout, "run_stream", return_value=(0, json.dumps({"windows": windows}), "")) as run:
            self.assertEqual(ft_layout.list_window_streams(self.host), ("saved-frame", windows))
        self.assertEqual(run.call_args.args, ("windows", "hal2", "--id", "saved-frame"))
        self.assertLessEqual(run.call_args.kwargs["timeout"], 20)

    def test_unpaired_identity_is_skipped(self):
        self.identity("a-unpaired")
        self.identity("b-paired")
        with patch.object(ft_layout, "run_stream", side_effect=[
                (1, "", "client is not paired"), (0, 'host log\n{"windows":[]}\n', "")]) as run:
            self.assertEqual(ft_layout.list_window_streams(self.host), ("b-paired", []))
        self.assertEqual([c.args[-1] for c in run.call_args_list], ["a-unpaired", "b-paired"])
        self.assertTrue(all(c.args[0] == "windows" for c in run.call_args_list))

    def test_verified_identity_is_tried_before_other_saved_clients(self):
        self.identity("a-old")
        self.identity("z-current")
        with patch.object(ft_layout, "run_stream", return_value=(0, '{"windows":[]}', "")) as run:
            self.assertEqual(ft_layout.list_window_streams(self.host, "z-current"), ("z-current", []))
        run.assert_called_once()
        self.assertEqual(run.call_args.args[-1], "z-current")

    def test_missing_or_incomplete_credentials_do_not_generate_new_identity(self):
        self.host["displays"] = [{"client": "missing"}]
        partial = self.keys / "partial"
        partial.mkdir()
        (partial / "client.pem").touch()
        with patch.object(ft_layout, "run_stream") as run, self.assertRaisesRegex(RuntimeError, "Pair a display"):
            ft_layout.list_window_streams(self.host)
        run.assert_not_called()

    def test_rejected_pairing_preserves_host_error(self):
        self.identity("revoked")
        with patch.object(ft_layout, "run_stream", return_value=(1, "", "client is not paired")), \
                self.assertRaisesRegex(RuntimeError, "client is not paired"):
            ft_layout.list_window_streams(self.host)


class RemovePairingTests(unittest.TestCase):
    def remove(self, shared, other_address="hal2"):
        window = {"id": "editor", "client": "paired-frame", "app": "window:uuid", "screen": 102}
        desktop = {"id": "desktop", "client": "paired-frame" if shared else "another-frame",
                   "app": "Desktop", "screen": 101}
        layout = {"hosts": [{"name": "hal2", "address": "hal2", "displays": [window]},
                            {"name": "other", "address": other_address, "displays": [desktop]}],
                  "profiles": {"work": {"remote": {"editor": {}, "desktop": {}}}}}
        sock, stream = Mock(), Mock(return_value=(0, "unpaired", ""))
        with patch.object(ft_layout, "load_layout", return_value=layout), \
                patch.object(ft_layout, "save_layout") as save, \
                patch.object(ft_layout, "screens_socket", return_value=sock), \
                patch.object(ft_layout, "run_stream", stream), \
                patch.object(ft_layout.time, "sleep"), patch.object(ft_layout, "log"):
            ft_layout.remote_command(["remove", "editor"])
        sock.ask.assert_called_once_with("remote 102 stop")
        save.assert_called_once_with(layout)
        self.assertEqual(layout["hosts"][0]["displays"], [])
        self.assertNotIn("editor", layout["profiles"]["work"]["remote"])
        self.assertIn("desktop", layout["profiles"]["work"]["remote"])
        return stream

    def test_shared_certificate_stays_paired(self):
        self.remove(shared=True).assert_not_called()

    def test_last_user_of_certificate_is_unpaired(self):
        self.remove(shared=False).assert_called_once_with("unpair", "hal2", "--id", "paired-frame", timeout=30)

    def test_same_client_name_on_another_host_does_not_prevent_unpair(self):
        self.remove(shared=True, other_address="elsewhere").assert_called_once()


class WindowResizeTests(unittest.TestCase):
    def resize(self, old_size, metres, new_size):
        display = {"id": "editor", "app": "window:uuid", "client": "paired", "screen": 102,
                   "size": list(old_size), "metres": 1, "pos": [1, 2, 3], "pin": {"hand": "left"}}
        layout = {"hosts": [{"address": "hal2", "displays": [display]}]}
        pose = "ok " + " ".join(["0"] * 12) + f" {metres} 0.8256 0 none"
        sock = Mock()
        sock.ask.side_effect = [f"ok 1 102:paired:live:{old_size[0]}x{old_size[1]}", pose, "ok"]
        with patch.object(ft_layout, "load_layout", return_value=layout), \
                patch.object(ft_layout, "save_layout") as save, \
                patch.object(ft_layout, "screens_socket", return_value=sock), \
                patch.object(ft_layout, "run_stream") as stream:
            ft_layout.remote_command(["window-size", "editor", *map(str, new_size)])
        save.assert_called_once_with(layout)
        stream.assert_not_called()
        self.assertEqual(display["pos"], [1, 2, 3])
        self.assertEqual(display["pin"], {"hand": "left"})
        self.assertEqual(display["size"], list(new_size))
        return display, sock

    def test_width_tracks_pixels_preserving_user_scale(self):
        display, sock = self.resize((1720, 1420), 1.5, (3440, 1420))
        self.assertEqual(display["metres"], 3)
        self.assertEqual(sock.ask.call_args.args, ("width 102 3.0000",))

    def test_reconnect_does_not_double_size_again(self):
        display, sock = self.resize((3440, 1420), 3, (3440, 1420))
        self.assertEqual(display["metres"], 3)
        self.assertEqual(sock.ask.call_count, 2)

    def test_height_only_keeps_physical_width(self):
        display, sock = self.resize((1720, 1420), 1.5, (1720, 1000))
        self.assertEqual(display["metres"], 1.5)
        self.assertEqual(sock.ask.call_count, 2)


if __name__ == "__main__":
    unittest.main()
