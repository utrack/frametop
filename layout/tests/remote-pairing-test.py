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

    def test_availability_probe_has_a_shorter_deadline(self):
        self.identity("saved-frame")
        with patch.object(ft_layout, "run_stream", return_value=(0, '{"windows":[]}', "")) as run:
            ft_layout.list_window_streams(self.host, timeout=4)
        self.assertGreater(run.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(run.call_args.kwargs["timeout"], 4)

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

    def test_short_polls_give_every_identity_a_full_attempt(self):
        for name in ("a-revoked", "b-revoked", "z-paired"):
            self.identity(name)
        now, cursor, attempts = [0.0], {}, []

        def probe(*args, timeout):
            attempts.append(args[-1])
            now[0] += min(timeout, 2.2)
            if timeout < 2.2:
                raise ft_layout.subprocess.TimeoutExpired(args, timeout)
            if args[-1] == "z-paired":
                return 0, '{"windows":[]}', ""
            return 1, "", "client is not paired"

        with patch.object(ft_layout.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(ft_layout, "run_stream", side_effect=probe):
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "did not answer in time"):
                    ft_layout.list_window_streams(self.host, "a-revoked", timeout=4, cursor=cursor)
                now[0] += 15
            self.assertEqual(ft_layout.list_window_streams(self.host, "a-revoked", timeout=4, cursor=cursor),
                             ("z-paired", []))
            self.assertEqual(attempts, ["a-revoked", "b-revoked", "b-revoked", "z-paired", "z-paired"])
            ft_layout.list_window_streams(self.host, "z-paired", timeout=4, cursor=cursor)
            self.assertEqual(attempts[-1], "z-paired")

    def test_a_client_that_times_out_on_a_full_poll_yields_to_the_next(self):
        self.identity("a-stalled")
        self.identity("b-paired")
        cursor = {}
        with patch.object(ft_layout, "run_stream", side_effect=[
                ft_layout.subprocess.TimeoutExpired("windows", 4), (0, '{"windows":[]}', "")]) as run:
            with self.assertRaisesRegex(RuntimeError, "did not answer in time"):
                ft_layout.list_window_streams(self.host, timeout=4, cursor=cursor)
            self.assertEqual(ft_layout.list_window_streams(self.host, timeout=4, cursor=cursor), ("b-paired", []))
        self.assertEqual([c.args[-1] for c in run.call_args_list], ["a-stalled", "b-paired"])


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
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        for name, filename in (("LAYOUT_PATH", "layout.json"), ("CONF_PATH", "frametop.conf")):
            setting = patch.object(ft_layout, name, str(Path(directory.name) / filename))
            setting.start()
            self.addCleanup(setting.stop)

    def resize(self, old_size, metres, new_size, concurrent=None):
        display = {"id": "editor", "app": "window:uuid", "client": "paired", "screen": 102,
                   "size": list(old_size), "metres": 1, "pos": [1, 2, 3], "pin": {"hand": "left"}}
        layout = {"hosts": [{"name": "hal2", "address": "hal2", "input": True, "displays": [display]}]}
        ft_layout.save_layout(layout)
        pose = "ok " + " ".join(["0"] * 12) + f" {metres} 0.8256 0 none"

        def ask(text):
            if text == "remotes":
                return f"ok 1 102:paired:live:{old_size[0]}x{old_size[1]}"
            if text == "get 102":
                if concurrent:
                    concurrent()
                return pose
            return "ok"

        sock = Mock()
        sock.ask.side_effect = ask
        with patch.object(ft_layout, "screens_socket", return_value=sock), \
                patch.object(ft_layout, "run_stream") as stream:
            ft_layout.remote_command(["window-size", "editor", *map(str, new_size)])
        stream.assert_not_called()
        display = ft_layout.load_layout()["hosts"][0]["displays"][0]
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

    def test_resize_preserves_concurrent_host_and_panel_changes(self):
        def change():
            layout = ft_layout.load_layout()
            host = layout["hosts"][0]
            host["input"] = False
            host["displays"][0]["off"] = True
            host["displays"].append({"id": "second", "app": "window:other", "size": [640, 480]})
            ft_layout.save_layout(layout)

        display, _ = self.resize((1720, 1420), 1.5, (3440, 1420), change)
        host = ft_layout.load_layout()["hosts"][0]
        self.assertIs(host["input"], False)
        self.assertIs(display["off"], True)
        self.assertEqual(host["displays"][1]["size"], [640, 480])

    def test_resize_does_not_restore_a_removed_or_replaced_panel(self):
        for replace in (False, True):
            with self.subTest(replace=replace):
                def remove():
                    layout = ft_layout.load_layout()
                    if replace:
                        layout["hosts"][0]["displays"][0]["app"] = "window:replacement"
                    else:
                        layout["hosts"][0]["displays"].clear()
                    ft_layout.save_layout(layout)

                with self.assertRaisesRegex(RuntimeError, "no longer configured"):
                    self.resize((1720, 1420), 1.5, (3440, 1420), remove)
                displays = ft_layout.load_layout()["hosts"][0]["displays"]
                if replace:
                    self.assertEqual(displays[0]["app"], "window:replacement")
                    self.assertEqual(displays[0]["size"], [1720, 1420])
                else:
                    self.assertEqual(displays, [])


if __name__ == "__main__":
    unittest.main()
