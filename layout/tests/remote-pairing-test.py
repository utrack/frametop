#!/usr/bin/env python3
"""Removing a window panel must not unpair the desktop sharing its certificate."""
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ft_layout


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
