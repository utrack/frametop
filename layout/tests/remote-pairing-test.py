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


if __name__ == "__main__":
    unittest.main()
