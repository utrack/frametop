#!/usr/bin/env python3
"""Offline checks: pointer mapping and bounded, fragmented network messages."""
import io
import math
import struct
import unittest

from protocol import absolute_position, packet, read_packet


class Fragments:
    def __init__(self, data, maximum=2):
        self.data = io.BytesIO(data)
        self.maximum = maximum

    def recv(self, length):
        return self.data.read(min(length, self.maximum))


class FramingTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        stream = Fragments(packet(b"C", b"move 24 32") + packet(b"C", b"blur"), 1)
        self.assertEqual(read_packet(stream), (b"C", b"move 24 32"))
        self.assertEqual(read_packet(stream), (b"C", b"blur"))

    def test_eof_mid_message(self):
        with self.assertRaises(EOFError):
            read_packet(Fragments(packet(b"C", b"key 42 1")[:-1]))

    def test_reject_size_before_reading_payload(self):
        with self.assertRaisesRegex(ValueError, "too large"):
            read_packet(Fragments(struct.pack("!cI", b"C", 0xffffffff)))

    def test_empty_payload(self):
        self.assertEqual(read_packet(Fragments(packet(b"C", b""))), (b"C", b""))


class PointerTests(unittest.TestCase):
    desktop = {"x": 0, "y": 0, "width": 3440, "height": 1440}
    window = {"x": 1720, "y": 20, "width": 1720, "height": 1420}

    def test_scaled_stream_maps_to_window_not_desktop(self):
        x, y = absolute_position(self.window, self.desktop, (860, 710), 430, 355)
        self.assertAlmostEqual(x / 65535 * 3440, 2580, delta=0.1)
        self.assertAlmostEqual(y / 65535 * 1440, 730, delta=0.1)

    def test_window_moves_after_connection(self):
        window = dict(self.window, x=0, width=1000)
        x, _ = absolute_position(window, self.desktop, (860, 710), 430, 0)
        self.assertAlmostEqual(x / 65535 * 3440, 500, delta=0.1)

    def test_negative_desktop_origin(self):
        desktop = {"x": -1920, "y": 0, "width": 3840, "height": 1080}
        window = {"x": -1920, "y": 0, "width": 1920, "height": 1080}
        x, y = absolute_position(window, desktop, (1920, 1080), 960, 540)
        self.assertAlmostEqual(x / 65535, 0.25, places=4)
        self.assertAlmostEqual(y / 65535, 0.5, places=4)

    def test_edge_does_not_click_beside_window(self):
        x, y = absolute_position(self.window, self.desktop, (860, 710), 10000, 10000)
        self.assertLess(x / 65535 * 3440, 3440)
        self.assertLess(y / 65535 * 1440, 1440)

    def test_off_desktop_input_is_refused(self):
        window = dict(self.window, x=3500)
        with self.assertRaisesRegex(ValueError, "outside"):
            absolute_position(window, self.desktop, (860, 710), 0, 0)

    def test_nonfinite_and_zero_geometry_are_refused(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value), self.assertRaises(ValueError):
                absolute_position(self.window, self.desktop, (860, 710), value, 0)
        with self.assertRaises(ValueError):
            absolute_position(dict(self.window, width=0), self.desktop, (860, 710), 0, 0)


if __name__ == "__main__":
    unittest.main()
