import runpy
import unittest
from pathlib import Path

tool = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "compare-patched-elf.py"))
differing_ranges = tool["differing_ranges"]


class DifferingRangesTests(unittest.TestCase):
    def test_identical_after_the_shift_has_no_differences(self):
        body = bytes(range(256)) * 8
        self.assertEqual(differing_ranges(body, b"\0" * 16 + body, 16), [])

    def test_reports_each_changed_range_in_upstream_offsets(self):
        body = bytearray(range(256)) * 8
        patched = bytearray(b"\0" * 16 + body)
        patched[16 + 5] ^= 1
        patched[16 + 100] ^= 1
        patched[16 + 101] ^= 1
        self.assertEqual(differing_ranges(bytes(body), bytes(patched), 16), [(5, 6), (100, 102)])

    def test_a_change_at_the_end_and_across_a_chunk_boundary(self):
        body = bytearray(3 << 20)
        patched = bytearray(b"\0" * 8 + body)
        patched[8 + (1 << 20) - 1] ^= 1
        patched[8 + (1 << 20)] ^= 1
        patched[8 + len(body) - 1] ^= 1
        self.assertEqual(differing_ranges(bytes(body), bytes(patched), 8),
                         [((1 << 20) - 1, (1 << 20) + 1), (len(body) - 1, len(body))])
