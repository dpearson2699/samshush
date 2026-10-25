"""CLI boundaries: inspection must preserve inputs and reject unsafe outputs."""

import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]


class OfflineTests(unittest.TestCase):
    def run_tool(self, name, *args):
        return subprocess.run(
            [sys.executable, str(TOOLS / name), *map(str, args)],
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_all_entry_points_offer_help_without_inputs(self):
        for name in (
            "frame",
            "inspect_firmware",
            "verify_images",
            "check_msd_signatures",
            "inventory_components",
            "prepare_emudhra_removal",
            "build_payloads",
        ):
            with self.subTest(tool=name):
                result = self.run_tool(name + ".py", "--help")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout)

    def test_empty_verification_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            result = self.run_tool(
                "verify_images.py", "--decrypted", tmp, "--report", report
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(report.exists())

    def test_extraction_refuses_existing_directory_and_zip_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, keys, output = root / "input.zip", root / "keys", root / "out"
            keys.write_text("")
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape", "bad")
            output.mkdir()
            marker = output / "original"
            marker.write_text("keep")
            args = (
                "--archive",
                archive,
                "--keys",
                keys,
                "--output",
                output,
                "--metadata",
                root / "metadata",
            )
            result = self.run_tool("inspect_firmware.py", *args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Refusing existing", result.stderr)
            self.assertEqual(marker.read_text(), "keep")
            marker.unlink()
            output.rmdir()
            result = self.run_tool("inspect_firmware.py", *args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unsafe archive member", result.stderr)
            self.assertFalse((root / "escape").exists())

    def test_verification_does_not_carve_without_explicit_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            family = root / "decrypted" / "test"
            family.mkdir(parents=True)
            metadata = root / "metadata"
            metadata.mkdir()
            image = bytearray(4096)
            entries = bytearray(128)
            entries[0] = 1
            struct.pack_into("<QQ", entries, 32, 4, 4)
            entries[56:64] = "data".encode("utf-16le")
            header = bytearray(512)
            header[:8] = b"EFI PART"
            struct.pack_into("<I", header, 12, 92)
            struct.pack_into("<QIII", header, 72, 2, 1, 128, zlib.crc32(entries))
            struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
            image[512:1024], image[1024:1152] = header, entries
            (family / "platform.img").write_bytes(image)
            for i in range(8):
                (family / f"section{i}.img").write_bytes(b"test")
            expected = {p.name: p.read_bytes() for p in family.iterdir()}
            (metadata / "test-extraction.log").write_text(
                "\n".join(
                    f"Original size: {len(data)} Name: {name} CRC32: {zlib.crc32(data):08x}"
                    for name, data in expected.items()
                )
            )
            partitions, report = root / "partitions", root / "report.json"
            result = self.run_tool(
                "verify_images.py",
                "--decrypted",
                family.parent,
                "--metadata",
                metadata,
                "--partitions",
                partitions,
                "--report",
                report,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(partitions.exists())
            self.assertIsNone(
                json.loads(report.read_text())[0]["partitions"][0]["path"]
            )
            self.assertEqual(
                {p.name: p.read_bytes() for p in family.iterdir()}, expected
            )


if __name__ == "__main__":
    unittest.main()
