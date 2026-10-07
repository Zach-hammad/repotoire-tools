"""Focused, offline packaging contract tests."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


SCRIPT = Path(__file__).with_name("package-organized-chaos.py")
spec = importlib.util.spec_from_file_location("package_organized_chaos", SCRIPT)
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackageContracts(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="organized-chaos-packaging-test-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name) / "skill"
        self.root.mkdir()
        for name in package.FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(package.DEFAULT_ROOT / name, target)

    def test_manifest_zip_parity_and_reproducibility(self):
        first = package.artifacts(self.root)
        self.assertEqual(first, package.artifacts(self.root))
        manifest = json.loads(first["source-manifest.json"])
        self.assertEqual(list(manifest), list(package.FILES))
        with zipfile.ZipFile(io.BytesIO(first["organized-chaos-v2.zip"])) as archive:
            self.assertEqual(archive.namelist(), ["organized-chaos/" + name for name in package.FILES])
            for name in package.FILES:
                source = (self.root / name).read_bytes()
                self.assertEqual(archive.read("organized-chaos/" + name), source)
                self.assertEqual(manifest[name], hashlib.sha256(source).hexdigest())
                info = archive.getinfo("organized-chaos/" + name)
                self.assertEqual(info.date_time, (2026, 1, 1, 0, 0, 0))
                self.assertEqual(info.external_attr >> 16, 0o100644)

    def test_cli_works_from_another_directory_and_detects_stale_bytes(self):
        other = Path(self.folder.name) / "other"
        other.mkdir()
        base = [sys.executable, "-B", str(SCRIPT), "--root", str(self.root)]
        write = subprocess.run(base + ["--write"], cwd=other, capture_output=True, text=True)
        self.assertEqual(write.returncode, 0, write.stderr)
        check = subprocess.run(base + ["--check"], cwd=other, capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        (self.root / "source-manifest.json").write_text("{}\n")
        stale = subprocess.run(base + ["--check"], cwd=other, capture_output=True, text=True)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("Stale", stale.stderr)

    def test_broken_and_escaping_local_links_are_rejected(self):
        readme = self.root / "README.md"
        original = readme.read_text()
        for link in ("missing.md", "../outside.md", "SKILL.md#missing-heading"):
            with self.subTest(link=link):
                readme.write_text(original + f"\n[bad]({link})\n")
                with self.assertRaisesRegex(ValueError, "Broken package"):
                    package.artifacts(self.root)
        readme.write_text(original)

    def test_unexpected_file_and_symlink_are_rejected(self):
        extra = self.root / "private-inventory.json"
        extra.write_text("{}")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            package.artifacts(self.root)
        extra.unlink()
        link = self.root / "references" / "linked.md"
        link.symlink_to(self.root / "README.md")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            package.artifacts(self.root)

    def test_nonregular_entry_is_rejected_without_reading_it(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO fixtures are unavailable on this host")
        fifo = self.root / "references" / "private-pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "nonregular"):
            package.artifacts(self.root)


if __name__ == "__main__":
    unittest.main()
