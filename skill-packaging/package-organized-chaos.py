#!/usr/bin/env python3
"""Build, check, or test the allowlisted Organized Chaos package offline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

FILES = (
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "SKILL.md",
    "agents/openai.yaml",
    "examples/offline.md",
    "references/delivery.md",
    "references/model-capabilities.md",
    "references/onboarding.md",
    "references/routing.md",
    "references/worker-gate.md",
    "scripts/codex_connection.py",
    "scripts/grok_connection.py",
    "scripts/jev_ledger.py",
    "scripts/jev_lookup.py",
    "scripts/jev_route.py",
    "scripts/local_connection.py",
    "scripts/local_worker.py",
    "scripts/onboarding.py",
    "scripts/onboarding_http.py",
    "scripts/performance_record.py",
    "scripts/test_worker_contracts.py",
    "scripts/worker_gate.py",
)
ARTIFACTS = ("organized-chaos-v2.zip", "source-manifest.json")
DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "organized-chaos"
LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def _anchors(content):
    """Return local Markdown heading slugs, including repeated headings."""
    slugs = set()
    repeats = {}
    for heading in HEADING.findall(content):
        slug = re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
        count = repeats.get(slug, 0)
        repeats[slug] = count + 1
        slugs.add(f"{slug}-{count}" if count else slug)
    return slugs


def _check_links(root, sources):
    for name, data in sources.items():
        if not name.endswith(".md"):
            continue
        for link in LINK.findall(data.decode("utf-8")):
            if ":" in link or link.startswith("/"):
                continue
            path_part, _, anchor = link.partition("#")
            target = ((root / name).parent / path_part).resolve() if path_part else root / name
            if not target.is_relative_to(root) or not target.is_file():
                raise ValueError(f"Broken package reference in {name}: {link}")
            relative = target.relative_to(root).as_posix()
            if anchor and (relative not in sources or anchor not in _anchors(sources[relative].decode("utf-8"))):
                raise ValueError(f"Broken package anchor in {name}: {link}")


def artifacts(root):
    """Return deterministic manifest and ZIP bytes for exactly the allowlisted sources."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Package root is not a directory: {root}")
    expected = set(FILES) | set(ARTIFACTS)
    expected_dirs = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != "."}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"Symlink in package: {name}")
        if path.is_dir():
            if name not in expected_dirs:
                raise ValueError(f"Unexpected directory in package: {name}")
        elif name not in expected or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError(f"Unexpected or nonregular file in package: {name}")
    sources = {name: (root / name).read_bytes() for name in FILES}
    _check_links(root, sources)
    manifest = (json.dumps({name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}, indent=2) + "\n").encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sources.items():
            info = zipfile.ZipInfo("organized-chaos/" + name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return {"source-manifest.json": manifest, "organized-chaos-v2.zip": buffer.getvalue()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Package source directory (default: sibling organized-chaos directory)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--write", action="store_true", help="Regenerate the manifest and archive")
    action.add_argument("--check", action="store_true", help="Check exact manifest and archive bytes (default)")
    parser.add_argument("--test", action="store_true", help="Run offline behavioral tests from the extracted archive")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    for name, data in artifacts(root).items():
        if args.write:
            (root / name).write_bytes(data)
        elif not (root / name).is_file() or (root / name).read_bytes() != data:
            raise ValueError(f"Stale {name}; review sources and run with --write")
    print(f"Package verified: {len(FILES)} files; all relative references resolve", flush=True)
    if args.test:
        with tempfile.TemporaryDirectory(prefix="organized-chaos-package-") as folder:
            with zipfile.ZipFile(root / "organized-chaos-v2.zip") as archive:
                archive.extractall(folder)
            result = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover"],
                cwd=Path(folder) / "organized-chaos/scripts", check=False)
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
