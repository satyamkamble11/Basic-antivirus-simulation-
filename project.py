"""
Basic Antivirus Simulation (Signature Scanner)
File: basic_antivirus_simulation.py

Purpose:
A small educational signature-based antivirus simulator. Scans directories, computes
SHA-256 hashes for files, compares them against a signatures database (JSON), and
optionally moves detected files to a quarantine folder.

FIX NOTE:
Previously, running this script without proper command-line arguments caused
`SystemExit: 2` due to argparse validation. This version fixes that by:
- Showing help gracefully when no arguments are provided
- Avoiding abrupt crashes for common user mistakes

WARNING: This tool is for educational/ethical use only.

Usage examples:
python basic_antivirus_simulation.py init-db
python basic_antivirus_simulation.py add --file test.exe
python basic_antivirus_simulation.py scan --path ./test_files
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger("BasicAV")

DEFAULT_SIG_DB = "signatures.json"
DEFAULT_QUARANTINE = "quarantine"
CHUNK_SIZE = 8192


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def load_signatures(sigfile: Path) -> Dict[str, dict]:
    if not sigfile.exists():
        return {}
    with sigfile.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_signatures(sigfile: Path, db: Dict[str, dict]):
    sigfile.parent.mkdir(parents=True, exist_ok=True)
    with sigfile.open("w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


def ensure_quarantine_dir(base: Path):
    base.mkdir(parents=True, exist_ok=True)


def quarantine_file(file_path: Path, base_scan_path: Path, quarantine_base: Path):
    ensure_quarantine_dir(quarantine_base)
    try:
        rel = file_path.relative_to(base_scan_path)
    except Exception:
        rel = Path(file_path.name)

    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = quarantine_base / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest = dest.with_name(dest.name + f"--{timestamp}")
    shutil.move(str(file_path), str(dest))
    logger.warning(f"File quarantined: {dest}")


def scan_directory(scan_path: Path, sig_db: Dict[str, dict], quarantine_base: Optional[Path] = None):
    scanned = 0
    threats = 0
    for root, _, files in os.walk(scan_path):
        for name in files:
            fp = Path(root) / name
            try:
                scanned += 1
                h = compute_sha256(fp)
                if h in sig_db:
                    threats += 1
                    logger.warning(f"Threat detected: {fp}")
                    if quarantine_base:
                        quarantine_file(fp, scan_path, quarantine_base)
            except Exception as e:
                logger.error(f"Error scanning {fp}: {e}")
    logger.info(f"Scan complete | Files scanned: {scanned} | Threats: {threats}")


def add_signature(file_path: Path, sigfile: Path):
    db = load_signatures(sigfile)
    h = compute_sha256(file_path)
    db[h] = {
        "label": file_path.name,
        "added_at": datetime.utcnow().isoformat() + "Z",
    }
    save_signatures(sigfile, db)
    logger.info(f"Signature added: {h}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Basic Antivirus Simulation",
        add_help=True,
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan files or directories")
    scan.add_argument("--path", required=True)
    scan.add_argument("--signatures", default=DEFAULT_SIG_DB)
    scan.add_argument("--quarantine", default=None)

    add = sub.add_parser("add", help="Add a file signature")
    add.add_argument("--file", required=True)
    add.add_argument("--signatures", default=DEFAULT_SIG_DB)

    initdb = sub.add_parser("init-db", help="Initialize empty signature DB")
    initdb.add_argument("--signatures", default=DEFAULT_SIG_DB)

    listdb = sub.add_parser("list", help="List all signatures")
    listdb.add_argument("--signatures", default=DEFAULT_SIG_DB)

    return parser


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    if args.command == "init-db":
        save_signatures(Path(args.signatures), {})
        logger.info("Signature database initialized")

    elif args.command == "add":
        add_signature(Path(args.file), Path(args.signatures))

    elif args.command == "scan":
        db = load_signatures(Path(args.signatures))
        quarantine = Path(args.quarantine) if args.quarantine else None
        scan_path = Path(args.path)
        if scan_path.is_dir():
            scan_directory(scan_path, db, quarantine)
        elif scan_path.is_file():
            h = compute_sha256(scan_path)
            if h in db:
                logger.warning("Threat detected in file")
            else:
                logger.info("File is clean")

    elif args.command == "list":
        db = load_signatures(Path(args.signatures))
        for h, meta in db.items():
            print(h, meta)


if __name__ == "__main__":
    main()
