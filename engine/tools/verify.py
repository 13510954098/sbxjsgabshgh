#!/usr/bin/env python3
"""Offline provenance/integrity check. Updating extraction requires reviewing this lock."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
lock = json.loads((root/'upstream-lock.json').read_text())
assert lock['commit'] == 'cd0ad5ca8dc501fb06426d83870f49e7e3b0adef'
listed = set()
for entry in lock['files']:
    p = (root/entry['file']).resolve()
    assert p.is_relative_to(root/'src/main/kotlin/upstream')
    assert hashlib.sha256(p.read_bytes()).hexdigest() == entry['sha256'], entry['file']
    listed.add(p)
assert listed == set((root/'src/main/kotlin/upstream').glob('*.kt'))
assert (root/'LICENSE-AGPL-3.0.txt').is_file()
print(f"Verified {len(listed)} extracted files from {lock['commit']}")
