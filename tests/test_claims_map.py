"""Every claim in docs/CLAIMS.md must point at a test that exists (see that file)."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLAIMS = ROOT / "docs" / "CLAIMS.md"


def _parse():
    out = []
    for line in CLAIMS.read_text().splitlines():
        if line.startswith("- ") and " | " in line:
            claim, refs = line[2:].rsplit(" | ", 1)
            out.append((claim.strip(), [r.strip() for r in refs.split(",")]))
    return out


def _functions(path):
    return {n.name for n in ast.walk(ast.parse(path.read_text())) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_enough_claims():
    assert len(_parse()) >= 10


def test_every_claim_maps_to_existing_tests():
    missing = []
    for claim, refs in _parse():
        assert refs, claim
        for ref in refs:
            m = re.fullmatch(r"(tests/\w+\.py)::(\w+)", ref)
            assert m, f"bad reference {ref!r}: {claim}"
            f = ROOT / m.group(1)
            if not f.exists() or m.group(2) not in _functions(f):
                missing.append(f"{ref}  <- {claim}")
    assert not missing, "claims whose proving test is gone:\n" + "\n".join(missing)
