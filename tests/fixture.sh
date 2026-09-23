#!/usr/bin/env sh
# Builds throwaway .kdbx fixtures for the test suite using keepassxc-cli
# (expected on PATH — not a Cargo dependency, see docs/plan.md's "Test
# fixtures" section: "every step below tests against those, never your
# real vault").
#
# Idempotent-ish: if $OUT already has the fixtures, does nothing, so
# `cargo test` re-runs stay fast. Delete $OUT (or just `/tests/fixtures`)
# to force a rebuild after changing this script.
set -eu

OUT="${1:-$(dirname "$0")/fixtures}"
mkdir -p "$OUT"

PASSWORD_DB="$OUT/fixture.kdbx"
KEYFILE_DB="$OUT/fixture-kf.kdbx"
KEYFILE="$OUT/fixture-kf.keyx"
KDBX4_DB="$OUT/fixture-kdbx4.kdbx"

if [ -f "$PASSWORD_DB" ] && [ -f "$KEYFILE_DB" ] && [ -f "$KEYFILE" ] && [ -f "$KDBX4_DB" ]; then
    exit 0
fi

# Password-only db with one group and one entry. The exact incantations
# below are verbatim from docs/plan.md step 1 — keepassxc-cli's interactive
# prompts are fed over stdin since there's no non-interactive password flag.
#
# Note this is a KDBX3 database, not KDBX4: keepassxc-cli 2.7.12's
# `db-create` has no flag to choose the format (verified against its
# `--help`), and defaults to AES-KDF, which implies KDBX3. See
# `fixture-kdbx4.kdbx` below for the KDBX4 case.
printf 'testpass123\ntestpass123\n' | keepassxc-cli db-create -p -q "$PASSWORD_DB"
printf 'testpass123\n' | keepassxc-cli mkdir -q "$PASSWORD_DB" Web
printf 'testpass123\nentrypass1\n' |
    keepassxc-cli add -p -u alice --url https://example.com "$PASSWORD_DB" Web/Example

# Keyfile-only db (no password), for the keyfile test case.
keepassxc-cli db-create -q --set-key-file "$KEYFILE" "$KEYFILE_DB" </dev/null

# A genuine KDBX4 database (pykeepass writes KDBX4 unconditionally, unlike
# keepassxc-cli here), with the same shape as the password-only fixture
# above, so vault.rs is exercised against both formats `keepass` claims to
# support rather than just the one keepassxc-cli happens to default to.
python3 - "$KDBX4_DB" <<'PYEOF'
import sys
from pykeepass import create_database

path = sys.argv[1]
kp = create_database(path, password="testpass123")
group = kp.add_group(kp.root_group, "Web")
kp.add_entry(group, "Example", "alice", "entrypass1", url="https://example.com")
kp.save()
PYEOF
