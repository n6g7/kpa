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
HOSTILE_DB="$OUT/fixture-hostile.kdbx"
FIELDS_DB="$OUT/fixture-fields.kdbx"
SSH_DB="$OUT/fixture-ssh.kdbx"

if [ -f "$PASSWORD_DB" ] && [ -f "$KEYFILE_DB" ] && [ -f "$KEYFILE" ] && [ -f "$KDBX4_DB" ] && [ -f "$HOSTILE_DB" ] && [ -f "$FIELDS_DB" ] && [ -f "$SSH_DB" ]; then
    exit 0
fi

# Some fixture is missing, so rebuild all of them: keepassxc-cli's db-create
# refuses to overwrite an existing file, so a partial set can't be topped up.
rm -f "$PASSWORD_DB" "$KEYFILE_DB" "$KEYFILE" "$KDBX4_DB" "$HOSTILE_DB" "$FIELDS_DB" "$SSH_DB"

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

# Entry text that a terminal would act on: C1 controls (CSI, OSC, ST),
# DEL, and bidi overrides and isolates. XML 1.0 allows these, so they
# survive into the file. C0 controls don't, which is why none appear here.
python3 - "$HOSTILE_DB" <<'PYEOF'
import sys
from pykeepass import create_database

path = sys.argv[1]
kp = create_database(path, password="testpass123")
group = kp.add_group(kp.root_group, "Web\u009b0m")
kp.add_entry(
    group,
    "A\u009d0;PWNED\u009cB\u007fC‮DCBA‬⁧E⁩​  \u0085",
    "alice‮",
    "entrypass1",
    url="https://example.com",
)
kp.save()
PYEOF

# Custom (user-defined) fields, a custom field colliding
# case-insensitively with a built-in name, and a valid `otp` field — for
# `list`'s `fields` array and `copy`'s `totp`/custom-field/collision
# cases. The otpauth:// URL and secret are the `keepass` crate's own test
# vector (`db/otp.rs`'s `kdbx4_otp_tests::totp_default`), reused here
# rather than a fresh one, so the generated code is independently
# checkable.
python3 - "$FIELDS_DB" <<'PYEOF'
import sys
from pykeepass import create_database

path = sys.argv[1]
kp = create_database(path, password="testpass123")
group = kp.add_group(kp.root_group, "Web")
entry = kp.add_entry(group, "Example", "alice", "entrypass1", url="https://example.com")
entry.set_custom_property("api-key", "abc123")
# A custom field whose key collides, case-insensitively, with a built-in
# name — legal in KeePass (keys are exact-case), and distinct from the
# entry's real `Password` field above.
entry.set_custom_property("PASSWORD", "not-the-real-password")
entry.otp = "otpauth://totp/KeePassXC:none?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=KeePassXC"

no_otp = kp.add_entry(group, "NoOtp", "bob", "entrypass2")

bad_otp = kp.add_entry(group, "BadOtp", "carol", "entrypass3")
bad_otp.otp = "not an otpauth url"

# pykeepass appends each new <String> after the existing <AutoType>
# element, but `keepass`'s XML deserializer only collects a run of
# consecutive same-named elements into its `string_fields` list — a
# <String> that resumes after a different tag starts a second, separate
# run, which it rejects as a duplicate field. Moving <AutoType> back to
# the end of each entry keeps every <String> contiguous, matching what a
# KeePass client itself would write.
for e in (entry, no_otp, bad_otp):
    auto_type = e._element.find("AutoType")
    if auto_type is not None:
        e._element.remove(auto_type)
        e._element.append(auto_type)

kp.save()
PYEOF

# SSH agent fixtures (`src/ssh_agent/keys.rs`): an Ed25519 key, an ECDSA
# key, an RSA key, and two keys that must be skipped, a passphrase-protected
# one and a PEM-format one — one entry each, plus one more Ed25519 key
# reachable only through history and one only through the recycle bin, to
# check both are ignored. Generated fresh each run, like the rest of $OUT: none of this is
# committed.
SSH_KEYS_DIR=$(mktemp -d)
trap 'rm -rf "$SSH_KEYS_DIR"' EXIT

ssh-keygen -q -t ed25519 -N '' -C '' -f "$SSH_KEYS_DIR/ed25519"
# `ssh-key` 0.7.0-rc.12 refuses an OpenSSH P-256 private key whose scalar
# encodes in 31 bytes, which about 1 generated key in 512 does
# (https://github.com/RustCrypto/SSH/issues/620, fixed upstream but not
# released). Generate until the scalar is 32 or 33 bytes long.
attempts=0
while :; do
    rm -f "$SSH_KEYS_DIR/ecdsa" "$SSH_KEYS_DIR/ecdsa.pub"
    ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$SSH_KEYS_DIR/ecdsa"
    python3 - "$SSH_KEYS_DIR/ecdsa" <<'PYEOF' && break
import base64
import struct
import sys

# An unencrypted OpenSSH private key (PROTOCOL.key): the magic, cipher,
# KDF, KDF options, key count and public key, then the private section:
# two check ints, the key type, the curve, the public point and the
# private scalar.
with open(sys.argv[1]) as f:
    body = "".join(line for line in f.read().splitlines() if not line.startswith("-----"))
data = base64.b64decode(body)
pos = len(b"openssh-key-v1\0")


def string(buf, at):
    (n,) = struct.unpack(">I", buf[at : at + 4])
    return buf[at + 4 : at + 4 + n], at + 4 + n


for _ in range(3):  # cipher, KDF, KDF options
    _, pos = string(data, pos)
pos += 4  # key count
_, pos = string(data, pos)  # public key
private, _ = string(data, pos)
at = 8  # check ints
for _ in range(3):  # key type, curve, public point
    _, at = string(private, at)
scalar, _ = string(private, at)
sys.exit(0 if len(scalar) in (32, 33) else 1)
PYEOF
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 20 ]; then
        echo "fixture.sh: no usable ECDSA key after $attempts tries" >&2
        exit 1
    fi
done
ssh-keygen -q -t ed25519 -N 'correct-horse-battery-staple' -C '' -f "$SSH_KEYS_DIR/encrypted"
ssh-keygen -q -t rsa -b 3072 -N '' -C '' -f "$SSH_KEYS_DIR/rsa"
# `-m PEM`: the old PKCS#1 format, not the OpenSSH one `ssh::keys` reads.
ssh-keygen -q -t rsa -b 2048 -N '' -C '' -m PEM -f "$SSH_KEYS_DIR/pem"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$SSH_KEYS_DIR/ed25519-history"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$SSH_KEYS_DIR/ed25519-recycled"

python3 - "$SSH_DB" "$SSH_KEYS_DIR" <<'PYEOF'
import sys
from pykeepass import create_database

path, keys_dir = sys.argv[1], sys.argv[2]


def read(name):
    with open(f"{keys_dir}/{name}", "rb") as f:
        return f.read()


kp = create_database(path, password="testpass123")
group = kp.add_group(kp.root_group, "SSH")

entry = kp.add_entry(group, "Ed25519", "", "")
entry.add_attachment(kp.add_binary(read("ed25519")), "id_ed25519")

entry = kp.add_entry(group, "Ecdsa", "", "")
entry.add_attachment(kp.add_binary(read("ecdsa")), "id_ecdsa")

entry = kp.add_entry(group, "Encrypted", "", "")
entry.add_attachment(kp.add_binary(read("encrypted")), "id_encrypted")

entry = kp.add_entry(group, "Rsa", "", "")
entry.add_attachment(kp.add_binary(read("rsa")), "id_rsa")

entry = kp.add_entry(group, "Pem", "", "")
entry.add_attachment(kp.add_binary(read("pem")), "id_rsa_pem")

# Held only in history: the snapshot below captures the attachment, then
# it's removed from the live entry, leaving only a historical revision
# that holds it — `ssh::keys::scan` must not look there.
entry = kp.add_entry(group, "Historical", "", "")
entry.add_attachment(kp.add_binary(read("ed25519-history")), "id_ed25519_history")
entry.save_history()
attachment = next(a for a in entry.attachments if a.filename == "id_ed25519_history")
entry.delete_attachment(attachment)

# Held only in the recycle bin.
entry = kp.add_entry(group, "Recycled", "", "")
entry.add_attachment(kp.add_binary(read("ed25519-recycled")), "id_ed25519_recycled")
recycle_bin = kp._create_or_get_recyclebin_group()
kp.move_entry(entry, recycle_bin)

kp.save()
PYEOF
