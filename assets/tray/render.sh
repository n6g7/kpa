#!/usr/bin/env bash
# Regenerates the PNGs in this directory from the SVGs beside it, at the
# sizes `src/tray.rs` embeds. Run from inside `nix develop` — `resvg` is a
# devShell-only tool (see flake.nix), not a Rust dependency — any time a
# .svg here changes:
#
#   assets/tray/render.sh
set -euo pipefail
cd "$(dirname "$0")"

for name in locked unlocked error; do
    for size in 22 32 44; do
        resvg --width "$size" --height "$size" "$name.svg" "$name-$size.png"
    done
done
