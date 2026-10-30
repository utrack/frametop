#!/usr/bin/env bash
# Run on the Linux host. Uses distribution packages, with no downloaded build dependencies.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
protocols=${PLASMA_WAYLAND_PROTOCOLS_DIR:-/usr/share/plasma-wayland-protocols}
xml=$protocols/zkde-screencast-unstable-v1.xml
if [ ! -f "$xml" ]; then
    echo "Install plasma-wayland-protocols and wayland on the Linux host." >&2
    exit 1
fi
mkdir -p "$here/build"
wayland-scanner client-header "$xml" "$here/build/screencast-client.h"
wayland-scanner private-code "$xml" "$here/build/screencast-protocol.c"
cc -std=c11 -O2 -Wall -Wextra -Werror -I"$here/build" \
    "$here/ft-wincast.c" "$here/build/screencast-protocol.c" \
    $(pkg-config --cflags --libs wayland-client) -o "$here/build/ft-wincast"
echo "built $here/build/ft-wincast"
