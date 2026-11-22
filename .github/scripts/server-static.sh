#!/bin/sh
# Builds slipstream-server static on Alpine
# (musl, OpenSSL linked in): one binary that runs on any Linux of its
# architecture, as raycontrol ships it. Run inside alpine:3.20 with the
# source at /src: server-static.sh BUILD_DIR
set -eu
build="${1:-build-static}"
apk add --no-cache build-base cmake ninja meson pkgconf git linux-headers \
	openssl-dev openssl-libs-static bash python3 openssl >/dev/null
git config --global --add safe.directory '*'
meson setup --buildtype=release --warnlevel=0 -Db_lto=false \
	-Ddefault_library=static -Dprefer_static=true -Dstatic_openssl=true \
	-Dc_link_args=-static -Dcpp_link_args='-static -static-libstdc++ -static-libgcc' \
	"$build" >/dev/null
ninja -C "$build" slipstream-server
for b in slipstream-server; do
	if ldd "$build/$b" 2>&1 | grep -q '=>'; then
		echo "$b is not static:"; ldd "$build/$b"; exit 1
	fi
done
strip "$build/slipstream-server"
"$build/slipstream-server" --help >/dev/null 2>&1 || true
