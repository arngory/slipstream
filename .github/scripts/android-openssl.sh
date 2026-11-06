#!/usr/bin/env bash
# OpenSSL for one Android ABI, static libraries and headers only: android-openssl.sh <ndk> <abi> <prefix>
set -euo pipefail
ndk=$1 abi=$2 prefix=$3
api=23
version=3.5.9
sha256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
case "$abi" in
  arm64-v8a) target=android-arm64 ;;
  armeabi-v7a) target=android-arm ;;
  x86) target=android-x86 ;;
  x86_64) target=android-x86_64 ;;
  *) echo "unknown ABI $abi" >&2; exit 1 ;;
esac
work=$(mktemp -d)
curl -fsSL --retry 3 -o "$work/openssl.tar.gz" \
  "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz"
echo "$sha256  $work/openssl.tar.gz" | sha256sum -c -
tar -xzf "$work/openssl.tar.gz" -C "$work"
cd "$work/openssl-$version"
export ANDROID_NDK_ROOT=$ndk
export PATH=$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
./Configure "$target" -D__ANDROID_API__=$api no-shared no-tests no-engine --prefix="$prefix" --libdir=lib
make -j"$(nproc)" build_libs > /dev/null
make install_dev > /dev/null
ls -l "$prefix/lib"
