#!/usr/bin/env bash
# 构建 tcpdump CFI-bench 漏洞样本 TC-001（UDP 栈溢出）
# 产物: build/tcpdump-cfi-bench/out/tcpdump
# 依赖: sources/tcpdump(pinned commit), sources/libpcap-1.10.5, patches/tcpdump/*.patch, flex, bison
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="199172821ffc1c9d7982a172d67dd8058591a57e"
LIBPCAP_VER="1.10.5"
LIBPCAP_SHA256="37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0"
WORK="$REPO_ROOT/build/tcpdump-cfi-bench"
OUT="$WORK/out"
PATCH="$REPO_ROOT/patches/tcpdump/0001-cfi-bench-tc001-udp-stack-overflow.patch"
SRC_TCPDUMP="$REPO_ROOT/sources/tcpdump"
SRC_LIBPCAP="$REPO_ROOT/sources/libpcap-$LIBPCAP_VER"

# 缓解措施配置：保留 NX/RELRO，显式关闭 PIE/canary/fortify
CFLAGS_BENCH="-g -O1 -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE"
LDFLAGS_BENCH="-no-pie"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v flex  >/dev/null || die "缺少 flex（构建 libpcap 需要，apt install flex bison）"
command -v bison >/dev/null || die "缺少 bison（构建 libpcap 需要，apt install flex bison）"
[ -d "$SRC_TCPDUMP/.git" ] || die "缺少 sources/tcpdump"
ACTUAL_COMMIT="$(git -C "$SRC_TCPDUMP" rev-parse HEAD)"
[ "$ACTUAL_COMMIT" = "$COMMIT" ] || die "sources/tcpdump 提交不符: $ACTUAL_COMMIT (期望 $COMMIT)"
if [ ! -x "$SRC_LIBPCAP/configure" ]; then
  die "缺少 sources/libpcap-$LIBPCAP_VER：
  curl -o /tmp/libpcap.tar.gz https://www.tcpdump.org/release/libpcap-$LIBPCAP_VER.tar.gz
  sha256sum /tmp/libpcap.tar.gz  # 应为 $LIBPCAP_SHA256
  tar -xzf /tmp/libpcap.tar.gz -C sources/"
fi
[ -f "$PATCH" ] || die "缺少 $PATCH"

# 清理工作目录，导出纯净源码
rm -rf "$WORK"
mkdir -p "$WORK/tcpdump-src" "$OUT"
git -C "$SRC_TCPDUMP" archive "$COMMIT" | tar -x -C "$WORK/tcpdump-src"
cp -a "$SRC_LIBPCAP" "$WORK/libpcap-$LIBPCAP_VER"

# 应用漏洞注入 patch（git apply 的路径相对仓库根解析，必须在仓库根执行）
git apply "$PATCH" --directory="$(realpath --relative-to="$REPO_ROOT" "$WORK/tcpdump-src")"
grep -q "CFI-BENCHMARK-INJECT" "$WORK/tcpdump-src/print-udp.c" || die "patch 应用异常"

# 构建 libpcap（静态库）
cd "$WORK/libpcap-$LIBPCAP_VER"
CFLAGS="$CFLAGS_BENCH" LDFLAGS="$LDFLAGS_BENCH" \
  ./configure --disable-shared --disable-dbus --disable-rdma \
              --without-libnl --without-libusb \
  > "$OUT/libpcap-configure.log" 2>&1
make -j"$(nproc)" > "$OUT/libpcap-make.log" 2>&1

# 构建 tcpdump（configure 自动探测兄弟目录 libpcap-1.10.5）
cd "$WORK/tcpdump-src"
./autogen.sh > "$OUT/tcpdump-autogen.log" 2>&1
CFLAGS="$CFLAGS_BENCH" LDFLAGS="$LDFLAGS_BENCH" \
  ./configure > "$OUT/tcpdump-configure.log" 2>&1
make -j"$(nproc)" > "$OUT/tcpdump-make.log" 2>&1

cp tcpdump "$OUT/tcpdump"
chmod 755 "$OUT/tcpdump"

# 记录构建信息与哈希（需同步到 labels/）
{
  echo "== build info =="
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "tcpdump_commit: $COMMIT"
  echo "libpcap: $LIBPCAP_VER sha256=$LIBPCAP_SHA256"
  echo "cflags: $CFLAGS_BENCH"
  echo "ldflags: $LDFLAGS_BENCH"
  echo "mitigations: NX=on RELRO=on(canary=off PIE=off FORTIFY=off)"
  gcc --version | head -1
  ldd --version | head -1
  echo "-- file --"
  file "$OUT/tcpdump"
  echo "-- sha256 --"
  sha256sum "$OUT/tcpdump"
} > "$OUT/build-info.txt"
cat "$OUT/build-info.txt"
