#!/usr/bin/env bash
# 构建 tcpdump CFI-bench 漏洞样本
# 用法: ./build.sh [tc001|tc002|all]   （默认 all）
#   tc001: 0001 patch（UDP 栈溢出）
#   tc002: 0001+0002 patch（栈溢出 + 堆 UAF，同一二进制包含两个漏洞）
# 产物: build/tcpdump-cfi-bench/out/tcpdump-<sample>
# 依赖: sources/tcpdump(pinned commit), sources/libpcap-1.10.5, patches/tcpdump/*.patch, flex, bison
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="199172821ffc1c9d7982a172d67dd8058591a57e"
LIBPCAP_VER="1.10.5"
LIBPCAP_SHA256="37ced90a19a302a7f32e458224a00c365c117905c2cd35ac544b6880a81488f0"
WORK="$REPO_ROOT/build/tcpdump-cfi-bench"
OUT="$WORK/out"
SRC_TCPDUMP="$REPO_ROOT/sources/tcpdump"
SRC_LIBPCAP="$REPO_ROOT/sources/libpcap-$LIBPCAP_VER"
PATCH_DIR="$REPO_ROOT/patches/tcpdump"

# 样本 -> patch 集合与构建后必须存在/必须不存在的代码标记
TC001_PATCHES=(0001-cfi-bench-tc001-udp-stack-overflow.patch)
TC001_MARKERS=(CFIB_MAGIC)
TC002_PATCHES=(0001-cfi-bench-tc001-udp-stack-overflow.patch
               0002-cfi-bench-tc002-udp-heap-uaf.patch)
TC002_MARKERS=(CFIB_MAGIC CFIB2_MAGIC)

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

SAMPLE="${1:-all}"
case "$SAMPLE" in
  tc001) SAMPLES=(tc001) ;;
  tc002) SAMPLES=(tc002) ;;
  all)   SAMPLES=(tc001 tc002) ;;
  *)     die "用法: $0 [tc001|tc002|all]" ;;
esac

mkdir -p "$OUT"

# libpcap 只构建一次（各样本共享，静态库）
if [ ! -f "$WORK/libpcap-$LIBPCAP_VER/libpcap.a" ]; then
  rm -rf "$WORK/libpcap-$LIBPCAP_VER"
  cp -a "$SRC_LIBPCAP" "$WORK/libpcap-$LIBPCAP_VER"
  cd "$WORK/libpcap-$LIBPCAP_VER"
  CFLAGS="$CFLAGS_BENCH" LDFLAGS="$LDFLAGS_BENCH" \
    ./configure --disable-shared --disable-dbus --disable-rdma \
                --without-libnl --without-libusb \
    > "$OUT/libpcap-configure.log" 2>&1
  make -j"$(nproc)" > "$OUT/libpcap-make.log" 2>&1
fi

for S in "${SAMPLES[@]}"; do
  # nameref 引用数组（${!VAR} 对数组只取首个元素，不能用）
  declare -n PATCHES="${S^^}_PATCHES"
  declare -n MARKERS="${S^^}_MARKERS"

  # 固定目录名 tcpdump-src：目录路径会进入二进制（影响 BuildID/哈希），
  # 因此多样本顺序构建复用同一目录名，保证同 patch 集产出同哈希 ELF。
  # 注意：每轮先回到仓库根——上一轮的 cwd 会被本轮 rm -rf 删除，
  # 异常 cwd 下 git apply 会静默跳过 patch（rc=0）。
  cd "$REPO_ROOT"
  SRC_DIR="$WORK/tcpdump-src"
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  git -C "$SRC_TCPDUMP" archive "$COMMIT" | tar -x -C "$SRC_DIR"

  # 应用漏洞注入 patch（git apply 的路径相对仓库根解析，必须在仓库根执行）
  for P in "${PATCHES[@]}"; do
    [ -f "$PATCH_DIR/$P" ] || die "缺少 $PATCH_DIR/$P"
    git -C "$REPO_ROOT" apply "$PATCH_DIR/$P" --directory="$(realpath --relative-to="$REPO_ROOT" "$SRC_DIR")"
  done
  for M in "${MARKERS[@]}"; do
    grep -q "$M" "$SRC_DIR/print-udp.c" || die "$S: 应用后缺少代码标记 $M（patch 未生效？）"
  done
  if [ "$S" = tc001 ] && grep -q "CFIB2_MAGIC" "$SRC_DIR/print-udp.c"; then
    die "tc001 源码不应包含 TC-002 代码"
  fi

  cd "$SRC_DIR"
  ./autogen.sh > "$OUT/tcpdump-$S-autogen.log" 2>&1
  CFLAGS="$CFLAGS_BENCH" LDFLAGS="$LDFLAGS_BENCH" \
    ./configure > "$OUT/tcpdump-$S-configure.log" 2>&1
  make -j"$(nproc)" > "$OUT/tcpdump-$S-make.log" 2>&1

  cp tcpdump "$OUT/tcpdump-$S"
  chmod 755 "$OUT/tcpdump-$S"

  # 记录构建信息与哈希（需同步到 labels/）
  {
    echo "== build info: $S =="
    echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "tcpdump_commit: $COMMIT"
    echo "patches: ${PATCHES[*]}"
    echo "libpcap: $LIBPCAP_VER sha256=$LIBPCAP_SHA256"
    echo "cflags: $CFLAGS_BENCH"
    echo "ldflags: $LDFLAGS_BENCH"
    echo "mitigations: NX=on RELRO=on(canary=off PIE=off FORTIFY=off)"
    gcc --version | head -1
    ldd --version | head -1
    echo "-- file --"
    file "$OUT/tcpdump-$S"
    echo "-- sha256 --"
    sha256sum "$OUT/tcpdump-$S"
  } > "$OUT/build-info-$S.txt"
  cat "$OUT/build-info-$S.txt"
done
