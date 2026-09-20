#!/usr/bin/env bash
# 构建 vim CFI-bench 漏洞样本 TC-001（文件读取路径堆 UAF）
# 产物: build/vim-cfi-bench/out/vim-tc001
# 依赖: sources/vim(pinned commit), patches/vim/*.patch
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
COMMIT="4b3e2e3db0a4926622da59ef6301ff79c99fff30"
WORK="$REPO_ROOT/build/vim-cfi-bench"
OUT="$WORK/out"
PATCH_DIR="$REPO_ROOT/patches/vim"
SRC_VIM="$REPO_ROOT/sources/vim"

PATCHES=(0001-cfi-bench-tc001-fileio-heap-uaf.patch)
# 构建后源码中必须存在的代码标记
MARKERS=(CFIV_MAGIC)

# 缓解措施配置：保留 NX/RELRO，显式关闭 PIE/canary/fortify
CFLAGS_BENCH="-g -O1 -fno-stack-protector -fno-pie -U_FORTIFY_SOURCE"
LDFLAGS_BENCH="-no-pie"
# vim 把编译时间嵌入 version.c（__DATE__/__TIME__），gcc 13 支持
# SOURCE_DATE_EPOCH；取 pinned commit 的提交时间，与源码版本绑定
SOURCE_DATE_EPOCH="$(git -C "$SRC_VIM" show -s --format=%ct "$COMMIT")"
export SOURCE_DATE_EPOCH

die() { echo "ERROR: $*" >&2; exit 1; }

[ -d "$SRC_VIM/.git" ] || die "缺少 sources/vim"
ACTUAL_COMMIT="$(git -C "$SRC_VIM" rev-parse HEAD)"
[ "$ACTUAL_COMMIT" = "$COMMIT" ] || die "sources/vim 提交不符: $ACTUAL_COMMIT (期望 $COMMIT)"

cd "$REPO_ROOT"
SRC_DIR="$WORK/vim-src"
rm -rf "$SRC_DIR"
mkdir -p "$SRC_DIR" "$OUT"
git -C "$SRC_VIM" archive "$COMMIT" | tar -x -C "$SRC_DIR"

# 应用漏洞注入 patch（git apply 的路径相对仓库根解析，必须在仓库根执行）
for P in "${PATCHES[@]}"; do
  [ -f "$PATCH_DIR/$P" ] || die "缺少 $PATCH_DIR/$P"
  git -C "$REPO_ROOT" apply "$PATCH_DIR/$P" --directory="$(realpath --relative-to="$REPO_ROOT" "$SRC_DIR/src")"
done
for M in "${MARKERS[@]}"; do
  grep -q "$M" "$SRC_DIR/src/fileio.c" || die "应用后缺少代码标记 $M（patch 未生效？）"
done

# vim 构建：src/configure + make
cd "$SRC_DIR/src"
CFLAGS="$CFLAGS_BENCH" LDFLAGS="$LDFLAGS_BENCH" \
  ./configure --with-features=normal --disable-gui --without-x --disable-nls \
  > "$OUT/vim-configure.log" 2>&1
make -j"$(nproc)" > "$OUT/vim-make.log" 2>&1

cp vim "$OUT/vim-tc001"
chmod 755 "$OUT/vim-tc001"

# 记录构建信息与哈希（需同步到 labels/）
{
  echo "== build info: tc001 =="
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "vim_commit: $COMMIT"
  echo "patches: ${PATCHES[*]}"
  echo "cflags: $CFLAGS_BENCH"
  echo "ldflags: $LDFLAGS_BENCH"
  echo "mitigations: NX=on RELRO=on(canary=off PIE=off FORTIFY=off)"
  gcc --version | head -1
  ldd --version | head -1
  echo "-- file --"
  file "$OUT/vim-tc001"
  echo "-- sha256 --"
  sha256sum "$OUT/vim-tc001"
} > "$OUT/build-info-tc001.txt"
cat "$OUT/build-info-tc001.txt"
