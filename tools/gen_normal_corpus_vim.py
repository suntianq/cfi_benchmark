#!/usr/bin/env python3
"""生成 vim 样本 TC-001 的正常输入语料（纯标准库，确定性）。

用于采集侧采集正常基线 trace：多样文本文件（不同行数/行长/内容形态），
不含触发 magic "CFIVIMBEN"。

用法:
  ./gen_normal_corpus_vim.py --out ../../build/normal-corpus/vim-tc001 \
                             --files 20 --seed 42
"""
import argparse
import hashlib
import json
import random
import string
import sys
from pathlib import Path

MAGIC = b"CFIVIMBEN"  # 触发门控，语料中必须避免


def make_text(rng: random.Random) -> bytes:
    lines = rng.randint(5, 200)
    style = rng.choice(["text", "code", "binary-ish", "mixed"])
    out = []
    for i in range(lines):
        if style == "binary-ish":
            out.append(bytes(rng.randrange(0x20, 0x7f) for _ in range(rng.randint(8, 96))))
        elif style == "code":
            n = rng.randint(4, 24)
            words = " ".join(
                "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(2, 10)))
                for _ in range(n))
            out.append(f"    {words} = {rng.randint(0, 9999)};".encode())
        elif style == "mixed":
            out.append(f"line {i}: {rng.getrandbits(64):016x} ".encode()
                       + bytes(rng.randrange(0x20, 0x7f) for _ in range(rng.randint(0, 40))))
        else:
            n = rng.randint(10, 80)
            out.append("".join(rng.choice(string.printable[:94]) for _ in range(n)).encode())
    data = b"\n".join(out) + b"\n"
    # 双保险：语料绝不包含触发前缀
    while data[:9] == MAGIC:
        data = b"\n" + data
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True)
    ap.add_argument("--files", type=int, default=20)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    for fi in range(args.files):
        rng = random.Random(args.seed * 1000 + fi)
        data = make_text(rng)
        path = out / f"normal_{fi:03d}.txt"
        path.write_bytes(data)
        manifest.append({
            "file": path.name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"[+] {args.files} 个正常语料文件 -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
