#!/usr/bin/env python3
"""采集会话自动化： workload 验证 + 采集侧验收 + 会话 manifest（纯标准库）。

一次运行完成：
  1. 预检：ELF 哈希核对 labels、setarch 可用、非 root、pwntools venv 可用、正常语料就位
  2. 正常采集 workload：20 个语料 × N 次运行（须全部干净：exit 0、无触发标记）
  3. 攻击采集 workload：TC-001 / TC-002 EXP --mode cmd（须 getshell 成功）
  4. 产出 session manifest（JSON）：每次运行的命令、pcap 哈希、退出码、标记、结论，
     以及"给采集侧的 replay 命令清单"（PT 采集时按此包裹执行）

本脚本本身不做 PT/ETM 采集——它验证 workload 正确性并生成采集侧直接可用的
执行清单。采集侧在其 tracer 下逐条 replay manifest 中的命令即可。

用法:
  python3 tools/capture_session.py                     # 全量
  python3 tools/capture_session.py --normal-repeats 3
  python3 tools/capture_session.py --skip-normal       # 只做攻击 workload
  python3 tools/capture_session.py --venv-python /path/to/python
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_ROOT = REPO_ROOT / "build/capture-sessions"
VENV_PY_DEFAULT = "/home/stq/venvs/cfi_bench/bin/python"
NORMAL_CORPUS_TCPDUMP = REPO_ROOT / "build/normal-corpus/tcpdump-tc001"
NORMAL_CORPUS_VIM = REPO_ROOT / "build/normal-corpus/vim-tc001"

SAMPLES = {
    "tc001": {
        "elf": REPO_ROOT / "build/tcpdump-cfi-bench/out/tcpdump-tc001",
        "labels": REPO_ROOT / "labels/tcpdump-tc001.json",
        "exp": REPO_ROOT / "exploits/tcpdump/exp_tcpdump.py",
        "exp_args": ["--offset", "136", "--mode", "cmd", "--cmd", "id"],
        "pcap_product": REPO_ROOT / "build/tcpdump-cfi-bench/out/poc_rop.pcap",
        "corpus": NORMAL_CORPUS_TCPDUMP,
        "corpus_glob": "*.pcap",
        "corpus_generator": ["tools/gen_normal_corpus.py",
                             "--out", str(NORMAL_CORPUS_TCPDUMP),
                             "--files", "20", "--packets", "50", "--seed", "42"],
        "normal_argv": lambda elf, f: ["setarch", "-R", str(elf), "-nn", "-r", str(f)],
        "normal_env": {},
    },
    "tc002": {
        "elf": REPO_ROOT / "build/tcpdump-cfi-bench/out/tcpdump-tc002",
        "labels": REPO_ROOT / "labels/tcpdump-tc002.json",
        "exp": REPO_ROOT / "exploits/tcpdump/exp_tcpdump_tc002.py",
        "exp_args": ["--mode", "cmd", "--cmd", "id"],
        "pcap_product": REPO_ROOT / "build/tcpdump-cfi-bench/out/poc_uaf.pcap",
        "corpus": NORMAL_CORPUS_TCPDUMP,
        "corpus_glob": "*.pcap",
        "corpus_generator": ["tools/gen_normal_corpus.py",
                             "--out", str(NORMAL_CORPUS_TCPDUMP),
                             "--files", "20", "--packets", "50", "--seed", "42"],
        "normal_argv": lambda elf, f: ["setarch", "-R", str(elf), "-nn", "-r", str(f)],
        "normal_env": {},
    },
    "vim_tc001": {
        "elf": REPO_ROOT / "build/vim-cfi-bench/out/vim-tc001",
        "labels": REPO_ROOT / "labels/vim-tc001.json",
        "exp": REPO_ROOT / "exploits/vim/exp_vim_tc001.py",
        "exp_args": ["--mode", "cmd", "--cmd", "id"],
        "pcap_product": REPO_ROOT / "build/vim-cfi-bench/out/poc_uaf_file.bin",
        "corpus": NORMAL_CORPUS_VIM,
        "corpus_glob": "*.txt",
        "corpus_generator": ["tools/gen_normal_corpus_vim.py",
                             "--out", str(NORMAL_CORPUS_VIM),
                             "--files", "20", "--seed", "42"],
        "normal_argv": lambda elf, f: [
            "setarch", "-R", str(elf),
            "-es", "-N", "-u", "NONE", "-i", "NONE", "-c", "qall!", str(f)],
        "normal_env": {"VIMRUNTIME": str(REPO_ROOT / "build/vim-cfi-bench/vim-src/runtime")},
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, **kw)


def check_elf_hashes(results: list) -> bool:
    ok = True
    for name, cfg in SAMPLES.items():
        labels = json.loads(cfg["labels"].read_text())
        expect = labels["target"]["elf"]["sha256"]
        actual = sha256(cfg["elf"])
        entry = {
            "check": f"elf_hash_{name}",
            "expect": expect,
            "actual": actual,
            "pass": actual == expect,
        }
        ok &= entry["pass"]
        results.append(entry)
    return ok


def preflight(venv_py: str, results: list) -> bool:
    ok = True
    for check, passed, detail in [
        ("setarch", shutil.which("setarch") is not None, shutil.which("setarch") or "missing"),
        ("non-root", os.geteuid() != 0, f"euid={os.geteuid()}（root 会触发 -Z 降权）"),
        ("venv-python", Path(venv_py).exists(), venv_py),
        ("dmesg-readable", Path("/proc/sys/kernel/core_pattern").exists(),
         Path("/proc/sys/kernel/core_pattern").read_text().strip()),
    ]:
        results.append({"check": check, "pass": passed, "detail": detail})
        ok &= passed
    r = run([venv_py, "-c", "import pwnlib; print(pwnlib.__version__)"])
    results.append({"check": "pwntools", "pass": r.returncode == 0,
                    "detail": r.stdout.strip() or r.stderr.strip()[-120:]})
    ok &= r.returncode == 0
    return ok


def ensure_corpus(results: list) -> bool:
    ok = True
    for name, cfg in SAMPLES.items():
        corpus = cfg["corpus"]
        glob = cfg["corpus_glob"]
        if corpus.exists() and len(list(corpus.glob(glob))) >= 20:
            results.append({"check": f"normal-corpus/{name}", "pass": True,
                            "detail": str(corpus)})
            continue
        r = run([sys.executable, str(REPO_ROOT / cfg["corpus_generator"][0])]
                + cfg["corpus_generator"][1:])
        gen_ok = r.returncode == 0 and len(list(corpus.glob(glob))) >= 20
        results.append({"check": f"normal-corpus-generated/{name}", "pass": gen_ok,
                        "detail": str(corpus)})
        ok &= gen_ok
    return ok


def run_normal(name: str, repeats: int, results: list, runs: list) -> bool:
    cfg = SAMPLES[name]
    ok = True
    for f in sorted(cfg["corpus"].glob(cfg["corpus_glob"])):
        for rep in range(1, repeats + 1):
            argv = cfg["normal_argv"](cfg["elf"], f)
            r = run(argv, env={**os.environ, **cfg["normal_env"]})
            clean = r.returncode == 0 and "cfi-bench" not in r.stdout \
                and "Segmentation fault" not in r.stderr
            entry = {
                "check": f"normal/{name}/{f.name}/run{rep}",
                "pass": clean,
                "detail": f"rc={r.returncode}",
            }
            results.append(entry)
            runs.append({
                "kind": "normal", "sample": name, "input": f.name,
                "input_sha256": sha256(f),
                "argv": argv, "env": cfg["normal_env"],
                "exit_code": r.returncode, "markers": [], "clean": clean,
            })
            ok &= clean
    return ok


def run_attack(name: str, venv_py: str, results: list, runs: list) -> bool:
    cfg = SAMPLES[name]
    r = run([venv_py, str(cfg["exp"])] + cfg["exp_args"])
    markers = [m for m in ("[cfi-bench]", "uid=", "CFI_DONE_", "SUCCESS: getshell")
               if m in r.stdout]
    success = "SUCCESS: getshell" in r.stdout and "uid=" in r.stdout
    pcap_hash = sha256(cfg["pcap_product"]) if cfg["pcap_product"].exists() else None
    entry = {
        "check": f"attack/{name}",
        "pass": success,
        "detail": f"rc={r.returncode} markers={markers}",
    }
    results.append(entry)
    runs.append({
        "kind": "attack", "sample": name,
        "poc": cfg["pcap_product"].name, "poc_sha256": pcap_hash,
        "argv": [venv_py, str(cfg["exp"])] + cfg["exp_args"],
        "exit_code": r.returncode, "markers": markers, "clean": success,
    })
    return success


def replay_commands(venv_py: str) -> list[dict]:
    """采集侧在其 tracer 下逐条 replay 的命令清单"""
    cmds = []
    for name, cfg in SAMPLES.items():
        for f in sorted(cfg["corpus"].glob(cfg["corpus_glob"])):
            cmds.append({
                "purpose": f"normal-trace/{name}/{f.name}",
                "argv": cfg["normal_argv"](cfg["elf"], f),
                "env": cfg["normal_env"],
            })
    for name, cfg in SAMPLES.items():
        cmds.append({
            "purpose": f"attack-trace/{name}",
            "argv": [venv_py, str(cfg["exp"])] + cfg["exp_args"],
            "note": "EXP 在采集机重跑以重新生成内嵌 libc 地址的 PoC，禁止跨机拷贝 PoC 文件",
        })
    return cmds


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None, help="manifest 输出目录")
    ap.add_argument("--normal-repeats", type=int, default=1)
    ap.add_argument("--venv-python", default=VENV_PY_DEFAULT)
    ap.add_argument("--skip-normal", action="store_true")
    ap.add_argument("--skip-attack", action="store_true")
    args = ap.parse_args()

    venv_py = args.venv_python

    results: list = []
    runs: list = []
    t0 = time.strftime("%Y%m%d-%H%M%S")

    print("== 预检 ==")
    ok = preflight(venv_py, results)
    ok &= ensure_corpus(results)
    ok &= check_elf_hashes(results)

    if not ok:
        print("预检失败：")
        for e in results:
            if not e["pass"]:
                print(f"  [FAIL] {e['check']}: {e.get('detail', '')}")
        return 1

    print("== 正常 workload ==")
    if not args.skip_normal:
        for name in SAMPLES:
            ok &= run_normal(name, args.normal_repeats, results, runs)

    print("== 攻击 workload ==")
    if not args.skip_attack:
        for name in SAMPLES:
            ok &= run_attack(name, venv_py, results, runs)

    # 汇总
    out_dir = Path(args.out) if args.out else OUT_ROOT / t0
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "session_id": t0,
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "distro": platform.freedesktop_os_release().get("PRETTY_NAME", ""),
            "python": sys.version.split()[0],
        },
        "checks": results,
        "runs": runs,
        "summary": {
            "total_checks": len(results),
            "failed_checks": sum(1 for e in results if not e["pass"]),
            "total_runs": len(runs),
            "all_pass": ok,
        },
        "capture_replay_commands": replay_commands(venv_py),
        "notes": [
            "本 manifest 只验证 workload；PT/ETM 采集由采集侧在相同命令外包裹 tracer 执行",
            "攻击 PoC pcap 由 EXP 在采集机本地生成（内嵌 libc 地址），禁止跨机复用",
            "ASLR 必须以 setarch -R 关闭（见 labels/*.json runtime_env）",
        ],
    }
    (out_dir / "session.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    print(f"== 汇总 ==")
    print(f"checks: {manifest['summary']['total_checks']}"
          f"（失败 {manifest['summary']['failed_checks']}）")
    print(f"runs:   {manifest['summary']['total_runs']}")
    for e in results:
        if not e["pass"]:
            print(f"  [FAIL] {e['check']}: {e.get('detail', '')}")
    print(f"manifest: {out_dir / 'session.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
