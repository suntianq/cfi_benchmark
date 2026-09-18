# 采集侧交接说明（Phase 1：tcpdump TC-001 / TC-002）

本仓库负责数据集构建（漏洞植入、编译、EXP、本地验证）；PT/ETM 采集、指令流还原、AI 检测在采集侧服务器。本文档是已交付样本的交接与联调指引。元数据见 `labels/tcpdump-tc001.json`、`labels/tcpdump-tc002.json`，实验记录见 `docs/phase1-tcpdump-tc001.md`、`docs/phase1-tcpdump-tc002.md`。

## 1. 交付物清单

| 项 | TC-001（栈溢出/非法 RET） | TC-002（堆 UAF/非法间接 CALL） |
|---|---|---|
| ELF（带符号） | `build/tcpdump-cfi-bench/out/tcpdump-tc001` | `build/tcpdump-cfi-bench/out/tcpdump-tc002` |
| ELF sha256 | `0853f0e448fd17b05edb6f7894457aefc7ba3131955f776f5703541f448cfa22` | `7049df068f99a492f5a11c6ba9106453ed1da132296d30dd2fb0a059088cf54d` |
| patches | `patches/tcpdump/0001-*.patch` | `0001-*.patch` + `0002-*.patch` |
| EXP | `exploits/tcpdump/exp_tcpdump.py` | `exploits/tcpdump/exp_tcpdump_tc002.py` |
| 触发 magic | `CFIBENCH1`（payload 偏移 9 为拷贝长度） | `CFIBENCH2`（payload 偏移 9 为对象重建长度） |
| stdout 触发标记 | `[cfi-bench] copy_len=N` | `[cfi-bench] uaf call` |
| 攻击原语 | 非法 RET（ROP ret2libc） | 非法间接 CALL（fn=system） |
| 正常语料 | `tools/gen_normal_corpus.py`（两样本共用，20 个 pcap，无任何 magic） | 同左 |

其余共享交付物：构建脚本 `targets/tcpdump/build.sh`（用法 `build.sh [tc001|tc002|all]`）、PoC 输入 `exploits/tcpdump/poc_pattern.pcap`、pwntools 版本 `tools/requirements.txt`。

## 2. 环境与运行约定（重要）

1. **ELF 强绑定**：采集侧符号还原必须使用上表 sha256 的 ELF。要么直接拷贝本仓库构建产物，要么用 `build.sh` 重建后核对哈希。任何其他构建（包括自行加优化参数）都不可用。
2. **ASLR 必须用 `setarch -R` 关闭**（或等价 personality 调用）。**不要用 pwntools 的 `aslr=False`**：实测其布局与 `setarch -R` 不一致（libc base `0x155554a00000` vs `0x7ffff7600000`），会导致 EXP 内嵌地址失配。启动方式必须与 EXP 内部一致。
3. **以非 root 运行 tcpdump**（root 会触发 `-Z` 降权，进程模型变化）。
4. 运行命令固定为 `tcpdump -nn -r <pcap>`（`-nn` 避免反解 DNS 引入噪声）。
5. **`poc_rop.pcap` 不能跨机复用**：内嵌 libc 地址。EXP 须在采集机上重新运行以生成该文件（EXP 动态解析本机 libc，天然适配）。
6. 采集时请记录 trace 元数据：启动命令、ASLR 状态、`/proc/<pid>/maps` 快照（如可获取）。

## 3. 采集流程

```bash
# 0) 依赖
pip3 install -r tools/requirements.txt   # pwntools==4.15.0

# 1) 核对 ELF（或用 build.sh 重建后核对）
sha256sum build/tcpdump-cfi-bench/out/tcpdump

# 2) 正常基线 trace：语料生成 + 逐文件采集（建议每文件 ≥3 次取多样性）
python3 tools/gen_normal_corpus.py --out build/normal-corpus/tcpdump-tc001 --files 20 --seed 42
setarch -R ./build/tcpdump-cfi-bench/out/tcpdump -nn -r build/normal-corpus/tcpdump-tc001/normal_000.pcap

# 3) 攻击 trace（非交互，采集侧推荐）
# TC-001:
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump.py --offset 136 --mode cmd --cmd id
#   成功判据: stdout 出现 uid=... 与 CFI_DONE_exit=0
#   EXP 内部生成 build/tcpdump-cfi-bench/out/poc_rop.pcap 后也可手动采集:
setarch -R ./build/tcpdump-cfi-bench/out/tcpdump-tc001 -nn -r build/tcpdump-cfi-bench/out/poc_rop.pcap

# TC-002:
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump_tc002.py --mode cmd --cmd id
#   成功判据: stdout 出现 uid=... 与 CFI_DONE_exit=0，且 preceded by "[cfi-bench] uaf call"
#   手动采集:
setarch -R ./build/tcpdump-cfi-bench/out/tcpdump-tc002 -nn -r build/tcpdump-cfi-bench/out/poc_uaf.pcap

# 4) 交互 shell 模式（人工验证用）
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump.py --offset 136 --mode shell
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump_tc002.py --mode shell
```

## 4. 攻击窗口标注指引

- **触发标记**：TC-001 为 `[cfi-bench] copy_len=N`；TC-002 为 `[cfi-bench] uaf call`。出现即漏洞路径已进入。
- **代码路径**：
  - TC-001：`udp_print`（print-udp.c）→ `cfi_bench_copy`（noinline，符号表可定位）→ `memcpy` 越界 → `ret` 劫持 → libc `system("/bin/sh")`；
  - TC-002：`udp_print`（"CFIBENCH2" 触发点）→ `free` → tcache 复用 → 悬空指针**间接调用** → libc `system`。
- **明确结束判据**：子进程 `execve("/bin/sh")` 或命令执行输出。
- **无攻击标记的正常样本**：正常语料无 magic，绝不会进入注入代码路径（两样本均验证 20/20 干净）。
- **两个样本是不同的 ELF**（tc001/tc002），采集与符号还原必须按样本使用对应 ELF。

## 5. 采集侧验收清单

- [ ] ELF sha256 与本文件一致（tc001/tc002 分别核对）
- [ ] 正常语料采集：无崩溃、无 `[cfi-bench]` 输出、正常退出（exit 0）
- [ ] TC-001 攻击采集：`[cfi-bench] copy_len=168` + shell 行为
- [ ] TC-002 攻击采集：`[cfi-bench] uaf call` + shell 行为
- [ ] 还原后的指令流：TC-001 覆盖 `udp_print → cfi_bench_copy` 且存在非法 RET；TC-002 覆盖悬空调用点且存在非法间接 CALL（目标均在 libc 段）
- [ ] 正常/攻击 trace 的窗口切分方案已与 AI 侧确认

## 6. 已知问题与边界

- 漏洞为**合成注入**（magic 门控），缓解措施被显式关闭（canary/PIE/FORTIFY off），与真实攻击场景有差距，评测结论需注明前提。
- 本样本仅覆盖用户态控制流异常（RET 劫持类）；不含数据流攻击与内核态。
- EXP 依赖 glibc `system`/`"/bin/sh"` 字符串，任何 glibc 均适用（地址动态解析）；但若采集侧使用 musl 等非 glibc 环境需另行适配。
