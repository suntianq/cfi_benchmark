# Phase 1 实验记录：tcpdump 样本 TC-001（UDP 栈溢出 → getshell）

日期：2026-09-18　|　状态：**已验证**（crash → 控制流劫持 → getshell，双模式）

## 1. 结论速览

| 项 | 值 |
|---|---|
| 样本 ID | tcpdump-TC001 |
| 目标 | tcpdump @ 199172821ffc1c9d7982a172d67dd8058591a57e（5.0.0-PRE-GIT）+ libpcap 1.10.5 静态链接 |
| 漏洞 | 合成栈溢出（CWE-121），magic "CFIBENCH1" 门控，正常报文不触发 |
| saved RIP 偏移 | **136**（静态推导 + 探针实证） |
| 利用 | ROP ret2libc → `system("/bin/sh")`，getshell 成功 |
| ELF sha256 | `0853f0e448fd17b05edb6f7894457aefc7ba3131955f776f5703541f448cfa22`（重跑构建哈希一致，可重复） |
| 缓解措施 | PIE=off, canary=off, FORTIFY=off；NX=on, RELRO=full |
| 元数据 | labels/tcpdump-tc001.json |

## 2. 流程与决策记录

1. **注入点选型**：读 `print-udp.c`，选 `udp_print()` 中 `cp = (const u_char *)(up + 1)` 之后——所有 UDP 报文必经、早于任何端口分发，`GET_U_1`/`ND_TTEST_LEN` 框架自带边界检查可复用。
2. **漏洞形态**：新增 `noinline` 函数 `cfi_bench_copy()`（128 字节栈缓冲 + 无界 memcpy），门控条件 = payload 前 9 字节 == `CFIBENCH1`；`copy_len` 取自 payload 偏移 9。独立函数使攻击窗口在 trace/符号表中清晰可辨。
3. **构建**：`targets/tcpdump/build.sh` 导出 pinned commit 纯净树 → `git apply` patch → libpcap 静态构建（需 flex/bison）→ tcpdump autogen/configure/make。libpcap 从 tcpdump.org 发行包（自带 configure），tcpdump configure 自动探测兄弟目录 `libpcap-1.10.5`。
4. **偏移确定（无 gdb）**：反汇编得帧布局 `scratch[0x80] + saved rbx(8) + saved RIP(8)` → 偏移 136；实证方法 = saved RIP 覆写 `0x1`，dmesg 出现 `segfault at 1 ip 0x1` 即确认。
5. **EXP**：Python + pwntools。libc 基址从存活进程 `/proc/<pid>/maps` 动态解析（tcpdump 读单个 pcap 秒退，改用 stdin 管道喂 pcap 并保持管道打开）；ASLR 用 personality 按进程关闭（`aslr=False`/`setarch -R`），无系统级设置。ROP 链 `ret + pop rdi;ret + /bin/sh + system`，栈 16 字节对齐修正。

## 3. 验证证据链

```
1. 触发:   [cfi-bench] copy_len=168          （stdout 标记）
2. 崩溃:   GP fault ip:45c02f               （ret 弹出 0x4242...，dmesg）
3. RIP 劫持: segfault at 1 ip 0x1            （offset 136 实证）
4. getshell: uid=1000(stq)... / CFI_PWNED_42 （cmd/shell 双模式）
5. 正常语料: 20 个 pcap（seed=42）全部无触发、正常退出
6. 可重复:  重跑 build.sh → ELF sha256 一致
```

## 4. 本机环境坑位记录（WSL2）

1. **WSL 会话中断两次**：dmesg 显示 vsock relay `UtilAcceptVsock: Waiting for abnormally long accept` + `SessionLeader accept4 failed 110`，VM 未重启。第一次发生于 gdb 加载大 debug_info 时段；第二次由本项目脚本 bug 诱发（见下）。长时间驻留的 gdb/debug 会话在本机不稳定，**调试策略已改为"无 gdb"**：静态反汇编 + dmesg 崩溃记录。
2. **脚本 bug（已修复）**：`gen_poc.py` 初版 de Bruijn 生成器会完整枚举 62^8 长度序列（内存/CPU 无界），疑似第二次中断诱因。已改为 64 位计数器 pattern（有界、0.03s）。
3. **core 不可用**：`core_pattern = |/wsl-capture-crash`（管道），core 不落盘 → pwntools corefile 方案在本机不可用，EXP 的 `find_offset` 改为探针 + dmesg（注意 dmesg 记录有 ~2s 延迟；`segfault` 行与 `traps:` 行格式不同，过滤要同时覆盖）。
4. **`git apply` 子目录行为**：在仓库子目录运行时路径按仓库根解析，目标在 cwd 外会被**静默跳过**（rc=0）。build.sh 从仓库根执行并使用 `--directory=`。
5. **no-ASLR 布局**：本机 setarch -R 下 libc 基址 `0x7ffff7600000`。**pwntools `aslr=False` 产生的是另一套确定布局（libc base `0x155554a00000`），与 setarch -R 不一致**——曾导致 EXP 解析的链地址在手动 setarch 复跑时失配崩溃。已统一：EXP 内部所有启动均显式使用 `setarch -R`（不用 aslr=False）。采集侧同理必须用 setarch -R。
6. **no-ASLR 基址**：WSL2 下 `ADDR_NO_RANDOMIZE` 的 libc 基址为 `0x7ffff7600000`（EXP 不依赖该值，动态解析）。

## 5. 复现步骤

```bash
# 0) 依赖: flex bison; pwntools: /home/stq/venvs/cfi_bench (tools/requirements.txt)
# 1) 源码就位: sources/tcpdump(commit 19917282...), sources/libpcap-1.10.5
# 2) 构建
./targets/tcpdump/build.sh
# 3) 验证 EXP（非交互）
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump.py --offset 136 --mode cmd --cmd id
# 4) 正常语料
python3 tools/gen_normal_corpus.py --out build/normal-corpus/tcpdump-tc001 --files 20 --seed 42
```

## 6. 交付采集侧清单（对照 AGENTS.md 约定 4）

- [x] `targets/tcpdump/build.sh` + 显式缓解配置
- [x] `patches/tcpdump/0001-cfi-bench-tc001-udp-stack-overflow.patch`
- [x] `exploits/tcpdump/`：exp_tcpdump.py + gen_poc.py + poc_pattern.pcap
- [x] `labels/tcpdump-tc001.json`（ELF 哈希、触发说明、攻击窗口标记、采集注意事项）
- [x] 正常输入集合生成器 `tools/gen_normal_corpus.py`

## 7. 遗留事项

- [ ] 采集侧联调：同哈希 ELF + setarch -R 采集正常/攻击 trace，确认攻击窗口标注可行
- [ ] Phase 1 扩展：同目标再注入 1~2 类漏洞（格式化字符串 / UAF）
- [ ] `poc_pattern.pcap` 的 `--pattern` 与 EXP 运行时报文生成路径已分离，后续如需支持非 8 对齐窗口反查再增强 `pattern_index`
