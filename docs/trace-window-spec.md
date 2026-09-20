# Trace 窗口切分与标签规范 v1（草案）

目的：定义采集侧产出的指令流如何切分、如何标注，供 AI 检测侧消费。**本规范是数据集格式的契约**，字段变更需双方确认。元数据由 `tools/capture_session.py` 生成的 session manifest 提供。

## 1. 层级与术语

```
session（采集会话，manifest: build/capture-sessions/<id>/session.json）
 └─ run（一次目标进程执行，正常或攻击）      ← 最小采集与标签单位
     └─ window（指令流切分片段）             ← 模型输入单位
```

## 2. 每个 run 采集侧必须记录

| 字段 | 来源 | 说明 |
|---|---|---|
| workload argv | session manifest | 与验证通过的命令逐字一致 |
| pcap_sha256 | manifest | 攻击 PoC 由采集机本地生成，哈希现场记录 |
| elf_sha256 | labels/*.json | 符号还原强绑定，逐 run 核对 |
| aslr 状态 | 启动方式 | 必须为 setarch -R（personality 禁用） |
| maps 快照 | /proc/<pid>/maps | 若 tracer 上下文可获取；否则以 no-ASLR 确定性布局替代 |
| stdout 全文 | workload 输出 | 触发标记人工核对用 |
| 还原指令流 | 采集侧产出 | ELF + maps 还原，含地址与符号信息 |

## 3. 窗口切分约定

- 窗口**不跨 run**；run 内按还原后的指令序列线性切分。
- 默认参数：窗口 W=4096 指令，步长 S=1024（75% 重叠）。AI 侧可调整，但最终值必须写进数据集 schema。
- 窗口标识：`(run_id, window_idx)`，window_idx 从 0 递增。
- 附加字段（可选，供归因）：窗口内起止虚拟地址区间、覆盖的符号集合。

## 4. 标签粒度（两级）

**run 级**（runs.jsonl，每 run 一条）：

| 字段 | 类型 | 说明 |
|---|---|---|
| run_id | str | `<session_id>/<kind>/<sample/pcap>/<seq>` |
| kind | enum | `normal` \| `attack` |
| sample_id | str | `tcpdump-TC001` / `tcpdump-TC002` / `-` |
| elf_sha256 / pcap_sha256 | str | |
| vuln_type | str | `stack-overflow/illegal-RET` / `heap-UAF/illegal-indirect-CALL` |
| mitigations | obj | pie/canary/nx/relro/fortify |
| libc_base | hex | no-ASLR 确定性基址（EXP 动态解析值） |

**window 级**（windows.jsonl，每窗口一条）：

| 字段 | 类型 | 说明 |
|---|---|---|
| run_id / window_idx | | 窗口标识 |
| is_attack | bool | 见下方正负定义 |
| attack_reason | enum | `none` / `injected-region`（窗口覆盖注入代码区域执行）/ `hijack-transfer`（窗口包含劫持产生的非法转移或其落点） |

**正负样本定义（关键设计）**：

- normal run：全部窗口 `is_attack=false`。
- attack run：只有与**攻击区间**重叠的窗口标 `is_attack=true`；该 run 的良性前缀窗口标 `is_attack=false`，但通过 run 级 `kind=attack` 可区分于 normal run。
- 理由：防止模型学到"该 pcap 的流量都是攻击"的捷径特征，攻击样本内部的正常路径仍可作为困难负样本。

## 5. 攻击区间定位

- **t0**：还原指令流中注入区域符号的首次执行——TC-001 为 `cfi_bench_copy` 入口，TC-002 为 "CFIBENCH2" 触发块（udp_print 内）。
- **t1**：`execve("/bin/sh")`（getshell 成功判据）或进程异常终止（崩溃变体）。
- 定位方式：**指令流符号对齐**（推荐，确定性强）。stdout 的 `[cfi-bench]` 标记只作人工核对——stdout 与 trace 之间没有硬时钟同步，不作为标签依据。
- 崩溃型变体（如 `--find-offset` 探针）t1 取 SIGSEGV 点，`attack_reason` 用 `hijack-transfer`。

## 6. 采集量要求（v1）

| 类别 | 要求 |
|---|---|
| normal | 每语料文件 ≥3 次（共 20 文件，覆盖输入多样性） |
| attack | 每样本 ≥5 次（EXP 生成报文确定性高，重复运行仍需以覆盖环境抖动） |
| 探针/崩溃变体 | 可选，单列 kind=`attack-crash`，不计入正常统计 |

## 7. 数据集交付格式（v1）

- `runs.jsonl`：run 级元数据。
- `windows.jsonl`：窗口级标签。
- 指令流的特征化（token 化/向量化）由 AI 侧自产；本仓库契约止步于元数据与标签。

## 8. 开放问题（待 AI 侧反馈后定版）

1. W/S 默认值（4096/1024）是否符合模型输入长度约束。
2. 是否需要 `first_bad_ip`（首个非法转移目标地址）等归因字段。
3. 训练集正负采样比例是否需要按漏洞类型分层。
