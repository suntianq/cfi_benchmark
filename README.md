# CFI Benchmark

基于硬件指令流追踪（Intel PT / Arm ETM）+ AI 异常检测的 CFI（Control-Flow Integrity）验证数据集与评测基准。

## 1. 项目背景

利用 CPU 硬件追踪能力（Intel PT、Arm ETM/CoreSight）抓取目标进程的指令流，借助**带符号表的 ELF** 与运行时 `/proc/<pid>/maps` 将 trace 还原为完整指令流，交给 AI 模型判断是否存在异常控制流（控制流劫持、ROP/JOP 等），用于验证 CFI 机制的有效性。

- AI 检测侧：已完成（在本项目之外）。
- 本项目职责：为 AI 检测侧构建**可复现的 benchmark 数据集**——目标构建、漏洞注入、EXP 编写、trace 采集、指令流还原、ground truth 标注。

## 2. 总体思路

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  构建目标     │ → │  采集 Trace   │ → │  还原指令流   │ → │  标注 / 评测  │
│ (带符号 ELF) │   │ (PT / ETM)  │   │ (ELF+maps)  │   │ (训练/测试)  │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
```

- **正常样本（训练数据）**：目标程序以正常输入反复运行，采集正常控制流轨迹；需覆盖多样化的正常输入，避免基线过窄。
- **攻击样本（测试数据）**：用 EXP/PoC 触发植入的漏洞或历史 CVE，采集攻击期间的指令流。
- **Ground Truth**：每个样本记录漏洞类型、触发输入、攻击窗口（trace 中的区间）、缓解措施配置，用于计算检测率/误报率。

## 3. 目录结构

```
cfi-benchmark/
├── README.md        # 本文件：目标、流程、限制
├── AGENTS.md        # AI agent / 新协作者快速上下文与硬性约定
├── sources/         # 第三方开源软件源码（git clone 原版，不入库）
├── patches/         # 对 sources/ 中软件的漏洞注入补丁（diff/patch 文件）
├── targets/         # 构建脚本与编译配置（Makefile、CFLAGS、缓解措施开关）
├── exploits/        # PoC / EXP 脚本与小型恶意输入文件（如构造的 pcap）
├── tools/           # 采集(perf/CoreSight)、还原、切分、标注、统计脚本
├── labels/          # ground truth 元数据：样本 ID、漏洞类型、攻击窗口、缓解配置、产物哈希
├── traces/          # 采集与还原产物（perf.data、原始 trace 等，不入库）
├── build/           # 构建中间产物与 ELF（不入库）
└── docs/            # 实验记录、设计细节、环境配置说明
```

| 目录 | 是否入库 | 说明 |
|---|---|---|
| `sources/` | ❌ | 体积大；改动一律以 patch 形式放 `patches/`，禁止直接改源码 |
| `patches/` | ✅ | 漏洞注入 diff，构建时应用 |
| `targets/` | ✅ | 构建脚本必须保证可重复构建（同配置产出相同地址布局） |
| `exploits/` | ✅ | 仅小型输入文件（如几 KB 的 poc.pcap），大文件不入库 |
| `traces/`、`build/` | ❌ | 单次 trace 可达数百 MB～GB 级；只入库脚本与统计信息 |

## 4. 目标软件（sources/ 现状）

当前已就位 5 个候选（均为近期 mainline 版本，未编译）：

| 软件 | 版本 | 适用性说明 |
|---|---|---|
| tcpdump | mainline | ⭐ 建议首选：单进程、输入为 pcap 文件、解析路径清晰、还原链路最短 |
| vim | 9.x | 输入为文件/按键序列，历史 CVE 多（UAF 类），进程生命周期长 |
| nginx | 1.31.7 | HTTP 解析类漏洞；master/worker 多进程架构，需明确追踪 worker 子进程 |
| openssh-portable | 10.5 | sshd fork-per-connection，需追踪连接子进程；权限分离架构复杂 |
| FFmpeg | mainline | 解析器复杂、输入为媒体文件，fuzz 公开语料丰富但代码量最大 |

注意：以上均为**现代版本**，默认开启全部缓解措施，适合做"合成漏洞注入"的基线；复现历史 CVE 需在 `sources/` 中另外下载**特定旧版本**。

## 5. 实施计划

### Phase 1：最小闭环（合成漏洞 + 单一目标）

1. 确认本机 Intel PT 可用（`perf record -e intel_pt//` 跑通）。
2. 以 tcpdump（或自写小型目标程序）为试点，用 `-g -O1` 构建带完整符号的 ELF。
3. 编写 1～2 个漏洞注入 patch（建议：栈溢出、格式化字符串）+ 对应 PoC 输入。
4. 采集：正常 trace（≥10 次不同正常输入）+ 攻击 trace（≥5 次）。
5. 还原为指令流并切分成窗口，**人工验证**攻击窗口确实覆盖漏洞函数执行路径。
6. 定义第一版标签格式（`labels/`），输出统计报告（trace 大小、指令数、还原率）。

### Phase 2：真实 CVE 扩充

- 选取有公开稳定 PoC 的历史 CVE，在 `sources/` 中下载对应旧版本，从源码构建。
- 编译时显式控制缓解措施（`-no-pie`/`-fno-stack-protector`/`-z norelro` 等），使 EXP 可行，并将缓解配置写入标签。
- 每个 CVE 成套交付：漏洞描述、PoC、构建配置、采集配置、正常/攻击 trace、标签。

### Phase 3：规模化与评测

- 构建→采集→还原→切分 流水线脚本化，输出标准数据格式对接 AI 侧。
- 评测指标：
  - TPR / FPR（按样本、按窗口两种粒度）；
  - 检测时延：从攻击开始到首次告警的指令数；
  - 归因能力：能否定位到第一个非法控制转移。

## 6. 采集与还原参考

```bash
# Intel PT（需 root，或 kernel.perf_event_paranoid <= -1）
perf record -e intel_pt//u -- ./tcpdump -r poc.pcap

# 解码还原（分支 + 指令流）
perf script --itrace=i0ns --fields=ip,sym,insn

# Arm CoreSight / ETM（需内核启用 CoreSight 框架）
perf record -e cs_etm/@tmc_etr0/u -- ./tcpdump -r poc.pcap
```

要点：

- trace 与符号 ELF 必须来自**同一次构建**（地址强绑定），重编译即失效；共享库加载基址用运行时 `/proc/<pid>/maps` 修正。
- 优先单线程目标；多线程引入调度非确定性，正常轨迹会发散。
- PT/ETM 只记录控制流（分支/间接转移目标），还原依赖对 ELF 的线性反汇编；无符号库（libc 等）构成还原盲区，建议统一自建工具链/glibc 或静态链接。

## 7. 限制与已知风险

1. **符号强绑定**：trace 与 ELF 版本一一对应，任何重编译都可能导致对齐失败；构建脚本必须可重复，产物哈希记录在 `labels/`。
2. **还原盲区**：无符号共享库、JIT、self-modifying code 无法完整还原；静态链接可消除 libc 盲区但改变程序行为，需权衡。
3. **缓解措施 vs EXP 可行性**：现代发行版默认 PIE + ASLR + canary + Full RELRO + NX，多数历史 CVE 的 EXP 会失效；需显式关闭部分缓解并在标签中记录，但这样会偏离真实攻击场景，结论需注明前提。
4. **环境权限**：PT 需 root 或 `perf_event_paranoid <= -1`，多数虚拟机/容器中 PT 不可用；Arm ETM 需要 CoreSight 硬件与驱动（手机平台常需自编内核），ETB/TRBE 缓冲区小，长运行需分段或 snapshot 模式。
5. **数据体量**：单次运行 trace 可达 GB 级，无法进 git；仓库只保留脚本、配置、标签与统计，原始数据另行归档。
6. **非确定性混淆**：若正常样本覆盖不足，模型可能学到"路径覆盖差异"而非"攻击特征"；正常/攻击样本必须在代码路径上可比（同一功能、相近输入规模）。
7. **攻击窗口标注**：需要可靠手段确定攻击发生区间（EXP 与目标间同步信号、特定 syscall 打点、或漏洞函数入口插桩），否则无法准确评测。
8. **检测边界**：本基准只覆盖**用户态控制流异常**，不覆盖纯数据流攻击（改数据、逻辑漏洞）与内核态攻击，结论中需明确。

## 8. 当前状态

- [x] 仓库初始化、目录规划、文档
- [x] 候选目标软件源码就位（`sources/`）
- [ ] Phase 1：试点目标 PT 采集链路验证
- [ ] Phase 1：漏洞注入 patch 与 PoC
- [ ] Phase 1：标签格式 v1
