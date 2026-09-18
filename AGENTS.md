# AGENTS.md — AI Agent 快速上下文

完整背景、流程、限制见 [README.md](README.md)，先读它。此处只列硬性约定。

## 仓库定位

基于 Intel PT / Arm ETM 指令流 + AI 异常检测的 CFI 验证 benchmark。本仓库负责**数据集构建**（目标构建、漏洞注入、EXP、采集、还原、标注），AI 检测部分在仓库外。

## 硬性约定

1. `sources/` 已被 .gitignore：只放第三方源码原版。**禁止提交其中任何文件，禁止直接修改其中代码**；对它们的改动一律以 patch 形式写入 `patches/`，由 `targets/` 中构建脚本应用。
2. `traces/`、`build/` 下的原始 trace、perf.data、ELF、core dump 等大文件**禁止入库**；可入库的是脚本、补丁、配置、小型 PoC 输入文件（KB 级）、标签与统计 JSON。
3. 顶层目录结构以 README.md 为准，不要擅自重命名或新增顶层目录。
4. 新增漏洞样本必须成套提供，缺一不可：
   - `targets/`：构建脚本 + 显式缓解措施编译选项（PIE / canary / RELRO / NX）；
   - `exploits/`：EXP 或 PoC 输入文件；
   - `labels/`：元数据（样本 ID、漏洞类型、触发输入说明、攻击窗口判定方式、缓解配置、ELF 哈希）。
5. trace 与符号 ELF 必须来自同一次构建；构建脚本需保证可重复构建，产物哈希记入 `labels/`。
6. 涉及系统级改动（`perf_event_paranoid`、`kptr_restrict`、内核/驱动、BIOS 设置）先征得用户同意。
7. 文档与说明用中文；代码标识符与提交信息用英文。

## 当前阶段

Phase 1（最小闭环）：优先以 tcpdump（单进程、pcap 输入）为试点，跑通 构建 → PT 采集 → 还原 → 标注 全链路，再扩展其他目标与真实 CVE。
