# AGENTS.md — AI Agent 快速上下文

完整背景、流程、限制见 [README.md](README.md)，先读它。此处只列硬性约定。

## 仓库定位

基于 Intel PT / Arm ETM 指令流 + AI 异常检测的 CFI 验证 benchmark。**本仓库/本服务器只负责数据集构建：漏洞植入、编译、EXP 构造与正确性验证**；PT/ETM 采集、指令流还原、AI 检测均在其他环境，不在本仓库范围。

## 硬性约定

1. `sources/` 已被 .gitignore：只放第三方源码原版。**禁止提交其中任何文件，禁止直接修改其中代码**；对它们的改动一律以 patch 形式写入 `patches/`，由 `targets/` 中构建脚本应用。
2. `build/` 下的 ELF、core dump 等大文件**禁止入库**；可入库的是脚本、补丁、配置、小型 PoC 输入文件（KB 级）、标签与统计 JSON。
3. 顶层目录结构以 README.md 为准，不要擅自重命名或新增顶层目录。
4. 新增漏洞样本必须成套提供，缺一不可：
   - `targets/`：可重复构建脚本 + 显式缓解措施编译选项（PIE / canary / RELRO / NX）；
   - `patches/`：漏洞注入 diff；
   - `exploits/`：EXP 或 PoC 输入文件；
   - `labels/`：元数据（样本 ID、漏洞类型、触发输入说明、预期攻击行为、缓解配置、ELF 哈希）。
5. 构建脚本需保证可重复构建（采集侧依赖同哈希 ELF 做符号还原）；交付前核对 ELF 哈希并记入 `labels/`。
6. **验证构建与交付构建分离**：ASAN/插桩构建只用于本地验证 EXP，交付给采集侧的必须是不带插桩的最终构建。
7. EXP 默认 Python + pwntools（版本固定于 `tools/requirements.txt`），统一支持 `--cmd` 非交互模式；成功标准默认 getshell。ASLR 用 personality 按进程关闭，不做系统级设置。
8. 本机 WSL2 调试限制：避免 gdb 长会话（vsock relay 会卡死会话）；core 不落盘（`core_pattern` 为管道），崩溃信息从 dmesg 获取（有 ~2s 延迟）；详见 `docs/phase1-tcpdump-tc001.md` 第 4 节。
9. 安装系统级依赖（apt、工具链、全局配置）先征得用户同意，避免破坏可重复构建的环境假设。
10. 文档与说明用中文；代码标识符与提交信息用英文。

## 当前阶段

Phase 1（最小闭环）：TC-001（栈溢出/非法 RET）与 TC-002（堆 UAF/非法间接 CALL）已跑通 构建 → 漏洞注入 → EXP 构造与本地验证 → 标签 全流程（见 docs/phase1-tcpdump-tc00*.md 与 docs/handoff-capture-side.md）。下一步：采集侧联调，再扩展第三类漏洞/其他目标、真实 CVE。
