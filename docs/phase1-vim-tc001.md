# Phase 1 实验记录：vim 样本 TC-001（堆 UAF → 间接调用劫持 → getshell）

日期：2026-09-20　|　状态：**已验证**（cmd/shell 双模式 getshell）

## 1. 结论速览

| 项 | 值 |
|---|---|
| 样本 ID | vim-TC001（第二个目标试点，复用 tcpdump 模板全流程） |
| 目标 | vim @ 4b3e2e3db0a4926622da59ef6301ff79c99fff30（patch 9.2.1119），`build/vim-cfi-bench/out/vim-tc001` |
| ELF sha256 | `3b872d5abc194a08b0dadc8db065439130ae24a99a2b1a907258fdccf9b52d19`（连续两次构建一致） |
| 漏洞 | 合成堆 UAF（CWE-416），magic "CFIVIMBEN" 门控，与 tcpdump TC-002 同构 |
| 攻击原语 | 非法间接 CALL，fn=system、buf=参数字符串，无 ROP 链 |
| 正常语料 | 20/20 干净（tools/gen_normal_corpus_vim.py，seed=42） |
| 元数据 | labels/vim-tc001.json |

## 2. 注入点与设计

- **注入位置**：`src/fileio.c` 的 `readfile()` 主体开始处（ATTENTION 对话框块之后、`++no_wait_return` 之前）——所有文件读取必经、fd 已就绪；调用 `cfiv_uaf_probe(fd)`，helper 自含 read+lseek 回卷，不干扰正常读取。
- **文件布局**：`magic "CFIVIMBEN"(9) + dlen(BE16)(2) + 对象重建数据(≤0x58)`。
- **UAF 序列**：`alloc(0x58)` 置回调 → `vim_free`（指针未置空）→ 同尺寸 `alloc`（tcache LIFO 复用）→ `mch_memmove` 文件数据整体重建 → `obj->fn((char*)obj->buf)` 悬空调用。`fn` 声明 volatile 防外提。
- **vim 代码规范适配**：用 `alloc/vim_free/mch_memmove` 包装（而非裸 malloc/free）、Allman 风格、tab 缩进。

## 3. 构建系统坑位记录

1. **vim 把编译时间嵌入二进制**：`version.c` 使用 `__DATE__/__TIME__`，导致每次构建哈希必变（实测连出三个不同哈希）。修复：`SOURCE_DATE_EPOCH=<pinned commit 提交时间>`（gcc 13 已支持，实测生效），两次构建哈希一致。**可重复构建必须验证"连续两次一致"而不仅是"重跑脚本成功"**。
2. **vim configure 强制 `-D_FORTIFY_SOURCE=1`**：出现在自定义 `-U_FORTIFY_SOURCE` 之后，实际 fortify=1 生效且无法经环境变量关闭。对本样本无影响（重建数据 ≤ 对象大小，无 OOB），但 labels 中 mitigations 如实记录。后续 vim 样本若需 OOB 类漏洞需注意 fortify 拦截。
3. **运行时依赖**：vim 需 runtime 文件，采集/EXP 统一用源码树 `VIMRUNTIME=build/vim-cfi-bench/vim-src/runtime`，不依赖系统安装。
4. patchgen 过程中有一次编辑丢失（误操作 stash 后状态混乱），重做并立即生成+roundtrip 验证 patch——**编辑后应立即完成 diff 落盘**。

## 4. EXP 设计

- libc 解析：`vim -es ... -`（从 stdin 读缓冲区）+ 保持 stdin 管道打开 → 进程存活 → 读 `/proc/<pid>/maps`（与 tcpdump 同法）。
- 运行形态：`setarch -R vim-tc001 -es -N -u NONE -i NONE -c 'qall!' <file>`（批处理读完即退）。
- 利用：fn=system + buf 参数字符串（shell 模式 `/bin/sh`；cmd 模式 `<cmd>; echo CFI_DONE_$?`）。

## 5. 验证证据链

```
1. 触发:   [cfi-bench] uaf trigger dlen=88 / [cfi-bench] uaf call （stderr 标记）
2. RIP 劫持: poc_hijack_probe.bin（fn=0x1）→ SIGSEGV rc=139
3. getshell: cmd（uid 输出 + CFI_DONE_exit=0）/ shell（CFI_PWNED_42）双模式
4. 正常语料: 20/20 无触发、正常退出
5. 可重复:  连续两次构建 sha256 一致（SOURCE_DATE_EPOCH 修复后）
6. 集成:    tools/capture_session.py 全量通过（74 检查 0 失败、63 次运行）
```

## 6. 复现步骤

```bash
./targets/vim/build.sh
python3 exploits/vim/gen_input.py --probe exploits/vim/poc_hijack_probe.bin
/home/stq/venvs/cfi_bench/bin/python exploits/vim/exp_vim_tc001.py --mode cmd --cmd id
python3 tools/gen_normal_corpus_vim.py --out build/normal-corpus/vim-tc001 --seed 42
```

## 7. 遗留事项

- [ ] 采集侧按 labels/vim-tc001.json 采集（注意 VIMRUNTIME 环境变量与 run_args）
- [ ] 若后续做 vim OOB 类样本：fortify=1 强制开启，需换不受 _FORTIFY_SOURCE 约束的原语或评估是否可接受
