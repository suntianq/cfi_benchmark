# Phase 1 实验记录：tcpdump 样本 TC-002（堆 UAF → 间接调用劫持 → getshell）

日期：2026-09-18　|　状态：**已验证**（cmd/shell 双模式 getshell）

## 1. 结论速览

| 项 | 值 |
|---|---|
| 样本 ID | tcpdump-TC002（与 TC-001 共用目标与构建，patch 叠加：0001+0002） |
| 目标 | tcpdump-tc002 ELF sha256 `7049df068f99a492f5a11c6ba9106453ed1da132296d30dd2fb0a059088cf54d` |
| 漏洞 | 合成堆 UAF（CWE-416），magic "CFIBENCH2" 门控，正常报文不触发 |
| 攻击原语 | **非法间接 CALL**（与 TC-001 非法 RET 对照）——RIP 完全受控，rdi 指向攻击者字符串 |
| 利用 | 无 ROP 链：fn=system、buf=参数字符串，单次调用完成 |
| 正常语料 | 20/20 干净；TC-001 漏洞在 tc002 二进制上共存可触发；TC-001 EXP 回归通过 |
| 元数据 | labels/tcpdump-tc002.json |

## 2. 注入设计

`print-udp.c` 新增（0002 patch）：

- `struct cfib_uaf_obj { void (*volatile fn)(char *); unsigned char buf[0x50]; }`（0x58 字节，malloc chunk 0x60）
- 触发序列（"CFIBENCH2" 门控，dlen 取 payload[9:11]）：`malloc` 置回调 → `free`（悬空指针未置空）→ 同尺寸 `malloc`（tcache LIFO 确定性复用同块）→ `memcpy(obj, 报文数据, dlen)` 整体重建 → `obj->fn((char*)obj->buf)` 悬空调用
- `fn` 声明为 `volatile`：防止编译器把"释放后读取"外提到 free 之前（GCC 对 free 有内建语义假设）
- 良性回调 `cfib_uaf_benign_cb` 为空实现——注意 **ND_PRINT 在无 ndo 参数的函数里不可用**（宏引用 `ndo`，首次构建即报错）

## 3. 利用设计

- 不需要 ROP/gadget/栈迁移：间接调用的第一个参数就是攻击者缓冲 `obj->buf`
- `fn ← &system`，`buf ← "/bin/sh"`（shell 模式）或 `"<cmd>; echo CFI_DONE_$?"`（cmd 模式）
- 附带尝试过栈迁移方案（CALL 劫持+ROP 常规路线）：扫描 libc/二进制中 `mov rsp,rdX; ret` 系列仅 libc 存在 `mov rsp,rdx; ret`（0x5ef6f），可用但无必要；设计取更简单路线
- libc 基址：从存活进程 `/proc/<pid>/maps` 动态解析（tcpdump 读单 pcap 秒退，用 stdin 管道保持存活，复用 TC-001 的 resolve_libc）

## 4. 构建系统坑位记录

1. **bash `${!VAR}` 间接展开对数组只取首个元素**：`PATCHES=("${!VAR}")` 导致 tc002 只应用了 0001（且 MARKERS 同被截断，断言形同虚设），构建"成功"却产出与 tc001 相同的 ELF。修复：`declare -n` nameref。教训：多样本构建必须在构建后断言二进制差异（如 strings 检查各自 magic）。
2. **源目录路径进入二进制**（影响 BuildID/哈希）：多样本构建必须复用固定目录名 `tcpdump-src` 顺序构建，否则同 patch 集哈希漂移。
3. 0002 patch 生成流程与 0001 相同：patchgen git 仓库中 "pristine → apply 0001 → commit → edit → diff"，round-trip 校验 pristine+0001+0002 == 编辑版。
4. build.sh 断言矩阵：每样本校验必备标记存在（tc001: CFIB_MAGIC；tc002: CFIB_MAGIC+CFIB2_MAGIC），tc001 额外断言不含 TC-002 代码。

## 5. 验证证据链

```
1. 触发:   [cfi-bench] uaf call                       （stdout 标记）
2. getshell: uid=1000(stq)... / CFI_PWNED_42           （cmd/shell 双模式）
3. 正常语料: 20/20 无触发、正常退出（tc002 二进制）
4. 共存:    TC-001 探针对 tc002 二进制 segfault rc=139
5. 回归:    TC-001 EXP 对 tcpdump-tc001 SUCCESS
```

## 6. 复现步骤

```bash
./targets/tcpdump/build.sh tc002
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump_tc002.py --mode cmd --cmd id
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump_tc002.py --mode shell
# 手动交互 shell:
/home/stq/venvs/cfi_bench/bin/python exploits/tcpdump/exp_tcpdump_tc002.py --mode cmd --cmd "echo ok"  # 生成 poc_uaf.pcap
echo "id; exit" | setarch -R ./build/tcpdump-cfi-bench/out/tcpdump-tc002 -nn -r build/tcpdump-cfi-bench/out/poc_uaf.pcap
```

## 7. 遗留事项

- [ ] 采集侧按 labels/tcpdump-tc002.json 采集攻击窗口（注意 tc001/tc002 使用不同 ELF）
- [ ] 后续样本构建统一加"产物差异断言"（strings magic 检查）防同类问题
