# macOS 内存转储

{{#include ../../../banners/hacktricks-training.md}}

## 内存伪迹

### Swap 文件

Swap 文件，例如 `/private/var/vm/swapfile0`，会在**物理内存已满时充当缓存**。当物理内存没有更多空间时，其中的数据会被传输到 Swap 文件，并在需要时重新加载到物理内存中。系统中可能存在多个 Swap 文件，名称类似于 swapfile0、swapfile1 等。

### 休眠映像

位于 `/private/var/vm/sleepimage` 的文件在**休眠模式**期间非常重要。**OS X 进入休眠时，内存中的数据会存储在此文件中**。计算机唤醒后，系统会从该文件中恢复内存数据，使用户能够继续之前的工作。

需要注意的是，在现代 MacOS 系统中，出于安全原因，该文件通常经过加密，因此难以恢复。

- 要检查 sleepimage 是否启用了加密，可以运行命令 `sysctl vm.swapusage`。该命令会显示该文件是否已加密。

### 内存压力日志

MacOS 系统中另一个重要的内存相关文件是**内存压力日志**。这些日志位于 `/var/log` 中，包含有关系统内存使用情况和内存压力事件的详细信息。它们对于诊断内存相关问题，或了解系统如何随时间管理内存尤其有用。

## 使用 osxpmem 转储内存

要转储 MacOS 设备中的内存，可以使用 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)。

**注意**：这现在基本上属于**legacy workflow**。`osxpmem` 依赖于加载 kernel extension，[Rekall](https://github.com/google/rekall) 项目已归档，最新版本发布于 **2017 年**，并且已发布的 binary 面向 **Intel Mac**。在当前 macOS 版本中，尤其是在 **Apple Silicon** 上，基于 kext 的完整 RAM acquisition 通常会受到现代 kernel-extension 限制、SIP 和平台签名要求的阻止。实际上，在现代系统上，你更有可能执行的是**进程范围的 dump**，而不是整个 RAM image。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果你遇到以下错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`，可以执行以下操作修复：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误**可能可以通过在“Security & Privacy --> General”中**允许加载 kext**来修复，只需**允许**即可。

你也可以使用此 **oneliner** 下载应用程序、加载 kext 并转储内存：
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## 使用 LLDB 对实时进程进行 dumping

对于**较新的 macOS 版本**，通常最实用的方法是 dump **特定进程**的内存，而不是尝试对全部物理内存进行镜像。

LLDB 可以从实时目标保存 Mach-O core 文件：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
默认情况下，这通常会创建一个 **skinny core**。要强制 LLDB 包含进程的所有映射内存：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
在 dumping 前可使用的实用后续命令：
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
当目标是恢复以下内容时，这通常已经足够：

- Decrypted configuration blobs
- 内存中的 tokens、cookies 或 credentials
- 仅在静态存储时受保护的明文 secrets
- 解包、JIT 或 runtime patching 后解密的 Mach-O pages

如果目标受 **hardened runtime** 保护，或 `taskgated` 拒绝 attach，通常需要满足以下条件之一：

- 目标携带 **`get-task-allow`**
- 你的 debugger 使用正确的 **debugger entitlement** 签名
- 你是 **root**，且目标是非 hardened 的第三方进程

有关获取 task port 以及利用它可以执行哪些操作的更多背景信息：

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

在花时间使用 LLDB/Frida 之前，快速确认目标是否实际可 **dump**：
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
在实际操作中，这通常意味着：

- 带有 **`get-task-allow`** 的第三方 app 通常可以直接使用 LLDB 进行 dump，生成的 dump 可能会暴露该 app 已经访问过的 TCC 保护数据。
- 没有 `get-task-allow` 的 **hardened** 目标通常会拒绝 attach，即使以 `root` 身份操作也是如此，除非你控制相关的 debugger entitlements / policy path。
- 未 hardened 的第三方进程仍然是使用 `lldb`、`vmmap`、Frida 或自定义 `task_for_pid`/`vm_read` reader 的最容易切入的位置。

### 搜索可 dump 的嵌套辅助进程

最近针对 notarized macOS app 的研究不断发现，嵌套 helper 中存在 **`get-task-allow`**，而不是主 GUI binary 中。当顶层 app 看起来已经 hardened 时，在放弃之前，应枚举其 **XPC services**、**login items**、**helper tools** 和捆绑的 CLI：
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
带有 `get-task-allow` 的嵌套 executable 通常是使用 `lldb` 进行 attach、dump core，或通过自定义的 `task_for_pid` client 提取内存的最简单位置，即使主 app 的加固更完善。

## 使用 Frida 或 userland readers 进行 selective dumps

当完整 core 过于嘈杂时，仅 dump **有意义的可读 ranges** 通常更快。Frida 尤其有用，因为一旦能够 attach 到进程，它非常适合进行 **targeted extraction**。

示例方法：

1. 枚举可读/可写 ranges
2. 按 module、heap、stack 或 anonymous memory 进行过滤
3. 仅 dump 包含候选 strings、keys、protobufs、plist/XML blobs 或 decrypted code/data 的 regions

使用 Frida dump 所有可读 anonymous ranges 的最小示例：
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
当你希望避免生成巨大的 core 文件，并且只收集以下内容时，这种方法很有用：

- 包含 secrets 的 App heap chunks
- 由 custom packers 或 loaders 创建的 Anonymous regions
- 更改 protections 后的 JIT / unpacked code pages

当目标在 dump 过程中持续进行 **allocating / freeing** 时，对于不稳定的 ranges，优先使用 Frida 的 **`readVolatile()`** primitive，而不是 **`readByteArray()`**。它速度较慢，但可以避免在读取过程中某个 page 变得不可读时导致目标进程崩溃。对于更大规模的 acquisition，还可以使用 `send(..., data)` 将 chunks 流式传回，并在 controller 端进行压缩，而不是在目标进程中创建数千个小文件。

较旧的 userland tools（例如 [`readmem`](https://github.com/gdbinit/readmem)）也存在，但它们主要适合作为直接使用 `task_for_pid`/`vm_read` 风格进行 dumping 的 **source references**，并不适合现代 Apple Silicon workflows，也缺乏良好维护。

## 使用 `.memgraph` 进行 Heap / VM snapshots

如果你主要关注 **heap objects**、**allocation provenance**，或需要一个可以移动到另一台机器的 snapshot，那么 `.memgraph` 通常比巨大的 Mach-O core 更实用。`leaks` tooling 可以从 live process 生成这种文件：
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
然后使用标准 Apple 工具在离线环境中对其进行初步分析：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` 是保留 `-fullContent` capture 的主要原因，因为描述 memory contents 的 labels 会从最小化的 `.memgraph` 中省略。

这在以下情况下尤其有用：

- 你想要一个**更小、可共享的 snapshot**，而不是完整的 core
- 已启用 `MallocStackLogging`，并且需要**allocation backtraces**
- 你已经知道一个**有趣的 heap address**，并想使用 `malloc_history` 进行 pivot
- 你需要在决定是否值得承受 full dump 的噪声之前，快速获取 **VM/heap breakdown**

### Differential memgraph triage

如果你能控制 target 的启动方式，请在 launch 前启用**历史 allocation logging**，这样后续 snapshots 就能保留有用的 alloc/free backtraces：
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
然后在相关操作前后捕获快照，并在离线状态下对其进行 diff：
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
这是一种实用的方法，用于隔离仅在解密、解包或 secret-retrieval 阶段之后出现的 **post-authentication objects**、**large `CFData` buffers** 或 **anonymous VM regions**。

## Swift-heavy targets：`swift-inspect`

对于将高价值数据保存在 **Swift runtime objects** 中的应用，`swift-inspect` 可以作为 LLDB 或 Frida 的良好补充。无需先转储所有内容，你可以从运行中的进程查询特定的 Swift runtime structures：
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
这对于识别以下内容很有帮助：

- 缓冲有趣数据的大型 Swift 数组
- 揭示运行时加载类型的 Metadata 分配
- 在进行更有针对性的 dump 之前，了解 Swift concurrency 状态（`Task`、actor、thread 关系）

如果需要在已经能够检查进程后进行更细粒度的对象级 runtime triage，请查看[专门介绍内存中对象的页面](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。

## 快速 triage 说明

- `sysctl vm.swapusage` 仍然是检查 **swap usage** 以及 swap 是否**加密**的快速方法。
- `sleepimage` 主要仍与 **hibernate/safe sleep** 场景相关，但现代系统通常会对其进行保护，因此应将其视为**需要检查的 artifact source**，而不是可靠的 acquisition path。
- 在较新的 macOS 版本中，除非你能控制 boot policy、SIP 状态和 kext 加载，否则 **process-level dumping** 通常比**完整物理内存成像**更现实。

## References

- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [https://keith.github.io/xcode-man-pages/leaks.1.html](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
