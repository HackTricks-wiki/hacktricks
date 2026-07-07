# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap files, such as `/private/var/vm/swapfile0`, serve as **caches when the physical memory is full**. When there's no more room in physical memory, its data is transferred to a swap file and then brought back to physical memory as needed. Multiple swap files might be present, with names like swapfile0, swapfile1, and so on.

### Hibernate Image

The file located at `/private/var/vm/sleepimage` is crucial during **hibernation mode**. **Data from memory is stored in this file when OS X hibernates**. Upon waking the computer, the system retrieves memory data from this file, allowing the user to continue where they left off.

It's worth noting that on modern MacOS systems, this file is typically encrypted for security reasons, making recovery difficult.

- To check if encryption is enabled for the sleepimage, the command `sysctl vm.swapusage` can be run. This will show if the file is encrypted.

### Memory Pressure Logs

Another important memory-related file in MacOS systems is the **memory pressure log**. These logs are located in `/var/log` and contain detailed information about the system's memory usage and pressure events. They can be particularly useful for diagnosing memory-related issues or understanding how the system manages memory over time.

## Dumping memory with osxpmem

In order to dump the memory in a MacOS machine you can use [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Note**: This is mostly a **legacy workflow** now. `osxpmem` depends on loading a kernel extension, the [Rekall](https://github.com/google/rekall) project is archived, the latest release is from **2017**, and the published binary targets **Intel Macs**. On current macOS releases, especially on **Apple Silicon**, kext-based full-RAM acquisition is usually blocked by modern kernel-extension restrictions, SIP, and platform-signing requirements. In practice, on modern systems you will more often end up doing a **process-scoped dump** instead of a whole-RAM image.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果你遇到这个错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 你可以这样修复：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误** 可能通过在 "Security & Privacy --> General" 中**允许加载 kext** 来修复，只需**允许**它即可。

你也可以使用这个 **oneliner** 来下载应用程序、加载 kext 并转储内存：
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## 使用 LLDB 进行实时进程转储

对于**较新的 macOS 版本**，最实用的方法通常是转储**特定进程**的内存，而不是尝试镜像所有物理内存。

LLDB 可以从实时目标保存一个 Mach-O 核心文件：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
默认情况下，这通常会创建一个 **skinny core**。要强制 LLDB 包含所有已映射的进程内存：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
在转储之前有用的后续命令：
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
这通常已经足够用于恢复：

- 已解密的配置 blob
- 内存中的 tokens、cookies 或凭证
- 仅在静态存储时受保护的明文 secrets
- unpacking / JIT / runtime patching 后已解密的 Mach-O pages

如果目标受 **hardened runtime** 保护，或者 `taskgated` 拒绝 attach，你通常需要满足以下条件之一：

- 目标带有 **`get-task-allow`**
- 你的 debugger 使用正确的 **debugger entitlement** 签名
- 你是 **root**，且目标是一个非 hardened 的第三方进程

关于获取 task port 以及可对其执行的操作的更多背景：

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Fast pre-attach checks

在花时间使用 LLDB/Frida 之前，先快速确认目标是否现实中可被 **dumpable**：
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
操作上，这通常意味着：

- 带有 **`get-task-allow`** 的第三方 app，通常可以直接用 LLDB dump，生成的 dump 可能会暴露该 app 已经访问过的 TCC 保护数据。
- 没有 `get-task-allow` 的 **hardened** 目标通常会拒绝 attach，即使是 `root`，除非你控制相关的 debugger entitlements / policy 路径。
- 未加固的第三方进程仍然是使用 `lldb`、`vmmap`、Frida，或自定义 `task_for_pid`/`vm_read` 读取器最容易的地方。

## 使用 Frida 或 userland readers 进行选择性 dump

当完整 core 太杂时，只 dump **有价值的可读范围** 往往更快。Frida 尤其有用，因为一旦你能 attach 到进程，它就非常适合进行 **targeted extraction**。

示例方法：

1. 枚举可读/可写范围
2. 按 module、heap、stack 或匿名内存过滤
3. 只 dump 包含候选字符串、key、protobufs、plist/XML blobs，或解密后的 code/data 的区域

最小 Frida 示例，用于 dump 所有可读的匿名范围：
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
这在你想避免生成巨大的 core 文件、并且只收集以下内容时很有用：

- 包含 secrets 的 App heap chunks
- 由自定义 packers 或 loaders 创建的匿名区域
- 在更改 protections 后的 JIT / unpacked 代码页

像 [`readmem`](https://github.com/gdbinit/readmem) 这样的较旧 userland 工具也存在，但它们主要适合作为直接 `task_for_pid`/`vm_read` 风格 dumping 的**source references**，并且没有很好地维护以适配现代 Apple Silicon workflows。

## 使用 `.memgraph` 的 Heap / VM snapshots

如果你主要关心 **heap objects**、**allocation provenance**，或者希望获得一个可以移到另一台机器上的 snapshot，那么 `.memgraph` 通常比一个巨大的 Mach-O core 更实用。`leaks` tooling 可以从一个 live process 生成它：
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
然后使用标准 Apple 工具离线 triage 它：
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` 是保留 `-fullContent` capture 的主要原因，因为描述内存内容的 labels 在最小的 `.memgraph` 中会被省略。

这在以下情况下尤其有用：

- 你想要一个 **更小、可共享的快照**，而不是完整 core
- 已启用 `MallocStackLogging`，并且你想要 **allocation backtraces**
- 你已经知道一个 **有意思的 heap address**，并且想用 `malloc_history` 继续 pivot
- 在决定是否值得为了噪声而做完整 dump 之前，你需要一个快速的 **VM/heap breakdown**

## Swift-heavy targets: `swift-inspect`

对于将高价值数据保存在 **Swift runtime objects** 中的应用，`swift-inspect` 可以作为 LLDB 或 Frida 的良好补充。与其先 dump 所有内容，不如直接从一个 live process 查询特定的 Swift runtime structures：
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
这有助于识别：

- 缓冲有趣数据的巨大 Swift arrays
- 暴露运行时加载类型的 Metadata allocations
- 在进行更有针对性的 dump 之前，Swift concurrency state（`Task`、actor、thread relationships）

对于在你已经可以检查进程后，进行更偏对象级别的 runtime triage，请查看[关于 memory 中 objects 的专页](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md)。

## Quick triage notes

- `sysctl vm.swapusage` 仍然是检查 **swap usage** 以及 swap 是否 **encrypted** 的快速方法。
- `sleepimage` 主要仍与 **hibernate/safe sleep** 场景相关，但现代系统通常会保护它，因此应将其视为一个**需要检查的 artifact source**，而不是可靠的获取路径。
- 在较新的 macOS 版本上，除非你控制 boot policy、SIP 状态和 kext loading，否则 **process-level dumping** 通常比 **full physical memory imaging** 更现实。

## References

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
