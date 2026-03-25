# macOS 内存转储

{{#include ../../../banners/hacktricks-training.md}}

## 内存工件

### 交换文件

交换文件，例如 `/private/var/vm/swapfile0`，当物理内存不足时充当 **缓存**。当物理内存没有足够空间时，其数据会被写入交换文件，并在需要时再加载回物理内存。系统可能存在多个交换文件，命名为 swapfile0、swapfile1 等。

### 休眠镜像

位于 `/private/var/vm/sleepimage` 的文件在 **休眠模式** 下至关重要。**当 OS X 进入休眠时，内存数据会存储到此文件中**。唤醒电脑后，系统会从该文件恢复内存数据，使用户可以从中断处继续。

值得注意的是，在现代 MacOS 系统上，该文件通常出于安全原因被加密，使得恢复变得困难。

- 要检查 sleepimage 是否启用了加密，可以运行命令 `sysctl vm.swapusage`。该命令会显示该文件是否被加密。

### 内存压力日志

在 MacOS 系统中另一个重要的与内存相关的文件是 **内存压力日志**。这些日志位于 `/var/log`，包含关于系统内存使用情况和内存压力事件的详细信息。它们对于诊断内存相关问题或理解系统随时间如何管理内存非常有用。

## 使用 osxpmem 转储内存

要在 MacOS 机器上转储内存，可以使用 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)。

**注意**：这在很大程度上已成为一个 **遗留工作流**。`osxpmem` 依赖于加载一个 kernel extension，[Rekall](https://github.com/google/rekall) 项目已被存档，最新发布来自 **2017** 年，且发布的二进制目标为 **Intel Macs**。在当前的 macOS 版本上，尤其是 **Apple Silicon**，基于 kext 的全内存采集通常会被现代的内核扩展限制、SIP 和平台签名要求阻止。实际上，在现代系统上，你更常进行的是 **进程范围的转储** 而不是整机内存镜像。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果你遇到此错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)`，你可以通过以下操作修复：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误** 可能通过在 "Security & Privacy --> General" 中 **允许加载 kext** 来修复，只需 **allow** 它。

你也可以使用这个 **oneliner** 来下载应用、加载 kext 并转储内存：
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## 使用 LLDB 进行实时进程转储

对于 **近期 macOS 版本**，通常最实用的方法是转储 **特定进程** 的内存，而不是尝试镜像所有物理内存。

LLDB 可以从运行中的目标保存一个 Mach-O core file：
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
默认情况下，这通常会创建一个 **skinny core**。要强制 LLDB 包含所有映射的进程内存：
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
当目标是恢复以下内容时，这通常足够：

- 已解密的配置 blob
- 内存中的 tokens、cookies 或凭证
- 仅在静态存储（at rest）时受保护的明文机密
- 解包 / JIT / 运行时修补 后的已解密 Mach-O 内存页

如果目标受 **hardened runtime** 保护，或 `taskgated` 拒绝附加，通常需要满足以下任一条件：

- 目标携带 **`get-task-allow`**
- 你的调试器已签名并具有正确的 **debugger entitlement**
- 你是 **root**，且目标是未启用 hardened runtime 的第三方进程

For more background on obtaining a task port and what can be done with it:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## Selective dumps with Frida or userland readers

当整体 core 太嘈杂时，仅转储 **interesting readable ranges** 往往更快。Frida 特别有用，因为一旦能附加到进程，它很适合 **targeted extraction**。

示例方法：

1. 枚举可读/可写范围
2. 按模块、heap、stack 或匿名内存过滤
3. 仅转储包含候选字符串、keys、protobufs、plist/XML blob，或已解密代码/数据的区域

Minimal Frida example to dump all readable anonymous ranges:
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
这在你想避免生成巨大的 core 文件并仅收集以下内容时很有用：

- 包含敏感信息的 App heap 区块
- 由自定义 packers 或 loaders 创建的匿名区域
- 在更改内存保护后 JIT / unpacked 的代码页

旧的 userland 工具，例如 [`readmem`](https://github.com/gdbinit/readmem) 也存在，但它们主要作为直接 `task_for_pid`/`vm_read` 风格转储的**来源参考**，并且对现代 Apple Silicon 工作流的维护不足。

## 快速初筛说明

- `sysctl vm.swapusage` 仍然是检查 **swap 使用情况** 以及 swap 是否被 **加密** 的快速方法。
- `sleepimage` 主要在 **hibernate/safe sleep** 场景下仍然相关，但现代系统通常会对其进行保护，因此应将其视为一个需要检查的**工件来源**，而不是可靠的采集路径。
- 在较新的 macOS 发行版上，除非你能控制引导策略、SIP 状态和 kext 加载，否则 **process-level dumping** 通常比 **full physical memory imaging** 更可行。

## 参考资料

- [https://www.appspector.com/blog/core-dump](https://www.appspector.com/blog/core-dump)
- [https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)

{{#include ../../../banners/hacktricks-training.md}}
