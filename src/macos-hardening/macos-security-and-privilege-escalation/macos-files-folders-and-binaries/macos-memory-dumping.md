# macOS 内存转储

{{#include ../../../banners/hacktricks-training.md}}

## 内存伪影

### 交换文件

交换文件，如 `/private/var/vm/swapfile0`，在 **物理内存满时充当缓存**。当物理内存没有更多空间时，其数据会被转移到交换文件中，然后根据需要再带回物理内存。可能会存在多个交换文件，名称如 swapfile0、swapfile1 等。

### 休眠映像

位于 `/private/var/vm/sleepimage` 的文件在 **休眠模式** 下至关重要。**当 OS X 进入休眠时，内存中的数据会存储在此文件中**。唤醒计算机时，系统会从此文件中检索内存数据，使用户能够继续之前的工作。

值得注意的是，在现代 MacOS 系统上，此文件通常出于安全原因被加密，导致恢复变得困难。

- 要检查 sleepimage 是否启用加密，可以运行命令 `sysctl vm.swapusage`。这将显示文件是否被加密。

### 内存压力日志

另一个与内存相关的重要文件是 **内存压力日志**。这些日志位于 `/var/log` 中，包含有关系统内存使用情况和压力事件的详细信息。它们对于诊断与内存相关的问题或理解系统如何随时间管理内存特别有用。

## 使用 osxpmem 转储内存

为了在 MacOS 机器上转储内存，可以使用 [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip)。

**注意**：以下说明仅适用于具有 Intel 架构的 Mac。此工具现已归档，最后一次发布是在 2017 年。根据以下说明下载的二进制文件针对 Intel 芯片，因为在 2017 年时 Apple Silicon 尚未出现。可能可以为 arm64 架构编译二进制文件，但您需要自己尝试。
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
如果您发现此错误：`osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` 您可以通过以下方式修复它：
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**其他错误**可能通过**允许加载kext**在“安全性与隐私 --> 常规”中修复，只需**允许**它。

您还可以使用此**单行命令**下载应用程序，加载kext并转储内存：
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}
