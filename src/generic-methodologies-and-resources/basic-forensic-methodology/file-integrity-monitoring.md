# 文件完整性监控

{{#include ../../banners/hacktricks-training.md}}

## 基线

基线是对系统的特定部分进行快照，以便**与未来的状态进行比较，从而突出显示变化**。

例如，可以计算并存储文件系统中每个文件的哈希值，以便找出哪些文件被修改。\
也可以对创建的用户账户、正在运行的进程、正在运行的服务，以及任何其他不应频繁变化或根本不应变化的内容执行相同操作。

一个**有用的基线**通常存储的不只是摘要：权限、所有者、组、时间戳、inode、符号链接目标、ACL 以及选定的扩展属性也值得进行跟踪。<sup>[[4]](#references)</sup> 从攻击者追踪的角度来看，即使内容哈希不是最先发生变化的项目，这也有助于检测**仅权限篡改**、**原子文件替换**以及**通过修改后的服务/unit 文件实现的持久化**。

### 文件完整性监控

文件完整性监控（FIM）是一项重要的安全技术，通过跟踪文件中的变化来保护 IT 环境和数据。它通常结合以下功能：<sup>[[1]](#references)[[3]](#references)</sup>

1. **基线比较：**存储元数据和加密校验和（优先使用 `SHA-256` 或更强的算法），以便进行后续比较。
2. **实时通知：**订阅操作系统原生的文件事件，以了解**哪个文件发生了变化、何时发生，以及理想情况下是哪个进程/用户对其进行了操作**。
3. **定期重新扫描：**在重启、事件丢失、agent 中断或蓄意反取证活动之后，重新建立可信度。

对于威胁 hunting，将 FIM 聚焦于**高价值路径**通常更有用，例如：

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron 位置、SSH 材料、PAM 模块、Web 根目录
- Windows 持久化位置、服务二进制文件、scheduled task 文件、启动文件夹
- 容器可写层以及 bind-mounted secrets/configuration

## 实时后端与盲点

### Linux

采集后端十分重要：<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**：简单且常见，但 watch 限制可能耗尽，并且会遗漏某些边缘情况。
- **`auditd` / audit framework**：当你需要知道**是谁修改了文件**（登录 UID、进程 ID 和进程名称）时，它更为合适。
- **`eBPF` / `kprobes`**：现代 FIM 堆栈使用的较新选项，可丰富事件信息，并减少纯 `inotify` 部署带来的一些运维负担。

一些实际使用中的注意事项：<sup>[[1]](#references)[[5]](#references)</sup>

- 如果程序通过 **`write temp -> rename`** 的方式**替换**文件，监控文件本身可能不再有用。应**监控父目录**，而不只是监控文件。
- 基于 `inotify` 的采集器在面对**超大型目录树**、**硬链接活动**，或**被监控文件遭删除之后**，可能会漏报或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 设置过低，非常大的递归 watch 集合可能会静默失效。
- 对于基于 `inotify` 的监控，网络文件系统是一个盲点，因为远程变化不会被报告。

使用 AIDE 进行基线创建与验证的示例：<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
专注于攻击者持久化路径的 `osquery` FIM 配置示例：<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
如果需要**进程归因**，而不仅仅是路径级变更，请优先使用由审计支持的 telemetry，例如 `osquery` `process_file_events` 或 Wazuh `whodata` mode。<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`：syscall telemetry 不是 FIM

在现代 Linux 上，监控 `openat(2)`、`write(2)` 或其他 syscall entry points，**不等同于监控最终产生的 filesystem operation**。2025 年的 **Curing** proof of concept 通过 `io_uring` 排队处理 file 和 network requests，因此仅附加到相应 per-operation syscall entries 的 products 或 policies 会丢失 process telemetry。在相同测试中，path-scoped FIM component 仍然观察到了 file modifications，这表明这是一个**hook-placement blind spot**，而不是 permission bypass，也不是击败所有 FIM backend 的方法。<sup>[[10]](#references)</sup>

验证 sensor 时，应通过多种路径修改同一个 canary：普通 `write`、`mmap` + `msync`、`truncate`、`sendfile`/`copy_file_range`、atomic replacement 以及 `io_uring`。检查的不仅应是是否发现最终的 hash drift，还应确认 event 是否保留 responsible process、container/cgroup、namespace-visible path、inode 以及 rename pair。实时 event 缺失，随后 periodic scan 发现 mismatch 时，必须将其视为**telemetry loss**，而不是例行的、无法解释的变更。<sup>[[10]](#references)[[11]](#references)</sup>

对于基于 eBPF 的 monitoring，应优先使用常见的 kernel enforcement points，而不是 syscall-entry probes 列表。例如，Tetragon 的 file-access policy 使用 `security_file_permission` 来覆盖 ordinary I/O、`sendfile`、`copy_file_range`、AIO 和 `io_uring`；它还通过 `security_mmap_file` 单独覆盖 memory mappings，并通过 `security_path_truncate` 覆盖 size changes。这也说明了为什么单个 hook 很少能提供完整覆盖。<sup>[[11]](#references)</sup>

### Windows

在 Windows 上，将**change journals**与**高信号的 process/file telemetry**结合使用时，FIM 更强：<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** 提供持久化的 per-volume file changes 日志。
- **Sysmon Event ID 11** 适用于 file creation/overwrite。
- **Sysmon Event ID 2** 有助于检测 **timestomping**。
- **Sysmon Event ID 15** 适用于 **named alternate data streams (ADS)**，例如 `Zone.Identifier` 或隐藏的 payload streams。

USN 快速 triage 示例：<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
有关 **timestamp manipulation**、**ADS abuse** 和 **USN tampering** 的更深入 anti-forensic 思路，请查看 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

Container FIM 经常无法监测到真实的写入路径。对于 Docker `overlay2`，容器文件系统将只读镜像 `lowerdir` 层与可写的 **upper layer**（`upperdir`/`diff`）组合在一起，对镜像文件的写入会被复制到该 upper layer 中。<sup>[[8]](#references)</sup> 因此：

- 仅监控短生命周期容器**内部**的路径，可能会遗漏容器重建后的更改。
- 监控承载可写层的**主机路径**，或相关的 bind-mounted volume，通常更有用。
- 对镜像层执行 FIM，与对运行中容器文件系统执行 FIM 并不相同。

## 面向攻击者的 Hunting 注意事项

- 像跟踪 binaries 一样仔细地跟踪 **service definitions** 和 **task schedulers**。攻击者通常通过修改 unit file、cron entry 或 task XML 来实现 persistence，而不是直接 patch `/bin/sshd`。
- 仅依赖内容 hash 是不够的。许多 compromise 最先表现为 **owner/mode/xattr/ACL drift**。
- 如果怀疑存在成熟的 intrusion，应同时执行两种方式：使用 **real-time FIM** 监控新活动，并从 trusted media 进行 **cold baseline comparison**。
- 如果攻击者已获得 root 或 kernel execution，应将 FIM agent 及其 database 视为不可信。尽可能将 logs 和 baselines 存储在远程位置或 read-only media 上。<sup>[[4]](#references)</sup>

## 工具

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)。<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [使用 osquery 进行 File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux：File Integrity Monitoring 使用场景（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring（Syscheck 和 whodata mode）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit Bypasses Linux Security Tools（ARMO）](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Filename access：covering synchronous, asynchronous, mapped, and truncation paths（Tetragon）](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
