# 文件完整性监控

## 基线

基线是对系统的特定部分创建快照，以便**与未来状态进行比较并突出显示变化**。

例如，你可以计算并存储文件系统中每个文件的哈希值，从而找出哪些文件被修改过。\
这同样适用于已创建的用户账户、正在运行的进程、正在运行的服务，以及其他不应频繁变化或完全不应变化的内容。

一个**有用的基线**通常存储的不只是摘要：权限、所有者、组、时间戳、inode、符号链接目标、ACL，以及选定的扩展属性也值得进行跟踪。<sup>[[4]](#references)</sup> 从攻击者追踪的角度来看，即使内容哈希不是最先发生变化的项目，这也有助于检测**仅修改权限的篡改**、**原子文件替换**，以及**通过修改后的 service/unit 文件实现的持久化**。

### 文件完整性监控

File Integrity Monitoring (FIM) 是一种关键的安全技术，通过跟踪文件变化来保护 IT 环境和数据。它通常结合以下功能：<sup>[[1]](#references)[[3]](#references)</sup>

1. **基线比较：** 存储元数据和加密校验和（优先使用 `SHA-256` 或更好的算法），以便未来进行比较。
2. **实时通知：** 订阅操作系统原生的文件事件，以了解**哪个文件在何时发生了变化，以及理想情况下是哪个进程/用户对其进行了操作**。
3. **定期重新扫描：** 在重启、事件丢失、agent 中断或蓄意反取证活动后，重新建立可信度。

对于威胁搜寻而言，当 FIM 专注于**高价值路径**时，通常更有用，例如：

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron 位置、SSH 材料、PAM modules、web roots
- Windows 持久化位置、service binaries、scheduled task files、startup folders
- Container writable layers 以及 bind-mounted secrets/configuration

## 实时后端与盲点

### Linux

采集后端非常重要：<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**：简单且常见，但 watch 限制可能被耗尽，并且会遗漏某些边缘情况。
- **`auditd` / audit framework**：当你需要知道**是谁修改了文件**（login UID、process ID 和 process name）时更好用。
- **`eBPF` / `kprobes`**：现代 FIM stacks 使用的较新选项，可丰富事件信息，并减少纯 `inotify` 部署带来的一些运维问题。

一些实际使用中的注意事项：<sup>[[1]](#references)[[5]](#references)</sup>

- 如果程序通过 `write temp -> rename` **替换**文件，仅监控文件本身可能会失去作用。应当**监控父目录**，而不只是监控文件。
- 基于 `inotify` 的 collectors 在**超大目录树**、**hard-link 活动**，或**被监控文件遭到删除**后，可能会遗漏事件或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 设置过低，非常大的递归 watch 集合可能会静默失败。
- 对于基于 `inotify` 的监控，network filesystems 是一个盲点，因为远程变化不会被报告。

使用 AIDE 进行基线创建与验证：<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
针对攻击者持久化路径的 `osquery` FIM 配置示例：<sup>[[1]](#references)</sup>
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
如果需要**进程归因**而不只是路径级变更，请优先使用由审计支持的 telemetry，例如 `osquery` `process_file_events` 或 Wazuh `whodata` mode。<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

在 Windows 上，将**变更日志**与**高信号进程/文件 telemetry**结合使用时，FIM 的效果更强：<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** 提供按卷持久记录的文件变更日志。
- **Sysmon Event ID 11** 适用于检测文件创建/覆盖。
- **Sysmon Event ID 2** 有助于检测**timestomping**。
- **Sysmon Event ID 15** 适用于检测**named alternate data streams (ADS)**，例如 `Zone.Identifier` 或隐藏的 payload streams。

快速 USN triage 示例：<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
如需深入了解围绕 **timestamp manipulation**、**ADS abuse** 和 **USN tampering** 的反取证思路，请参阅 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

Container FIM 经常会遗漏实际的写入路径。使用 Docker `overlay2` 时，容器文件系统会将只读镜像 `lowerdir` 层与可写的 **upper layer**（`upperdir`/`diff`）组合起来，对镜像文件的写入会被复制到该 upper layer 中。<sup>[[8]](#references)</sup> 因此：

- 仅监控来自**容器内部**的路径，可能会遗漏容器重新创建后的变更。
- 监控支撑可写层的**主机路径**或相关的 bind-mounted volume，通常更有用。
- 对镜像层执行 FIM，与对运行中容器文件系统执行 FIM 是不同的。

## 面向攻击者的 Hunting 注意事项

- 应像仔细跟踪二进制文件一样跟踪**服务定义**和**任务调度器**。攻击者通常通过修改 unit 文件、cron 条目或任务 XML 来实现持久化，而不是修补 `/bin/sshd`。
- 仅凭内容哈希是不够的。许多入侵最初会表现为 **owner/mode/xattr/ACL drift**。
- 如果怀疑存在成熟的入侵活动，应同时执行两项操作：使用**实时 FIM**监控新活动，并从可信介质执行**冷基线比对**。
- 如果攻击者已获得 root 或 kernel execution 权限，应将 FIM agent 及其数据库视为不可信。尽可能将日志和基线存储在远程位置或只读介质上。<sup>[[4]](#references)</sup>

## 工具

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)。<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [使用 osquery 进行文件完整性监控](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux：文件完整性监控用例（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh 文件完整性监控（Syscheck 和 whodata 模式）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE 手册 0.16.2 版](https://aide.github.io/doc/)
- [5] [inotify(7) Linux 手册页](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS 存储驱动程序](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM 高级设置](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
