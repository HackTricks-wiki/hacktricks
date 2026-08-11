# 文件完整性监控

{{#include ../../banners/hacktricks-training.md}}

## 基线

基线是对系统的某些部分进行快照，以便**将其与未来的状态进行比较，从而突出显示变化**。

例如，可以计算并存储文件系统中每个文件的哈希，以便找出哪些文件被修改过。\
也可以对已创建的用户账户、正在运行的进程、正在运行的服务，以及其他不应频繁变化或完全不应变化的内容执行相同操作。

**有用的基线**通常存储的不仅仅是摘要：权限、所有者、组、时间戳、inode、符号链接目标、ACL，以及选定的扩展属性也值得跟踪。<sup>[[4]](#references)</sup> 从攻击者追踪的角度来看，即使内容哈希并不是最先发生变化的项目，这也有助于检测**仅修改权限的篡改**、**原子文件替换**，以及**通过修改后的 service/unit 文件实现的持久化**。

### 文件完整性监控

文件完整性监控（FIM）是一项关键的安全技术，通过跟踪文件变化来保护 IT 环境和数据。它通常结合以下功能：<sup>[[1]](#references)[[3]](#references)</sup>

1. **基线比较：**存储元数据和加密校验和（优先使用 `SHA-256` 或更高强度的算法），以便进行后续比较。
2. **实时通知：**订阅操作系统原生的文件事件，以了解**哪个文件发生了变化、何时变化，以及理想情况下是哪个进程/用户对其进行了操作**。
3. **定期重新扫描：**在重启、事件丢失、agent 中断或蓄意反取证活动后重新建立可信度。

对于威胁搜寻，FIM 通常在关注**高价值路径**时更有用，例如：

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron 位置、SSH material、PAM modules、web roots
- Windows persistence locations、service binaries、scheduled task files、startup folders
- Container writable layers and bind-mounted secrets/configuration

## 实时后端与盲点

### Linux

采集后端非常重要：<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**：简单且常见，但 watch 限制可能被耗尽，并且会遗漏某些边界情况。
- **`auditd` / audit framework**：当你需要知道**谁修改了文件**（login UID、process ID 和 process name）时更好用。
- **`eBPF` / `kprobes`**：现代 FIM stacks 使用的较新选项，可丰富事件信息，并减少纯 `inotify` 部署带来的部分运维问题。

一些实际使用中的注意事项：<sup>[[1]](#references)[[5]](#references)</sup>

- 如果程序通过 `write temp -> rename` **替换**文件，那么仅监控文件本身可能不再有用。应**监控父目录**，而不只是文件本身。
- 基于 `inotify` 的 collectors 在面对**超大的目录树**、**硬链接活动**，或**被监控文件遭删除后**，可能会丢失事件或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 设置过低，非常大的递归 watch 集合可能会静默失败。
- 对于基于 `inotify` 的监控，network filesystems 是一个盲点，因为不会报告远程变化。

使用 AIDE 进行基线建立和验证：<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
示例 `osquery` FIM 配置，重点监控攻击者持久化路径：<sup>[[1]](#references)</sup>
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
如果需要进行**进程归因**，而不仅仅是路径级别的变更监控，应优先使用基于审计的遥测数据，例如 `osquery` 的 `process_file_events` 或 Wazuh 的 `whodata` 模式。<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

在 Windows 上，将**变更日志**与**高信号进程/文件遥测**结合使用时，FIM 的效果更强：<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** 提供每个卷的持久化文件变更日志。
- **Sysmon Event ID 11** 适用于检测文件创建/覆盖。
- **Sysmon Event ID 2** 有助于检测**时间戳伪造（timestomping）**。
- **Sysmon Event ID 15** 适用于检测**命名的备用数据流（ADS）**，例如 `Zone.Identifier` 或隐藏的 payload 流。

USN 快速 triage 示例：<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
关于 **timestamp manipulation**、**ADS abuse** 和 **USN tampering** 的更深入 **anti-forensic** 思路，请查看 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

Container FIM 经常会遗漏真正的写入路径。对于 Docker `overlay2`，容器文件系统会将只读镜像 `lowerdir` 层与可写的 **upper layer**（`upperdir`/`diff`）组合起来，对镜像文件的写入会被复制到该 upper layer 中。<sup>[[8]](#references)</sup> 因此：

- 仅监控短生命周期容器**内部**的路径，可能会遗漏容器重新创建后的更改。
- 监控为可写层提供支持的**主机路径**，或相关的 bind-mounted volume，通常更有用。
- 对镜像层执行 FIM，与对运行中容器文件系统执行 FIM，是不同的操作。

## 面向攻击者的 Hunting 注意事项

- 应像仔细跟踪二进制文件一样跟踪 **service definitions** 和 **task schedulers**。攻击者通常通过修改 unit file、cron entry 或 task XML 来建立 persistence，而不是修补 `/bin/sshd`。
- 仅有内容 hash 并不足够。许多 compromise 首先表现为 **owner/mode/xattr/ACL drift**。
- 如果怀疑存在成熟的 intrusion，应同时执行两项措施：使用 **real-time FIM** 监控最新活动，并从可信介质进行 **cold baseline comparison**。
- 如果攻击者已获得 root 或 kernel execution 权限，应将 FIM agent 及其数据库视为不可信。只要条件允许，就应将日志和 baselines 远程存储，或存储在只读介质上。<sup>[[4]](#references)</sup>

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
{{#include ../../banners/hacktricks-training.md}}
