# 文件完整性监控

{{#include ../../banners/hacktricks-training.md}}

## 基线

基线是对系统的特定部分进行快照，以便**将其与未来的状态进行比较，从而突出显示变化**。

例如，你可以计算并存储文件系统中每个文件的 hash，以便找出哪些文件被修改过。\
对于创建的用户账户、正在运行的进程、正在运行的服务，以及其他不应频繁变化或完全不应变化的内容，也可以采用相同的方法。

一个**有用的基线**通常存储的不只是摘要：权限、所有者、组、时间戳、inode、symlink 目标、ACL，以及选定的扩展属性也值得跟踪。从攻击者狩猎的角度来看，即使内容 hash 不是首先发生变化的内容，这也有助于检测**仅修改权限的篡改**、**原子文件替换**，以及**通过修改后的 service/unit 文件实现的持久化**。

### 文件完整性监控

文件完整性监控（FIM）是一项关键的安全技术，通过跟踪文件变化来保护 IT 环境和数据。它通常结合以下功能：

1. **基线比较：**存储元数据和加密校验和（建议使用 `SHA-256` 或更好的算法），以便进行后续比较。
2. **实时通知：**订阅操作系统原生的文件事件，以了解**哪个文件发生了变化、何时发生，以及理想情况下哪个进程/用户触碰了该文件**。
3. **定期重新扫描：**在系统重启、事件丢失、agent 中断或蓄意反取证活动后，重新建立可信度。

对于威胁狩猎而言，FIM 通常在关注以下**高价值路径**时更有用：

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron 位置、SSH material、PAM modules、web roots
- Windows persistence locations、service binaries、scheduled task files、startup folders
- Container writable layers 和 bind-mounted secrets/configuration

## 实时后端与盲点

### Linux

采集后端很重要：<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**：简单且常见，但 watch 限制可能耗尽，并且可能遗漏某些边界情况。
- **`auditd` / audit framework**：当你需要知道**谁修改了文件**（`auid`、进程、pid、可执行文件）时更好用。
- **`eBPF` / `kprobes`**：现代 FIM stacks 使用的较新选项，可丰富事件信息，并减轻纯 `inotify` 部署带来的一些运维负担。

一些实际使用中的注意事项：<sup>[[1]](#references)</sup>

- 如果程序通过 `write temp -> rename` **替换**文件，监控文件本身可能不再有用。应当**监控父目录**，而不只是文件本身。
- 基于 `inotify` 的 collectors 在处理**超大的目录树**、**hard-link 活动**，或**被监控文件删除后**，可能会遗漏事件或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 设置过低，非常大的递归 watch 集合可能会静默失败。
- 对于低噪声监控而言，Network filesystems 通常不是理想的 FIM 目标。

使用 AIDE 进行基线创建与验证的示例：
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
如果你需要的是**进程归因**而不仅仅是路径级变更，请优先使用由审计支持的 telemetry，例如 `osquery` 的 `process_file_events` 或 Wazuh 的 `whodata` mode。<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

在 Windows 上，将 **change journals** 与**高信号进程/文件 telemetry** 结合使用时，FIM 的效果更强：

- **NTFS USN Journal** 提供每个卷的持久化文件变更日志。
- **Sysmon Event ID 11** 适用于检测文件创建/覆盖。
- **Sysmon Event ID 2** 有助于检测 **timestomping**。
- **Sysmon Event ID 15** 适用于检测**命名备用数据流（ADS）**，例如 `Zone.Identifier` 或隐藏的 payload 流。

快速 USN triage 示例：
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
对于 **timestamp manipulation**、**ADS abuse** 和 **USN tampering** 等更深入的反取证思路，请参阅 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

容器 FIM 经常无法监控到真实的写入路径。使用 Docker `overlay2` 时，变更会提交到容器的**可写上层**（`upperdir`/`diff`），而不是只读的镜像层。因此：

- 仅监控一个短生命周期容器**内部**的路径，可能会遗漏容器重建后的变更。
- 监控支撑可写层的**主机路径**或相关的 bind-mounted volume，通常更有用。
- 对镜像层执行 FIM，与对运行中容器的文件系统执行 FIM 并不相同。

## 面向攻击者的狩猎笔记

- 应像仔细跟踪二进制文件一样跟踪**服务定义**和**任务调度器**。攻击者通常通过修改 unit 文件、cron 条目或任务 XML 来实现持久化，而不是修补 `/bin/sshd`。
- 仅凭内容哈希是不够的。许多 compromise 最初表现为**所有者/模式/xattr/ACL 漂移**。
- 如果怀疑存在成熟的入侵，应同时执行：针对新活动的**实时 FIM**，以及从可信介质进行的**冷基线对比**。
- 如果攻击者获得了 root 或 kernel execution，应假设 FIM agent、其数据库，甚至事件源都可能被篡改。尽可能将日志和基线存储在远程位置或只读介质上。

## 工具

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 参考资料

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
