# 文件完整性监控

{{#include ../../banners/hacktricks-training.md}}

## 基线

基线是对系统的特定部分进行快照，以便**将其与未来状态进行比较，从而突出显示变化**。

例如，你可以计算并存储文件系统中每个文件的 hash，以便找出哪些文件被修改过。\
这也可以应用于已创建的用户账户、正在运行的进程、正在运行的服务，以及任何其他不应频繁变化或根本不应变化的内容。

一个**有用的基线**通常不只存储摘要：权限、所有者、组、时间戳、inode、symlink 目标、ACL 以及选定的扩展属性也值得跟踪。从攻击者狩猎的角度来看，即使内容 hash 不是最先发生变化的对象，这也有助于检测**仅修改权限的篡改**、**atomic file replacement**以及**通过修改后的 service/unit 文件实现的持久化**。

### 文件完整性监控

File Integrity Monitoring（FIM）是一项关键的安全技术，通过跟踪文件变化来保护 IT 环境和数据。它通常结合以下功能：

1. **基线比较：**存储元数据和加密校验和（最好使用 `SHA-256` 或更强的算法）以供后续比较。
2. **实时通知：**订阅操作系统原生的文件事件，以了解**哪个文件发生了变化、何时变化，以及理想情况下哪个进程/用户访问或修改了它**。
3. **定期重新扫描：**在重启、事件丢失、agent 中断或蓄意的反取证活动后，重新建立可信度。

对于威胁狩猎而言，FIM 通常更适合关注**高价值路径**，例如：

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron 位置、SSH material、PAM modules、web roots
- Windows 持久化位置、service binaries、scheduled task files、startup folders
- Container writable layers 以及 bind-mounted secrets/configuration

## 实时后端与盲点

### Linux

采集后端很重要：<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**：简单且常见，但 watch limits 可能耗尽，并且可能遗漏某些 edge cases。
- **`auditd` / audit framework**：当你需要知道**谁修改了文件**（`auid`、进程、pid、可执行文件）时更好用。
- **`eBPF` / `kprobes`**：现代 FIM stacks 使用的较新选项，可丰富事件信息，并减少普通 `inotify` 部署中的一些运维负担。

一些实际使用中的注意事项：<sup>[[1]](#references)</sup>

- 如果程序通过 `write temp -> rename` **替换**文件，监视文件本身可能不再有用。应当**监视父目录**，而不仅是文件本身。
- 基于 `inotify` 的 collectors 在面对**超大的目录树**、**hard-link activity**，或**被监视文件遭删除**后，可能出现遗漏或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 设置过低，非常大的 recursive watch sets 可能会静默失败。
- 对于低噪声监控而言，network filesystems 通常不是理想的 FIM 目标。

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
如果需要的是**进程归因**，而不仅仅是路径级变更，请优先使用基于 audit 的 telemetry，例如 `osquery` `process_file_events` 或 Wazuh `whodata` mode。<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

在 Windows 上，将**变更日志**与**高信号进程/文件 telemetry**结合使用时，FIM 的效果更强：

- **NTFS USN Journal** 提供按卷持久记录文件变更的日志。
- **Sysmon Event ID 11** 适用于检测文件创建/覆盖。
- **Sysmon Event ID 2** 有助于检测 **timestomping**。
- **Sysmon Event ID 15** 适用于检测**命名备用数据流（ADS）**，例如 `Zone.Identifier` 或隐藏的 payload 流。

快速 USN triage 示例：
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
关于 **timestamp manipulation**、**ADS abuse** 和 **USN tampering** 的更深入 anti-forensic 思路，请查看 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

Container FIM 经常无法监控到真实的写入路径。使用 Docker `overlay2` 时，更改会被提交到容器的**可写 upper layer**（`upperdir`/`diff`），而不是只读的 image layers。因此：

- 仅监控一个短生命周期容器**内部**的路径，可能会遗漏容器重新创建后的更改。
- 监控承载可写层的**主机路径**，或相关的 bind-mounted volume，通常更有用。
- 对 image layers 执行 FIM，与对运行中容器的 filesystem 执行 FIM 并不相同。

## 面向攻击者的 Hunting 注意事项

- 应像仔细追踪 binaries 一样追踪**服务定义**和**任务调度器**。攻击者通常通过修改 unit file、cron entry 或 task XML 来建立 persistence，而不是修补 `/bin/sshd`。
- 仅依赖 content hash 并不充分。许多 compromise 最初表现为 **owner/mode/xattr/ACL drift**。
- 如果怀疑存在成熟的 intrusion，应同时执行：针对最新活动的 **real-time FIM**，以及从可信介质进行的 **cold baseline comparison**。
- 如果攻击者已获得 root 或 kernel execution，应假设 FIM agent、其 database，甚至 event source 都可能被篡改。应尽可能将 logs 和 baselines 存储在远程位置或只读介质上。

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [使用 osquery 进行 File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux：一个 file integrity monitoring 使用场景（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring（Syscheck 和 whodata mode）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
