# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## 基线

基线是对系统某些部分拍摄快照，以便**与未来状态比较以突出更改**。

例如，可以计算并存储文件系统中每个文件的哈希，以便找出哪些文件被修改了。\
这也可以对已创建的用户账户、正在运行的进程、正在运行的服务以及任何其他不应频繁或根本不应改变的内容进行。

A **有用的基线**通常不仅存储摘要：权限、owner、group、时间戳、inode、symlink 目标、ACLs 和选定的扩展属性也值得跟踪。从 attacker-hunting 的角度，这有助于检测**仅权限篡改**、**原子文件替换**以及**通过修改的 service/unit 文件实现的持久化**，即使内容哈希不是最先发生变化的部分。

### File Integrity Monitoring

File Integrity Monitoring (FIM) 是一种关键的安全技术，通过跟踪文件更改来保护 IT 环境和数据。它通常组合了：

1. **Baseline comparison:** 存储元数据和加密校验和（优先使用 `SHA-256` 或更高）以便将来比较。
2. **Real-time notifications:** 订阅操作系统原生的文件事件以了解**哪个文件更改、何时以及理想情况下哪个进程/用户触及它**。
3. **Periodic re-scan:** 在重启、事件丢失、agent 中断或蓄意反取证活动后重建信心。

对于 threat hunting，FIM 在关注**高价值路径**时通常更有用，例如：

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

采集后端很重要：

- **`inotify` / `fsnotify`**：简单且常见，但 watch 限制可能被耗尽，并且会错过某些边缘情况。
- **`auditd` / audit framework**：当你需要知道**谁更改了文件**（`auid`、进程、pid、executable）时更好。
- **`eBPF` / `kprobes`**：较新的选项，被现代 FIM 堆栈用来丰富事件并减少纯 `inotify` 部署的一些运维痛点。

一些实际的注意事项：

- 如果程序通过 `write temp -> rename` **替换** 文件，仅监视该文件本身可能变得无效。**监视父目录**，不要只监视文件。
- 基于 `inotify` 的收集器在面对**巨大目录树**、**硬链接活动**或在**被监视的文件被删除之后**可能会丢失事件或性能下降。
- 如果 `fs.inotify.max_user_watches`、`max_user_instances` 或 `max_queued_events` 太低，超大的递归监视集可能会无声失败。
- 网络文件系统通常不是用于低噪声监控的好 FIM 目标。

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
示例 `osquery` FIM 配置，重点关注攻击者持久性路径：
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
如果你需要不仅是路径级别更改而是**process attribution**，优先使用有审计支持的遥测，例如 `osquery` 的 `process_file_events` 或 Wazuh `whodata` 模式。

### Windows

在 Windows 上，将 **change journals** 与 **high-signal process/file telemetry** 结合时，FIM 更强大：

- **NTFS USN Journal** 提供每个卷上的持久文件更改日志。
- **Sysmon Event ID 11** 对文件创建/覆盖很有用。
- **Sysmon Event ID 2** 有助于检测 **timestomping**。
- **Sysmon Event ID 15** 对 **named alternate data streams (ADS)**（例如 `Zone.Identifier` 或 hidden payload streams）很有用。

快速 USN 甄别示例：
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
有关更深入的反取证想法，针对 **timestamp manipulation**、**ADS abuse** 和 **USN tampering**，请查看 [Anti-Forensic Techniques](anti-forensic-techniques.md)。

### 容器

Container FIM 常常无法检测到真实的写入路径。使用 Docker `overlay2` 时，更改会提交到容器的 **writable upper layer**（`upperdir`/`diff`），而不是只读镜像层。因此：

- 仅监控短生命周期容器 **内部** 的路径可能会在容器重建后漏掉更改。
- 监控支撑可写层的 **主机路径** 或相关的绑定挂载卷通常更有用。
- 对镜像层的 FIM 与对运行中容器文件系统的 FIM 不同。

## 针对攻击者的狩猎要点

- 像对二进制文件那样关注 **service definitions** 和 **task schedulers**。攻击者通常通过修改 unit 文件、cron 条目或任务 XML 来实现持久化，而不是去修改 `/bin/sshd`。
- 仅凭内容哈希不足以判断。许多入侵最早表现为 **owner/mode/xattr/ACL drift**。
- 如果怀疑是成熟的入侵，请两者都做：用于检测新活动的 **real-time FIM**，以及来自可信介质的 **cold baseline comparison**。
- 如果攻击者获得了 root 或内核级执行，则应假设 FIM agent、其数据库甚至事件源都可能被篡改。尽可能将日志和基线远程存储或保存到只读介质上。

## 工具

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 参考资料

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
