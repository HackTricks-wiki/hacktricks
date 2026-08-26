# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baselineとは、システムの特定部分のスナップショットを取得し、**将来の状態と比較して変更を明らかにする**ことです。

たとえば、ファイルシステム内の各ファイルの hash を計算して保存し、どのファイルが変更されたかを確認できます。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービス、その他大きな変更がない、またはまったく変更されるべきでないものにも適用できます。

**有用な baseline** では通常、digestだけでなく、permissions、owner、group、timestamps、inode、symlink target、ACLs、選択した extended attributes も保存して追跡します。<sup>[[4]](#references)</sup> attacker-hunting の観点では、これにより、コンテンツの hash が最初に変化しない場合でも、**permissionsのみの改ざん**、**atomic file replacement**、**変更された service/unit files を介した persistence** を検出できます。

### File Integrity Monitoring

File Integrity Monitoring (FIM) は、ファイルの変更を追跡することで IT environments とデータを保護する重要な security technique です。通常、以下を組み合わせます。<sup>[[1]](#references)[[3]](#references)</sup>

1. **Baseline comparison:** 将来の比較に備えて、metadata と cryptographic checksums（`SHA-256` またはそれ以上を推奨）を保存します。
2. **Real-time notifications:** OS-native file events を購読し、**どのファイルが、いつ変更され、理想的にはどの process/user が操作したか**を把握します。
3. **Periodic re-scan:** reboots、イベントの欠落、agent outages、または意図的な anti-forensic activity の後に、信頼性を再構築します。

Threat hunting では、FIM は通常、以下のような**重要度の高い path**に焦点を当てると、より有用です。

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron locations、SSH material、PAM modules、web roots
- Windows persistence locations、service binaries、scheduled task files、startup folders
- Container writable layers と bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

collection backend は重要です。<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: 簡単で一般的ですが、watch limits が枯渇する可能性があり、一部の edge cases は見逃されます。
- **`auditd` / audit framework**: **誰がファイルを変更したか**（login UID、process ID、process name）を知る必要がある場合に適しています。
- **`eBPF` / `kprobes`**: modern FIM stacks で使用される新しい選択肢で、イベントを補強し、単純な `inotify` deployments に伴う運用上の負担を一部軽減します。

実際に注意すべき点は次のとおりです。<sup>[[1]](#references)[[5]](#references)</sup>

- プログラムが `write temp -> rename` によってファイルを**置き換える**場合、ファイル自体を監視しても役に立たなくなる可能性があります。ファイルだけでなく、**親ディレクトリを監視**してください。
- `inotify`-based collectors は、**巨大な directory trees**、**hard-link activity**、または**監視対象のファイルが削除された後**に、イベントを見逃したり、性能が低下したりする可能性があります。
- 再帰的な watch sets が非常に大きい場合、`fs.inotify.max_user_watches`、`max_user_instances`、または `max_queued_events` の値が低すぎると、通知なしに失敗する可能性があります。
- `inotify`-based monitoring では、network filesystems は blind spot です。リモートでの変更は報告されないためです。

AIDE を使用した baseline + verification の例:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
攻撃者の永続化パスに焦点を当てた `osquery` FIM 設定例:<sup>[[1]](#references)</sup>
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
**process attribution** が必要で、path-level changes だけでは不十分な場合は、`osquery` の `process_file_events` や Wazuh の `whodata` mode など、audit-backed telemetry を優先してください。<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: syscall telemetry is not FIM

現代の Linux では、`openat(2)`、`write(2)`、その他の syscall entry point を監視することは、結果として生じる filesystem operation を監視することと**同等ではありません**。2025 年の **Curing** proof of concept では、`io_uring` を通じて file および network requests をキューに追加したため、対応する per-operation syscall entry にのみ紐付けられた製品やポリシーでは、process telemetry が失われました。同じテストでは、path-scoped FIM component が file modifications を引き続き検知しており、これは **hook-placement blind spot** であって、permission bypass や、すべての FIM backend を無効化する方法ではないことを示しています。<sup>[[10]](#references)</sup>

sensor を検証する際は、同じ canary を複数の経路で変更してください。通常の `write`、`mmap` + `msync`、`truncate`、`sendfile`/`copy_file_range`、atomic replacement、および `io_uring` を使用します。最終的な hash drift が検知されるかだけでなく、event に responsible process、container/cgroup、namespace-visible path、inode、rename pair が保持されているかも確認してください。real-time event が欠落し、その後の periodic-scan mismatch で検知された場合は、通常の説明不能な変更ではなく、**telemetry loss** として扱う必要があります。<sup>[[10]](#references)[[11]](#references)</sup>

eBPF-based monitoring では、syscall-entry probes のリストよりも、一般的な kernel enforcement points を優先してください。たとえば、Tetragon の file-access policy は `security_file_permission` を使用して、通常の I/O、`sendfile`、`copy_file_range`、AIO、および `io_uring` をカバーします。また、memory mappings は `security_mmap_file` で、size changes は `security_path_truncate` で個別にカバーします。これは、1 つの hook だけでは完全な coverage になることがほとんどない理由も示しています。<sup>[[11]](#references)</sup>

### Windows

Windows では、**change journals** と **high-signal process/file telemetry** を組み合わせると、FIM はより強固になります。<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** は、file changes の persistent な per-volume log を提供します。
- **Sysmon Event ID 11** は、file creation/overwrite に役立ちます。
- **Sysmon Event ID 2** は、**timestomping** の検知に役立ちます。
- **Sysmon Event ID 15** は、`Zone.Identifier` や hidden payload streams などの **named alternate data streams (ADS)** に役立ちます。

USN の簡単な triage 例:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
**timestamp manipulation**、**ADS abuse**、**USN tampering**に関する、より深いanti-forensicのアイデアについては、[Anti-Forensic Techniques](anti-forensic-techniques.md)を確認してください。

### Containers

Container FIMでは、実際のwrite pathを見落とすことがよくあります。Dockerの`overlay2`では、container filesystemはread-onlyのimage `lowerdir` layersと、書き込み可能な**upper layer**（`upperdir`/`diff`）を組み合わせて構成され、image filesへのwritesはそのupper layerへcopy upされます。<sup>[[8]](#references)</sup> したがって:

- 短期間だけ存在するcontainerの**内部**からpathのみを監視すると、containerの再作成後に発生したchangesを見落とす可能性があります。
- 書き込み可能なlayerを保持する**host path**、または関連するbind-mounted volumeを監視するほうが、多くの場合有用です。
- image layersに対するFIMは、running container filesystemに対するFIMとは異なります。

## Attacker-Oriented Hunting Notes

- binaryと同じくらい注意深く、**service definitions**と**task schedulers**を追跡してください。Attackersは`/bin/sshd`にpatchを適用するのではなく、unit file、cron entry、またはtask XMLを変更してpersistenceを得ることがよくあります。
- content hashだけでは不十分です。多くのcompromiseは、最初に**owner/mode/xattr/ACL drift**として現れます。
- 成熟したintrusionが疑われる場合は、両方を実施してください: 新しいactivityを検出する**real-time FIM**と、trusted mediaからの**cold baseline comparison**です。
- attackerがrootまたはkernel executionを取得している場合、FIM agentとそのdatabaseはuntrustedとして扱ってください。可能な限り、logsとbaselinesはremote、またはread-only mediaに保存してください。<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osqueryによるFile Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [LinuxのTracing: File Integrity Monitoringのユースケース（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring（Syscheckおよびwhodata mode）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring RootkitによるLinux Security ToolsのBypasses（ARMO）](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Filename access: synchronous、asynchronous、mapped、およびtruncation pathsを網羅（Tetragon）](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
