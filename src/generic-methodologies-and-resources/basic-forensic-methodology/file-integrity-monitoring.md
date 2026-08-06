# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline とは、システムの特定部分のスナップショットを取得し、**将来の状態と比較して変更を明らかにする**ことです。

たとえば、ファイルシステム内の各ファイルの hash を計算して保存すれば、どのファイルが変更されたかを特定できます。\
これは、作成された user account、実行中の process、実行中の service、その他、大きく変更されるべきではないもの、あるいはまったく変更されるべきでないものにも適用できます。

**有用な baseline** では通常、digest だけでなく、permissions、owner、group、timestamps、inode、symlink target、ACL、選択した extended attributes も追跡します。attacker hunting の観点では、content hash が最初に変化しない場合でも、**permission-only tampering**、**atomic file replacement**、**変更された service/unit file を介した persistence** の検知に役立ちます。

### File Integrity Monitoring

File Integrity Monitoring (FIM) は、file の変更を追跡することで IT environment と data を保護する、重要な security technique です。通常は以下を組み合わせます。

1. **Baseline comparison:** 将来の比較に備えて、metadata と cryptographic checksum（`SHA-256` 以上を推奨）を保存します。
2. **Real-time notifications:** OS native の file event を購読し、**どの file が、いつ変更され、理想的にはどの process/user が操作したか**を把握します。
3. **Periodic re-scan:** reboot、event の取りこぼし、agent の停止、または意図的な anti-forensic activity の後に、信頼性を再構築します。

Threat hunting では、FIM は通常、以下のような**高価値な path**に対象を絞ると、より有用になります。

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` unit、cron の配置場所、SSH material、PAM module、web root
- Windows の persistence location、service binary、scheduled task file、startup folder
- Container の writable layer と bind-mount された secret/configuration

## Real-Time Backends & Blind Spots

### Linux

収集 backend は重要です。<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: 容易で一般的ですが、watch limit が枯渇する可能性があり、一部の edge case は見逃されます。
- **`auditd` / audit framework**: **誰が file を変更したか**（`auid`、process、pid、executable）を把握する必要がある場合に優れています。
- **`eBPF` / `kprobes`**: modern FIM stack で使用される新しい option で、event の情報を拡充し、単純な `inotify` deployment における運用上の負担を一部軽減します。

実際に注意すべき点を以下に示します。<sup>[[1]](#references)</sup>

- Program が `write temp -> rename` によって file を**置き換える**場合、file 自体を watch しても役に立たなくなる可能性があります。file だけでなく、**親 directory を watch**してください。
- `inotify` ベースの collector は、**巨大な directory tree**、**hard-link activity**、または **watch 中の file が削除された後**に、event を取りこぼしたり、性能が低下したりする可能性があります。
- 再帰的な watch set が非常に大きい場合、`fs.inotify.max_user_watches`、`max_user_instances`、または `max_queued_events` の値が低すぎると、気付かないうちに失敗する可能性があります。
- Network filesystem は、noise の少ない monitoring を行う FIM の対象としては、通常適していません。

AIDE を使用した baseline + verification の例:
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
**プロセス帰属**が必要で、パスレベルの変更だけでは不十分な場合は、`osquery` の `process_file_events` や Wazuh の `whodata` mode など、audit に基づく telemetry を優先してください。<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows では、**change journals** と**high-signal なプロセス/ファイル telemetry**を組み合わせることで、FIM の精度が向上します。

- **NTFS USN Journal** は、ファイル変更の永続的なボリューム単位のログを提供します。
- **Sysmon Event ID 11** は、ファイルの作成や上書きの検出に役立ちます。
- **Sysmon Event ID 2** は、**timestomping** の検出に役立ちます。
- **Sysmon Event ID 15** は、`Zone.Identifier` や hidden payload streams などの**名前付き alternate data streams (ADS)** に役立ちます。

USN triage の簡単な例:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
**timestamp manipulation**、**ADS abuse**、**USN tampering**に関する、より深い anti-forensic のアイデアについては、[Anti-Forensic Techniques](anti-forensic-techniques.md) を確認してください。

### コンテナ

Container FIM では、実際の書き込み経路を見落とすことがよくあります。Docker の `overlay2` では、変更は読み取り専用の image layers ではなく、コンテナの **writable upper layer**（`upperdir`/`diff`）にコミットされます。そのため、以下の点に注意してください。

- 短期間で破棄されるコンテナの **内部** のパスだけを監視していると、コンテナの再作成後に発生した変更を見落とす可能性があります。
- **writable layer** の基盤となる **host path**、または関連する bind-mounted volume を監視するほうが有用な場合があります。
- image layers に対する FIM は、実行中のコンテナ filesystem に対する FIM とは異なります。

## Attacker-Oriented Hunting Notes

- バイナリと同じように、**service definitions** と **task schedulers** を注意深く追跡してください。攻撃者は `/bin/sshd` にパッチを適用するのではなく、unit file、cron entry、または task XML を変更して persistence を確保することがよくあります。
- content hash だけでは不十分です。多くの compromise は、まず **owner/mode/xattr/ACL drift** として現れます。
- 成熟した intrusion が疑われる場合は、両方を実施してください。新しい活動を検出する **real-time FIM** と、trusted media から取得した **cold baseline comparison** です。
- 攻撃者が root または kernel execution を取得している場合は、FIM agent、その database、さらには event source さえも改ざんされていると想定してください。可能な限り、logs と baselines はリモートまたは read-only media に保存してください。

## ツール

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 参考資料

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
