# ファイル完全性監視

{{#include ../../banners/hacktricks-training.md}}

## ベースライン

ベースラインとは、システムの特定部分のスナップショットを取得し、**将来の状態と比較して変更点を明らかにする**ものです。

たとえば、ファイルシステム内の各ファイルのハッシュを計算して保存すれば、どのファイルが変更されたかを特定できます。\
作成されたユーザーアカウント、実行中のプロセス、実行中のサービスなど、大きく変更されるべきではないもの、またはまったく変更されるべきでないものにも同じことを行えます。

**有用なベースライン**には通常、digest だけでなく、権限、所有者、グループ、タイムスタンプ、inode、symlink のターゲット、ACL、選択した拡張属性も保存します。攻撃者ハンティングの観点では、これにより、コンテンツハッシュに最初の変更が現れない場合でも、**権限のみの改ざん**、**atomic file replacement**、**変更された service/unit ファイルによる persistence**を検出しやすくなります。

### File Integrity Monitoring

File Integrity Monitoring (FIM) は、ファイルの変更を追跡することで IT 環境とデータを保護する、重要なセキュリティ技術です。通常は以下を組み合わせます。

1. **ベースライン比較:** 将来の比較に備えて、メタデータと暗号学的チェックサム（`SHA-256` 以上を推奨）を保存します。
2. **リアルタイム通知:** OS ネイティブのファイルイベントを購読し、**どのファイルが、いつ変更され、理想的にはどのプロセス/ユーザーが操作したか**を把握します。
3. **定期的な再スキャン:** reboot、イベントの取りこぼし、agent の停止、または意図的な anti-forensic activity の後に、信頼性を再構築します。

Threat hunting では、FIM は通常、以下のような**高価値な path**に焦点を当てると、より有用です。

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron の場所、SSH material、PAM modules、web roots
- Windows の persistence locations、service binaries、scheduled task files、startup folders
- Container writable layers と bind-mounted secrets/configuration

## リアルタイムバックエンドと盲点

### Linux

収集バックエンドは重要です。<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: 簡単で一般的ですが、watch limit が枯渇する可能性があり、一部の edge case を見逃します。
- **`auditd` / audit framework**: **誰がファイルを変更したか**（`auid`、process、pid、executable）が必要な場合に優れています。
- **`eBPF` / `kprobes`**: modern FIM stacks で使用される新しい選択肢で、イベントを enrich し、単純な `inotify` deployments における運用上の負担を一部軽減します。

実際に注意すべき点は以下のとおりです。<sup>[[1]](#references)</sup>

- プログラムが `write temp -> rename` でファイルを**置き換える**場合、ファイル自体を監視しても有用でなくなる可能性があります。ファイルだけでなく、**親ディレクトリを監視**してください。
- `inotify`-based collectors は、**巨大なディレクトリツリー**、**hard-link activity**、または**監視対象のファイルが削除された後**に、イベントを見逃したり性能が低下したりする可能性があります。
- `fs.inotify.max_user_watches`、`max_user_instances`、`max_queued_events` の値が低すぎると、非常に大規模な recursive watch sets が警告なしに失敗する可能性があります。
- Network filesystems は通常、noise の少ない monitoring の FIM targets には適していません。

AIDE を使用したベースライン作成と verification の例:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
攻撃者の永続化パスに焦点を当てた `osquery` FIM 設定例：<sup>[[1]](#references)</sup>
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
プロセスの帰属情報が必要で、パスレベルの変更だけでは不十分な場合は、`osquery` の `process_file_events` や Wazuh の `whodata` mode など、audit に基づく telemetry を優先します。<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Windows では、**change journals** と **high-signal process/file telemetry** を組み合わせることで、FIM の精度が向上します。

- **NTFS USN Journal** は、ファイル変更に関する永続的なボリューム単位のログを提供します。
- **Sysmon Event ID 11** は、ファイルの作成や上書きの検出に有用です。
- **Sysmon Event ID 2** は、**timestomping** の検出に役立ちます。
- **Sysmon Event ID 15** は、`Zone.Identifier` や hidden payload streams などの **named alternate data streams (ADS)** に有用です。

USN の簡単な triage の例:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
**timestamp manipulation**、**ADS abuse**、**USN tampering**に関する、より深いanti-forensicのアイデアについては、[Anti-Forensic Techniques](anti-forensic-techniques.md)を確認してください。

### コンテナ

Container FIMでは、実際のwrite pathを見落とすことがよくあります。Dockerの`overlay2`では、変更はread-onlyのimage layersではなく、コンテナの**writable upper layer**（`upperdir`/`diff`）にcommitされます。したがって：

- 短命なコンテナ**内部**のパスだけを監視していると、コンテナが再作成された後の変更を見落とす可能性があります。
- writable layerをバッキングする**host path**、または関連するbind-mounted volumeを監視する方が有用な場合が多くあります。
- image layersに対するFIMは、実行中のcontainer filesystemに対するFIMとは異なります。

## Attacker-Oriented Hunting Notes

- バイナリと同じくらい慎重に、**service definitions**と**task schedulers**を追跡してください。攻撃者は`/bin/sshd`をpatchするのではなく、unit file、cron entry、またはtask XMLを変更してpersistenceを得ることがよくあります。
- content hashだけでは不十分です。多くのcompromiseは、まず**owner/mode/xattr/ACL drift**として現れます。
- 成熟したintrusionが疑われる場合は、**real-time FIM**による新しいactivityの検知と、信頼できるmediaからの**cold baseline comparison**の両方を実施してください。
- 攻撃者がrootまたはkernel executionを取得している場合、FIM agent、そのdatabase、さらにはevent sourceまでtamperされていると想定してください。可能な限り、logsとbaselinesはremote、またはread-only mediaに保存してください。

## ツール

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 参考文献

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
