# ファイル整合性監視

{{#include ../../banners/hacktricks-training.md}}

## ベースライン

ベースラインとは、システムの特定の部分のスナップショットを取得し、**将来の状態と比較して変更を明らかにする**ことです。

例えば、ファイルシステム内の各ファイルのハッシュを計算して保存し、どのファイルが変更されたかを特定できるようにします。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービス、その他ほとんど、またはまったく変更されるべきでないものについても実行できます。

**有用なベースライン**では、通常、ダイジェストだけでなく、パーミッション、所有者、グループ、タイムスタンプ、inode、シンボリックリンクのターゲット、ACL、選択した拡張属性も保存する価値があります。<sup>[[4]](#references)</sup> 攻撃者ハンティングの観点では、これにより、コンテンツハッシュが最初に変化しない場合でも、**パーミッションのみの改ざん**、**atomic file replacement**、**変更された service/unit ファイルを介した永続化**を検知できます。

### ファイル整合性監視

File Integrity Monitoring (FIM) は、ファイルの変更を追跡することでIT環境とデータを保護する、重要なセキュリティ技術です。通常、以下を組み合わせます。<sup>[[1]](#references)[[3]](#references)</sup>

1. **ベースライン比較:** 将来の比較に備えて、メタデータと暗号学的チェックサム（`SHA-256`またはそれ以上を推奨）を保存します。
2. **リアルタイム通知:** OSネイティブのファイルイベントを購読し、**どのファイルが、いつ変更され、理想的にはどのプロセスまたはユーザーが操作したか**を把握します。
3. **定期的な再スキャン:** 再起動、イベントの欠落、agentの停止、または意図的なanti-forensic activityの後に、信頼性を再構築します。

Threat hunting では、FIM は通常、次のような**高価値のパス**に焦点を絞ると、より有用になります。

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` units、cron の場所、SSH material、PAM modules、web roots
- Windows の persistence locations、service binaries、scheduled task files、startup folders
- Container writable layers と bind-mounted secrets/configuration

## リアルタイムバックエンドと死角

### Linux

収集バックエンドは重要です。<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: 簡単で一般的ですが、watch limits が枯渇する可能性があり、一部の edge cases が見逃されます。
- **`auditd` / audit framework**: **誰がファイルを変更したか**（login UID、process ID、process name）が必要な場合に適しています。
- **`eBPF` / `kprobes`**: plain `inotify` deployments における運用上の負担の一部を軽減し、イベントを拡張するために modern FIM stacks で使用される新しい選択肢です。

実務上の注意点: <sup>[[1]](#references)[[5]](#references)</sup>

- プログラムが `write temp -> rename` によってファイルを**置き換える**場合、ファイル自体を監視しても役に立たなくなる可能性があります。ファイルだけでなく、**親ディレクトリを監視**してください。
- `inotify`-based collectors は、**巨大なディレクトリツリー**、**hard-link activity**、または**監視対象のファイルが削除された後**に、イベントを見逃したり、機能が低下したりする可能性があります。
- 再帰的な watch set が非常に大きい場合、`fs.inotify.max_user_watches`、`max_user_instances`、または `max_queued_events` の値が低すぎると、fsnotify は通知なしに失敗することがあります。
- `inotify`-based monitoring では、network filesystems は死角になります。リモートでの変更は報告されないためです。

AIDE を使用したベースライン作成と検証の例: <sup>[[4]](#references)</sup>
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
If you need **process attribution** instead of only path-level changes, prefer audit-backed telemetry such as `osquery` `process_file_events` or Wazuh `whodata` mode.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

On Windows, FIM is stronger when you combine **change journals** with **high-signal process/file telemetry**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** gives a persistent per-volume log of file changes.
- **Sysmon Event ID 11** is useful for file creation/overwrite.
- **Sysmon Event ID 2** helps detect **timestomping**.
- **Sysmon Event ID 15** is useful for **named alternate data streams (ADS)** such as `Zone.Identifier` or hidden payload streams.

USN の簡易トリアージ例:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
より深い **timestamp manipulation**、**ADS abuse**、**USN tampering** に関する anti-forensic のアイデアについては、[Anti-Forensic Techniques](anti-forensic-techniques.md) を確認してください。

### コンテナ

Container FIM では、実際の書き込み経路を見落とすことがよくあります。Docker の `overlay2` では、コンテナのファイルシステムは読み取り専用のイメージ **lowerdir** レイヤーと、書き込み可能な **upper layer**（`upperdir`/`diff`）を組み合わせて構成されます。また、イメージファイルへの書き込みは、その **upper layer** に copy-up されます。<sup>[[8]](#references)</sup> そのため、以下の点に注意してください。

- 短時間だけ存在するコンテナの**内部**パスのみを監視していると、コンテナの再作成後に発生した変更を見落とす可能性があります。
- 書き込み可能なレイヤーの基盤となる**ホストパス**や、関連する bind-mounted volume を監視するほうが有用な場合が多くあります。
- イメージレイヤーに対する FIM と、実行中のコンテナファイルシステムに対する FIM は異なります。

## 攻撃者視点のハンティングメモ

- バイナリと同じように、**サービス定義**と**タスクスケジューラ**を慎重に追跡してください。攻撃者は `/bin/sshd` にパッチを適用するのではなく、unit file、cron エントリ、task XML を変更して persistence を確保することがよくあります。
- コンテンツハッシュだけでは不十分です。多くの compromise は、まず **owner/mode/xattr/ACL drift** として現れます。
- 成熟した intrusion が疑われる場合は、**real-time FIM** による新たな activity の監視と、信頼できるメディアからの **cold baseline comparison** の両方を実施してください。
- 攻撃者が root または kernel execution を取得している場合、FIM agent とその database は untrusted として扱ってください。可能な限り、ログと baseline はリモートまたは read-only media に保存します。<sup>[[4]](#references)</sup>

## ツール

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osquery による File Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Linux の tracing: File Integrity Monitoring のユースケース（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring（Syscheck と whodata mode）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
