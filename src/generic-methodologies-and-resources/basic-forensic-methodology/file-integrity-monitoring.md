# ファイル整合性監視

## 基準状態

基準状態とは、システムの特定部分のスナップショットを取得し、**将来の状態と比較して変更を明らかにする**ことです。

たとえば、ファイルシステム内の各ファイルのハッシュを計算して保存すれば、どのファイルが変更されたかを確認できます。\
これは、作成されたユーザーアカウント、実行中のプロセス、実行中のサービス、その他あまり変更されるべきでないもの、またはまったく変更されるべきでないものにも適用できます。

**有用な基準状態**では、通常、ダイジェストだけでなく、権限、所有者、グループ、タイムスタンプ、inode、シンボリックリンクのターゲット、ACL、選択した拡張属性も保存して追跡します。<sup>[[4]](#references)</sup> 攻撃者ハンティングの観点では、コンテンツハッシュに最初の変化が現れない場合でも、**権限のみの改ざん**、**atomic file replacement**、**変更されたサービス/unitファイルを介した永続化**の検出に役立ちます。

### ファイル整合性監視

File Integrity Monitoring (FIM) は、ファイルの変更を追跡することでIT環境とデータを保護する重要なセキュリティ技術です。通常、以下を組み合わせます。<sup>[[1]](#references)[[3]](#references)</sup>

1. **基準状態との比較:** 将来の比較に備えて、メタデータと暗号学的チェックサム（`SHA-256`以上を推奨）を保存します。
2. **リアルタイム通知:** OSネイティブのファイルイベントを購読し、**どのファイルが、いつ変更され、理想的にはどのプロセス/ユーザーが操作したか**を把握します。
3. **定期的な再スキャン:** 再起動、イベントの欠落、agentの停止、または意図的なanti-forensic activityの後に、信頼性を再構築します。

threat huntingでは、FIMは通常、以下のような**高価値なパス**に対象を絞ると、より有用です。

- `/etc`、`/boot`、`/usr/local/bin`、`/usr/local/sbin`
- `systemd` unit、cronの配置場所、SSHマテリアル、PAMモジュール、web root
- Windowsの永続化場所、サービスバイナリ、scheduled taskファイル、startup folder
- コンテナの書き込み可能レイヤー、bind-mountされたsecret/configuration

## リアルタイムバックエンドと盲点

### Linux

収集バックエンドは重要です。<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: 簡単で一般的ですが、watch limitを使い果たす可能性があり、一部のedge caseを見逃します。
- **`auditd` / audit framework**: **誰がファイルを変更したか**（login UID、process ID、process name）が必要な場合に適しています。
- **`eBPF` / `kprobes`**: modern FIM stackで使用される新しい選択肢で、イベントを拡充し、単純な`inotify`導入に伴う運用上の負担の一部を軽減します。

実用上の注意点:<sup>[[1]](#references)[[5]](#references)</sup>

- プログラムが`write temp -> rename`でファイルを**置き換える**場合、ファイル自体を監視しても役に立たなくなることがあります。ファイルだけでなく、**親ディレクトリを監視**してください。
- `inotify`ベースのcollectorは、**巨大なディレクトリツリー**、**hard-link activity**、または**監視対象ファイルが削除された後**に、イベントを見逃したり、性能が低下したりすることがあります。
- 再帰的なwatch setが非常に大きい場合、`fs.inotify.max_user_watches`、`max_user_instances`、または`max_queued_events`の値が低すぎると、警告なく失敗することがあります。
- `inotify`ベースの監視では、remote changeが報告されないため、network filesystemは盲点になります。

AIDEを使用した基準状態の作成と検証の例:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
攻撃者の永続化パスに焦点を当てた`osquery` FIM設定の例:<sup>[[1]](#references)</sup>
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
**process attribution**が必要で、パスレベルの変更だけでは不十分な場合は、`osquery` の `process_file_events` や Wazuh の `whodata` mode など、audit に裏付けられた telemetry を優先してください。<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Windows では、**change journals** と **high-signal process/file telemetry** を組み合わせることで、FIM の精度が向上します。<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** は、ファイル変更の永続的なボリューム単位のログを提供します。
- **Sysmon Event ID 11** は、ファイルの作成や上書きの検出に役立ちます。
- **Sysmon Event ID 2** は、**timestomping** の検出に役立ちます。
- **Sysmon Event ID 15** は、`Zone.Identifier` や hidden payload streams などの **named alternate data streams (ADS)** に役立ちます。

USN の簡単な triage 例:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
**timestamp manipulation**、**ADS abuse**、**USN tampering**に関する、より詳しいanti-forensicのアイデアについては、[Anti-Forensic Techniques](anti-forensic-techniques.md)を確認してください。

### Containers

Container FIMでは、実際の書き込み経路を見落とすことがよくあります。Dockerの`overlay2`では、コンテナのファイルシステムは読み取り専用のイメージ`lowerdir`レイヤーと、書き込み可能な**upper layer**（`upperdir`/`diff`）を組み合わせて構成され、イメージファイルへの書き込みはその**upper layer**へcopy upされます。<sup>[[8]](#references)</sup> したがって、以下の点に注意してください。

- 短時間しか存在しないコンテナの**内部**パスのみを監視していると、コンテナが再作成された後の変更を見落とす可能性があります。
- 書き込み可能なレイヤーを支える**host path**、または関連するbind-mounted volumeを監視するほうが有用な場合が多くあります。
- イメージレイヤーに対するFIMは、実行中のコンテナファイルシステムに対するFIMとは異なります。

## Attacker-Oriented Hunting Notes

- バイナリと同じように、**service definitions**と**task schedulers**を慎重に追跡してください。攻撃者は`/bin/sshd`にパッチを適用するのではなく、unit file、cron entry、またはtask XMLを変更してpersistenceを確保することがよくあります。
- コンテンツハッシュだけでは不十分です。多くのcompromiseは、まず**owner/mode/xattr/ACL drift**として現れます。
- 成熟したintrusionを疑う場合は、**real-time FIM**による新たな活動の監視と、信頼できるメディアからの**cold baseline comparison**の両方を実施してください。
- 攻撃者がrootまたはkernel executionを取得している場合、FIM agentとそのデータベースを信頼できないものとして扱ってください。可能な限り、ログとbaselineをリモート、または読み取り専用メディアに保存してください。<sup>[[4]](#references)</sup>

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [osqueryによるFile Integrity Monitoring](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [LinuxのTracing：File Integrity Monitoringのユースケース（Elastic）](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring（Syscheckおよびwhodata mode）](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [AIDE Manual Version 0.16.2](https://aide.github.io/doc/)
- [5] [inotify(7) Linux manual page](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [OverlayFS storage driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
