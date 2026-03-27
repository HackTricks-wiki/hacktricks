# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## ベースライン

ベースラインは、システムの特定部分のスナップショットを取得して、将来の状態と比較して変更点を強調することです。**compare it with a future status to highlight changes**

例えば、ファイルシステム上の各ファイルのハッシュを算出して保存すれば、どのファイルが変更されたかを特定できます。\
これは、作成されたユーザーアカウント、実行中のプロセス、稼働中のサービス、あるいはほとんど（または全く）変わるべきでないその他の項目にも適用できます。

A **useful baseline** usually stores more than just a digest: permissions, owner, group, timestamps, inode, symlink target, ACLs, and selected extended attributes are also worth tracking. From an attacker-hunting perspective, this helps detect **permission-only tampering**, **atomic file replacement**, and **persistence via modified service/unit files** even when the content hash is not the first thing that changes.

### File Integrity Monitoring

File Integrity Monitoring (FIM) は、ファイルの変更を追跡することで IT 環境とデータを保護する重要なセキュリティ技術です。通常は次を組み合わせます:

1. **Baseline comparison:** メタデータと暗号学的チェックサム（`SHA-256` またはそれ以上を推奨）を保存して将来の比較に備えます。  
2. **Real-time notifications:** OS ネイティブのファイルイベントに購読して、**どのファイルがいつ変更され、理想的にはどのプロセス/ユーザーが触ったか**を把握します。  
3. **Periodic re-scan:** 再起動、イベントのドロップ、エージェントの停止、または意図的なアンチフォレンジック活動の後に信頼性を再構築します。

脅威ハンティングのために、FIM は通常、**高価値パス**に焦点を当てるとより有用です。例:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## リアルタイムバックエンドと盲点

### Linux

収集バックエンドは重要です:

- **`inotify` / `fsnotify`**: 簡単で一般的だが、watch の上限に達する可能性があり、一部のエッジケースが見逃される。  
- **`auditd` / audit framework**: ファイルを**誰が変更したか**（`auid`、process、pid、executable）を把握したい場合に有利。  
- **`eBPF` / `kprobes`**: 近年の FIM スタックで使用される新しい選択肢で、イベントを強化し、単純な `inotify` デプロイによる運用上の負担を軽減する。

実際の注意点:

- プログラムが `write temp -> rename` によりファイルを**置換**する場合、ファイル自体を監視しても有用性が失われることがある。**ファイルだけでなく親ディレクトリを監視する**こと。  
- `inotify` ベースのコレクタは、**巨大なディレクトリツリー**、**ハードリンクの動作**、または**監視対象ファイルが削除された後**にイベントを見逃したり動作が劣化したりすることがある。  
- 再帰的な大規模ウォッチ集合は、`fs.inotify.max_user_watches`、`max_user_instances`、または `max_queued_events` が低すぎると黙って失敗する可能性がある。  
- ネットワークファイルシステムは、低ノイズ監視の対象としては通常適していない。

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
attacker persistence paths に焦点を当てた `osquery` FIM の設定例:
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
If you need **process attribution** instead of only path-level changes, prefer audit-backed telemetry such as `osquery` `process_file_events` or Wazuh `whodata` mode.

### Windows

Windows では、FIM は **変更ジャーナル** と **高信号のプロセス/ファイル テレメトリ** を組み合わせるとより強力になります：

- **NTFS USN Journal** はファイル変更の永続的なボリューム単位のログを提供します。
- **Sysmon Event ID 11** はファイルの作成や上書きの検出に有用です。
- **Sysmon Event ID 2** は **timestomping** の検出に役立ちます。
- **Sysmon Event ID 15** は `Zone.Identifier` や隠しペイロードストリームなどの **named alternate data streams (ADS)** に有用です。

Quick USN triage examples:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### コンテナ

コンテナの FIM は実際の書き込みパスを見逃すことがよくあります。Docker `overlay2` では、変更は読み取り専用のイメージレイヤーではなく、コンテナの **writable upper layer** (`upperdir`/`diff`) にコミットされます。したがって:

- 短命なコンテナの**内部**からだけパスを監視していると、コンテナが再作成された後の変更を見落とす可能性があります。
- 書き込みレイヤーを支える**ホストパス**や関連する bind-mounted ボリュームを監視する方が有用なことが多いです。
- イメージレイヤー上の FIM は、稼働中のコンテナのファイルシステムに対する FIM とは異なります。

## 攻撃者向けハンティングノート

- バイナリと同じくらい、**service definitions** と **task schedulers** を注意深く追跡してください。攻撃者はしばしば `/bin/sshd` をパッチする代わりに、unit file、cron エントリ、または task XML を変更して永続化を得ます。
- コンテンツハッシュだけでは不十分です。多くの侵害は最初に **owner/mode/xattr/ACL drift** として現れます。
- 成熟した侵害が疑われる場合は、両方行ってください：新しい活動のための **real-time FIM** と、信頼できる媒体からの **cold baseline comparison**。
- 攻撃者が root やカーネル実行権を持っている場合、FIM エージェント、そのデータベース、さらにはイベントソースまでも改ざんされうると想定してください。ログやベースラインは可能な限りリモートまたは読み取り専用メディアに保存してください。

## ツール

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## 参考文献

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
