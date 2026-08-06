# iOS Backup Forensics（Messaging-centric triage）

{{#include ../../banners/hacktricks-training.md}}

このページでは、messaging app の添付ファイルを介した 0-click exploit delivery の痕跡を再構成・分析するための、iOS backup の実践的な手順を説明します。Apple の hashed backup layout を human-readable なパスに変換し、一般的なアプリ全体で添付ファイルを列挙・スキャンすることに重点を置いています。

Goals:
- Manifest.db から readable paths を再構築する
- messaging databases（iMessage、WhatsApp、Signal、Telegram、Viber）を列挙する
- attachment paths を解決し、埋め込まれたオブジェクト（PDF/Images/Fonts）を抽出して structural detectors に渡す


## iOS backup の再構築

MobileSync に保存された backup は、human-readable ではない hashed filenames を使用します。Manifest.db SQLite database は、保存された各オブジェクトを logical path にマッピングします。

High-level procedure:
1) Manifest.db を開き、file records（domain、relativePath、flags、fileID/hash）を読み取る
2) domain + relativePath に基づいて、元の folder hierarchy を再作成する
3) 各 stored object を reconstructed path にコピーまたは hardlink する

この処理を end-to-end で実行する tool（ElegantBouncer）を使用した example workflow:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注意:
- 暗号化されたバックアップは、extractor にバックアップパスワードを渡して処理する
- 証拠としての価値を保つため、可能な限り元のタイムスタンプ/ACL を保持する

### バックアップの取得と復号（USB / Finder / libimobiledevice）

- macOS/Finder で「ローカルバックアップを暗号化」を設定し、キーチェーン項目が含まれるように*新規の*暗号化バックアップを作成する。
- クロスプラットフォームの場合: `idevicebackup2`（libimobiledevice ≥1.4.0）は iOS 17/18 のバックアッププロトコルの変更に対応しており、以前の restore/backup handshake エラーを修正している。<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### MVTによるIOC駆動のトリアージ

AmnestyのMobile Verification Toolkit（mvt-ios）は、暗号化されたiTunes/Finderバックアップを直接処理できるようになり、傭兵型スパイウェアのケースにおける復号とIOCマッチングを自動化します。<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
出力は `mvt-results/` 配下に保存され（例: analytics_detected.json、safari_history_detected.json）、以下で復元された添付ファイルのパスと相関分析できます。

### 一般的なアーティファクト解析（iLEAPP）

メッセージング以外のタイムラインやメタデータを解析するには、バックアップフォルダーに対して iLEAPP を直接実行します（iOS 11〜17 のスキーマに対応）。
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

復元後、popular apps の添付ファイルを列挙します。正確な schema は app/version によって異なりますが、approach は同様です。messaging database を query し、messages と attachments を join して、disk 上の paths を解決します。<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Example queries:
```sql
-- List attachments with basic message linkage
SELECT
m.ROWID            AS message_rowid,
a.ROWID            AS attachment_rowid,
a.filename         AS attachment_path,
m.handle_id,
m.date,
m.is_from_me
FROM message m
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;

-- Include chat names via chat_message_join
SELECT
c.display_name,
a.filename AS attachment_path,
m.date
FROM chat c
JOIN chat_message_join cmj ON cmj.chat_id = c.ROWID
JOIN message m ON m.ROWID = cmj.message_id
JOIN message_attachment_join maj ON maj.message_id = m.ROWID
JOIN attachment a ON a.ROWID = maj.attachment_id
ORDER BY m.date DESC;
```
Attachment のパスは、絶対パスの場合と、Library/SMS/Attachments/ 配下の再構築されたツリーを基準とした相対パスの場合があります。

### WhatsApp (ChatStorage.sqlite)
一般的な関連付け: message テーブル ↔ media/attachment テーブル（バージョンによって名称は異なります）。media の行をクエリして、ディスク上のパスを取得します。最近の iOS ビルドでも、ZWAMEDIAITEM 内の `ZMEDIALOCALPATH` は引き続き確認できます。
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
通常、パスは再構築された backup 内の `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 以下に解決されます。

### Signal / Telegram / Viber
- Signal: message DB は暗号化されていますが、disk 上に cached された attachments（および thumbnails）は通常 scan 可能です
- Telegram: cache は sandbox 内の `Library/Caches/` 以下に残ります。iOS 18 builds では cache-clearing bugs が見られるため、大量の残存 media cache が一般的な evidence sources になります<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite には message/attachment tables と disk 上の references が含まれています

Tip: metadata が暗号化されている場合でも、media/cache directories を scan することで malicious objects が見つかることがあります。


## structural exploits のための attachments の scan

attachment paths を取得したら、signatures ではなく file-format invariants を検証する structural detectors に渡します。ElegantBouncer を使った例:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
構造ルールで検出されるものには、以下が含まれます。<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 不可能な JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 過大な Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): 文書化されていない bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata と stream component の不一致


## Validation、注意事項、false positives

- Time conversions: iMessage は一部のバージョンで Apple epochs/units に基づいて日付を保存するため、reporting 時に適切に変換する
- Schema drift: app SQLite schemas は時間の経過とともに変化するため、device build ごとに table/column names を確認する
- Recursive extraction: PDF には JBIG2 streams や fonts が埋め込まれている場合があるため、inner objects を抽出して scan する
- False positives: structural heuristics は保守的ですが、まれに存在する malformed だが benign な media を検出する場合がある<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
