# iOS Backup Forensics（Messaging-centric triage）

このページでは、messaging app の添付ファイルを介した 0-click exploit delivery の痕跡を調査するために、iOS backup を再構築・分析する実践的な手順を説明します。Apple の hash 化された backup layout を human-readable な path に変換し、一般的な app 全体で添付ファイルを列挙・scan することに焦点を当てています。

目標:
- Manifest.db から readable path を再構築する
- messaging database（iMessage、WhatsApp、Signal、Telegram、Viber）を列挙する
- attachment path を解決し、対応している場合は埋め込みオブジェクト（PDF/Images/Fonts）を抽出して structural detector に渡す


## iOS backup の再構築

MobileSync 配下に保存された backup は、human-readable ではない hash 化されたファイル名を使用します。SQLite database である Manifest.db は、各保存オブジェクトを logical path にマッピングします。<sup>[[1]](#references)[[2]](#references)</sup>

High-level procedure:
1) Manifest.db を開き、file record（domain、relativePath、flags、fileID/hash）を読み取る
2) domain + relativePath に基づいて元の folder hierarchy を再作成する
3) 各保存オブジェクトを再構築した path に copy または hardlink する

この処理を end-to-end で実装する tool（ElegantBouncer）を使用した workflow 例:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- 再構築ツールに渡す前に、暗号化されたバックアップを復号してください。ElegantBouncer は復号済みのバックアップを必要とします。<sup>[[2]](#references)[[3]](#references)</sup>
- 証拠としての価値を保つため、可能な限り元のタイムスタンプ/ACL を保持してください

### バックアップの取得と復号（USB / Finder / libimobiledevice）

- Finder/Apple Devices/iTunes で「Encrypt local backup」を有効にして新しいバックアップを作成します。暗号化されたバックアップには、暗号化されていないバックアップでは省略される保存済みパスワードや Health データが含まれる場合があります。<sup>[[8]](#references)</sup>
- クロスプラットフォームでは、libimobiledevice 1.4.0 に `idevicebackup2` の修正が含まれています。<sup>[[4]](#references)</sup> 対話的に暗号化を有効にしてから、記載されたコマンド順序を使用し、対象ディレクトリを最後に指定して完全なバックアップを強制的に実行します。<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVT による IOC 主導のトリアージ

Amnesty’s Mobile Verification Toolkit は、暗号化された iTunes/Finder バックアップから key を抽出して復号し、その後、復号されたバックアップを STIX2 IOC ファイルでスキャンできます。<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o` を指定すると、JSON の結果は `/tmp/mvt-results/` 配下に書き込まれます。IOC マッチには `_detected` サフィックスが付加され、以下で復元された添付ファイルのパスと相関付けることができます。<sup>[[3]](#references)</sup>

### 一般的なアーティファクト解析（iLEAPP）

メッセージング以外のタイムラインやメタデータを解析するには、raw backup フォルダーに対して iLEAPP を実行します。`itunes` 入力タイプは iTunes/Finder backups を受け付け、現行リリースでは iOS/iPadOS 11 から現行バージョンまでサポートされています。<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## メッセージングアプリの添付ファイル列挙

復元後、主要なアプリの添付ファイルを列挙します。正確なスキーマはアプリやバージョンによって異なりますが、アプローチは似ています。メッセージングデータベースにクエリを実行し、メッセージと添付ファイルを結合して、ディスク上のパスを解決します。<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
主要なテーブル: message、attachment、message_attachment_join (MAJ)、chat、chat_message_join (CMJ)。<sup>[[2]](#references)</sup>

クエリ例:
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
Attachment のパスは、絶対パスの場合と、Library/SMS/Attachments 配下の再構築されたツリーを基準とする相対パスの場合があります。<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
一般的な関連付け: message table ↔ media/attachment table（命名はバージョンによって異なります）。media rows をクエリして、ディスク上のパスを取得します。Belkasoft は、`ZWAMEDIAITEM` 内の `ZMEDIALOCALPATH` を media-file の場所として識別します。ElegantBouncer の現在の実装では、`ZWAMEDIAITEM.ZMESSAGE` と `ZWAMESSAGE.Z_PK` を結合し、`Media/` で始まるパスを解決する際に `Message/` を先頭に付加します。<sup>[[9]](#references)[[10]](#references)</sup>
```sql
SELECT
m.Z_PK                 AS message_pk,
mi.ZMEDIALOCALPATH     AS media_path,
datetime(m.ZMESSAGEDATE + 978307200, 'unixepoch') AS message_date,
CASE m.ZISFROMME WHEN 1 THEN 'outgoing' ELSE 'incoming' END AS direction
FROM ZWAMEDIAITEM mi
JOIN ZWAMESSAGE m ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
For that ElegantBouncer reconstruction path, `Media/` で始まる media path は `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 配下に解決されます。一方、Belkasoft の guide では `Messages/Media/` path が記載されているため、どちらの表記かを決めつける前に backup を確認してください。<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB は encrypted です。ただし、disk 上に cached された attachments（および thumbnails）は通常 scan 可能です。<sup>[[2]](#references)</sup>
- Telegram: app の media/cache directories を確認してください。Telegram は iOS 18.0.1 上の iOS app 11.2 で cache-cleanup bug を documented しており、11.3 で fixed とされています。そのため、残存 files を確認してください。<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite には、disk 上の references を持つ message/attachment tables が含まれています。<sup>[[2]](#references)</sup>

Tip: metadata が encrypted されている場合でも、media/cache directories を scan することで malicious objects を発見できます。<sup>[[2]](#references)</sup>


## structural exploits のための attachments の Scanning

attachment paths を取得したら、signatures ではなく file-format invariants を検証する structural detectors に渡します。ElegantBouncer を使用した例:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
構造ルールで対象となる検出には、以下が含まれます。<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 不可能な JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata と stream component の不一致


## 検証、注意事項、false positives

- 時刻変換: iMessage は一部のバージョンで Apple の epoch/units を使用して日付を保存するため、報告時には適切に変換してください。<sup>[[2]](#references)</sup>
- Schema drift: app SQLite schemas は時間の経過とともに変化するため、device build ごとに table/column names を確認してください
- Recursive extraction: PDF には JBIG2 streams や fonts が埋め込まれている場合があるため、内部オブジェクトを抽出してスキャンできる parser を使用してください
- False positives: structural heuristics は保守的ですが、まれに存在する malformed だが無害な media を検出する場合があります。<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [サンプルを入手できなくても脅威を検出する必要がある場合の ELEGANTBOUNCER](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP project (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [iPhone、iPad、iPod touch の encrypted backups について (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Belkasoft X による iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner and path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
