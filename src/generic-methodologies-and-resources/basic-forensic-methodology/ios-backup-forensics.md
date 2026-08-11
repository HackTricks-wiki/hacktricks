# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

このページでは、messaging app の添付ファイルを介した 0‑click exploit delivery の痕跡を確認するために、iOS backup を再構築して分析する実践的な手順を説明します。Apple の hashed backup layout を human‑readable paths に変換し、一般的な app 全体で添付ファイルを列挙・スキャンすることに重点を置いています。

Goals:
- Manifest.db から readable paths を再構築する
- messaging databases（iMessage、WhatsApp、Signal、Telegram、Viber）を列挙する
- attachment paths を解決し、対応している場合は埋め込みオブジェクト（PDF/Images/Fonts）を抽出して、structural detectors に渡す


## iOS backup の再構築

MobileSync 配下に保存された backup は、human‑readable ではない hashed filenames を使用しています。Manifest.db SQLite database は、各 stored object を logical path にマッピングします。<sup>[[1]](#references)[[2]](#references)</sup>

High‑level procedure:
1) Manifest.db を開き、file records（domain、relativePath、flags、fileID/hash）を読み取る
2) domain + relativePath に基づいて元の folder hierarchy を再作成する
3) 各 stored object を再構築した path に copy または hardlink する

この処理を end‑to‑end で実装する tool（ElegantBouncer）を使用した Example workflow:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注:
- 暗号化された backup は reconstruction tool に渡す前に復号してください。ElegantBouncer は復号済みの backup を想定しています。<sup>[[2]](#references)[[3]](#references)</sup>
- 証拠価値を保つため、可能な限り元の timestamps/ACLs を保持してください。

### backup の取得と復号（USB / Finder / libimobiledevice）

- Finder/Apple Devices/iTunes で "Encrypt local backup" を有効にして新しい backup を作成します。暗号化された backup には、暗号化されていない backup では省略される保存済みパスワードや Health データが含まれる場合があります。<sup>[[8]](#references)</sup>
- クロスプラットフォームでは、libimobiledevice 1.4.0 に `idevicebackup2` の修正が含まれています。<sup>[[4]](#references)</sup> 対話形式で暗号化を有効にした後、記載されたコマンドの順序に従って完全な backup を強制的に実行し、対象ディレクトリを最後に指定します。<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVTによるIOCベースのトリアージ

Amnesty’s Mobile Verification Toolkitは、暗号化されたiTunes/Finderバックアップからkeyを抽出して復号し、その後、復号されたバックアップをSTIX2 IOCファイルでscanできます。<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o`を使用すると、JSONの結果は`/tmp/mvt-results/`配下に書き込まれます。IOCの一致結果には`_detected`サフィックスが付加され、以下で復元された添付ファイルのパスと関連付けることができます。<sup>[[3]](#references)</sup>

### 一般的なartifactの解析（iLEAPP）

メッセージング以外のタイムラインやメタデータを調査するには、raw backup folderに対してiLEAPPを実行します。`itunes` input typeはiTunes/Finder backupsを受け付け、current releasesではiOS/iPadOS 11からcurrent versionsまでサポートされています。<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

再構築後、popular apps の添付ファイルを列挙します。正確な schema は app/version によって異なりますが、approach は似ています。messaging database を query し、messages と attachments を join して、disk 上の paths を解決します。<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
主な tables：message、attachment、message_attachment_join (MAJ)、chat、chat_message_join (CMJ)。<sup>[[2]](#references)</sup>

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
Attachment paths may be absolute or reconstructed tree under Library/SMS/Attachments relative.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
一般的な関連付け: message table ↔ media/attachment table（version により命名は異なる）。media rows を query して on-disk paths を取得する。Belkasoft は `ZWAMEDIAITEM` 内の `ZMEDIALOCALPATH` を media-file location として識別する。ElegantBouncer の current implementation は、`ZWAMEDIAITEM.ZMESSAGE` と `ZWAMESSAGE.Z_PK` を join し、`Media/` で始まる path を解決する際に `Message/` を先頭に付加する。<sup>[[9]](#references)[[10]](#references)</sup>
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
For that ElegantBouncer reconstruction path, `Media/` で始まる media path は `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 配下として解決されます。一方、Belkasoft の guide では `Messages/Media/` path が記載されているため、どちらの表記かを想定する前に backup を確認してください。<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB は暗号化されています。ただし、disk 上に cached された attachments（および thumbnails）は通常 scan 可能です。<sup>[[2]](#references)</sup>
- Telegram: app の media/cache directories を確認してください。Telegram は、iOS 18.0.1 上の iOS app 11.2 で cache-cleanup bug を documented し、11.3 で fixed としています。そのため、residual files を確認してください。<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite には、disk 上の references を含む message/attachment tables があります。<sup>[[2]](#references)</sup>

Tip: metadata が暗号化されている場合でも、media/cache directories を scan することで malicious objects を検出できます。<sup>[[2]](#references)</sup>


## Scanning attachments for structural exploits

attachment paths を取得したら、signatures ではなく file-format invariants を検証する structural detectors に渡します。ElegantBouncer を使用した例:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
構造ルールで対象となる検知には、次のものがあります：<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860)：不可能な JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863)：サイズ超過した Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990)：文書化されていない bytecode opcodes
- DNG/TIFF CVE‑2025‑43300：metadata と stream component の不一致


## Validation, caveats, and false positives

- Time conversions：iMessage は一部のバージョンで Apple の epochs/units を使用して日付を保存するため、報告時に適切に変換する必要があります。<sup>[[2]](#references)</sup>
- Schema drift：アプリの SQLite schemas は時間の経過とともに変化するため、デバイスの build ごとに table/column names を確認する
- Recursive extraction：PDF には JBIG2 streams や fonts が埋め込まれている場合があるため、内部オブジェクトを抽出してスキャンできる parser を使用する
- False positives：structural heuristics は保守的ですが、まれに存在する、悪意のない壊れた media を検知することがあります。<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [サンプルを入手できなくても脅威を検知する必要がある場合の ELEGANTBOUNCER](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP project (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [About encrypted backups on your iPhone, iPad or iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics with Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner and path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
