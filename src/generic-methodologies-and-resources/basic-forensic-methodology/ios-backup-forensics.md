# iOS バックアップフォレンジクス（メッセージ中心のトリアージ）

{{#include ../../banners/hacktricks-training.md}}

このページでは、messaging app attachments を介した 0‑click exploit 配布の痕跡を確認するために、iOS バックアップを再構築・解析する実践的手順を説明します。Apple のハッシュ化されたバックアップレイアウトを人間が読めるパスに変換し、その後、主要なアプリの添付ファイルを列挙してスキャンすることに重点を置いています。

Goals:
- Manifest.db から可読パスを再構築する
- メッセージングデータベースを列挙する (iMessage, WhatsApp, Signal, Telegram, Viber)
- 添付ファイルのパスを解決し、埋め込まれたオブジェクト（PDF/画像/フォント）を抽出して、構造検出器に渡す


## iOS バックアップの再構築

MobileSync 下に保存されたバックアップは、人間が読めないハッシュ化されたファイル名を使用します。Manifest.db SQLite データベースは、保存された各オブジェクトを論理パスにマップします。

大まかな手順：
1) Manifest.db を開き、ファイルレコードを読み取る (domain, relativePath, flags, fileID/hash)
2) domain + relativePath に基づいて元のフォルダ階層を再構築する
3) 保存されている各オブジェクトを再構築されたパスにコピーまたはハードリンクする

エンドツーエンドでこれを実装するツール（ElegantBouncer）を使った例：
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注意事項:
- 暗号化されたバックアップは、バックアップのパスワードを抽出ツールに渡して処理する
- 証拠価値のため、可能な限り元のタイムスタンプ/ACLを保持する

### バックアップの取得と復号化 (USB / Finder / libimobiledevice)

- macOS/Finder では「Encrypt local backup」を設定し、keychain items が存在するように*fresh*な暗号化バックアップを作成する。
- Cross‑platform: `idevicebackup2` (libimobiledevice ≥1.4.0) は iOS 17/18 のバックアッププロトコル変更に対応しており、以前の restore/backup ハンドシェイクエラーを修正している。
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### MVT による IOC 主導のトリアージ

Amnesty の Mobile Verification Toolkit (mvt-ios) は、暗号化された iTunes/Finder バックアップを直接処理できるようになり、復号化と IOC マッチングを自動化して傭兵型 spyware の事例に対応します。
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
`mvt-results/` 以下に出力されます（例: analytics_detected.json、safari_history_detected.json）。以下で復元された添付ファイルのパスと照合できます。

### General artifact parsing (iLEAPP)

メッセージング以外のタイムライン／メタデータについては、バックアップフォルダ上で直接 iLEAPP を実行してください（iOS 11‑17 スキーマをサポート）:
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## メッセージングアプリの添付ファイル列挙

再構築後、主要なアプリの添付ファイルを列挙します。スキーマはアプリやバージョンによって異なりますが、アプローチは同様です：メッセージのデータベースをクエリし、messages を attachments に結合し、ディスク上のパスを解決します。

### iMessage (sms.db)
主要テーブル: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

サンプルクエリ:
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
添付ファイルのパスは、Library/SMS/Attachments/ の下に再構築されたツリーに対して絶対パスまたは相対パスである場合があります。

### WhatsApp (ChatStorage.sqlite)
一般的な関連付け: message table ↔ media/attachment table（名前はバージョンによって異なります）。media 行をクエリしてディスク上のパスを取得します。最近の iOS ビルドでは、`ZWAMEDIAITEM` に `ZMEDIALOCALPATH` がまだ含まれています。
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
パスは通常、再構築したバックアップ内の `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 以下に解決されます。

### Signal / Telegram / Viber
- Signal: メッセージDBは暗号化されていますが、ディスクにキャッシュされた添付ファイル（およびサムネイル）は通常スキャン可能です
- Telegram: キャッシュはサンドボックス内の `Library/Caches/` に残ります。iOS 18 のビルドではキャッシュ消去のバグが見られるため、大量の残存メディアキャッシュがよく証拠になります
- Viber: Viber.sqlite にはディスク上の参照を持つメッセージ/添付テーブルが含まれます

ヒント: メタデータが暗号化されている場合でも、media/cache ディレクトリをスキャンすれば悪意のあるオブジェクトが見つかることがあります。


## 添付ファイルの構造的エクスプロイトのスキャン

添付ファイルのパスを取得したら、署名ではなくファイルフォーマットの不変条件を検証する構造検出器に渡します。ElegantBouncer の例:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 不可能なJBIG2辞書の状態
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 過大なHuffmanテーブル構成
- TrueType TRIANGULATION (CVE‑2023‑41990): 未文書化のbytecodeオペコード
- DNG/TIFF CVE‑2025‑43300: メタデータとストリーム成分の不一致


## 検証、注意点、誤検知

- 時間の変換: iMessageは一部のバージョンで日付をAppleのエポック/単位で保存します。報告時に適切に変換してください
- スキーマのドリフト: アプリのSQLiteスキーマは時間とともに変化します。デバイスのビルドごとにテーブル/カラム名を確認してください
- 再帰的抽出: PDFsはJBIG2ストリームやフォントを埋め込むことがあります。内側のオブジェクトを抽出してスキャンしてください
- 誤検知: 構造的ヒューリスティックは保守的ですが、まれに破損しているが無害なメディアを誤って検出することがあります


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
