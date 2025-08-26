# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

このページでは、メッセージングアプリの添付ファイルを介した 0‑click エクスプロイト配信の痕跡を検出するため、iOS バックアップを再構築および解析する実践的な手順を説明します。Apple のハッシュ化されたバックアップレイアウトを人間が読めるパスに変換し、その後一般的なアプリの添付ファイルを列挙してスキャンすることに焦点を当てています。

Goals:
- Manifest.db から読みやすいパスを再構築する
- メッセージングデータベースを列挙する (iMessage, WhatsApp, Signal, Telegram, Viber)
- 添付ファイルのパスを解決し、埋め込まれたオブジェクト（PDF/Images/Fonts）を抽出して、構造検出器に投入する


## Reconstructing an iOS backup

MobileSync 配下に保存されたバックアップは、可読性のないハッシュ化されたファイル名を使用します。Manifest.db SQLite データベースは、保存された各オブジェクトを論理パスにマッピングします。

High‑level procedure:
1) Manifest.db を開き、ファイルレコード（domain、relativePath、flags、fileID/hash）を読み取る
2) domain + relativePath に基づいて元のフォルダ階層を再作成する
3) 保存された各オブジェクトを再構築したパスにコピーまたはハードリンクする

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- 暗号化されたバックアップは、バックアップパスワードを抽出ツールに渡して処理する
- 証拠価値のため、可能な限り元のタイムスタンプ／ACLを保持する


## Messaging app attachment enumeration

復元後、主要なアプリの添付ファイルを列挙する。スキーマはアプリ／バージョンごとに異なるが、アプローチは類似している：messaging データベースをクエリし、message を attachment に結合し、ディスク上のパスを解決する。

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
添付ファイルのパスは絶対パスであるか、または再構築されたツリーの Library/SMS/Attachments/ 以下の相対パスである可能性があります。

### WhatsApp (ChatStorage.sqlite)
一般的な関連付け: message table ↔ media/attachment table（名称はバージョンによって異なる）。media 行をクエリしてオンディスクのパスを取得する。

例（一般的）:
```sql
SELECT
m.Z_PK          AS message_pk,
mi.ZMEDIALOCALPATH AS media_path,
m.ZMESSAGEDATE  AS message_date
FROM ZWAMESSAGE m
LEFT JOIN ZWAMEDIAITEM mi ON mi.ZMESSAGE = m.Z_PK
WHERE mi.ZMEDIALOCALPATH IS NOT NULL
ORDER BY m.ZMESSAGEDATE DESC;
```
Adjust table/column names to your app version (ZWAMESSAGE/ZWAMEDIAITEM are common in iOS builds).

### Signal / Telegram / Viber
- Signal: メッセージ DB は暗号化されているが、ディスクにキャッシュされた添付ファイル（サムネイルを含む）は通常スキャン可能
- Telegram: キャッシュディレクトリ（photo/video/document caches）を調査し、可能な場合はチャットに紐付ける
- Viber: Viber.sqlite はメッセージ／添付ファイルのテーブルを含み、オンディスク参照が存在する

ヒント: メタデータが暗号化されている場合でも、media/cache ディレクトリをスキャンすれば悪意のあるオブジェクトが検出されることがある。


## 添付ファイルを構造的エクスプロイト用にスキャンする

添付ファイルのパスが取得できたら、それらを構造ベースの検出器に投入し、シグネチャの代わりにファイル形式の不変条件を検証させる。ElegantBouncer を使った例：
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
構造ルールでカバーされる検出例には以下が含まれる:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): impossible JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata vs. stream component mismatches


## 検証、注意点、および誤検知

- Time conversions: iMessage stores dates in Apple epochs/units on some versions; convert appropriately during reporting
- Schema drift: app SQLite schemas change over time; confirm table/column names per device build
- Recursive extraction: PDFs may embed JBIG2 streams and fonts; extract and scan inner objects
- False positives: structural heuristics are conservative but can flag rare malformed yet benign media


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
