# iOS Backup Forensics（以 Messaging 为中心的 triage）

{{#include ../../banners/hacktricks-training.md}}

本页面介绍用于重建和分析 iOS backups 的实用步骤，以查找通过 messaging app attachments 传递 0-click exploit 的迹象。重点是将 Apple 的 hashed backup layout 转换为人类可读的路径，然后枚举并扫描常见 apps 中的 attachments。

目标：
- 根据 Manifest.db 重建可读路径
- 枚举 messaging databases（iMessage、WhatsApp、Signal、Telegram、Viber）
- 解析 attachment paths，提取嵌入对象（PDF/Images/Fonts），并将其提供给 structural detectors


## 重建 iOS backup

存储在 MobileSync 下的 backups 使用不可读的 hashed filenames。Manifest.db SQLite database 将每个 stored object 映射到其 logical path。

高级流程：
1) 打开 Manifest.db 并读取 file records（domain、relativePath、flags、fileID/hash）
2) 根据 domain + relativePath 重建原始 folder hierarchy
3) 将每个 stored object 复制或 hardlink 到其重建后的路径

使用实现此端到端流程的 tool 的示例工作流（ElegantBouncer）：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注意：
- 处理加密备份时，将备份密码提供给 extractor
- 在可能的情况下保留原始时间戳/ACL，以维护证据价值

### 获取并解密备份（USB / Finder / libimobiledevice）

- 在 macOS/Finder 中启用“Encrypt local backup”，并创建一个*全新的*加密备份，以确保 keychain 项目存在。
- 跨平台：`idevicebackup2`（libimobiledevice ≥1.4.0）支持 iOS 17/18 备份协议变更，并修复早期 restore/backup 握手错误。<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### 基于 IOC 的 MVT 分诊

Amnesty 的 Mobile Verification Toolkit（mvt-ios）现在可以直接处理加密的 iTunes/Finder backups，自动完成解密，并针对 mercenary spyware 案件匹配 IOC。<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
输出位于 `mvt-results/` 下（例如 `analytics_detected.json`、`safari_history_detected.json`），并可与下方恢复的附件路径进行关联。

### 通用 artifact 解析（iLEAPP）

如需获取 messaging 之外的时间线/元数据，请直接对备份文件夹运行 iLEAPP（支持 iOS 11‑17 schemas）：
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app 附件枚举

完成重建后，枚举常用 app 的附件。具体 schema 会因 app/版本而异，但方法类似：查询 messaging database，将消息与附件进行 join，并解析磁盘上的路径。<sup>[[1]](#references)[[2]](#references)</sup>

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
附件路径可能是绝对路径，也可能是相对于重建树中 `Library/SMS/Attachments/` 的路径。

### WhatsApp (ChatStorage.sqlite)
常见关联关系：message table ↔ media/attachment table（命名因版本而异）。查询 media rows 以获取磁盘路径。近期的 iOS 构建版本仍会在 `ZWAMEDIAITEM` 中暴露 `ZMEDIALOCALPATH`。
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
路径通常会解析到重建备份中的 `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`。

### Signal / Telegram / Viber
- Signal：消息 DB 已加密；但磁盘上缓存的附件（以及缩略图）通常仍可扫描
- Telegram：缓存保留在 sandbox 内的 `Library/Caches/` 下；iOS 18 构建版本存在清理缓存的 bugs，因此大型残留媒体缓存通常是常见的证据来源<sup>[[5]](#references)</sup>
- Viber：Viber.sqlite 包含消息/附件表以及磁盘上的引用

提示：即使元数据已加密，扫描媒体/缓存目录仍可发现恶意对象。


## 扫描附件以发现结构化 exploits

获取附件路径后，将其输入结构检测器，验证文件格式不变量，而不是检查 signatures。使用 ElegantBouncer 的示例：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
结构化规则涵盖的检测包括：<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860)：不可能的 JBIG2 dictionary 状态
- WebP/VP8L BLASTPASS (CVE‑2023‑4863)：超大的 Huffman table 构造
- TrueType TRIANGULATION (CVE‑2023‑41990)：未记录的 bytecode opcodes
- DNG/TIFF CVE‑2025‑43300：metadata 与 stream 组件不匹配


## 验证、注意事项和误报

- 时间转换：iMessage 在某些版本中使用 Apple epochs/units；报告时请进行适当转换
- Schema 漂移：app SQLite schemas 会随时间变化；请根据设备 build 确认 table/column 名称
- 递归提取：PDF 可能嵌入 JBIG2 streams 和 fonts；请提取并扫描内部对象
- 误报：结构启发式规则较为保守，但可能将罕见的、格式错误却无害的 media 标记为异常<sup>[[1]](#references)[[2]](#references)</sup>


## 参考资料

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
