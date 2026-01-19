# iOS 备份取证（以消息为中心的初步筛查）

{{#include ../../banners/hacktricks-training.md}}

本页面描述了重建和分析 iOS 备份的实用步骤，以查找通过消息应用附件进行 0‑click exploit delivery 的迹象。重点是将 Apple 的哈希备份布局转换为人类可读的路径，然后枚举并扫描常见应用中的附件。

目标:
- 从 Manifest.db 重建可读路径
- 列举消息数据库 (iMessage, WhatsApp, Signal, Telegram, Viber)
- 解析附件路径，提取嵌入对象 (PDF/Images/Fonts)，并将其提供给结构检测器


## 重建 iOS 备份

存储在 MobileSync 下的备份使用哈希文件名，无法被人类直接读取。Manifest.db SQLite 数据库将每个存储对象映射到其逻辑路径。

高层流程：
1) 打开 Manifest.db 并读取文件记录 (domain, relativePath, flags, fileID/hash)
2) 根据 domain + relativePath 重建原始文件夹层次
3) 将每个存储对象复制或创建硬链接到重建后的路径

使用实现此端到端流程的工具（ElegantBouncer）的示例工作流程：
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注意：
- 处理加密的备份时，向你的提取工具提供备份密码
- 在可能的情况下保留原始时间戳/ACLs，以保持其作为证据的价值

### 获取并解密备份（USB / Finder / libimobiledevice）

- 在 macOS/Finder 上将 "Encrypt local backup" 设置为启用，并创建一个 *新的* 加密备份，以确保包含 keychain 条目。
- 跨平台：`idevicebackup2` (libimobiledevice ≥1.4.0) 支持 iOS 17/18 的备份协议更改，并修复了早期的恢复/备份握手错误。
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### 基于 IOC 的 MVT 分诊

Amnesty’s Mobile Verification Toolkit (mvt-ios) 现在可以直接在加密的 iTunes/Finder 备份上运行，自动化解密并对 mercenary spyware 案件进行 IOC 匹配。
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
输出文件位于 `mvt-results/`（例如 analytics_detected.json、safari_history_detected.json），并可与下面恢复的附件路径相关联。

### 通用工件解析 (iLEAPP)

对于消息之外的时间线/元数据，请在备份文件夹上直接运行 iLEAPP（支持 iOS 11‑17 模式）：
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## 消息应用附件枚举

重建之后，为流行的应用列举附件。具体的结构会因应用/版本而异，但方法相似：查询消息数据库，将消息与附件关联，并解析磁盘上的路径。

### iMessage (sms.db)
关键表: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

示例查询:
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
附件路径可能是绝对路径，也可能是相对于重建的树 Library/SMS/Attachments/ 的相对路径。

### WhatsApp (ChatStorage.sqlite)

常见关联：message 表 ↔ media/attachment 表（命名随版本不同）。查询 media 行以获取磁盘上的路径。最近的 iOS 构建仍在 `ZWAMEDIAITEM` 中暴露 `ZMEDIALOCALPATH`。
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
在重建的备份中，路径通常解析到 `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 下。

### Signal / Telegram / Viber
- Signal: the message DB 是加密的；然而，缓存在磁盘上的 attachments（以及 thumbnails）通常可以被扫描
- Telegram: 缓存位于沙盒内的 `Library/Caches/` 下；iOS 18 构建存在 cache‑clearing bugs，因此大量残留的媒体缓存通常是常见证据来源
- Viber: Viber.sqlite 包含带有 on‑disk 引用的 message/attachment 表

Tip: 即便元数据被加密，扫描 media/cache 目录仍然会发现恶意对象。


## Scanning attachments for structural exploits

一旦获取到附件路径，将它们送入验证文件格式不变量（file‑format invariants）的结构检测器，而不是依赖 signatures。示例使用 ElegantBouncer：
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 不可能的 JBIG2 字典状态
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 过大的 Huffman 表构造
- TrueType TRIANGULATION (CVE‑2023‑41990): 未记录的字节码操作码
- DNG/TIFF CVE‑2025‑43300: 元数据与流组件不匹配


## Validation, caveats, and false positives

- 时间转换：iMessage 在某些版本中以 Apple epochs/单位 存储日期；在报告时适当转换
- 模式漂移：应用的 SQLite schema 会随时间变化；请根据设备构建确认表/列名
- 递归提取：PDFs 可能嵌入 JBIG2 流和字体；提取并扫描内部对象
- 误报：结构性启发式规则较为保守，但可能标记罕见的格式错误但无害的媒体


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
