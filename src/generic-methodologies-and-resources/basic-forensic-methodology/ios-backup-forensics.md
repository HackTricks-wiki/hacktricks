# iOS 备份取证（以消息为中心的初步检查）

{{#include ../../banners/hacktricks-training.md}}

本页描述了重建和分析 iOS 备份的实用步骤，以查找通过消息应用附件交付的 0‑click exploit 的迹象。重点是将 Apple 的哈希备份布局转换为可读路径，然后枚举并扫描常见应用中的附件。

目标：
- 从 Manifest.db 重建可读路径
- 枚举消息数据库（iMessage、WhatsApp、Signal、Telegram、Viber）
- 解析附件路径，提取嵌入对象（PDF/Images/Fonts），并将它们送入结构检测器


## 重建 iOS 备份

存储在 MobileSync 下的备份使用哈希文件名，不可读。Manifest.db SQLite 数据库将每个存储对象映射到其逻辑路径。

高层流程：
1) 打开 Manifest.db 并读取文件记录（domain, relativePath, flags, fileID/hash）
2) 基于 domain + relativePath 重建原始文件夹层次结构
3) 将每个存储对象复制或创建硬链接到其重建的路径

示例工作流：使用实现此端到端流程的工具（ElegantBouncer）：
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
注意：
- 通过向 extractor 提供备份密码来处理加密备份
- 在可能的情况下保留原始时间戳/ACLs 以保留证据价值


## 消息应用附件枚举

重建之后，对常用应用的附件进行枚举。具体 schema 会因应用/版本而异，但方法类似：查询消息数据库，将 message 与 attachment 关联，并解析磁盘上的路径。

### iMessage (sms.db)
关键表： message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

示例查询：
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
附件路径可能是绝对路径，也可能相对于重建的目录树 Library/SMS/Attachments/。

### WhatsApp (ChatStorage.sqlite)
常见关联：message table ↔ media/attachment table（命名随版本而异）。查询 media rows 以获取磁盘上的路径。

示例（通用）：
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
根据你的应用版本调整表/列名（ZWAMESSAGE/ZWAMEDIAITEM 在 iOS 构建中常见）。

### Signal / Telegram / Viber
- Signal: the message DB 是加密的；然而，缓存在磁盘上的附件（及缩略图）通常是可扫描的
- Telegram: 检查缓存目录（照片/视频/文档 缓存），并在可能时将其映射到聊天
- Viber: Viber.sqlite 包含带有磁盘引用的 message/attachment 表

Tip: 即使元数据被加密，扫描媒体/缓存 目录仍能发现恶意对象。


## 对附件进行结构化漏洞扫描

一旦获取到附件路径，将它们输入到结构化检测器，这些检测器验证文件格式的不变量而不是基于签名。以下以 ElegantBouncer 为例：
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
结构规则检测涵盖：
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): 不可能的 JBIG2 字典状态
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): 过大的 Huffman 表构造
- TrueType TRIANGULATION (CVE‑2023‑41990): 未记录的字节码操作码
- DNG/TIFF CVE‑2025‑43300: 元数据与流组件不匹配


## 验证、注意事项与误报

- 时间转换：iMessage 在某些版本中以 Apple epochs/units 存储日期；在报告时请做相应转换
- Schema drift：应用的 SQLite schema 随时间变化；请根据设备 build 确认表/列名
- 递归提取：PDFs 可能嵌入 JBIG2 流和字体；提取并扫描内部对象
- 误报：结构性启发式方法较为保守，但可能会标记罕见的格式异常但无害的媒体


## 参考资料

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
