# iOS Backup Forensics（以 Messaging 为中心的 triage）

{{#include ../../banners/hacktricks-training.md}}

本页介绍如何重建和分析 iOS backup，以查找通过 messaging app 附件投递 0-click exploit 的迹象。重点是将 Apple 的 hashed backup 布局转换为人类可读的路径，然后枚举并扫描常见 app 中的附件。

目标：
- 从 Manifest.db 重建可读路径
- 枚举 messaging databases（iMessage、WhatsApp、Signal、Telegram、Viber）
- 解析附件路径，在支持的情况下提取嵌入对象（PDF/Images/Fonts），并将其交给 structural detectors


## 重建 iOS backup

存储在 MobileSync 下的 backup 使用无法直接供人阅读的 hashed filenames。SQLite database Manifest.db 会将每个存储对象映射到其 logical path。<sup>[[1]](#references)[[2]](#references)</sup>

高级流程：
1) 打开 Manifest.db 并读取 file records（domain、relativePath、flags、fileID/hash）
2) 根据 domain + relativePath 重建原始 folder hierarchy
3) 将每个存储对象复制或 hardlink 到其重建后的路径

使用实现了端到端流程的工具的示例（ElegantBouncer）：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
备注：
- 在将加密备份传递给 reconstruction tool 之前，先解密备份；ElegantBouncer 需要解密后的备份。<sup>[[2]](#references)[[3]](#references)</sup>
- 在可能的情况下保留原始时间戳/ACL，以维护证据价值

### 获取并解密备份（USB / Finder / libimobiledevice）

- 在 Finder/Apple Devices/iTunes 中启用“加密本地备份”并创建新备份；加密备份可以包含未加密备份会省略的已保存密码和 Health 数据。<sup>[[8]](#references)</sup>
- 跨平台：libimobiledevice 1.4.0 包含对 `idevicebackup2` 的修复。<sup>[[4]](#references)</sup> 以交互方式启用加密，然后按照文档规定的命令顺序强制执行完整备份，并将目标目录放在最后。<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### 使用 MVT 进行 IOC 驱动的分诊

Amnesty 的 Mobile Verification Toolkit 可以提取密钥并解密加密的 iTunes/Finder 备份，然后使用 STIX2 IOC 文件扫描解密后的备份。<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
使用 `-o` 时，JSON 结果会写入 `/tmp/mvt-results/`；IOC 匹配项使用 `_detected` 后缀，并可与下文恢复的附件路径进行关联。<sup>[[3]](#references)</sup>

### 通用工件解析（iLEAPP）

如需获取消息之外的时间线/元数据，可针对原始备份文件夹运行 iLEAPP；其 `itunes` 输入类型接受 iTunes/Finder 备份，当前版本支持 iOS/iPadOS 11 及更高版本。<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment 枚举

重建后，枚举常用 app 的附件。具体 schema 因 app/版本而异，但方法类似：查询 messaging database，将消息与附件进行 join，并解析磁盘上的路径。<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
关键表：message、attachment、message_attachment_join (MAJ)、chat、chat_message_join (CMJ)。<sup>[[2]](#references)</sup>

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
附件路径可能是绝对路径，也可能是相对于重建树中 `Library/SMS/Attachments` 的相对路径。<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
常见关联：message 表 ↔ media/attachment 表（命名因版本而异）。查询 media 行以获取磁盘上的路径。Belkasoft 将 `ZWAMEDIAITEM` 中的 `ZMEDIALOCALPATH` 标识为媒体文件位置；ElegantBouncer 当前的实现将 `ZWAMEDIAITEM.ZMESSAGE` 与 `ZWAMESSAGE.Z_PK` 进行连接，并在解析以 `Media/` 开头的路径时添加 `Message/` 前缀。<sup>[[9]](#references)[[10]](#references)</sup>
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
对于 ElegantBouncer 重建路径，以 `Media/` 开头的媒体路径会解析到 `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` 下；而 Belkasoft 的指南记录的是 `Messages/Media/` 路径，因此在假定任一拼写之前，应先检查 backup。<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal：消息 DB 已加密；但是，缓存在磁盘上的附件（以及缩略图）通常仍可扫描。<sup>[[2]](#references)</sup>
- Telegram：检查 app 的 media/cache 目录；Telegram 记录了 iOS app 11.2 在 iOS 18.0.1 上存在 cache 清理 bug，并标记为在 11.3 中修复，因此应检查残留文件。<sup>[[2]](#references)[[5]](#references)</sup>
- Viber：Viber.sqlite 包含带有磁盘引用的消息/附件表。<sup>[[2]](#references)</sup>

提示：即使 metadata 已加密，扫描 media/cache 目录仍可发现恶意对象。<sup>[[2]](#references)</sup>


## 扫描附件中的结构性漏洞利用

获取附件路径后，将其输入结构检测器，由这些检测器验证文件格式不变量，而不是验证 signatures。以 ElegantBouncer 为例：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
结构化规则涵盖的检测包括：<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860)：不可能的 JBIG2 dictionary 状态
- WebP/VP8L BLASTPASS (CVE‑2023‑4863)：过大的 Huffman table 构造
- TrueType TRIANGULATION (CVE‑2023‑41990)：未公开的 bytecode opcode
- DNG/TIFF CVE‑2025‑43300：metadata 与 stream 组件不匹配


## 验证、注意事项和误报

- 时间转换：iMessage 在某些版本中使用 Apple epochs/units 存储日期；报告时请进行适当转换。<sup>[[2]](#references)</sup>
- Schema 漂移：app SQLite schemas 会随时间变化；请根据设备 build 确认 table/column 名称
- Recursive extraction：PDF 可能嵌入 JBIG2 streams 和 fonts；请使用能够提取并扫描内部 objects 的 parser
- 误报：结构化启发式规则较为保守，但可能将罕见的、格式错误却无害的媒体标记为可疑。<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER：无法获取样本但仍需要检测威胁](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer 项目 (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup 工作流](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 发布说明](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 导致 iOS 18.0.1 上的 cache cleanup 损坏 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 手册](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP 项目 (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [关于 iPhone、iPad 或 iPod touch 上的加密 backups (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [使用 Belkasoft X 进行 iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner 和 path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
