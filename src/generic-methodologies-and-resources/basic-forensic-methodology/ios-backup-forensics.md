# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

यह पेज messaging app attachments के माध्यम से 0‑click exploit delivery के संकेतों के लिए iOS backups को reconstruct और analyze करने के practical steps का वर्णन करता है। इसका focus Apple के hashed backup layout को human-readable paths में बदलने, फिर common apps में attachments को enumerate और scan करने पर है।

Goals:
- Manifest.db से readable paths को rebuild करना
- Messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber) को enumerate करना
- Attachment paths को resolve करना, embedded objects (PDF/Images/Fonts) को extract करना और उन्हें structural detectors को feed करना


## Reconstructing an iOS backup

MobileSync के अंतर्गत stored backups में hashed filenames होते हैं, जो human-readable नहीं होते। Manifest.db SQLite database प्रत्येक stored object को उसके logical path से map करता है।

High-level procedure:
1) Manifest.db खोलें और file records (domain, relativePath, flags, fileID/hash) पढ़ें
2) domain + relativePath के आधार पर original folder hierarchy को recreate करें
3) प्रत्येक stored object को उसके reconstructed path पर copy या hardlink करें

ऐसे tool के साथ example workflow जो इस end-to-end प्रक्रिया को implement करता है (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
नोट्स:
- Encrypted backups को अपने extractor में backup password देकर handle करें
- Evidentiary value के लिए, जहाँ संभव हो, original timestamps/ACLs को preserve करें

### Backup प्राप्त करना और decrypt करना (USB / Finder / libimobiledevice)

- macOS/Finder में "Encrypt local backup" सेट करें और एक *fresh* encrypted backup बनाएं, ताकि keychain items मौजूद रहें।
- Cross-platform: `idevicebackup2` (libimobiledevice ≥1.4.0) iOS 17/18 backup protocol में हुए बदलावों को समझता है और पहले की restore/backup handshake errors को ठीक करता है।<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### MVT के साथ IOC-आधारित triage

Amnesty का Mobile Verification Toolkit (mvt-ios) अब सीधे encrypted iTunes/Finder backups पर काम करता है और mercenary spyware मामलों के लिए decryption तथा IOC matching को automate करता है।<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Outputs `mvt-results/` के अंतर्गत सेव होते हैं (जैसे, `analytics_detected.json`, `safari_history_detected.json`) और नीचे रिकवर किए गए attachment paths के साथ correlate किए जा सकते हैं।

### General artifact parsing (iLEAPP)

Messaging से आगे की timeline/metadata के लिए, backup folder पर सीधे iLEAPP चलाएँ (iOS 11‑17 schemas को support करता है):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

Reconstruction के बाद, popular apps के attachments enumerate करें। Exact schema app/version के अनुसार अलग हो सकता है, लेकिन approach समान है: messaging database को query करें, messages को attachments के साथ join करें, और disk पर paths resolve करें।<sup>[[1]](#references)[[2]](#references)</sup>

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
Attachment paths reconstructed tree के अंतर्गत Library/SMS/Attachments/ के लिए absolute या relative हो सकते हैं।

### WhatsApp (ChatStorage.sqlite)
सामान्य linkage: message table ↔ media/attachment table (version के अनुसार naming अलग हो सकती है)। On-disk paths प्राप्त करने के लिए media rows को query करें। हाल के iOS builds में भी `ZWAMEDIAITEM` में `ZMEDIALOCALPATH` उपलब्ध रहता है।
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
Paths आमतौर पर reconstructed backup के अंदर `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` के अंतर्गत resolve होते हैं।

### Signal / Telegram / Viber
- Signal: message DB encrypted है; हालांकि, disk पर cached attachments (और thumbnails) आमतौर पर scan किए जा सकते हैं
- Telegram: cache sandbox के अंदर `Library/Caches/` में रहता है; iOS 18 builds में cache-clearing bugs दिखाई देते हैं, इसलिए बड़े residual media caches अक्सर महत्वपूर्ण evidence sources होते हैं<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite में message/attachment tables और on-disk references मौजूद होते हैं

Tip: metadata encrypted होने पर भी media/cache directories को scan करने से malicious objects का पता चल जाता है।


## Structural exploits के लिए attachments को scan करना

एक बार attachment paths मिल जाने पर, उन्हें structural detectors में feed करें, जो signatures के बजाय file-format invariants को validate करते हैं। ElegantBouncer के साथ उदाहरण:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Structural rules द्वारा कवर किए गए detections में शामिल हैं:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): असंभव JBIG2 dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oversized Huffman table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): undocumented bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata और stream component mismatches


## Validation, caveats, और false positives

- Time conversions: कुछ versions पर iMessage dates को Apple epochs/units में store करता है; reporting के दौरान उचित रूप से convert करें
- Schema drift: app SQLite schemas समय के साथ बदलते हैं; प्रत्येक device build के अनुसार table/column names की पुष्टि करें
- Recursive extraction: PDFs में JBIG2 streams और fonts embed हो सकते हैं; inner objects को extract और scan करें
- False positives: structural heuristics conservative होते हैं, लेकिन rare malformed yet benign media को flag कर सकते हैं<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: जब आप Samples प्राप्त नहीं कर सकते, लेकिन फिर भी Threat को पकड़ना आवश्यक है](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
