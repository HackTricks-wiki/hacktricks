# iOS Backup Forensics (Messaging‑centric triage)

यह पेज messaging app attachments के माध्यम से 0‑click exploit delivery के संकेतों के लिए iOS backups को reconstruct और analyze करने के practical steps का वर्णन करता है। इसमें Apple के hashed backup layout को human‑readable paths में बदलने, फिर common apps में attachments को enumerate और scan करने पर ध्यान दिया गया है।

Goals:
- Manifest.db से readable paths को दोबारा बनाना
- messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber) को enumerate करना
- attachment paths को resolve करना, जहाँ supported हो वहाँ embedded objects (PDF/Images/Fonts) extract करना, और उन्हें structural detectors को feed करना


## iOS backup को reconstruct करना

MobileSync के अंतर्गत stored backups में hashed filenames होते हैं, जो human‑readable नहीं होते। Manifest.db SQLite database प्रत्येक stored object को उसके logical path से map करता है।<sup>[[1]](#references)[[2]](#references)</sup>

High‑level procedure:
1) Manifest.db खोलें और file records (domain, relativePath, flags, fileID/hash) पढ़ें
2) domain + relativePath के आधार पर original folder hierarchy दोबारा बनाएँ
3) प्रत्येक stored object को उसके reconstructed path पर copy या hardlink करें

ऐसे tool के साथ example workflow जो इसे end‑to‑end implement करता है (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
नोट्स:
- Encrypted backups को reconstruction tool में पास करने से पहले decrypt करें; ElegantBouncer को decrypted backup की आवश्यकता होती है।<sup>[[2]](#references)[[3]](#references)</sup>
- Evidentiary value के लिए, जहाँ संभव हो original timestamps/ACLs सुरक्षित रखें

### Backup प्राप्त करना और decrypt करना (USB / Finder / libimobiledevice)

- Finder/Apple Devices/iTunes में "Encrypt local backup" सक्षम करें और नया backup बनाएं; encrypted backups में saved passwords और Health data शामिल हो सकते हैं, जिन्हें unencrypted backups छोड़ देते हैं।<sup>[[8]](#references)</sup>
- Cross-platform: libimobiledevice 1.4.0 में `idevicebackup2` के लिए fixes शामिल हैं।<sup>[[4]](#references)</sup> Encryption को interactively सक्षम करें, फिर documented command ordering का उपयोग करके full backup force करें, जिसमें target directory सबसे अंत में हो।<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### MVT के साथ IOC-आधारित ट्रायेज

Amnesty’s Mobile Verification Toolkit encrypted iTunes/Finder backups से key extract और उन्हें decrypt कर सकता है, फिर decrypted backup को STIX2 IOC file से scan कर सकता है।<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
`-o` के साथ, JSON results `/tmp/mvt-results/` के अंतर्गत लिखे जाते हैं; IOC matches में `_detected` suffix का उपयोग होता है और उन्हें नीचे पुनर्प्राप्त किए गए attachment paths के साथ correlate किया जा सकता है।<sup>[[3]](#references)</sup>

### सामान्य artifact parsing (iLEAPP)

Messaging से आगे के timeline/metadata के लिए, raw backup folder पर iLEAPP चलाएँ; इसका `itunes` input type iTunes/Finder backups को स्वीकार करता है और वर्तमान releases iOS/iPadOS 11 से लेकर वर्तमान versions तक support करते हैं।<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging app attachment enumeration

Reconstruction के बाद, popular apps के attachments enumerate करें। Exact schema app/version के अनुसार अलग होता है, लेकिन approach समान रहती है: messaging database को query करें, messages को attachments के साथ join करें, और disk पर paths resolve करें।<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)।<sup>[[2]](#references)</sup>

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
Attachment paths reconstructed tree के अंतर्गत Library/SMS/Attachments के लिए absolute या relative हो सकते हैं।<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
सामान्य linkage: message table ↔ media/attachment table (naming version के अनुसार अलग हो सकती है)। on-disk paths प्राप्त करने के लिए media rows पर Query करें। Belkasoft `ZWAMEDIAITEM` में `ZMEDIALOCALPATH` को media-file location के रूप में पहचानता है; ElegantBouncer का current implementation path resolve करते समय `ZWAMEDIAITEM.ZMESSAGE` को `ZWAMESSAGE.Z_PK` से join करता है और `Media/` से शुरू होने वाले path के आगे `Message/` जोड़ता है।<sup>[[9]](#references)[[10]](#references)</sup>
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
उस ElegantBouncer reconstruction path के लिए, `Media/` से शुरू होने वाला media path `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` के अंतर्गत resolve होता है; Belkasoft की guide इसके बजाय `Messages/Media/` path documented करती है, इसलिए इनमें से किसी spelling को मानने से पहले backup का निरीक्षण करें।<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: message DB encrypted है; हालांकि, disk पर cached attachments (और thumbnails) आमतौर पर scan किए जा सकते हैं।<sup>[[2]](#references)</sup>
- Telegram: app की media/cache directories का निरीक्षण करें; Telegram ने iOS 18.0.1 पर iOS app 11.2 में cache-cleanup bug documented किया था, जिसे 11.3 में fixed बताया गया है, इसलिए residual files की जांच करें।<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite में on-disk references वाली message/attachment tables होती हैं।<sup>[[2]](#references)</sup>

Tip: metadata encrypted होने पर भी, media/cache directories को scan करने से malicious objects मिल सकते हैं।<sup>[[2]](#references)</sup>


## Structural exploits के लिए attachments को scan करना

Attachment paths मिलने के बाद, उन्हें ऐसे structural detectors में feed करें जो signatures के बजाय file-format invariants को validate करते हैं। ElegantBouncer के साथ उदाहरण:<sup>[[1]](#references)[[2]](#references)</sup>
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


## Validation, caveats, and false positives

- Time conversions: कुछ versions में iMessage dates को Apple epochs/units में store करता है; reporting के दौरान उचित रूप से convert करें।<sup>[[2]](#references)</sup>
- Schema drift: app SQLite schemas समय के साथ बदलते हैं; प्रत्येक device build के अनुसार table/column names की पुष्टि करें
- Recursive extraction: PDFs में JBIG2 streams और fonts embed हो सकते हैं; ऐसा parser उपयोग करें जो inner objects को extract और scan कर सके
- False positives: structural heuristics conservative होते हैं, लेकिन rare malformed yet benign media को flag कर सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: जब आप Samples प्राप्त नहीं कर सकते, लेकिन फिर भी Threat को Catch करना आवश्यक हो](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 में iOS 18.0.1 पर cache cleanup broken है (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 manual](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP project (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [आपके iPhone, iPad या iPod touch पर encrypted backups के बारे में (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [Belkasoft X के साथ iOS WhatsApp Forensics](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner और path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
