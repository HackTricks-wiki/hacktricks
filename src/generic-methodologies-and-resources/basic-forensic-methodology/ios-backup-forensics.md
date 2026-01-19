# iOS बैकअप फॉरेंसिक्स (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ iOS बैकअप्स को पुनर्निर्मित और विश्लेषित करने के व्यावहारिक चरण बताता है ताकि messaging app attachments के माध्यम से 0‑click exploit delivery के संकेत पहचाने जा सकें। यह Apple के hashed बैकअप लेआउट को human‑readable paths में बदलने, और सामान्य ऐप्स में attachments को सूचीबद्ध व स्कैन करने पर केंद्रित है।

लक्ष्य:
- Manifest.db से readable paths पुनर्निर्मित करना
- messaging डेटाबेसों (iMessage, WhatsApp, Signal, Telegram, Viber) को सूचीबद्ध करना
- attachment paths को resolve करना, embedded objects (PDF/Images/Fonts) निकालना, और उन्हें structural detectors को देना


## Reconstructing an iOS backup

MobileSync के अंतर्गत स्टोर किए गए बैकअप hashed filenames का उपयोग करते हैं जो human‑readable नहीं होते। Manifest.db SQLite database हर स्टोर किए गए object को उसके logical path से मैप करता है।

उच्च‑स्तरीय प्रक्रिया:
1) Manifest.db खोलें और file records पढ़ें (domain, relativePath, flags, fileID/hash)
2) domain + relativePath के आधार पर मूल फ़ोल्डर हायार्की पुनर्निर्मित करें
3) प्रत्येक स्टोर किए गए object को उसके पुनर्निर्मित path पर copy या hardlink करें

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- एन्क्रिप्टेड बैकअप्स को हैंडल करने के लिए अपने extractor को बैकअप पासवर्ड दें
- साक्ष्य के मूल्य के लिए संभव होने पर मूल timestamps/ACLs सुरक्षित रखें

### बैकअप प्राप्त करना और डिक्रिप्ट करना (USB / Finder / libimobiledevice)

- macOS/Finder पर "Encrypt local backup" सेट करें और keychain items मौजूद हों इसलिए *ताज़ा* एन्क्रिप्टेड बैकअप बनाएं।
- क्रॉस‑प्लेटफ़ॉर्म: `idevicebackup2` (libimobiledevice ≥1.4.0) iOS 17/18 backup protocol परिवर्तनों को समझता है और पहले के restore/backup handshake errors को फिक्स करता है।
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑driven ट्रायेज़ MVT के साथ

Amnesty’s Mobile Verification Toolkit (mvt-ios) अब encrypted iTunes/Finder backups पर सीधे काम करता है, mercenary spyware मामलों के लिए decryption और IOC matching को स्वचालित करता है।
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
`mvt-results/` के अंतर्गत आउटपुट आते हैं (उदा., analytics_detected.json, safari_history_detected.json) और इन्हें नीचे पुनर्प्राप्त किए गए संलग्नक पथों के साथ संबंधित किया जा सकता है।

### सामान्य आर्टिफैक्ट पार्सिंग (iLEAPP)

संदेशों से परे टाइमलाइन/मेटाडेटा के लिए, बैकअप फ़ोल्डर पर सीधे iLEAPP चलाएँ (iOS 11‑17 स्कीमा का समर्थन):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Messaging ऐप अटैचमेंट सूचीकरण

पुनर्निर्माण के बाद, लोकप्रिय ऐप्स के attachments सूचीबद्ध करें। सटीक schema ऐप/वर्शन के अनुसार बदलता है, लेकिन तरीका समान है: messaging database को query करें, messages को attachments के साथ join करें, और डिस्क पर paths को resolve करें।

### iMessage (sms.db)
Key tables: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

उदाहरण क्वेरी:
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
Attachment paths absolute हो सकते हैं या Library/SMS/Attachments/ के अंतर्गत पुनर्निर्मित पेड़ के सापेक्ष हो सकते हैं।

### WhatsApp (ChatStorage.sqlite)
सामान्य लिंक: message table ↔ media/attachment table (नामकरण संस्करण के अनुसार भिन्न होता है)। on‑disk paths प्राप्त करने के लिए media rows को क्वेरी करें। हाल के iOS builds अभी भी `ZMEDIALOCALPATH` को `ZWAMEDIAITEM` में उजागर करते हैं।
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
Paths usually resolve under `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` inside the reconstructed backup.

### Signal / Telegram / Viber
- Signal: message DB encrypted है; हालाँकि, disk पर cached attachments (और thumbnails) आमतौर पर scan‑able होते हैं
- Telegram: cache sandbox के भीतर `Library/Caches/` के अंतर्गत रहता है; iOS 18 builds cache‑clearing bugs दिखाते हैं, इसलिए बड़े residual media caches सामान्यतः सबूत स्रोत होते हैं
- Viber: Viber.sqlite में message/attachment tables होते हैं जिनमें on‑disk references मौजूद हैं

टिप: भले ही metadata encrypted हो, media/cache directories को स्कैन करने से फिर भी हानिकारक ऑब्जेक्ट्स सामने आ जाते हैं।


## संरचनात्मक exploits के लिए attachments स्कैन करना

एक बार जब आपके पास attachment paths हो जाएं, तो उन्हें structural detectors में डालें जो signatures की बजाय file‑format invariants को validate करते हैं। ElegantBouncer के साथ उदाहरण:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): असंभव JBIG2 डिक्शनरी स्थितियाँ
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): अत्यधिक बड़े Huffman तालिका निर्माण
- TrueType TRIANGULATION (CVE‑2023‑41990): दस्तावेज़ित नहीं bytecode ऑपकोड्स
- DNG/TIFF CVE‑2025‑43300: metadata बनाम stream component असंगतताएँ


## सत्यापन, सावधानियाँ, और false positives

- Time conversions: iMessage कुछ वर्ज़नों में तिथियों को Apple epochs/units में संग्रहीत करता है; रिपोर्टिंग के दौरान उपयुक्त रूप से रूपांतरित करें
- Schema drift: ऐप के SQLite schemas समय के साथ बदलते हैं; डिवाइस बिल्ड के अनुसार table/column नामों की पुष्टि करें
- Recursive extraction: PDFs में JBIG2 streams और fonts एम्बेड हो सकते हैं; आंतरिक ऑब्जेक्ट्स को निकालें और स्कैन करें
- False positives: structural heuristics आम तौर पर कंज़र्वेटिव होते हैं, लेकिन यह दुर्लभ malformed पर भी निशान लगा सकते हैं जो हानिरहित मीडिया होते हैं


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
