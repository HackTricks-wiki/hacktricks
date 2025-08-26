# iOS Backup Forensics (Messaging‑केंद्रित प्राथमिक जाँच)

{{#include ../../banners/hacktricks-training.md}}

यह पेज messaging app अटैचमेंट्स के माध्यम से 0‑click exploit delivery के संकेतों के लिए iOS बैकअप को पुनर्निर्माण और विश्लेषण करने के व्यावहारिक कदम बताता है। यह Apple के hashed backup layout को मानव‑पठनीय पथों में बदलने पर केंद्रित है, और फिर सामान्य ऐप्स में attachments की सूची बनाकर और स्कैन करके उनका विश्लेषण करता है।

Goals:
- Manifest.db से पठनीय पथ पुनर्निर्माण करें
- 메시जिंग डेटाबेस (iMessage, WhatsApp, Signal, Telegram, Viber) को सूचीबद्ध करें
- अटैचमेंट पथ हल करें, embedded objects (PDF/Images/Fonts) निकालें, और उन्हें structural detectors को फ़ीड करें


## iOS बैकअप का पुनर्निर्माण

MobileSync के अंतर्गत स्टोर किए गए बैकअप hashed filenames का उपयोग करते हैं जो मानव‑पठनीय नहीं होते। The Manifest.db SQLite database हर स्टोर किए गए ऑब्जेक्ट को उसके logical path से मैप करता है।

High‑level procedure:
1) Manifest.db खोलें और file records पढ़ें (domain, relativePath, flags, fileID/hash)
2) domain + relativePath के आधार पर मूल फ़ोल्डर हायरार्की पुनःनिर्मित करें
3) प्रत्येक स्टोर किए गए ऑब्जेक्ट को उसके reconstructed path पर copy या hardlink करें

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
नोट:
- एन्क्रिप्टेड बैकअप को संभालें — अपने extractor को बैकअप पासवर्ड प्रदान करके
- जहाँ संभव हो, साक्ष्य के मूल्य के लिए मूल timestamps/ACLs बनाए रखें


## मैसेजिंग ऐप अटैचमेंट सूचीकरण

पुनर्निर्माण के बाद, लोकप्रिय ऐप्स के लिए अटैचमेंट्स की सूची बनाएं। सटीक schema ऐप/वर्ज़न के अनुसार भिन्न होता है, लेकिन तरीका समान है: messaging database को query करें, messages को attachments से join करें, और डिस्क पर paths को resolve करें।

### iMessage (sms.db)
मुख्य टेबल्स: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
संलग्नक पथ Library/SMS/Attachments/ के अंतर्गत पुनर्निर्मित पेड़ के सापेक्ष (relative) या पूर्ण-पथ (absolute) हो सकते हैं।

### WhatsApp (ChatStorage.sqlite)
सामान्य संबंध: message table ↔ media/attachment table (नामकरण संस्करण के अनुसार भिन्न हो सकता है). ऑन‑डिस्क पाथ प्राप्त करने के लिए media पंक्तियों को query करें।

उदाहरण (सामान्य):
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
- Signal: the message DB is encrypted; however, attachments cached on disk (and thumbnails) are usually scan‑able
- Telegram: inspect cache directories (photo/video/document caches) and map to chats when possible
- Viber: Viber.sqlite contains message/attachment tables with on‑disk references

Tip: even when metadata is encrypted, scanning the media/cache directories still surfaces malicious objects.


## Scanning attachments for structural exploits

Once you have attachment paths, feed them into structural detectors that validate file‑format invariants instead of signatures. Example with ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
स्ट्रक्चरल नियमों द्वारा कवर किए जाने वाले detections में शामिल हैं:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): JBIG2 शब्दकोश की असंभव स्थितियाँ
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): अत्यधिक बड़े Huffman तालिका निर्माण
- TrueType TRIANGULATION (CVE‑2023‑41990): अप्रलेखित bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: metadata और stream component के बीच असंगतियाँ


## मान्यता, सावधानियाँ और false positives

- Time conversions: कुछ संस्करणों में iMessage तिथियों को Apple epochs/units में स्टोर करता है; रिपोर्टिंग के दौरान उचित रूप से रूपांतरित करें
- Schema drift: ऐप के SQLite schemas समय के साथ बदलते हैं; device build के अनुसार table/column नामों की पुष्टि करें
- Recursive extraction: PDFs अंदर JBIG2 streams और fonts embed कर सकते हैं; अंदरूनी objects को extract करके scan करें
- False positives: structural heuristics रूढ़िवादी होते हैं लेकिन दुर्लभ malformed पर भी flag कर सकते हैं जो benign media हैं


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
