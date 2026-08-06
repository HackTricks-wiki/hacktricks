# Forensics ya iOS Backup (triage inayolenga Messaging)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza hatua za kiutendaji za kujenga upya na kuchanganua iOS backups ili kutafuta dalili za uwasilishaji wa 0‑click exploit kupitia attachments za messaging apps. Unalenga kubadilisha mpangilio wa backup wenye majina ya hash wa Apple kuwa paths zinazoeleweka na binadamu, kisha kuorodhesha na kuchanganua attachments katika apps zinazotumika sana.

Malengo:
- Kujenga upya paths zinazosomwa kutoka Manifest.db
- Kuorodhesha messaging databases (iMessage, WhatsApp, Signal, Telegram, Viber)
- Kutatua paths za attachments, kutoa objects zilizopachikwa (PDF/Images/Fonts), na kuziwasilisha kwa structural detectors


## Kujenga upya iOS backup

Backups zilizohifadhiwa chini ya MobileSync hutumia filenames zenye hash ambazo hazisomeki na binadamu. SQLite database ya Manifest.db huunganisha kila object iliyohifadhiwa na logical path yake.

Utaratibu wa jumla:
1) Fungua Manifest.db na usome records za files (domain, relativePath, flags, fileID/hash)
2) Jenga upya folder hierarchy ya awali kulingana na domain + relativePath
3) Nakili au tumia hardlink kwa kila object iliyohifadhiwa hadi kwenye path yake iliyojengwa upya

Mfano wa workflow unaotumia tool inayotekeleza mchakato huu kuanzia mwanzo hadi mwisho (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notes:
- Shughulikia backup zilizosimbwa kwa encryption kwa kumpa extractor nenosiri la backup
- Hifadhi timestamps/ACLs za awali inapowezekana kwa thamani ya ushahidi

### Kupata na kusimbua backup (USB / Finder / libimobiledevice)

- Kwenye macOS/Finder weka "Encrypt local backup" na uunde backup mpya iliyosimbwa kwa encryption ili vipengee vya keychain viwepo.
- Kwa majukwaa yote: `idevicebackup2` (libimobiledevice ≥1.4.0) inaelewa mabadiliko ya iOS 17/18 kwenye backup protocol na hurekebisha makosa ya awali ya restore/backup handshake.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage inayoongozwa na IOC kwa kutumia MVT

Mobile Verification Toolkit ya Amnesty (mvt-ios) sasa hufanya kazi moja kwa moja kwenye iTunes/Finder backups zilizotiwa usimbaji fiche, ikiendesha kiotomatiki usimbuaji na ulinganishaji wa IOC kwa kesi za mercenary spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Matokeo huwekwa kwenye `mvt-results/` (kwa mfano, analytics_detected.json, safari_history_detected.json) na yanaweza kuhusishwa na njia za attachment zilizopatikana hapa chini.

### Uchambuzi wa jumla wa artifacts (iLEAPP)

Kwa timeline/metadata iliyo nje ya messaging, endesha iLEAPP moja kwa moja kwenye backup folder (inaunga mkono schemas za iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Kuhesabu attachments za messaging app

Baada ya reconstruction, hesabu attachments za apps maarufu. Schema halisi hutofautiana kulingana na app/version, lakini mbinu ni sawa: query messaging database, unganisha messages na attachments, kisha tambua paths kwenye disk.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Tables muhimu: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Mifano ya queries:
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
Njia za viambatisho zinaweza kuwa absolute au relative kwa tree iliyoundwa upya chini ya Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Uhusishaji wa kawaida: jedwali la message ↔ jedwali la media/attachment (majina hutofautiana kulingana na version). Query rows za media ili kupata njia za kwenye diski. iOS builds za hivi karibuni bado huonyesha `ZMEDIALOCALPATH` katika `ZWAMEDIAITEM`.
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
Njia kwa kawaida hutatuliwa chini ya `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` ndani ya backup iliyoundwa upya.

### Signal / Telegram / Viber
- Signal: message DB imesimbwa kwa njia fiche; hata hivyo, attachments zilizohifadhiwa kwenye disk (pamoja na thumbnails) kwa kawaida zinaweza kuchanganuliwa
- Telegram: cache hubaki chini ya `Library/Caches/` ndani ya sandbox; iOS 18 builds zinaonyesha bugs za kufuta cache, hivyo cache kubwa za media zilizosalia ni vyanzo vya kawaida vya ushahidi<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite ina majedwali ya message/attachment yenye marejeo ya kwenye disk

Kidokezo: hata metadata ikiwa imesimbwa kwa njia fiche, kuchanganua directories za media/cache bado hufichua objects hasidi.


## Kuchanganua attachments kwa structural exploits

Baada ya kupata attachment paths, zipitishe kwenye structural detectors zinazothibitisha file-format invariants badala ya signatures. Mfano kwa kutumia ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Madhara yanayogunduliwa na structural rules yanajumuisha:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): hali zisizowezekana za kamusi ya JBIG2
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): uundaji wa jedwali kubwa kupita kiasi za Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): bytecode opcodes ambazo hazijaandikwa kwenye nyaraka
- DNG/TIFF CVE‑2025‑43300: kutolingana kati ya metadata na vipengele vya stream


## Uthibitishaji, tahadhari, na false positives

- Mabadiliko ya muda: iMessage huhifadhi tarehe kwa Apple epochs/units katika baadhi ya matoleo; zibadilishe ipasavyo wakati wa reporting
- Schema drift: app SQLite schemas hubadilika baada ya muda; thibitisha majina ya table/column kulingana na device build
- Recursive extraction: PDFs zinaweza kupachika JBIG2 streams na fonts; extract na scan inner objects
- False positives: structural heuristics ni za tahadhari, lakini zinaweza kuripoti media adimu yenye hitilafu ambayo haina madhara<sup>[[1]](#references)[[2]](#references)</sup>


## Marejeo

- [1] [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
