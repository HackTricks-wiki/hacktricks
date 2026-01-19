# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaelezea hatua za vitendo za kujenga upya na kuchambua iOS backups kwa dalili za utoaji wa exploit wa 0‑click kupitia attachments za app za ujumbe. Unalenga kubadilisha muundo wa backup wa Apple uliopigwa hash kuwa njia zinazoweza kusomwa na binadamu, kisha kuorodhesha na kuchambua attachments katika apps za kawaida.

Goals:
- Jenga tena readable paths kutoka Manifest.db
- Orodhesha hifadhidata za ujumbe (iMessage, WhatsApp, Signal, Telegram, Viber)
- Tatua attachment paths, choma vitu vilivyowekwa (PDF/Images/Fonts), na vitumie kwa structural detectors


## Kujenga upya backup ya iOS

Backups zilizohifadhiwa chini ya MobileSync zinatumia majina ya faili yaliyopigwa hash ambayo hayajasomeka kwa binadamu. Hifadhidata ya Manifest.db ya SQLite inaweka ramani kila kitu kilichohifadhiwa kwenda kwenye njia yake ya kimantiki.

High‑level procedure:
1) Open Manifest.db and read the file records (domain, relativePath, flags, fileID/hash)
2) Recreate the original folder hierarchy based on domain + relativePath
3) Copy or hardlink each stored object to its reconstructed path

Example workflow with a tool that implements this end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Vidokezo:
- Shughulikia backups zilizosimbwa kwa kutoa nywila ya backup kwa extractor yako
- Hifadhi timestamps/ACLs asili inapowezekana kwa ajili ya thamani ya ushahidi

### Kupata na ku-decrypt backup (USB / Finder / libimobiledevice)

- Kwenye macOS/Finder weka "Encrypt local backup" na tengeneza *mpya* backup iliyosimbwa ili keychain items ziwepo.
- Inafanya kazi kwa majukwaa mbalimbali: `idevicebackup2` (libimobiledevice ≥1.4.0) inaelewa mabadiliko ya itifaki za backup za iOS 17/18 na inarekebisha matatizo ya handshake ya kurejesha/backup ya awali.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑driven triage with MVT

Mobile Verification Toolkit (mvt-ios) ya Amnesty sasa inafanya kazi moja kwa moja kwenye encrypted iTunes/Finder backups, ikiautomatisha decryption na IOC matching kwa kesi za mercenary spyware.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Matokeo huwekwa chini ya `mvt-results/` (kwa mfano, analytics_detected.json, safari_history_detected.json) na yanaweza kuendanishwa na njia za viambatisho zilizopatikana hapa chini.

### Uchambuzi wa artefakti kwa ujumla (iLEAPP)

Kwa mfululizo wa matukio/metadata zaidi ya ujumbe, endesha iLEAPP moja kwa moja kwenye folda ya backup (inaunga mkono miundo ya iOS 11‑17):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Kuorodhesha viambatisho vya app za ujumbe

Baada ya kujenga upya, orodhesha viambatisho kwa apps maarufu. Muundo halisi hutofautiana kwa app/toleo, lakini mbinu ni sawa: query kwenye messaging database, join messages na attachments, na resolve paths kwenye disk.

### iMessage (sms.db)
Majedwali muhimu: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Njia za viambatisho zinaweza kuwa kamili au jamaa kwa mti uliorejeshwa chini ya Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Uhusiano wa kawaida: jedwali la ujumbe ↔ jedwali la media/viambatisho (majina yanatofautiana kulingana na toleo). Fanya query kwa safu za media ili kupata njia za kwenye diski. Builds za iOS za hivi karibuni bado zinaonyesha `ZMEDIALOCALPATH` katika `ZWAMEDIAITEM`.
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
Njia kawaida huonekana chini ya `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` ndani ya backup iliyojengwa upya.

### Signal / Telegram / Viber
- Signal: DB ya ujumbe imefungiwa; hata hivyo, viambatisho vilivyohifadhiwa kwenye disk (na thumbnails) kawaida vinaweza kuchunguzwa
- Telegram: cache hubaki chini ya `Library/Caches/` ndani ya sandbox; builds za iOS 18 zinaonyesha mdudu wa kufuta cache, hivyo caches kubwa za vyombo zenye mabaki mara nyingi ni vyanzo vya ushahidi
- Viber: Viber.sqlite ina meza za ujumbe/viambatisho zenye marejeo kwenye disk

Kidokezo: hata pale metadata imefungwa, kuchunguza saraka za media/cache bado hutoa vitu hatarishi.


## Kuchunguza viambatisho kwa exploits za kimuundo

Mara utakapo kuwa na njia za viambatisho, ziingize katika vichunguzi vya kimuundo vinavyothibitisha kanuni zisizobadilika za muundo wa faili badala ya saini. Mfano na ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Utambuzi zinazofunikwa na kanuni za kimuundo ni pamoja na:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): hali za kamusi za JBIG2 zisizowezekana
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): miundo ya jedwali kubwa za Huffman
- TrueType TRIANGULATION (CVE‑2023‑41990): opcode za bytecode zisizoandikwa kwenye nyaraka
- DNG/TIFF CVE‑2025‑43300: kutofautiana kati ya metadata na sehemu za stream


## Uthibitisho, tahadhari, na matokeo ya uongo

- Mabadiliko ya wakati: iMessage huhifadhi tarehe katika Apple epochs/units kwenye baadhi ya matoleo; badilisha ipasavyo wakati wa kuripoti
- Schema drift: skimu za SQLite za app hubadilika kwa muda; thibitisha majina ya jedwali/kolamu kwa kila build ya kifaa
- Uchimbaji wa kurudia (Recursive extraction): PDF zinaweza kujumuisha JBIG2 streams na fonts; toa na skani vitu vya ndani
- Matokeo ya uongo: heuristics za kimuundo ni za tahadhari lakini zinaweza kuonyesha mfano nadra uliokatwa lakini usio hatari wa media


## Marejeo

- [ELEGANTBOUNCER: Wakati Huwezi Kupata Sampuli lakini Unahitaji Kufuatilia Tishio](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [Mradi wa ElegantBouncer (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT mtiririko wa chelezo za iOS](https://docs.mvt.re/en/latest/ios/backup/check/)
- [Notisi za kutolewa za libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
