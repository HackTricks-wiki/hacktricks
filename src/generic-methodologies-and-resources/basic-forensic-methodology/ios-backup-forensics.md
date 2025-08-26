# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy beskryf praktiese stappe om iOS‑rugsteune te herbou en te ontleed vir tekens van 0‑click exploit‑aflewering via boodskap‑app‑aanhangsels. Dit fokus op die omskakeling van Apple se gehashede rugsteunstruktuur na mensleesbare paadjies, en daarna die opsomming en skandering van aanhangsels oor algemene apps.

Doelwitte:
- Herbou mensleesbare paaie vanaf Manifest.db
- Lys boodskapdatabasisse (iMessage, WhatsApp, Signal, Telegram, Viber)
- Los aanhangselpaaie op, ekstraheer ingeslote voorwerpe (PDF/Images/Fonts), en voer dit aan strukturele detektors


## Herbou van 'n iOS‑rugsteun

Rugsteune wat onder MobileSync gestoor word, gebruik gehashede lêernaamme wat nie mensleesbaar is nie. Die Manifest.db SQLite‑databasis koppel elke gestoorde objek aan sy logiese pad.

Hoëvlak prosedure:
1) Maak Manifest.db oop en lees die lêerrekords (domain, relativePath, flags, fileID/hash)
2) Herskep die oorspronklike vouerhiërargie gebaseer op domain + relativePath
3) Kopieer of hardlink elke gestoorde objek na sy herboude pad

Voorbeeldwerkvloei met 'n gereedskap wat dit end‑to‑end implementeer (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Aantekeninge:
- Hanteer encrypted backups deur die backup password aan jou extractor te verskaf
- Behou oorspronklike timestamps/ACLs waar moontlik vir bewysewaarde


## Boodskap-app aanhegselopsomming

Na rekonstruksie, lys aanhegsels vir gewilde apps. Die presiese schema verskil per app/weergawe, maar die benadering is soortgelyk: voer navrae op die messaging-databasis uit, koppel boodskappe aan aanhegsels, en los paaie op die skyf op.

### iMessage (sms.db)
Belangrike tabelle: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Voorbeeld navrae:
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
Aanhegselpaaie kan absoluut wees of relatief tot die herkonstrueerde boom onder Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Algemene koppeling: message table ↔ media/attachment table (benaming verskil per weergawe). Voer navrae op media-rye uit om die paaie op die skyf te verkry.

Example (generic):
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
Adjust table/column names to your app-weergawe (ZWAMESSAGE/ZWAMEDIAITEM is algemeen in iOS-builds).

### Signal / Telegram / Viber
- Signal: die boodskap-DB is geïnkripteer; attachments wat op skyf gecache is (en miniatuurprente) is gewoonlik deursoekbaar
- Telegram: ondersoek cache-gidse (foto-/video-/dokument-cache) en koppel dit aan gesprekke waar moontlik
- Viber: Viber.sqlite bevat boodskap-/aanhangsel-tabelle met verwysings op skyf

Tip: selfs wanneer metadata geïnkripteer is, openbaar die deursoeking van media-/cache-gidse steeds kwaadwillige voorwerpe.


## Scanning attachments for structural exploits

Sodra jy aanhangselpade het, voer hulle in strukturele detectors wat file‑format invariants valideer in plaas van signatures. Voorbeeld met ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): onmoontlike JBIG2-woordeboektoestande
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oorgrootte Huffman-tabelkonstruksies
- TrueType TRIANGULATION (CVE‑2023‑41990): ongedokumenteerde bytecode-opkodes
- DNG/TIFF CVE‑2025‑43300: onversoenbaarhede tussen metadata en stroomkomponente


## Validering, voorbehoude en vals positiewe

- Tydomsettings: iMessage stoor datums in Apple-epoche/enhede in sommige weergawes; skakel dit toepaslik om tydens verslaggewing
- Schema drift: app SQLite-skema's verander oor tyd; bevestig tabel- en kolomname per device build
- Rekursiewe ekstraksie: PDFs kan JBIG2-strome en lettertipes inkapsel; ekstraheer en skandeer inwendige voorwerpe
- Vals positiewe: strukturele heuristieke is konserwatief maar kan seldsame, verkeerd gevormde maar onskadelike media aandui


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)

{{#include ../../banners/hacktricks-training.md}}
