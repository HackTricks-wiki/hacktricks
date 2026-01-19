# iOS Backup Forensics (Messaging‑centric triage)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy beskryf praktiese stappe om iOS-rugsteun te herbou en te ontleed vir tekens van 0‑click eksplootlewering via boodskap‑app‑aanhangsels. Dit fokus op die omskakeling van Apple se gehashde rugsteunstruktuur na mensleesbare paadjies, en daarna die opsomming en deursoeking van aanhangsels oor algemene apps.

Doelwitte:
- Herbou mensleesbare paadjies vanaf Manifest.db
- Enumereer boodskapdatabasisse (iMessage, WhatsApp, Signal, Telegram, Viber)
- Los aanhangselpaadjies op, onttrek ingebedde objekte (PDF/Images/Fonts), en voer dit aan strukturele detektore

## Herbouing van 'n iOS‑rugsteun

Rugsteune gestoor onder MobileSync gebruik gehashde lêernaamE wat nie mensleesbaar is nie. Die Manifest.db SQLite databasis karteer elke gestoorde objek na sy logiese pad.

Hoëvlak prosedure:
1) Maak Manifest.db oop en lees die filerekords (domain, relativePath, flags, fileID/hash)
2) Herstel die oorspronklike vouerhiërargie gebaseer op domain + relativePath
3) Kopieer of hardlink elke gestoorde objek na sy heropgeboude pad

Voorbeeld‑werksvloei met 'n hulpmiddel wat dit end‑to‑end implementeer (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Aantekeninge:
- Hanteer versleutelde rugsteunkopieë deur die rugsteunwagwoord aan jou extractor te verskaf
- Behou oorspronklike tydstempels/ACLs waar moontlik vir bewyswaarde

### Verkryging & ontsleuteling van die rugsteun (USB / Finder / libimobiledevice)

- Op macOS/Finder stel "Encrypt local backup" en skep 'n *vars* versleutelde rugsteun sodat keychain-items teenwoordig is.
- Platformonafhanklik: `idevicebackup2` (libimobiledevice ≥1.4.0) verstaan iOS 17/18 rugsteunprotokolveranderinge en herstel vroeër restore/backup-handshake-foute.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑gedrewe triage met MVT

Amnesty se Mobile Verification Toolkit (mvt-ios) werk nou direk op geënkripteerde iTunes/Finder‑rugsteun, en outomatiseer die ontsleuteling en IOC‑vergelyking vir huursigware‑sake.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Uitsette beland onder `mvt-results/` (bv., analytics_detected.json, safari_history_detected.json) en kan gekorreleer word met die aanhangselpaaie wat hieronder gevind is.

### Algemene artefakontleding (iLEAPP)

Voer iLEAPP direk op die backup-lêergids uit (ondersteun iOS 11‑17 skemas):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerasie van boodskap-app-aanhangsels

Na rekonstruksie, lys aanhangsels vir gewilde apps. Die presiese skema verskil per app/weergawe, maar die benadering is soortgelyk: voer navrae op die boodskapdatabasis uit, koppel boodskappe aan aanhangsels, en los padlokasies op die skyf op.

### iMessage (sms.db)
Belangrike tabelle: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Voorbeeldnavrae:
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
Aanhangselspaaie kan absoluut wees of relatief tot die herboude lêerboom onder Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Algemene koppeling: message table ↔ media/attachment table (benaming verskil per weergawe). Voer navrae uit op media-rye om paaie op skyf te bekom. Onlangse iOS-boue openbaar steeds `ZMEDIALOCALPATH` in `ZWAMEDIAITEM`.
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
Paaie los gewoonlik op onder `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` binne die hergestelde rugsteun.

### Signal / Telegram / Viber
- Signal: die boodskap-DB is versleutel; egter is aanhegsels wat op skyf in die cache gestoor is (en miniatuurbeelde) gewoonlik deursoekbaar
- Telegram: die cache bly onder `Library/Caches/` binne die sandbox; iOS 18-weergawes vertoon cache-skoonmaak-foute, so groot residuele mediacaches is algemene bewysbronne
- Viber: Viber.sqlite bevat boodskap-/aanhegsel-tabelle met op-skyf verwysings

Wenk: selfs wanneer metadata versleutel is, bring die deursoeking van die media-/cache-gidse steeds kwaadwillige objekte aan die lig.


## Scanning attachments for structural exploits

Sodra jy aanhegsels‑paadjies het, voer hulle in strukturele detektore in wat lêer‑formaat‑invariantes valideer in plaas van handtekeninge. Voorbeeld met ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detections covered by structural rules include:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): onmoontlike JBIG2 woordeboektoestande
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oorgroot Huffman-tabelkonstruksies
- TrueType TRIANGULATION (CVE‑2023‑41990): ondokumenteerde bytecode-opkodes
- DNG/TIFF CVE‑2025‑43300: onversoenbaarhede tussen metadata en stroomkomponente


## Validering, kanttekeninge en vals positiewe

- Tydomskakelings: iMessage stoor datums in Apple-epochs/eenhede in sekere weergawes; skakel dit toepaslik om tydens rapportering
- Skemadrift: app SQLite-skema's verander oor tyd; bevestig tabel- en kolomname per toestelbou
- Rekursiewe uittrekking: PDF's kan JBIG2-strome en lettertipes inkorporeer; ekstraheer en ondersoek binneste objekte
- Vals positiewe: strukturele heuristieke is konserwatief, maar kan seldsame misvormde maar onskadelike media aandui


## References

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
