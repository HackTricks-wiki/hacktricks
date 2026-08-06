# iOS Backup Forensics (Boodskapgesentreerde triage)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy beskryf praktiese stappe om iOS-backups te rekonstrueer en te ontleed vir tekens van 0-click exploit-lewering via boodskapapp-aanhegsels. Dit fokus daarop om Apple se gehashte backuplay-out na mensleesbare paaie om te skakel, en dan aanhegsels oor algemene apps heen te inventariseer en te skandeer.

Doelwitte:
- Herbou leesbare paaie vanaf Manifest.db
- Inventariseer boodskapdatabasisse (iMessage, WhatsApp, Signal, Telegram, Viber)
- Los aanhegselpaaie op, onttrek ingebedde objekte (PDF/Images/Fonts), en voer dit aan strukturele detektors

## Rekonstruksie van ’n iOS-backup

Backups wat onder MobileSync gestoor word, gebruik gehashte lêername wat nie mensleesbaar is nie. Die Manifest.db SQLite-databasis koppel elke gestoorde objek aan sy logiese pad.

Hoëvlakprosedure:
1) Maak Manifest.db oop en lees die lêerrekords (domain, relativePath, flags, fileID/hash)
2) Herskep die oorspronklike vouerhiërargie gebaseer op domain + relativePath
3) Kopieer of hardlink elke gestoorde objek na sy gerekonstueerde pad

Voorbeeldwerkvloei met ’n tool wat dit end-to-end implementeer (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Aantekeninge:
- Hanteer geënkripteerde rugsteune deur die rugsteunwagwoord aan jou extractor te verskaf
- Behou oorspronklike tydstempels/ACL's waar moontlik vir bewyswaarde

### Verkryging en dekripsie van die rugsteun (USB / Finder / libimobiledevice)

- Stel op macOS/Finder "Encrypt local backup" en skep 'n *vars* geënkripteerde rugsteun sodat sleutelketting-items teenwoordig is.
- Kruisplatform: `idevicebackup2` (libimobiledevice ≥1.4.0) verstaan iOS 17/18-rugsteunprotokolveranderinge en stel vroeëre herstel-/rugsteun-handshake-foute reg.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC-gedrewe triage met MVT

Amnesty se Mobile Verification Toolkit (mvt-ios) werk nou direk met geënkripteerde iTunes/Finder-rugsteunkopieë en outomatiseer dekripsie en IOC-passing vir gevalle van huursoldaat-spyware.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Uitsette word onder `mvt-results/` gestoor (bv. `analytics_detected.json`, `safari_history_detected.json`) en kan gekorreleer word met die aanhegselpaaie wat hieronder herwin is.

### Algemene artefakontleding (iLEAPP)

Vir tydlyn-/metadata buite boodskappe, voer iLEAPP direk op die backup-lêergids uit (ondersteun iOS 11‑17-skemas):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerasie van aanhegsels in messaging-apps

Na rekonstruksie, enumereer aanhegsels vir gewilde apps. Die presiese skema verskil volgens app/weergawe, maar die benadering is soortgelyk: doen navraag oor die messaging-databasis, koppel boodskappe aan aanhegsels, en bepaal die paaie op skyf.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Sleuteltabelle: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

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
Aanhegselpaaie kan absoluut wees of relatief tot die gerekonstrueerde boom onder Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Algemene koppeling: boodskapstabel ↔ media-/aanhegselstabel (benaming wissel volgens weergawe). Doen navraag oor media-rye om paaie op skyf te verkry. Onlangse iOS-builds stel steeds `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` bloot.
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
Paaie word gewoonlik opgelos onder `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` binne die gerekonstrueerde backup.

### Signal / Telegram / Viber
- Signal: die message DB is geïnkripteer; aanhegsels wat op die skyf gekas is (en duimnaels) kan egter gewoonlik geskandeer word
- Telegram: die kas bly onder `Library/Caches/` binne die sandbox; iOS 18 builds toon foute met die skoonmaak van die kas, dus is groot oorblywende mediakasse algemene bewysbronne<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite bevat message-/attachment-tabelle met verwysings na data op die skyf

Wenk: selfs wanneer metadata geïnkripteer is, bring die skandering van die media-/kas-gidse steeds malicious objects na vore.


## Skandering van aanhegsels vir structural exploits

Sodra jy attachment-paaie het, voer hulle na structural detectors wat file-format-invariante valideer in plaas van signatures. Voorbeeld met ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Opsporings wat deur strukturele reëls gedek word, sluit in:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): onmoontlike JBIG2-woordeboektoestande
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): buitensporig groot Huffman-tabelkonstruksies
- TrueType TRIANGULATION (CVE‑2023‑41990): ongedokumenteerde bytecode-opkodes
- DNG/TIFF CVE‑2025‑43300: wanpassings tussen metadata- en stroomkomponente


## Validering, voorbehoude en vals positiewe

- Tydomskakelings: iMessage stoor datums in Apple-epogge/eenhede op sommige weergawes; skakel dit toepaslik om tydens verslagdoening
- Skemaveranderinge: app SQLite-skemas verander met verloop van tyd; bevestig tabel-/kolomname per toestelbou
- Rekursiewe ekstraksie: PDF's kan JBIG2-strome en fonts inbed; ekstraheer en skandeer interne objekte
- Vals positiewe: strukturele heuristieke is konserwatief, maar kan seldsame, misvormde maar onskadelike media aandui<sup>[[1]](#references)[[2]](#references)</sup>


## Verwysings

- [1] [ELEGANTBOUNCER: Wanneer jy nie die samples kan bekom nie, maar steeds die bedreiging moet opspoor](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer-projek (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS-rugsteunwerkvloei](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0-vrystellingsnotas](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Opdatering 11.2 het kasopruiming op iOS 18.0.1 gebreek (Telegram-foutspoorder)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
