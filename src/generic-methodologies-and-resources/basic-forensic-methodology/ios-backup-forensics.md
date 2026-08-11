# iOS-rugsteunforensika (boodskapgesentreerde triage)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy beskryf praktiese stappe om iOS-rugsteuns te rekonstrueer en te ontleed vir tekens van 0‑click exploit-aflewering via aanhegsels in messaging-apps. Dit fokus daarop om Apple se gehashte rugsteunuitleg na mensleesbare paaie om te skakel, en dan aanhegsels oor algemene apps heen te enumerereer en te skandeer.

Doelwitte:
- Herbou leesbare paaie vanaf Manifest.db
- Enumerere messaging-databasisse (iMessage, WhatsApp, Signal, Telegram, Viber)
- Los aanhegselpaaie op, onttrek ingebedde objekte waar dit ondersteun word (PDF/Images/Fonts), en voer dit na strukturele detektors


## Rekonstrueer ’n iOS-rugsteun

Rugsteuns wat onder MobileSync gestoor word, gebruik gehashte lêername wat nie mensleesbaar is nie. Die Manifest.db SQLite-databasis koppel elke gestoorde objek aan sy logiese pad.<sup>[[1]](#references)[[2]](#references)</sup>

Hoëvlakprosedure:
1) Maak Manifest.db oop en lees die lêerrekords (domain, relativePath, flags, fileID/hash)
2) Herbou die oorspronklike vouerhiërargie gebaseer op domain + relativePath
3) Kopieer of hardlink elke gestoorde objek na sy gerekonstrueerde pad

Voorbeeldwerkvloei met ’n tool wat dit end-tot-end implementeer (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- De-enkripteer geënkripteerde rugsteune voordat jy dit aan ’n rekonstruksienutsding deurgee; ElegantBouncer verwag ’n gede-enkripteerde rugsteun.<sup>[[2]](#references)[[3]](#references)</sup>
- Behou oorspronklike tydstempels/ACL’s waar moontlik vir bewyswaarde

### Verkryging en de-enkripsie van die rugsteun (USB / Finder / libimobiledevice)

- In Finder/Apple Devices/iTunes, aktiveer "Encrypt local backup" en skep ’n nuwe rugsteun; geënkripteerde rugsteune kan gestoorde wagwoorde en Health-data insluit wat ongeënkripteerde rugsteune weglaat.<sup>[[8]](#references)</sup>
- Platform-onafhanklik: libimobiledevice 1.4.0 sluit regstellings vir `idevicebackup2` in.<sup>[[4]](#references)</sup> Aktiveer enkripsie interaktief, en forseer dan ’n volledige rugsteun deur die gedokumenteerde bevelvolgorde te gebruik, met die teikengids laaste.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### IOC-gedrewe triage met MVT

Amnesty se Mobile Verification Toolkit kan ’n sleutel uit geïnkripteerde iTunes/Finder-rugsteunlêers onttrek en dit dekripteer, en dan die gedekripteerde rugsteun met ’n STIX2 IOC-lêer skandeer.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Met `-o` word JSON-resultate onder `/tmp/mvt-results/` geskryf; IOC-treffers gebruik ’n `_detected`-agtervoegsel en kan gekorreleer word met die aanhegselpaaie wat hieronder herwin is.<sup>[[3]](#references)</sup>

### Algemene artefakontleding (iLEAPP)

Vir tydlyn-/metadata-inligting buiten messaging, voer iLEAPP teen die rou rugsteunlêergids uit; die `itunes`-invoertipe aanvaar iTunes/Finder-rugsteun en huidige vrystellings ondersteun iOS/iPadOS 11 tot die huidige weergawes.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumerasie van aanhegsels in messaging apps

Na rekonstruksie, lys aanhegsels vir gewilde apps. Die presiese skema verskil volgens app/weergawe, maar die benadering is soortgelyk: doen navrae op die messaging-databasis, koppel boodskappe aan aanhegsels, en bepaal die paaie op skyf.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Sleuteltabelle: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Attachment-paaie kan absoluut wees of relatief tot die gerekonstrueerde boom onder Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Algemene koppeling: message-tabel ↔ media/attachment-tabel (benaming wissel volgens weergawe). Doen navrae op media-rye om paaie op die skyf te verkry. Belkasoft identifiseer `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` as die ligging van die medialêer; ElegantBouncer se huidige implementering koppel `ZWAMEDIAITEM.ZMESSAGE` aan `ZWAMESSAGE.Z_PK` en voeg `Message/` vooraan wanneer ’n pad opgelos word wat met `Media/` begin.<sup>[[9]](#references)[[10]](#references)</sup>
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
Vir daardie ElegantBouncer-rekonstruksiepad word ’n mediapad wat met `Media/` begin, opgelos onder `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; Belkasoft se gids dokumenteer egter ’n `Messages/Media/`-pad, dus moet jy die backup inspekteer voordat jy enige van die twee spellings aanvaar.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: die boodskap-DB is geënkripteer; aanhegsels wat op die skyf gekas is (en duimnaels) is egter gewoonlik skandeerbaar.<sup>[[2]](#references)</sup>
- Telegram: inspekteer die app se media-/kasgidse; Telegram het ’n kas-skoonmaakfout in iOS-app 11.2 op iOS 18.0.1 gedokumenteer, wat as reggestel in 11.3 gemerk is, dus moet jy vir oorblywende lêers kyk.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite bevat boodskap-/aanhegsel-tabelle met verwysings na data op die skyf.<sup>[[2]](#references)</sup>

Wenk: selfs wanneer metadata geënkripteer is, sal die skandering van media-/kasgidse steeds kwaadwillige objekte na vore bring.<sup>[[2]](#references)</sup>


## Skandering van aanhegsels vir strukturele exploits

Sodra jy aanhegselpaaie het, voer dit in strukturele detektors in wat lêerformaat-invariante eerder as handtekeninge valideer. Voorbeeld met ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Deteksies wat deur strukturele reëls gedek word, sluit in:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): onmoontlike JBIG2-dictionary states
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): oorgrootte Huffman-table constructions
- TrueType TRIANGULATION (CVE‑2023‑41990): ongedokumenteerde bytecode-opcodes
- DNG/TIFF CVE‑2025‑43300: teenstrydighede tussen metadata en stream-komponente


## Validering, voorbehoude en vals positiewe

- Tydomskakelings: iMessage stoor datums in Apple-epogte/-eenhede op sommige weergawes; skakel dit toepaslik om tydens rapportering.<sup>[[2]](#references)</sup>
- Schema drift: app SQLite-schemas verander met verloop van tyd; bevestig tabel-/kolomname per toestel-build
- Rekursiewe ekstraksie: PDFs kan JBIG2-streams en fonts insluit; gebruik ’n parser wat inner objects kan ekstraheer en skandeer
- Vals positiewe: strukturele heuristieke is konserwatief, maar kan seldsame misvormde dog onskadelike media merk.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Wanneer jy nie die samples kan kry nie, maar steeds die threat moet opspoor](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer-projek (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS-backup-workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0-vrystellingsnotas](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 het cache cleanup op iOS 18.0.1 gebreek (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2-handleiding](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP-projek (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Oor encrypted backups op jou iPhone, iPad of iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics met Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp-scanner en path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
