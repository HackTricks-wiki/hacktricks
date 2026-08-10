# iOS Backup Forensics (boodskapgesentreerde triage)

Hierdie bladsy beskryf praktiese stappe om iOS-backups te rekonstrueer en te ontleed vir tekens van 0-click exploit-lewering via aanhegsels in boodskaptoepassings. Dit fokus daarop om Apple se gehashte backup-uitleg in mensleesbare paaie om te skakel, en dan aanhegsels oor algemene toepassings heen op te som en te skandeer.

Doelwitte:
- Herbou leesbare paaie vanaf Manifest.db
- Som boodskapdatabasisse op (iMessage, WhatsApp, Signal, Telegram, Viber)
- Bepaal aanhegselpaaie, onttrek ingebedde objek­te waar dit ondersteun word (PDF/Images/Fonts), en voer dit na strukturele detektors

## Rekonstruksie van ’n iOS-backup

Backups wat onder MobileSync gestoor word, gebruik gehashte lêername wat nie mensleesbaar is nie. Die Manifest.db SQLite-databasis karteer elke gestoorde objek na sy logiese pad.<sup>[[1]](#references)[[2]](#references)</sup>

Hoëvlak-prosedure:
1) Maak Manifest.db oop en lees die lêerrekords (domain, relativePath, flags, fileID/hash)
2) Herskep die oorspronklike vouerhiërargie gebaseer op domain + relativePath
3) Kopieer of hardlink elke gestoorde objek na sy gerekonstrueerde pad

Voorbeeldwerkvloei met ’n tool wat dit end-tot-end implementeer (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Notas:
- De-enkripteer geënkripteerde rugsteune voordat jy dit aan 'n reconstruction tool deurgee; ElegantBouncer verwag 'n gede-enkripteerde rugsteun.<sup>[[2]](#references)[[3]](#references)</sup>
- Behou oorspronklike tydstempels/ACL's waar moontlik vir bewyswaarde

### Verkryging en dekriptering van die rugsteun (USB / Finder / libimobiledevice)

- Aktiveer "Encrypt local backup" in Finder/Apple Devices/iTunes en skep 'n nuwe rugsteun; geënkripteerde rugsteune kan gestoorde wagwoorde en Health-data insluit wat ongeënkripteerde rugsteune weglaat.<sup>[[8]](#references)</sup>
- Kruisplatform: libimobiledevice 1.4.0 sluit regstellings vir `idevicebackup2` in.<sup>[[4]](#references)</sup> Aktiveer enkripsie interaktief, en dwing dan 'n volledige rugsteun af met die gedokumenteerde bevelvolgorde, met die teikengids laaste.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### IOC-gedrewe triage met MVT

Amnesty se Mobile Verification Toolkit kan ’n sleutel uit geënkripteerde iTunes/Finder-backups onttrek en dit dekripteer, en dan die gedekripteerde backup met ’n STIX2 IOC-lêer skandeer.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Met `-o` word JSON-resultate onder `/tmp/mvt-results/` geskryf; IOC-treffers gebruik ’n `_detected`-agtervoegsel en kan gekorreleer word met die paaie van aanhegsels wat hieronder herwin is.<sup>[[3]](#references)</sup>

### Algemene artefakontleding (iLEAPP)

Vir tydlyn-/metadata-inligting buiten boodskappe, voer iLEAPP teen die rou rugsteunlêergids uit; die `itunes`-invoertipe aanvaar iTunes/Finder-rugsteun en huidige uitgawes ondersteun iOS/iPadOS 11 tot en met die huidige weergawes.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Opsomming van aanhegsels in messaging apps

Na rekonstruksie, lys aanhegsels vir gewilde apps. Die presiese skema wissel volgens app/weergawe, maar die benadering is soortgelyk: doen navraag oor die messaging-databasis, koppel messages aan attachments, en bepaal paaie op skyf.<sup>[[1]](#references)[[2]](#references)</sup>

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
Aanhegselpaaie kan absoluut wees of relatief tot die gerekonstrueerde boom onder Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Algemene koppeling: message-tabel ↔ media/attachment-tabel (benaming wissel volgens weergawe). Doen ’n navraag oor media-rye om paaie op die skyf te verkry. Belkasoft identifiseer `ZMEDIALOCALPATH` in `ZWAMEDIAITEM` as die ligging van die medialêer; ElegantBouncer se huidige implementering koppel `ZWAMEDIAITEM.ZMESSAGE` aan `ZWAMESSAGE.Z_PK` en voeg `Message/` vooraan wanneer ’n pad opgelos word wat met `Media/` begin.<sup>[[9]](#references)[[10]](#references)</sup>
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
Vir daardie ElegantBouncer-rekonstruksiepad word ’n mediapad wat met `Media/` begin, opgelos onder `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; Belkasoft se gids dokumenteer egter ’n `Messages/Media/`-pad, dus moet die backup geïnspekteer word voordat enige spelling aanvaar word.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: die boodskap-DB is encrypted; aanhegsels wat egter op skyf gecache is (en duimnaels), kan gewoonlik geskandeer word.<sup>[[2]](#references)</sup>
- Telegram: inspekteer die app se media-/cache-gidse; Telegram het ’n cache-skoonmaakbug in iOS-app 11.2 op iOS 18.0.1 gedokumenteer, wat in 11.3 as reggestel gemerk is, dus moet daar na oorblywende lêers gesoek word.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite bevat boodskap-/aanhegsel-tabelle met verwysings na data op skyf.<sup>[[2]](#references)</sup>

Wenk: selfs wanneer metadata encrypted is, bring die skandering van die media-/cache-gidse steeds malicious objects na vore.<sup>[[2]](#references)</sup>


## Skandering van aanhegsels vir strukturele exploits

Sodra jy aanhegselpaaie het, voer dit deur strukturele detectors wat lêerformaat-invariante eerder as signatures valideer. Voorbeeld met ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
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
- DNG/TIFF CVE‑2025‑43300: teenstrydighede tussen metadata- en stroomkomponente


## Validering, voorbehoude en vals positiewe

- Tydomskakelings: iMessage stoor datums in Apple-epogge/-eenhede op sommige weergawes; skakel dit toepaslik om tydens verslagdoening.<sup>[[2]](#references)</sup>
- Skemaverandering: app SQLite-skemas verander met verloop van tyd; bevestig tabel- en kolomname volgens die toestelbou
- Rekursiewe ekstraksie: PDF's kan JBIG2-strome en fonts inbed; gebruik 'n ontleder wat innerlike objekte kan onttrek en skandeer
- Vals positiewe: strukturele heuristieke is konserwatief, maar kan seldsame, misvormde dog onskadelike media merk.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Wanneer jy nie die monsters kan kry nie, maar steeds die bedreiging moet opspoor](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer-projek (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS-rugsteunwerkvloei](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0-vrystellingsnotas](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Opdatering 11.2 het kasopruiming op iOS 18.0.1 gebreek (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2-handleiding](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP-projek (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [Meer oor geënkripteerde rugsteun op jou iPhone, iPad of iPod touch (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp-forensika met Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp-skandeerder en padoplosser](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
