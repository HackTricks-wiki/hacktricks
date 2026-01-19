# iOS forenzička analiza rezervnih kopija (trijaža fokusirana na aplikacije za razmenu poruka)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje praktične korake za rekonstrukciju i analizu iOS rezervnih kopija u potrazi za znakovima isporuke 0‑click exploit-a putem priloga u aplikacijama za poruke. Fokus je na pretvaranju Apple‑ovog hashiranog rasporeda rezervnih kopija u čitljive putanje, a zatim na enumeraciji i skeniranju priloga u uobičajenim aplikacijama.

Ciljevi:
- Rekreirati čitljive putanje iz Manifest.db
- Enumerisati baze poruka (iMessage, WhatsApp, Signal, Telegram, Viber)
- Resolvirati putanje priloga, izdvojiti ugrađene objekte (PDF/slike/fontovi) i proslediti ih strukturnim detektorima


## Rekonstrukcija iOS rezervne kopije

Rezervne kopije smeštene pod MobileSync koriste hashirane nazive fajlova koji nisu čitljivi. SQLite baza Manifest.db mapira svaki sačuvan objekat na njegovu logičku putanju.

Opšti postupak:
1) Otvoriti Manifest.db i pročitati zapise fajlova (domain, relativePath, flags, fileID/hash)
2) Rekreirati originalnu hijerarhiju foldera na osnovu domain + relativePath
3) Kopirati ili napraviti hardlink za svaki sačuvan objekat do njegove rekonstruisane putanje

Primer toka rada uz alat koji implementira ovo end‑to‑end (ElegantBouncer):
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Napomene:
- Rukujte enkriptovanim rezervnim kopijama tako što ćete svom extractor‑u obezbediti lozinku rezervne kopije
- Sačuvajte originalne vremenske oznake/ACL-ove kad je moguće zbog dokazne vrednosti

### Pribavljanje i dešifrovanje rezervne kopije (USB / Finder / libimobiledevice)

- Na macOS/Finder podesite "Encrypt local backup" i napravite *novu* enkriptovanu rezervnu kopiju tako da keychain stavke budu prisutne.
- Višeplatformsko: `idevicebackup2` (libimobiledevice ≥1.4.0) razume izmene protokola rezervne kopije u iOS 17/18 i ispravlja ranije greške u handshake‑u pri restore/backup.
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### IOC‑vođena trijaža sa MVT

Amnesty’s Mobile Verification Toolkit (mvt-ios) sada radi direktno na šifrovanim iTunes/Finder backup-ima, automatizujući dešifrovanje i IOC upoređivanje za slučajeve mercenary spyware-a.
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Rezultati se nalaze u `mvt-results/` (npr. analytics_detected.json, safari_history_detected.json) i mogu se povezati sa putanjama priloga oporavljenim ispod.

### Opšte parsiranje artefakata (iLEAPP)

Za timeline i metapodatke koji nisu iz poruka, pokrenite iLEAPP direktno na folderu rezervne kopije (podržava iOS 11‑17 sheme):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracija priloga u aplikacijama za poruke

Nakon rekonstrukcije, nabrojte priloge za popularne aplikacije. Tačna šema varira po aplikaciji/versiji, ali pristup je sličan: upitajte bazu podataka poruka, povežite poruke sa prilozima (join) i razrešite putanje na disku.

### iMessage (sms.db)
Ključne tabele: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ)

Primeri upita:
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
Putanje priloga mogu biti apsolutne ili relativne u odnosu na rekonstruisano stablo pod Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Uobičajena povezanost: message table ↔ media/attachment table (nazivi se razlikuju po verziji). Pretražite redove media da biste dobili putanje na disku. Noviji iOS buildovi i dalje izlažu `ZMEDIALOCALPATH` u `ZWAMEDIAITEM`.
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
Putanje se obično nalaze pod `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` unutar rekonstruisane rezervne kopije.

### Signal / Telegram / Viber
- Signal: baza poruka je šifrovana; međutim, privitci keširani na disku (i thumbnaili) su obično skenirabilni
- Telegram: keš ostaje pod `Library/Caches/` unutar sandboxa; iOS 18 buildovi pokazuju greške u čišćenju keša, pa su veliki preostali keševi medija čest izvor dokaza
- Viber: Viber.sqlite sadrži tabele poruka/privitaka sa referencama na disku

Savet: čak i kada su metapodaci šifrovani, skeniranje direktorijuma media/cache i dalje otkriva maliciozne objekte.


## Scanning attachments for structural exploits

Kada imate putanje privitaka, prosledite ih strukturnim detektorima koji proveravaju invarijante formata fajla umesto potpisa. Primer sa ElegantBouncer:
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcije obuhvaćene strukturnim pravilima uključuju:
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): nemoguća stanja JBIG2 rečnika
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): prevelike konstrukcije Huffmanovih tabela
- TrueType TRIANGULATION (CVE‑2023‑41990): nedokumentovani opcode-i bajtkoda
- DNG/TIFF CVE‑2025‑43300: neusklađenosti metapodataka i komponenti toka


## Validacija, napomene i lažno pozitivni nalazi

- Konverzije vremena: iMessage čuva datume u Apple epoch jedinicama u nekim verzijama; prilikom izveštavanja konvertujte ih odgovarajuće
- Promene šeme: SQLite šeme aplikacija se menjaju tokom vremena; potvrdite nazive tabela/kolona za build uređaja
- Rekurzivno izdvajanje: PDF-ovi mogu ugraditi JBIG2 tokove i fontove; izdvojite i skenirajte unutrašnje objekte
- Lažno pozitivni nalazi: strukturne heuristike su konzervativne, ali mogu označiti retke, malformirane, ali bezopasne medijske fajlove


## Reference

- [ELEGANTBOUNCER: When You Can't Get the Samples but Still Need to Catch the Threat](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)

{{#include ../../banners/hacktricks-training.md}}
