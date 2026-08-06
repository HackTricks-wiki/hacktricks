# iOS Backup Forensics (triage fokusiran na Messaging)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje praktične korake za rekonstrukciju i analizu iOS backup-a radi pronalaženja znakova isporuke 0-click exploit-a putem priloga u messaging aplikacijama. Fokus je na pretvaranju Apple-ovog hash-ovanog rasporeda backup-a u putanje čitljive ljudima, a zatim na nabrajanju i skeniranju priloga u uobičajenim aplikacijama.

Ciljevi:
- Ponovo izgraditi čitljive putanje iz Manifest.db
- Nabrojati messaging baze podataka (iMessage, WhatsApp, Signal, Telegram, Viber)
- Razrešiti putanje priloga, izdvojiti ugrađene objekte (PDF/Images/Fonts) i proslediti ih strukturnim detektorima


## Rekonstrukcija iOS backup-a

Backup-i sačuvani u okviru MobileSync koriste hash-ovana imena datoteka koja nisu čitljiva ljudima. SQLite baza podataka Manifest.db mapira svaki sačuvani objekat na njegovu logičku putanju.

Procedura na visokom nivou:
1) Otvoriti Manifest.db i pročitati zapise datoteka (domain, relativePath, flags, fileID/hash)
2) Ponovo izgraditi originalnu hijerarhiju foldera na osnovu domain + relativePath
3) Kopirati ili kreirati hardlink za svaki sačuvani objekat na njegovu rekonstruisanu putanju

Primer workflow-a pomoću alata koji ovo implementira end-to-end (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Napomene:
- Rukujte šifrovanim rezervnim kopijama tako što ćete lozinku rezervne kopije proslediti svom extractor-u
- Kada je moguće, sačuvajte originalne vremenske oznake/ACL-ove zbog dokazne vrednosti

### Preuzimanje i dešifrovanje rezervne kopije (USB / Finder / libimobiledevice)

- U macOS/Finder-u omogućite opciju "Encrypt local backup" i kreirajte *novu* šifrovanu rezervnu kopiju kako bi stavke iz keychain-a bile prisutne.
- Više platformi: `idevicebackup2` (libimobiledevice ≥1.4.0) podržava izmene protokola rezervnih kopija za iOS 17/18 i otklanja ranije greške pri restore/backup handshake-u.<sup>[[4]](#references)</sup>
```bash
# Pair then create a full encrypted backup over USB
$ idevicepair pair
$ idevicebackup2 backup --full --encrypt --password '<pwd>' ~/backups/iphone17
```
### Triage vođen IOC-ovima sa MVT

Amnestyjev Mobile Verification Toolkit (mvt-ios) sada direktno radi sa šifrovanim iTunes/Finder backup-ima, automatizujući dešifrovanje i IOC matching za slučajeve mercenary spyware-a.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt in-place copy of the backup
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree
$ mvt-ios check-backup -i indicators.csv /tmp/dec-backup
```
Rezultati se čuvaju u fascikli `mvt-results/` (npr. `analytics_detected.json`, `safari_history_detected.json`) i mogu se povezati sa putanjama priloga pronađenim u nastavku.

### Opšte parsiranje artefakata (iLEAPP)

Za vremensku liniju/metapodatke izvan messaging-a, pokrenite iLEAPP direktno nad fasciklom backup-a (podržava iOS 11–17 schema):
```bash
$ python3 ileapp.py -b /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracija priloga u aplikacijama za razmenu poruka

Nakon rekonstrukcije, izvršite enumeraciju priloga za popularne aplikacije. Tačna šema se razlikuje u zavisnosti od aplikacije/verzije, ali je pristup sličan: upitajte bazu podataka za razmenu poruka, povežite poruke sa prilozima i razrešite putanje na disku.<sup>[[1]](#references)[[2]](#references)</sup>

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
Putanje priloga mogu biti apsolutne ili relativne u odnosu na rekonstruisano stablo ispod Library/SMS/Attachments/.

### WhatsApp (ChatStorage.sqlite)
Uobičajena veza: tabela poruka ↔ tabela medija/priloga (naziv se razlikuje u zavisnosti od verzije). Upit nad redovima medija daje putanje na disku. Novije verzije iOS-a i dalje imaju polje `ZMEDIALOCALPATH` u tabeli `ZWAMEDIAITEM`.
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
Putanje se obično razrešavaju unutar `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/` u rekonstruisanom backup-u.

### Signal / Telegram / Viber
- Signal: message DB je enkriptovana; međutim, attachments keširani na disku (i thumbnails) obično mogu da se skeniraju
- Telegram: cache ostaje u `Library/Caches/` unutar sandbox-a; iOS 18 build-ovi pokazuju bugove pri čišćenju cache-a, pa su veliki rezidualni media cache-ovi česti izvori dokaza<sup>[[5]](#references)</sup>
- Viber: Viber.sqlite sadrži tabele poruka/attachments sa referencama na disku

Savet: čak i kada su metadata enkriptovani, skeniranje media/cache direktorijuma i dalje otkriva malicious objekte.


## Skeniranje attachments za structural exploite

Kada imate putanje do attachments, prosledite ih structural detector-ima koji validiraju file-format invarijante umesto signature-a. Primer sa ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcije obuhvaćene strukturnim pravilima uključuju:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): nemoguća stanja JBIG2 rečnika
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): konstrukcije Huffmanovih tabela prevelike veličine
- TrueType TRIANGULATION (CVE‑2023‑41990): nedokumentovani bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: nepodudarnosti između metadata i stream komponenti


## Validacija, napomene i false positives

- Konverzije vremena: iMessage na nekim verzijama čuva datume u Apple epoch/units; konvertujte ih odgovarajuće tokom izveštavanja
- Schema drift: SQLite schemas aplikacija se vremenom menjaju; potvrdite nazive tabela/kolona za konkretnu verziju sistema uređaja
- Rekurzivna ekstrakcija: PDF-ovi mogu sadržati JBIG2 streams i fonts; izdvojite ih i skenirajte unutrašnje objekte
- False positives: strukturne heuristike su konzervativne, ali mogu označiti retke neispravne, a ipak benigne media fajlove<sup>[[1]](#references)[[2]](#references)</sup>


## Reference

- [1] [ELEGANTBOUNCER: Kada ne možete da nabavite samples, ali i dalje morate da uhvatite pretnju](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer project (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [libimobiledevice 1.4.0 release notes](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Update 11.2 has broken cache cleanup on iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)

{{#include ../../banners/hacktricks-training.md}}
