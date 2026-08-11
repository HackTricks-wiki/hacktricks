# iOS Backup Forensics (triage usmeren na messaging)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica opisuje praktične korake za rekonstrukciju i analizu iOS backup-a radi pronalaženja znakova isporuke 0-click exploit-a putem priloga u messaging aplikacijama. Fokus je na pretvaranju Apple-ovog hashed rasporeda backup-a u putanje čitljive ljudima, a zatim na enumeraciji i skeniranju priloga u uobičajenim aplikacijama.

Ciljevi:
- Ponovo izgraditi čitljive putanje iz Manifest.db
- Enumerisati messaging baze podataka (iMessage, WhatsApp, Signal, Telegram, Viber)
- Razrešiti putanje priloga, izdvojiti ugrađene objekte tamo gde je podržano (PDF/Images/Fonts) i proslediti ih structural detector-ima


## Rekonstrukcija iOS backup-a

Backup-ovi sačuvani u MobileSync koriste hashed nazive datoteka koji nisu čitljivi ljudima. SQLite baza podataka Manifest.db mapira svaki sačuvani objekat na njegovu logičku putanju.<sup>[[1]](#references)[[2]](#references)</sup>

Procedura na visokom nivou:
1) Otvoriti Manifest.db i pročitati zapise o datotekama (domain, relativePath, flags, fileID/hash)
2) Ponovo izgraditi originalnu hijerarhiju foldera na osnovu domain + relativePath
3) Kopirati ili napraviti hardlink za svaki sačuvani objekat na njegovu rekonstruisanu putanju

Primer workflow-a pomoću alata koji ovo implementira od početka do kraja (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Napomene:
- Dešifrujte šifrovane rezervne kopije pre nego što ih prosledite alatu za rekonstrukciju; ElegantBouncer očekuje dešifrovanu rezervnu kopiju.<sup>[[2]](#references)[[3]](#references)</sup>
- Kad god je moguće, sačuvajte originalne vremenske oznake/ACL-ove radi dokazne vrednosti

### Preuzimanje i dešifrovanje rezervne kopije (USB / Finder / libimobiledevice)

- U Finder/Apple Devices/iTunes-u omogućite opciju „Encrypt local backup“ i kreirajte novu rezervnu kopiju; šifrovane rezervne kopije mogu da sadrže sačuvane lozinke i Health podatke koje nešifrovane rezervne kopije izostavljaju.<sup>[[8]](#references)</sup>
- Višeplatformski: libimobiledevice 1.4.0 uključuje ispravke za `idevicebackup2`.<sup>[[4]](#references)</sup> Interaktivno omogućite šifrovanje, a zatim prinudno napravite potpunu rezervnu kopiju koristeći dokumentovani redosled komandi, pri čemu direktorijum odredišta treba da bude naveden poslednji.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Trijaža zasnovana na IOC-ovima pomoću MVT

Amnesty’s Mobile Verification Toolkit može da izvuče ključ iz šifrovanih iTunes/Finder rezervnih kopija i da ih dešifruje, a zatim da skenira dešifrovanu rezervnu kopiju pomoću STIX2 IOC datoteke.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Sa opcijom `-o`, JSON rezultati se upisuju u `/tmp/mvt-results/`; IOC podudaranja koriste sufiks `_detected` i mogu se povezati sa putanjama priloga oporavljenim u nastavku.<sup>[[3]](#references)</sup>

### Opšte parsiranje artefakata (iLEAPP)

Za vremensku liniju/metapodatke koji se odnose na sadržaj izvan razmene poruka, pokrenite iLEAPP nad folderom sa sirovom rezervnom kopijom; njegov tip ulaza `itunes` prihvata iTunes/Finder rezervne kopije, a aktuelna izdanja podržavaju iOS/iPadOS 11 do najnovijih verzija.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracija priloga u aplikacijama za razmenu poruka

Nakon rekonstrukcije, enumerišite priloge za popularne aplikacije. Tačna schema se razlikuje u zavisnosti od aplikacije/verzije, ali je pristup sličan: izvršite upit nad bazom podataka za razmenu poruka, povežite poruke sa prilozima i razrešite putanje na disku.<sup>[[1]](#references)[[2]](#references)</sup>

### iMessage (sms.db)
Ključne tabele: message, attachment, message_attachment_join (MAJ), chat, chat_message_join (CMJ).<sup>[[2]](#references)</sup>

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
Putanje priloga mogu biti apsolutne ili relativne u odnosu na rekonstruisano stablo pod Library/SMS/Attachments.<sup>[[2]](#references)</sup>

### WhatsApp (ChatStorage.sqlite)
Uobičajeno povezivanje: tabela poruka ↔ tabela medija/priloga (nazivi se razlikuju u zavisnosti od verzije). Upit nad redovima medija daje putanje na disku. Belkasoft identifikuje `ZMEDIALOCALPATH` u `ZWAMEDIAITEM` kao lokaciju medijske datoteke; trenutna implementacija alata ElegantBouncer povezuje `ZWAMEDIAITEM.ZMESSAGE` sa `ZWAMESSAGE.Z_PK` i dodaje prefiks `Message/` prilikom određivanja putanje koja počinje sa `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Za putanju rekonstrukcije ElegantBouncer, medijska putanja koja počinje sa `Media/` razrešava se unutar `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; Belkasoft vodič umesto toga dokumentuje putanju `Messages/Media/`, zato pregledajte backup pre nego što pretpostavite bilo koji od ta dva oblika.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: DB poruka je šifrovan; međutim, prilozi keširani na disku (kao i thumbnails) obično mogu da se skeniraju.<sup>[[2]](#references)</sup>
- Telegram: pregledajte direktorijume za media/cache aplikacije; Telegram je dokumentovao bug čišćenja keša u iOS aplikaciji 11.2 na iOS-u 18.0.1, koji je označen kao ispravljen u verziji 11.3, zato proverite da li postoje preostale datoteke.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite sadrži tabele poruka/priloga sa referencama na disku.<sup>[[2]](#references)</sup>

Savet: čak i kada su metadata šifrovani, skeniranje media/cache direktorijuma i dalje otkriva zlonamerne objekte.<sup>[[2]](#references)</sup>


## Skeniranje priloga radi strukturnih exploit-a

Kada imate putanje do priloga, prosledite ih strukturnim detektorima koji proveravaju invarijante formata datoteka umesto potpisa. Primer sa ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcije obuhvaćene strukturnim pravilima uključuju:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): nemoguća JBIG2 stanja rečnika
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): konstrukcije Huffmanovih tabela prevelike veličine
- TrueType TRIANGULATION (CVE‑2023‑41990): nedokumentovani bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: nepodudarnosti između metapodataka i komponenti stream-a


## Validacija, napomene i false positives

- Konverzija vremena: iMessage na nekim verzijama čuva datume u Apple epochama/jedinicama; tokom izveštavanja izvršite odgovarajuću konverziju.<sup>[[2]](#references)</sup>
- Promene schema-e: SQLite schema-e aplikacija se vremenom menjaju; potvrdite nazive tabela/kolona za konkretnu verziju sistema na uređaju
- Rekurzivna ekstrakcija: PDF-ovi mogu sadržati JBIG2 stream-ove i fontove; koristite parser koji može da izdvoji i skenira unutrašnje objekte
- False positives: strukturne heuristike su konzervativne, ali mogu označiti retke neispravne, a bezopasne medije.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Kada ne možete da dobijete uzorke, ali i dalje morate da otkrijete pretnju](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer projekat (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Beleške o izdanju libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Ažuriranje 11.2 je pokvarilo čišćenje cache-a na iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 priručnik](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP projekat (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [O encrypted backups na vašem iPhone-u, iPad-u ili iPod touch-u (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics pomoću Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner i path resolver](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
