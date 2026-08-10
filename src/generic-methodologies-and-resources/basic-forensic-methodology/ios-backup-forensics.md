# Forenzika iOS backup-a (trijaža usmerena na messaging)

Ova stranica opisuje praktične korake za rekonstrukciju i analizu iOS backup-a u potrazi za znakovima isporuke 0-click exploit-a putem privitaka u messaging aplikacijama. Fokus je na pretvaranju Apple-ovog hešovanog rasporeda backup-a u putanje čitljive ljudima, a zatim na nabrajanju i skeniranju privitaka u uobičajenim aplikacijama.

Ciljevi:
- Ponovo izgraditi čitljive putanje iz Manifest.db
- Nabrojati messaging baze podataka (iMessage, WhatsApp, Signal, Telegram, Viber)
- Razrešiti putanje privitaka, izdvojiti ugrađene objekte gde je podržano (PDF/Images/Fonts) i proslediti ih detektorima strukture


## Rekonstrukcija iOS backup-a

Backup-i sačuvani u okviru MobileSync koriste hešovana imena fajlova koja nisu čitljiva ljudima. SQLite baza podataka Manifest.db mapira svaki sačuvani objekat na njegovu logičku putanju.<sup>[[1]](#references)[[2]](#references)</sup>

Procedura na visokom nivou:
1) Otvoriti Manifest.db i pročitati zapise o fajlovima (domen, relativna putanja, zastavice, fileID/hash)
2) Ponovo izgraditi originalnu hijerarhiju foldera na osnovu domena + relativPath
3) Kopirati ili hardlink-ovati svaki sačuvani objekat u njegovu rekonstruisanu putanju

Primer workflow-a sa alatom koji ovo implementira od početka do kraja (ElegantBouncer):<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Rebuild the backup into a readable folder tree
$ elegant-bouncer --ios-extract /path/to/backup --output /tmp/reconstructed
[+] Reading Manifest.db ...
✓ iOS backup extraction completed successfully!
```
Napomene:
- Dešifrujte šifrovane backup-e pre nego što ih prosledite alatu za rekonstrukciju; ElegantBouncer očekuje dešifrovan backup.<sup>[[2]](#references)[[3]](#references)</sup>
- Kada je moguće, sačuvajte originalne vremenske oznake/ACL-ove zbog dokazne vrednosti

### Nabavljanje i dešifrovanje backup-a (USB / Finder / libimobiledevice)

- U Finder/Apple Devices/iTunes-u omogućite opciju "Encrypt local backup" i kreirajte novi backup; šifrovani backup-i mogu da sadrže sačuvane lozinke i Health podatke koje nešifrovani backup-i izostavljaju.<sup>[[8]](#references)</sup>
- Više platformi: libimobiledevice 1.4.0 uključuje ispravke za `idevicebackup2`.<sup>[[4]](#references)</sup> Interaktivno omogućite šifrovanje, zatim prinudno napravite kompletan backup koristeći dokumentovani redosled komandi, pri čemu ciljni direktorijum treba da bude naveden poslednji.<sup>[[6]](#references)</sup>
```bash
# Pair, then enable encrypted backups (prompts for the password); keep the target directory last
$ idevicepair pair
$ idevicebackup2 -i encryption on ~/backups/iphone17

# Create a full encrypted backup over USB
$ idevicebackup2 backup --full ~/backups/iphone17
```
### Triage zasnovan na IOC-ovima pomoću MVT-a

Amnestyjev Mobile Verification Toolkit može da izdvoji ključ iz šifrovanih iTunes/Finder rezervnih kopija i da ih dešifruje, a zatim da skenira dešifrovanu rezervnu kopiju pomoću STIX2 IOC datoteke.<sup>[[3]](#references)</sup>
```bash
# Optionally extract a reusable key file
$ mvt-ios extract-key -k /tmp/keyfile ~/backups/iphone17

# Decrypt to a separate destination
$ mvt-ios decrypt-backup -p '<pwd>' -d /tmp/dec-backup ~/backups/iphone17

# Run IOC scanning on the decrypted tree with a STIX2 indicator file
$ mvt-ios check-backup -i indicators.stix2.json -o /tmp/mvt-results /tmp/dec-backup
```
Sa `-o`, JSON rezultati se upisuju u `/tmp/mvt-results/`; IOC podudaranja koriste sufiks `_detected` i mogu se korelisati sa putanjama priloga oporavljenim u nastavku.<sup>[[3]](#references)</sup>

### Opšte parsiranje artefakata (iLEAPP)

Za timeline/metapodatke koji nisu povezani sa messagingom, pokrenite iLEAPP nad folderom sirovog backup-a; njegov `itunes` input type prihvata iTunes/Finder backup-e, a aktuelna izdanja podržavaju iOS/iPadOS 11 do trenutnih verzija.<sup>[[7]](#references)</sup>
```bash
$ mkdir -p /tmp/ileapp-report
$ python3 ileapp.py -t itunes -i /tmp/dec-backup -o /tmp/ileapp-report
```
## Enumeracija priloga u aplikacijama za razmenu poruka

Nakon rekonstrukcije, enumerirajte priloge za popularne aplikacije. Tačna shema se razlikuje u zavisnosti od aplikacije/verzije, ali je pristup sličan: izvršite upit nad bazom podataka za razmenu poruka, povežite poruke sa prilozima i razrešite putanje na disku.<sup>[[1]](#references)[[2]](#references)</sup>

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
Uobičajeno povezivanje: tabela poruka ↔ tabela media/attachment (imenovanje varira u zavisnosti od verzije). Pretražite media redove da biste dobili putanje na disku. Belkasoft identifikuje `ZMEDIALOCALPATH` u `ZWAMEDIAITEM` kao lokaciju media fajla; trenutna implementacija alata ElegantBouncer povezuje `ZWAMEDIAITEM.ZMESSAGE` sa `ZWAMESSAGE.Z_PK` i dodaje prefiks `Message/` prilikom razrešavanja putanje koja počinje sa `Media/`.<sup>[[9]](#references)[[10]](#references)</sup>
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
Za tu putanju rekonstrukcije za ElegantBouncer, putanja medija koja počinje sa `Media/` razrešava se unutar `AppDomainGroup-group.net.whatsapp.WhatsApp.shared/Message/Media/`; Belkasoft vodič umesto toga dokumentuje putanju `Messages/Media/`, zato pregledajte backup pre nego što pretpostavite da je neki od ta dva oblika ispravan.<sup>[[9]](#references)[[10]](#references)</sup>

### Signal / Telegram / Viber
- Signal: baza poruka je šifrovana; međutim, prilozi keširani na disku (kao i thumbnail slike) obično mogu da se skeniraju.<sup>[[2]](#references)</sup>
- Telegram: pregledajte direktorijume za medije/keš aplikacije; Telegram je dokumentovao bug pri čišćenju keša u iOS aplikaciji 11.2 na iOS 18.0.1, označen kao ispravljen u verziji 11.3, zato proverite da li postoje zaostali fajlovi.<sup>[[2]](#references)[[5]](#references)</sup>
- Viber: Viber.sqlite sadrži tabele poruka/priloga sa referencama na disku.<sup>[[2]](#references)</sup>

Savet: čak i kada su metapodaci šifrovani, skeniranje direktorijuma za medije/keš i dalje otkriva maliciozne objekte.<sup>[[2]](#references)</sup>


## Skeniranje priloga na strukturne exploit-e

Kada imate putanje do priloga, prosledite ih strukturnim detektorima koji proveravaju invarijante formata datoteka umesto potpisa. Primer sa ElegantBouncer:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Recursively scan only messaging attachments under the reconstructed tree
$ elegant-bouncer --scan --messaging /tmp/reconstructed
[+] Found N messaging app attachments to scan
✗ THREAT in WhatsApp chat 'John Doe': suspicious_document.pdf → FORCEDENTRY (JBIG2)
✗ THREAT in iMessage: photo.webp → BLASTPASS (VP8L)
```
Detekcije obuhvaćene strukturnim pravilima uključuju:<sup>[[1]](#references)[[2]](#references)</sup>
- PDF/JBIG2 FORCEDENTRY (CVE‑2021‑30860): nemoguća stanja JBIG2 rečnika
- WebP/VP8L BLASTPASS (CVE‑2023‑4863): konstrukcije Huffman tabela prevelike veličine
- TrueType TRIANGULATION (CVE‑2023‑41990): nedokumentovani bytecode opcodes
- DNG/TIFF CVE‑2025‑43300: nepodudarnosti između komponenti metapodataka i stream-a


## Validacija, napomene i lažno pozitivne detekcije

- Konverzija vremena: iMessage na nekim verzijama čuva datume u Apple epohama/jedinicama; tokom izveštavanja izvršite odgovarajuću konverziju.<sup>[[2]](#references)</sup>
- Promene sheme: SQLite sheme aplikacija se vremenom menjaju; potvrdite nazive tabela/kolona za konkretnu verziju sistema na uređaju
- Rekurzivna ekstrakcija: PDF-ovi mogu sadržati JBIG2 stream-ove i fontove; koristite parser koji može da izdvoji i skenira unutrašnje objekte
- Lažno pozitivne detekcije: strukturne heuristike su konzervativne, ali mogu označiti retke neispravne, a ipak bezopasne medije.<sup>[[1]](#references)[[2]](#references)</sup>


## References

- [1] [ELEGANTBOUNCER: Kada ne možete da nabavite uzorke, ali i dalje morate da otkrijete pretnju](https://www.msuiche.com/posts/elegantbouncer-when-you-cant-get-the-samples-but-still-need-to-catch-the-threat/)
- [2] [ElegantBouncer projekat (GitHub)](https://github.com/msuiche/elegant-bouncer)
- [3] [MVT iOS backup workflow](https://docs.mvt.re/en/latest/ios/backup/check/)
- [4] [Napomene o izdanju libimobiledevice 1.4.0](https://libimobiledevice.org/news/2025/10/10/libimobiledevice-1.4.0-release/)
- [5] [Ažuriranje 11.2 je pokvarilo čišćenje cache-a na iOS 18.0.1 (Telegram Bug Tracker)](https://bugs.telegram.org/c/44361)
- [6] [idevicebackup2 priručnik](https://github.com/libimobiledevice/libimobiledevice/blob/master/docs/idevicebackup2.1)
- [7] [iLEAPP projekat (GitHub)](https://github.com/abrignoni/iLEAPP)
- [8] [O šifrovanim backup-ima na vašem iPhone-u, iPad-u ili iPod touch-u (Apple Support)](https://support.apple.com/en-ie/108353)
- [9] [iOS WhatsApp Forensics uz Belkasoft X](https://belkasoft.com/ios-whatsapp-forensics-with-belkasoft-x)
- [10] [ElegantBouncer WhatsApp scanner i razrešivač putanja](https://github.com/msuiche/elegant-bouncer/blob/main/src/messaging.rs)
{{#include ../../banners/hacktricks-training.md}}
