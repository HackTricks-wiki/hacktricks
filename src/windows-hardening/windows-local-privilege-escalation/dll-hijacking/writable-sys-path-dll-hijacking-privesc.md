# Writable System PATH + DLL Hijacking Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

Ikiwa unaweza **kuandika kwenye directory iliyo katika `PATH` ya mfumo mzima** (si `PATH` ya mtumiaji wako pekee), unaweza kuweza **kuongeza privileges** kwenye mfumo.

Hili linaweza kutumiwa vibaya kupitia **DLL hijacking** wakati service au process yenye privileges zaidi inapojaribu kupakia DLL ambayo haipo katika maeneo yake ya awali ya utafutaji, na hatimaye inatafuta kwenye directory ya mfumo iliyo katika `PATH` yenye ruhusa ya kuandikwa.

Ingizo la Machine `PATH` lenye ruhusa ya kuandikwa ni **primitive** pekee, si uthibitisho wa code execution. Kwa application isiyopakiwa kama package inayotumia mpangilio wa kawaida wa utafutaji, `PATH` hufikiwa baada ya redirection, API sets, SxS, orodha ya loaded modules, KnownDLLs, application na Windows directories, pamoja na current directory. Full path au sera ya `LOAD_LIBRARY_SEARCH_*` / `SetDefaultDllDirectories` inaweza kuondoa kabisa matumizi ya `PATH`.<sup>[[4]](#references)</sup>

Kwa maelezo zaidi kuhusu **DLL hijacking**, tazama:

{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

Kwanza, **tambua process** inayoendeshwa ikiwa na **privileges zaidi** ambayo hujaribu **kupakia DLL kutoka kwenye directory ya mfumo iliyo katika `PATH` yenye ruhusa ya kuandikwa**.

Kumbuka kwamba technique hii inategemea ingizo la **Machine/System PATH**, si **User PATH** pekee. Kwa hiyo, kabla ya kutumia muda kwenye Procmon, inafaa kuorodhesha maingizo ya **Machine PATH** na kukagua ni yapi yenye ruhusa ya kuandikwa:<sup>[[1]](#references)</sup>
```powershell
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ';' | Where-Object { $_ }
$machinePath | ForEach-Object {
$path = $_.Trim()
if ($path) {
Write-Host "`n[*] $path"
icacls $path 2>$null
}
}
```
Maandishi ya ACL yanaweza kupotosha kwa sababu uanachama wa group, deny ACEs, na ruhusa zilizorithiwa huathiri matokeo. Katika authorized test, create/delete probe hukagua **ufikiaji halisi wa token ya sasa** (ni intrusive na inaweza kuzalisha alerts):<sup>[[1]](#references)</sup>
```powershell
$dirs = [Environment]::GetEnvironmentVariable('Path','Machine') -split ';' |
ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.Trim().Trim('"')) } |
Where-Object { $_ } | Sort-Object -Unique
foreach ($dir in $dirs) {
if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
$probe = Join-Path $dir ('.ht-write-' + [guid]::NewGuid().ToString('N') + '.tmp')
try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force; "[WRITABLE] $dir" }
catch { }
}
```
### Thibitisha `PATH` halisi ya target

Machine `PATH` iliyosomwa kutoka kwenye registry ni data ya configuration; loader hutumia environment block ya **target process**. Kila process ina environment block yake, na child kwa kawaida hurithi nakala ya environment ya parent wake. Kwa hiyo, service inayofanya kazi kwa muda mrefu inaweza kuhifadhi value ya zamani, na service iliyoanzishwa kwa custom environment inaweza kutofautiana na value inayoonekana kwenye shell yako. Chukulia Procmon probe iliyozingatia directory halisi na target PID kuwa ukweli wa msingi; baada ya kubadilisha `PATH` kwenye lab, anzisha upya process tree husika au reboot kabla ya kuhitimisha kuwa lookup hiyo haitokei.<sup>[[5]](#references)</sup>

Tatizo katika hali hizi ni kwamba processes hizo huenda tayari zinafanya kazi. Ili kutambua DLL ambazo services hujaribu ku-load lakini hushindwa, launch Procmon mapema iwezekanavyo (kabla processes hazijaanza), kisha:

> [!WARNING]
> Kuongeza directory inayoweza kuandikwa na user kwenye Machine `PATH` **hutengeneza hali ya vulnerability**. Fanya hivi tu kwenye research VM iliyotengwa ili kubaini ni privileged processes zipi zinazofikia `PATH`; kwenye host inayofanyiwa assessment, monitor entry iliyopo inayoweza kuandikwa bila kubadilisha system configuration.<sup>[[1]](#references)</sup>

- **Unda** folder `C:\privesc_hijacking` na uongeze path `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **kwa mkono** au kwa kutumia **PS**:
```bash
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
- Anzisha **`procmon`** na uende kwenye **`Options`** --> **`Enable boot logging`** kisha ubonyeze **`OK`** kwenye prompt.
- Kisha, **reboot**. Kompyuta ikiwashwa upya, **`procmon`** itaanza **kurekodi** events mara moja.
- Baada ya **Windows** **kuanza, tekeleza `procmon`** tena. Itakuambia kuwa imekuwa ikiendesha na **itakuuliza kama unataka kuhifadhi** events kwenye file. Jibu **yes** na **hifadhi events kwenye file**.
- **Baada ya** **file** **kutengenezwa**, funga **`procmon`** window iliyofunguka na **ufungue events file**.
- Ongeza **filters** hizi ili kupata DLL zote ambazo **process ilijaribu kupakia** kutoka kwenye writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging** inahitajika tu kwa services zinazoanza **mapema sana** kiasi kwamba haziwezi kuangaliwa kwa njia nyingine. Ikiwa unaweza **kuanzisha target service/program unapohitaji** (kwa mfano, kwa kuingiliana na COM interface yake, kuanzisha service upya, au kuanzisha tena scheduled task), kwa kawaida ni haraka zaidi kuweka Procmon capture ya kawaida yenye filters kama **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, na **`Path begins with <writable_machine_path>`**.

### Missed DLLs

Nilipoendesha hii kwenye **virtual (vmware) Windows 11 machine** ya bure, nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika hali hii, puuza matokeo ya `.exe`. Probes za DLL zilizokosekana zilitoka kwa:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Mfano ufuatao unatumia technique iliyoelezwa katika makala hii kuhusu [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Other candidates worth triaging

`WptsExtensions.dll` ni mfano mzuri, lakini si **phantom DLL** pekee inayojitokeza mara kwa mara kwenye privileged services. Modern hunting rules na public hijack catalogs bado hufuatilia majina kama:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidate ya kawaida ya **SYSTEM** kwenye client systems. Inafaa wakati writable directory iko kwenye **Machine PATH** na service inafanya probe ya DLL wakati wa kuanza. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Inavutia kwenye **server editions** kwa sababu service huendesha kama **SYSTEM** na inaweza **kuanzishwa unapohitaji na normal user** kwenye baadhi ya builds, hivyo kuwa bora kuliko hali zinazohitaji reboot pekee. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Kwa kawaida kwanza hutoa **`NT AUTHORITY\LOCAL SERVICE`**. Hii mara nyingi bado inatosha kwa sababu token ina **`SeImpersonatePrivilege`**, hivyo unaweza kuiunganisha na [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Zichukulie majina haya kama **triage hints**, si mafanikio yaliyohakikishwa: zinategemea **SKU/build**, na Microsoft inaweza kubadilisha tabia kati ya releases. Jambo muhimu ni kutafuta **missing DLLs kwenye privileged services zinazopita kwenye Machine PATH**, hasa ikiwa service inaweza **kuanzishwa tena bila rebooting**.

### Validate a candidate before weaponizing it

Event ya `NAME NOT FOUND` pekee haitoshi. Kabla ya kuweka payload, thibitisha chain nzima:<sup>[[1]](#references)[[4]](#references)</sup>

1. Event inahusiana na **PID, command line, service account, na integrity level** inayotarajiwa, na path iliyokosekana ni directory sahihi ya writable Machine `PATH`.
2. Kwa DLL basename hiyo hiyo, hakuna directory ya awali inayorudisha `SUCCESS`, na module haijapatikana kupitia loaded-module list, KnownDLLs, redirection, au SxS manifest.
3. Probe inarudiwa wakati low-privileged user anapoanzisha intended trigger. Lookup ya boot-only inaweza kutumika, lakini kiutendaji ni mbaya zaidi kuliko ile ya on-demand.
4. Payload architecture inalingana na process. Ikiwa application baadaye inaresolve exports, tumia legitimate DLL kama proxy au export symbols zinazotarajiwa; tazama [Creating and compiling DLLs](README.md#creating-and-compiling-dlls).
5. Kwanza tumia harmless canary DLL inayorekodi PID, identity, na timestamp. Kwenye Procmon, hakikisha kuna **`Load Image`** iliyofanikiwa kutoka kwenye planted path badala ya kudhani kuwa file probe iliyotangulia ilisababisha execution.

### Exploitation

Ili **ku-escalate privileges**, hijack **`WptsExtensions.dll`**. Baada ya **path** na **name** kujulikana, tengeneza malicious DLL.

Unaweza [**kujaribu kutumia yoyote kati ya mifano hii**](README.md#creating-and-compiling-dlls). Unaweza kuendesha payloads kama vile: kupata rev shell, kuongeza user, ku-execute beacon...

> [!WARNING]
> Kumbuka kuwa **si services zote huendesha** kama **`NT AUTHORITY\SYSTEM`**. Baadhi huendesha kama **`NT AUTHORITY\LOCAL SERVICE`**, ambayo ina **privileges chache**, hivyo abusing mojawapo ya services hizi huenda kusikuruhusu kuunda user mpya.\
> Hata hivyo, account hiyo ina user right ya **`SeImpersonatePrivilege`**, kwa hiyo unaweza kutumia [**Potato suite ku-escalate privileges**](../roguepotato-and-printspoofer.md). Katika hali hii, reverse shell ni chaguo bora kuliko kujaribu kuunda user.

Service ya **Task Scheduler** kwa kawaida huendesha kama **`NT AUTHORITY\SYSTEM`**, lakini thibitisha deployment halisi na usikadirie execution identity kwa kutegemea jina la service pekee:<sup>[[3]](#references)</sup>
```powershell
Get-CimInstance Win32_Service -Filter "Name='Schedule'" | Select-Object Name, StartName, State, PathName
```
Baada ya **kutengeneza Dll hasidi** (_katika hali yangu nilitumia x64 rev shell na nikapata shell, lakini defender iliizuia kwa sababu ilitoka kwa msfvenom_), ihifadhi kwenye System Path inayoweza kuandikwa kwa jina **WptsExtensions.dll**, kisha **anzisha upya** kompyuta (au anzisha upya service, au fanya chochote kinachohitajika ili kuendesha tena service/program iliyoathirika).

Service inapoanzishwa tena, **DLL inapaswa kupakiwa na kutekelezwa** (unaweza **kutumia tena** mbinu ya **Procmon** kuangalia kama **library ilipakiwa kama ilivyotarajiwa**).

> [!NOTE]
> Panga usafishaji kabla ya ku-trigger. Service inaweza kuendelea kuiweka DLL ikiwa imepakiwa na kufunga faili hadi isimamishwe; kwa `WptsExtensions.dll`, kusimamisha Task Scheduler kunahitaji haki zilizoinuliwa. Baada ya kupata context iliyokusudiwa, simamisha target kwa usalama, ondoa payload, na urejeshe mabadiliko yoyote ya `PATH` yaliyofanywa kwa ajili ya lab.<sup>[[1]](#references)</sup>

### Marekebisho / utambuzi

Ondoa ruhusa dhaifu za kuandika kutoka kila directory ya Machine `PATH` na uondoe entries zilizopitwa na wakati. Developers wanapaswa kupakia libraries zinazoaminika kwa kutumia full path au kudhibiti resolution kwa kutumia `SetDefaultDllDirectories` / search flags za `LoadLibraryEx`. Defenders wanaweza kuhusianisha mabadiliko kwenye Machine `PATH` na privileged processes zinazopakia DLL kutoka kwenye directories zisizo za mfumo na zinazoweza kuandikwa na watumiaji.<sup>[[2]](#references)[[4]](#references)</sup>



## References

- [1] [Windows DLL Hijacking (Kwa matumaini) Imefafanuliwa](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [DLL Inayotiliwa Shaka Iliyopakiwa kwa Persistence au Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
- [4] [Mpangilio wa utafutaji wa dynamic-link library](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [5] [Environment Variables](https://learn.microsoft.com/en-us/windows/win32/procthread/environment-variables)
{{#include ../../../banners/hacktricks-training.md}}
