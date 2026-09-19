# Writable Sys Path +DLL Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Ikiwa unaweza **kuandika kwenye directory iliyo ndani ya system-wide `PATH`** (sio tu `PATH` ya mtumiaji wako), huenda ukaweza **kuongeza privileges** kwenye mfumo.

Hili linaweza kutumiwa kupitia **DLL hijacking** wakati service au process yenye privileges za juu zaidi inapojaribu kupakia DLL ambayo haipo katika maeneo yake ya awali ya utafutaji, na hatimaye kutafuta kwenye directory ya system `PATH` inayoweza kuandikiwa.

Kwa maelezo zaidi kuhusu **DLL hijacking**, angalia:


{{#ref}}
./
{{#endref}}

## Privesc with DLL Hijacking

### Finding a Missing DLL

Kwanza, **tambua process** inayoendesha ikiwa na **privileges za juu zaidi** na inayojaribu **kupakia DLL kutoka kwenye directory ya system `PATH` inayoweza kuandikiwa**.

Kumbuka kwamba technique hii inategemea ingizo la **Machine/System PATH**, si **User PATH** yako pekee. Kwa hiyo, kabla ya kutumia muda kwenye Procmon, inafaa kuorodhesha entries za **Machine PATH** na kuangalia ni zipi zinazoweza kuandikiwa:<sup>[[1]](#references)</sup>
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
Tatizo katika hali hizi ni kwamba michakato hiyo huenda tayari inaendeshwa. Ili kutambua DLLs ambazo services hujaribu kupakia lakini hushindwa, zindua Procmon mapema iwezekanavyo (kabla michakato haijaanza), kisha:

- **Create** folda `C:\privesc_hijacking` na uongeze njia `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **manually** au kwa kutumia **PS**:
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
- Zindua **`procmon`** na uende kwenye **`Options`** --> **`Enable boot logging`**, kisha bonyeza **`OK`** kwenye ujumbe wa uthibitisho.
- Kisha, **anzisha upya kompyuta**. Kompyuta ikishawashwa tena, **`procmon`** itaanza **kurekodi** matukio haraka iwezekanavyo.
- Mara **Windows** **inapoanza, tekeleza `procmon`** tena; itakuambia kuwa imekuwa ikiendesha na **itakuuliza ikiwa unataka kuhifadhi** matukio kwenye faili. Jibu **ndiyo** na **hifadhi matukio kwenye faili**.
- **Baada ya** **faili** **kutengenezwa**, funga dirisha la **`procmon`** lililofunguka na **ufungue faili la matukio**.
- Ongeza **filters** hizi ili kupata DLL zote ambazo **process ilijaribu kupakia** kutoka kwenye folda ya writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging inahitajika tu kwa services zinazoanza mapema sana** kiasi kwamba haziwezi kuangaliwa kwa njia nyingine. Ikiwa unaweza **kuanzisha target service/program unapohitaji** (kwa mfano, kwa kuingiliana na COM interface yake, kuanzisha upya service, au kuzindua tena scheduled task), kwa kawaida ni haraka zaidi kutumia Procmon capture ya kawaida yenye filters kama **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, na **`Path begins with <writable_machine_path>`**.

### DLL zilizokosekana

Nilipoendesha hii kwenye **virtual (vmware) Windows 11 machine** isiyolipiwa, nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika hali hii, puuza matokeo ya `.exe`. Probes za DLL zilizokosekana zilitoka kwenye:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Mfano unaofuata unatumia technique iliyoelezwa kwenye makala hii kuhusu [**kutumia vibaya `WptsExtensions.dll` kwa privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Candidates nyingine zinazofaa kufanyiwa triage

`WptsExtensions.dll` ni mfano mzuri, lakini siyo **phantom DLL** pekee inayojirudia na kuonekana kwenye services zenye privileges. Sheria za kisasa za hunting na catalogs za public hijack bado zinafuatilia majina kama:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidate wa kawaida wa **SYSTEM** kwenye client systems. Ni nzuri wakati directory inayoweza kuandikwa iko kwenye **Machine PATH** na service inachunguza DLL wakati wa startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Inavutia kwenye **server editions** kwa sababu service inaendesha kama **SYSTEM** na inaweza **kuanzishwa unapohitaji na normal user** kwenye baadhi ya builds, hivyo ni bora kuliko hali zinazohitaji reboot pekee. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Kwa kawaida kwanza hupata **`NT AUTHORITY\LOCAL SERVICE`**. Hii mara nyingi bado inatosha kwa sababu token ina **`SeImpersonatePrivilege`**, kwa hiyo unaweza kuiunganisha na [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Chukulia majina haya kama **vidokezo vya triage**, si ushindi uliohakikishwa: yanategemea **SKU/build**, na Microsoft inaweza kubadilisha tabia hii kati ya releases. Jambo muhimu ni kutafuta **DLL zilizokosekana kwenye services zenye privileges zinazopita kwenye Machine PATH**, hasa ikiwa service inaweza **kuanzishwa tena bila kufanya reboot**.

### Exploitation

Ili **ku-escalate privileges**, hijack **`WptsExtensions.dll`**. Mara tu **path** na **name** vinapojulikana, tengeneza DLL yenye malicious code.

Unaweza [**kujaribu kutumia mojawapo ya mifano hii**](#creating-and-compiling-dlls). Unaweza kuendesha payloads kama: kupata rev shell, kuongeza user, kutekeleza beacon...

> [!WARNING]
> Kumbuka kuwa **si services zote zinazoendesha** kama **`NT AUTHORITY\SYSTEM`**. Baadhi zinaendesha kama **`NT AUTHORITY\LOCAL SERVICE`**, ambayo ina **privileges chache**, kwa hiyo kutumia vibaya mojawapo ya services hizi huenda kusikuruhusu kuunda user mpya.\
> Hata hivyo, account hiyo ina user right ya **`SeImpersonatePrivilege`**, kwa hiyo unaweza kutumia [**Potato suite ku-escalate privileges**](../roguepotato-and-printspoofer.md). Katika hali hii, reverse shell ni chaguo bora kuliko kujaribu kuunda user.

Wakati wa kuandika hii, service ya **Task Scheduler** inaendeshwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kutengeneza malicious Dll** (_katika hali yangu nilitumia x64 rev shell na nikapata shell back, lakini defender iliifunga kwa sababu ilitoka kwenye msfvenom_), ihifadhi kwenye writable System Path kwa jina **WptsExtensions.dll** na **uanzishe upya** kompyuta (au uanzishe upya service, au ufanye chochote kinachohitajika ili affected service/program iendeshwe tena).

Service inapoanzishwa tena, **dll inapaswa kupakiwa na kutekelezwa** (unaweza **kutumia tena** mbinu ya **procmon** kuangalia ikiwa **library ilipakiwa kama ilivyotarajiwa**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
