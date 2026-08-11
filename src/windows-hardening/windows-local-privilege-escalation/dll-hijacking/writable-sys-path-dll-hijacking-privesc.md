# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Ikiwa unaweza **kuandika kwenye directory iliyo katika `PATH` ya mfumo mzima** (si `PATH` ya user wako pekee), unaweza **kuongeza privileges** kwenye mfumo.

Hili linaweza kutumiwa kupitia **DLL hijacking** wakati service au process yenye privileges zaidi inapojaribu kupakia DLL ambayo haipo katika maeneo yake ya awali ya utafutaji, na hatimaye inatafuta kwenye directory ya mfumo iliyo katika `PATH` na inayoweza kuandikwa.

Kwa maelezo zaidi kuhusu **DLL hijacking**, angalia:


{{#ref}}
./
{{#endref}}

## Privesc kupitia Dll Hijacking

### Kutafuta DLL Iliyokosekana

Kwanza, **tambua process** inayoendeshwa ikiwa na **privileges zaidi** na inayojaribu **kupakia DLL kutoka kwenye directory ya mfumo iliyo katika `PATH` na inayoweza kuandikwa**.

Kumbuka kwamba technique hii inategemea entry ya **Machine/System PATH**, si **User PATH** yako pekee. Kwa hiyo, kabla ya kutumia muda kwenye Procmon, inafaa kuorodhesha entries za **Machine PATH** na kuangalia ni zipi zinazoweza kuandikwa:<sup>[[1]](#references)</sup>
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
Tatizo katika hali hizi ni kwamba huenda michakato hiyo tayari inaendelea. Ili kubaini DLL ambazo services hujaribu kupakia lakini hushindwa, zindua Procmon mapema iwezekanavyo (kabla michakato haijaanza), kisha:

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
- Zindua **`procmon`** na uende kwenye **`Options`** --> **`Enable boot logging`**, kisha bonyeza **`OK`** kwenye prompt.
- Kisha, **reboot**. Kompyuta ikiwashwa upya, **`procmon`** itaanza **recording** events mara moja.
- Baada ya **Windows** **kuanza, execute `procmon`** tena. Itakuambia kuwa imekuwa ikiendesha na **itakuuliza ikiwa unataka kuhifadhi** events kwenye file. Jibu **yes** na **hifadhi events kwenye file**.
- **Baada ya** **file** **kutengenezwa**, funga dirisha la **`procmon`** lililofunguka na **ufungue events file**.
- Ongeza **filters** hizi ili kupata DLL zote ambazo **process ilijaribu ku-load** kutoka kwenye writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging inahitajika tu kwa services zinazoanza mapema sana** kiasi kwamba haziwezi kuonekana vinginevyo. Ikiwa unaweza **trigger target service/program on demand** (kwa mfano, kwa kuingiliana na COM interface yake, kuanzisha service upya, au kuzindua scheduled task tena), kwa kawaida ni haraka zaidi kutumia Procmon capture ya kawaida yenye filters kama **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, na **`Path begins with <writable_machine_path>`**.

### DLL Zilizokosekana

Nilipoendesha hii kwenye **virtual (vmware) Windows 11 machine** ya bure, nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika hali hii, puuza matokeo ya `.exe`. Probes za DLL zilizokosekana zilitoka kwenye:

| Service                         | Dll                | Mstari wa CMD                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Mfano unaofuata unatumia technique iliyoelezwa katika article hii kuhusu [**abusing `WptsExtensions.dll` for privilege escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll).<sup>[[3]](#references)</sup>

### Candidates wengine wanaostahili triage

`WptsExtensions.dll` ni mfano mzuri, lakini siyo **phantom DLL** inayojirudia pekee inayoonekana kwenye privileged services. Modern hunting rules na public hijack catalogs bado zinafuatilia majina kama haya:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidate wa kawaida wa **SYSTEM** kwenye client systems. Ni nzuri wakati writable directory iko kwenye **Machine PATH** na service inafanya probe ya DLL wakati wa startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Inavutia kwenye **server editions** kwa sababu service inaendesha kama **SYSTEM** na inaweza kuwa **triggered on demand by a normal user** kwenye baadhi ya builds, hivyo ni bora kuliko cases zinazohitaji reboot pekee. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Kwa kawaida kwanza hupata **`NT AUTHORITY\LOCAL SERVICE`**. Hii mara nyingi bado inatosha kwa sababu token ina **`SeImpersonatePrivilege`**, hivyo unaweza kui-chain na [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Chukulia majina haya kama **triage hints**, si ushindi uliohakikishwa: yanategemea **SKU/build**, na Microsoft inaweza kubadilisha tabia hiyo kati ya releases. Jambo muhimu ni kutafuta **missing DLLs kwenye privileged services zinazopitia Machine PATH**, hasa ikiwa service inaweza **ku-triggeriwa tena bila rebooting**.

### Exploitation

Ili **ku-escalate privileges**, hijack **`WptsExtensions.dll`**. Baada ya **path** na **name** kujulikana, generate malicious DLL.

Unaweza [**kujaribu kutumia mojawapo ya mifano hii**](#creating-and-compiling-dlls). Unaweza ku-run payloads kama: kupata rev shell, kuongeza user, ku-execute beacon...

> [!WARNING]
> Kumbuka kuwa **si services zote zina-run** kama **`NT AUTHORITY\SYSTEM`**. Baadhi zina-run kama **`NT AUTHORITY\LOCAL SERVICE`**, ambayo ina **privileges chache**, hivyo kutumia vibaya mojawapo ya services hizi huenda kusikuruhusu kuunda user mpya.\
> Hata hivyo, account hiyo ina user right ya **`SeImpersonatePrivilege`**, hivyo unaweza kutumia [**Potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Katika hali hii, reverse shell ni option bora kuliko kujaribu kuunda user.

Wakati wa kuandika haya, service ya **Task Scheduler** inaendeshwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **ku-generate malicious Dll** (_kwangu nilitumia x64 rev shell na nikapata shell, lakini defender ili-kill kwa sababu ilitoka kwa msfvenom_), ihifadhi kwenye writable System Path kwa jina **WptsExtensions.dll** na **restart** kompyuta (au restart service, au fanya chochote kinachohitajika ili ku-run affected service/program tena).

Service inapoanzishwa upya, **dll inapaswa ku-load na ku-execute** (unaweza **kutumia tena** **procmon** trick kuangalia ikiwa **library ilipakiwa kama ilivyotarajiwa**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)
{{#include ../../../banners/hacktricks-training.md}}
