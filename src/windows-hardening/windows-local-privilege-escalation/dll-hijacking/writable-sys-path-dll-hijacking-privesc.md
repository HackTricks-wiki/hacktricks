# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Ukigundua kwamba unaweza **kuandika katika folder ya System Path** (kumbuka kwamba hii haitafanya kazi ikiwa unaweza kuandika katika folder ya User Path), inawezekana ukaweza **kuongeza privileges** kwenye mfumo.

Ili kufanya hivyo, unaweza kutumia **Dll Hijacking**, ambapo utaenda **kuteka library inayopakiwa** na service au process yenye **privileges** nyingi kuliko zako. Kwa sababu service hiyo inapakia Dll ambayo huenda hata haipo katika mfumo mzima, itajaribu kuipakia kutoka kwenye System Path ambako unaweza kuandika.

Kwa maelezo zaidi kuhusu **Dll Hijackig** angalia:


{{#ref}}
./
{{#endref}}

## Privesc kwa kutumia Dll Hijacking

### Kutafuta Dll inayokosekana

Jambo la kwanza unalohitaji ni **kutambua process** inayoendeshwa ikiwa na **privileges** nyingi kuliko zako, na inayojaribu **kupakia Dll kutoka kwenye System Path** ambayo unaweza kuandikia.

Kumbuka kwamba technique hii inategemea entry ya **Machine/System PATH**, si **User PATH** pekee. Kwa hiyo, kabla ya kutumia muda kwenye Procmon, inafaa ku-enumerate entries za **Machine PATH** na kukagua ni zipi zinazoweza kuandikiwa:<sup>[[1]](#references)</sup>
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
Tatizo katika hali hizi ni kwamba huenda processes hizo tayari zinaendeshwa. Ili kupata Dlls ambazo services zinakosa, unahitaji kuzindua procmon haraka iwezekanavyo (kabla processes hazijapakiwa). Kwa hiyo, ili kupata .dlls zinazokosekana, fanya yafuatayo:

- **Unda** folder `C:\privesc_hijacking` na uongeze path `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **manually** au kwa kutumia **PS**:
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
- Fungua **`procmon`** na uende kwenye **`Options`** --> **`Enable boot logging`**, kisha bonyeza **`OK`** kwenye ujumbe wa kuthibitisha.
- Kisha, **anzisha upya kompyuta**. Kompyuta itakapoanzishwa upya, **`procmon`** itaanza **kurekodi** matukio haraka iwezekanavyo.
- Baada ya **Windows** **kuanzishwa, endesha `procmon`** tena. Itakuambia kuwa imekuwa ikiendesha na **itakuuliza ikiwa unataka kuhifadhi** matukio kwenye faili. Jibu **yes** na **uhifadhi matukio kwenye faili**.
- **Baada ya** **faili** **kutengenezwa**, funga dirisha la **`procmon`** lililofunguka na **ufungue faili la matukio**.
- Ongeza **filters** hizi na utapata Dll zote ambazo **process fulani ilijaribu kupakia** kutoka kwenye folda ya writable System Path:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging inahitajika tu kwa services zinazoanza mapema sana** kiasi kwamba huwezi kuzichunguza vinginevyo. Ikiwa unaweza **kuanzisha target service/program unapohitaji** (kwa mfano, kwa kuingiliana na COM interface yake, kuanzisha service upya, au kuzindua tena scheduled task), kwa kawaida ni haraka zaidi kuweka Procmon capture ya kawaida yenye filters kama **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, na **`Path begins with <writable_machine_path>`**.

### Dll zilizokosekana

Nilipoendesha hii kwenye **virtual (vmware) Windows 11 machine** ya bure, nilipata matokeo haya:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika hali hii .exe hazina manufaa, kwa hiyo zipuuze; DLL zilizokosekana zilitoka kwenye:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kugundua hili, nilipata blog post hii ya kuvutia ambayo pia inaeleza jinsi ya [**kutumia vibaya WptsExtensions.dll kwa privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Hilo ndilo **tutakalofanya sasa**.<sup>[[3]](#references)</sup>

### Candidates wengine wanaofaa kufanyiwa triage

`WptsExtensions.dll` ni mfano mzuri, lakini siyo **phantom DLL** pekee inayojirudia katika privileged services. Sheria za kisasa za hunting na catalogs za umma za hijack bado hufuatilia majina kama:<sup>[[2]](#references)</sup>

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Candidate wa kawaida wa **SYSTEM** kwenye client systems. Ni nzuri wakati directory inayoweza kuandikwa iko kwenye **Machine PATH** na service inachunguza DLL wakati wa kuanza. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Inavutia kwenye **server editions** kwa sababu service huendeshwa kama **SYSTEM** na inaweza **kuanzishwa unapohitaji na user wa kawaida** katika baadhi ya builds, hivyo ni bora kuliko hali zinazohitaji reboot pekee. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Kwa kawaida hupata **`NT AUTHORITY\LOCAL SERVICE`** kwanza. Mara nyingi hii bado inatosha kwa sababu token hiyo ina **`SeImpersonatePrivilege`**, hivyo unaweza kuiunganisha na [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Chukulia majina haya kama **vidokezo vya triage**, si ushindi wa uhakika: yanategemea **SKU/build**, na Microsoft inaweza kubadilisha tabia hii kati ya releases. Jambo muhimu ni kutafuta **DLL zilizokosekana kwenye privileged services zinazopita kwenye Machine PATH**, hasa ikiwa service inaweza **kuanzishwa tena bila reboot**.

### Exploitation

Kwa hiyo, ili **kuongeza privileges**, tutahijack library **WptsExtensions.dll**. Kwa kuwa tuna **path** na **name**, tunachohitaji ni **kutengeneza malicious dll**.

Unaweza [**kujaribu kutumia mojawapo ya mifano hii**](#creating-and-compiling-dlls). Unaweza kuendesha payloads kama vile: kupata rev shell, kuongeza user, kuendesha beacon...

> [!WARNING]
> Kumbuka kwamba **si services zote huendeshwa** na **`NT AUTHORITY\SYSTEM`**; baadhi pia huendeshwa na **`NT AUTHORITY\LOCAL SERVICE`**, ambayo ina **privileges chache** na **hutaweza kuunda user mpya** kwa kutumia vibaya permissions zake.\
> Hata hivyo, user huyo ana **`seImpersonate`** privilege, kwa hiyo unaweza kutumia [ **potato suite kuongeza privileges**](../roguepotato-and-printspoofer.md). Kwa hiyo, katika hali hii rev shell ni chaguo bora kuliko kujaribu kuunda user.

Wakati wa kuandika hii, **Task Scheduler** service inaendeshwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kutengeneza malicious Dll** (_kwangu nilitumia x64 rev shell na nikapata shell lakini defender iliimaliza kwa sababu ilitoka kwenye msfvenom_), ihifadhi kwenye writable System Path kwa jina **WptsExtensions.dll** na **uanzishe upya** kompyuta (au uanze service upya, au ufanye chochote kinachohitajika ili affected service/program iendeshwe tena).

Service inapoanzishwa tena, **dll inapaswa kupakiwa na kutekelezwa** (unaweza **kutumia tena** mbinu ya **procmon** kuangalia ikiwa **library ilipakiwa kama ilivyotarajiwa**).

## References

- [1] [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [2] [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)
- [3] [DLL Hijacking – Windows Privilege Escalation](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll)

{{#include ../../../banners/hacktricks-training.md}}
