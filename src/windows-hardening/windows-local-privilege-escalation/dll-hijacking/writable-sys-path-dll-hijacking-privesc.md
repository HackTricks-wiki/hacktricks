# Writable Sys Path +Dll Hijacking Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Ukigundua kuwa unaweza **kuandika katika folda ya System Path** (kumbuka kwamba hii haitafanya kazi ikiwa unaweza kuandika katika folda ya User Path), inawezekana kwamba unaweza **kuongeza privileges** kwenye mfumo.

Ili kufanya hivyo unaweza kutumia vibaya **Dll Hijacking** ambapo uta **hijack library inayopakiwa** na service au process yenye **privileges zaidi** kuliko zako, na kwa sababu service hiyo inapakia Dll ambayo pengine hata haipo kwenye mfumo mzima, itajaribu kuipakia kutoka kwenye System Path ambako unaweza kuandika.

Kwa maelezo zaidi kuhusu **Dll Hijackig ni nini** angalia:


{{#ref}}
./
{{#endref}}

## Privesc na Dll Hijacking

### Kupata missing Dll

Jambo la kwanza unalohitaji ni **kutambua process** inayoendeshwa na **privileges zaidi** kuliko zako ambayo inajaribu **kupakia Dll kutoka System Path** unayoweza kuandika ndani yake.

Kumbuka kwamba technique hii inategemea entry ya **Machine/System PATH**, si tu kwenye **User PATH** yako. Kwa hiyo, kabla ya kutumia muda kwenye Procmon, ni vyema kuorodhesha entries za **Machine PATH** na kuangalia zipi zinaweza kuandikwa:
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
Tatizo katika kesi hizi ni kwamba pengine hizo processes tayari zinaendelea. Ili kujua ni Dll gani zinakosekana, unahitaji kuanzisha procmon haraka iwezekanavyo (kabla processes hazijapakiwa). Kwa hiyo, ili kujua zinazokosekana .dlls fanya hivi:

- **Create** folda `C:\privesc_hijacking` na ongeza path `C:\privesc_hijacking` kwenye **System Path env variable**. Unaweza kufanya hivi **manually** au kwa **PS**:
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
- Zindua **`procmon`** na nenda kwenye **`Options`** --> **`Enable boot logging`** na bonyeza **`OK`** kwenye prompt.
- Kisha, **reboot**. Kompyuta ikianza upya, **`procmon`** itaanza **kurekodi** events mara moja.
- Mara tu **Windows** **ikianza endesha `procmon`** tena, itakuambia kuwa imekuwa ikiendeshwa na itakuuliza kama unataka **kuhifadhi** events kwenye file. Sema **yes** na **hifadhi events kwenye file**.
- **Baada ya** **file** kuundwa, **funga** window ya **`procmon`** iliyofunguliwa na **fungua file ya events**.
- Ongeza **filters** hizi na utapata Dll zote ambazo baadhi ya **proccess ilijaribu kupakia** kutoka kwenye writable System Path folder:

<figure><img src="../../../images/image (945).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **Boot logging inahitajika tu kwa services zinazoanza mapema sana** kiasi kwamba vinginevyo haziwezi kuangaliwa. Ukifanikiwa **kuchochea target service/program unapohitaji** (kwa mfano, kwa kuingiliana na COM interface yake, kuanzisha upya service, au kuzindua scheduled task tena), mara nyingi ni haraka zaidi kuendelea na normal Procmon capture ukiwa na filters kama **`Path contains .dll`**, **`Result is NAME NOT FOUND`**, na **`Path begins with <writable_machine_path>`**.

### Missed Dlls

Nikiiendesha hii kwenye free **virtual (vmware) Windows 11 machine** nilipata results hizi:

<figure><img src="../../../images/image (607).png" alt=""><figcaption></figcaption></figure>

Katika case hii .exe hazina manufaa, kwa hiyo zipuuze; missed DLLs zilikuwa kutoka:

| Service                         | Dll                | CMD line                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Task Scheduler (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostic Policy Service (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Baada ya kupata hii, nilipata blog post hii ya kuvutia ambayo pia inaeleza jinsi ya [**abuse WptsExtensions.dll for privesc**](https://juggernaut-sec.com/dll-hijacking/#Windows_10_Phantom_DLL_Hijacking_-_WptsExtensionsdll). Hicho ndicho tutakachofanya **sasa**.

### Other candidates worth triaging

`WptsExtensions.dll` ni mfano mzuri, lakini sio pekee **phantom DLL** inayojirudia ambayo huonekana kwenye privileged services. Modern hunting rules na public hijack catalogs bado hufuatilia majina kama:

| Service / Scenario | Missing DLL | Notes |
| --- | --- | --- |
| Task Scheduler (`Schedule`) | `WptsExtensions.dll` | Classic **SYSTEM** candidate on client systems. Good when the writable directory is in the **Machine PATH** and the service probes the DLL during startup. |
| NetMan on Windows Server | `wlanhlp.dll` / `wlanapi.dll` | Interesting on **server editions** because the service runs as **SYSTEM** and can be **triggered on demand by a normal user** in some builds, making it better than reboot-only cases. |
| Connected Devices Platform Service (`CDPSvc`) | `cdpsgshims.dll` | Usually yields **`NT AUTHORITY\LOCAL SERVICE`** first. That is often still enough because the token has **`SeImpersonatePrivilege`**, so you can chain it with [RoguePotato / PrintSpoofer](../roguepotato-and-printspoofer.md). |

Chukulia hizi names kama **triage hints**, sio wins zilizohakikishwa: zinategemea **SKU/build**, na Microsoft inaweza kubadilisha behavior kati ya releases. Funzo muhimu ni kutafuta **missing DLLs katika privileged services zinazopita kupitia Machine PATH**, hasa ikiwa service inaweza **kuchochewa tena bila reboot**.

### Exploitation

Kwa hiyo, ili **kukuza privileges** tuta-hijack library **WptsExtensions.dll**. Tukiwa na **path** na **name** tunachohitaji tu ni **kuzalisha malicious dll**.

Unaweza [**kujaribu kutumia mifano yoyote kati ya hii**](#creating-and-compiling-dlls). Unaweza kuendesha payloads kama: get a rev shell, add a user, execute a beacon...

> [!WARNING]
> Kumbuka kwamba **sio services zote zinaendeshwa** kwa **`NT AUTHORITY\SYSTEM`** baadhi pia zinaendeshwa kwa **`NT AUTHORITY\LOCAL SERVICE`** ambayo ina **privileges chache zaidi** na **hutaweza kuunda user mpya** kwa kutumia permissions zake.\
> Hata hivyo, user huyo ana privilege ya **`seImpersonate`**, kwa hiyo unaweza kutumia [**potato suite to escalate privileges**](../roguepotato-and-printspoofer.md). Kwa hiyo, katika case hii rev shell ni chaguo bora kuliko kujaribu kuunda user.

Wakati wa kuandika, service ya **Task Scheduler** inaendeshwa na **Nt AUTHORITY\SYSTEM**.

Baada ya **kuzalisha malicious Dll** (_kwangu niliitumia x64 rev shell na nikapata shell ya kurudi lakini defender iliua kwa sababu ilitoka msfvenom_), ihifadhi kwenye writable System Path kwa jina **WptsExtensions.dll** na **restart** kompyuta (au restart service au fanya chochote kinachohitajika ili kuendesha tena affected service/program).

Service ikianza tena, **dll inapaswa kupakiwa na kutekelezwa** (unaweza **kutumia tena** ujanja wa **procmon** kuangalia kama **library ilipakiwa kama ilivyotarajiwa**).

## References

- [Windows DLL Hijacking (Hopefully) Clarified](https://itm4n.github.io/windows-dll-hijacking-clarified/)
- [Suspicious DLL Loaded for Persistence or Privilege Escalation](https://www.elastic.co/guide/en/security/current/suspicious-dll-loaded-for-persistence-or-privilege-escalation.html)

{{#include ../../../banners/hacktricks-training.md}}
