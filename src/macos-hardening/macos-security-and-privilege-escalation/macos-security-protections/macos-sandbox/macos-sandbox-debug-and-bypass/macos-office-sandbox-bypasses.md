# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox-Bypass über Launch Agents

Die Anwendung verwendet einen **benutzerdefinierten Sandbox** mit der Berechtigung **`com.apple.security.temporary-exception.sbpl`** und dieser benutzerdefinierte Sandbox erlaubt das Schreiben von Dateien überall, solange der Dateiname mit `~$` beginnt: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daher war das Entkommen so einfach wie **das Schreiben eines `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Überprüfen Sie den [**originalen Bericht hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox-Bypass über Login Items und zip

Denken Sie daran, dass Word von der ersten Umgehung an beliebige Dateien schreiben kann, deren Name mit `~$` beginnt, obwohl es nach dem Patch der vorherigen Schwachstelle nicht möglich war, in `/Library/Application Scripts` oder in `/Library/LaunchAgents` zu schreiben.

Es wurde entdeckt, dass es innerhalb des Sandboxes möglich ist, ein **Login Item** (Apps, die beim Anmelden des Benutzers ausgeführt werden) zu erstellen. Diese Apps **werden jedoch nicht ausgeführt**, es sei denn, sie sind **notarisiert** und es ist **nicht möglich, Argumente hinzuzufügen** (Sie können also nicht einfach eine Reverse-Shell mit **`bash`** ausführen).

Von der vorherigen Sandbox-Umgehung hat Microsoft die Option deaktiviert, Dateien in `~/Library/LaunchAgents` zu schreiben. Es wurde jedoch entdeckt, dass, wenn Sie eine **zip-Datei als Login Item** hinzufügen, das `Archive Utility` sie einfach **entpackt** an ihrem aktuellen Standort. Da der Ordner `LaunchAgents` von `~/Library` standardmäßig nicht erstellt wird, war es möglich, eine **plist in `LaunchAgents/~$escape.plist`** zu **zippen** und die zip-Datei in **`~/Library`** zu **platzieren**, sodass sie beim Dekomprimieren das Ziel für die Persistenz erreicht.

Überprüfen Sie den [**originalen Bericht hier**](https://objective-see.org/blog/blog_0x4B.html).

### Word Sandbox-Bypass über Login Items und .zshenv

(Denken Sie daran, dass Word von der ersten Umgehung an beliebige Dateien schreiben kann, deren Name mit `~$` beginnt).

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existiert, weil eine andere Software ihn erstellt hat, würde es fehlschlagen. Daher wurde eine andere Kette von Login Items für dies entdeckt.

Ein Angreifer könnte die Dateien **`.bash_profile`** und **`.zshenv`** mit der Payload erstellen und sie dann zippen und **die zip-Datei im Benutzerordner des Opfers** schreiben: **`~/~$escape.zip`**.

Dann fügen Sie die zip-Datei zu den **Login Items** hinzu und dann die **`Terminal`**-App. Wenn der Benutzer sich erneut anmeldet, wird die zip-Datei im Benutzerverzeichnis entpackt, wodurch **`.bash_profile`** und **`.zshenv`** überschrieben werden und daher wird das Terminal eine dieser Dateien ausführen (je nachdem, ob bash oder zsh verwendet wird).

Überprüfen Sie den [**originalen Bericht hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox-Bypass mit Open und env-Variablen

Von sandboxed Prozessen ist es weiterhin möglich, andere Prozesse mit dem **`open`**-Utility aufzurufen. Darüber hinaus werden diese Prozesse **innerhalb ihres eigenen Sandboxes** ausgeführt.

Es wurde entdeckt, dass das Open-Utility die **`--env`**-Option hat, um eine App mit **spezifischen env**-Variablen auszuführen. Daher war es möglich, die **`.zshenv`-Datei** innerhalb eines Ordners **innerhalb** des **Sandboxes** zu erstellen und `open` mit `--env` zu verwenden, um die **`HOME`-Variable** auf diesen Ordner zu setzen, der die `Terminal`-App öffnet, die die `.zshenv`-Datei ausführt (aus irgendeinem Grund war es auch notwendig, die Variable `__OSINSTALL_ENVIROMENT` zu setzen).

Überprüfen Sie den [**originalen Bericht hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox-Bypass mit Open und stdin

Das **`open`**-Utility unterstützte auch den **`--stdin`**-Parameter (und nach der vorherigen Umgehung war es nicht mehr möglich, `--env` zu verwenden).

Das Problem ist, dass selbst wenn **`python`** von Apple signiert war, es **kein Skript** mit dem **`quarantine`**-Attribut **ausführen wird**. Es war jedoch möglich, ihm ein Skript von stdin zu übergeben, sodass nicht überprüft wird, ob es quarantiniert war oder nicht:

1. Legen Sie eine **`~$exploit.py`**-Datei mit beliebigen Python-Befehlen ab.
2. Führen Sie _open_ **`–stdin='~$exploit.py' -a Python`** aus, was die Python-App mit unserer abgelegten Datei als Standard-Eingabe ausführt. Python führt unseren Code gerne aus, und da es sich um einen Kindprozess von _launchd_ handelt, ist es nicht an die Sandbox-Regeln von Word gebunden.

{{#include ../../../../../banners/hacktricks-training.md}}
