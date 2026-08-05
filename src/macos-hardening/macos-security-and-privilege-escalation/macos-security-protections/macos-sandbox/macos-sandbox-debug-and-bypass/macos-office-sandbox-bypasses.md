# macOS Office Sandbox-Umgehungen

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

Die Anwendung verwendet eine **custom Sandbox** mit dem Entitlement **`com.apple.security.temporary-exception.sbpl`**, und diese custom Sandbox erlaubt das Schreiben von Dateien überall, solange der Dateiname mit `~$` beginnt: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daher war das Entkommen so einfach wie das **Schreiben eines `plist`**-LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Siehe den [**originalen Bericht hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Word Sandbox bypass via Login Items and zip

Denken Sie daran, dass Word seit dem ersten Escape beliebige Dateien schreiben kann, deren Name mit `~$` beginnt, obwohl es nach dem Patch der vorherigen Schwachstelle nicht mehr möglich war, in `/Library/Application Scripts` oder in `/Library/LaunchAgents` zu schreiben.

Es wurde entdeckt, dass es innerhalb der Sandbox möglich ist, ein **Login Item** zu erstellen (Apps, die beim Anmelden des Benutzers ausgeführt werden). Diese Apps **werden jedoch nicht ausgeführt, sofern sie nicht** **notarized** sind, und es ist **nicht möglich, args hinzuzufügen** (daher kann man nicht einfach eine reverse shell mit **`bash`** ausführen).

Nach dem vorherigen Sandbox bypass deaktivierte Microsoft die Möglichkeit, Dateien in `~/Library/LaunchAgents` zu schreiben. Es wurde jedoch entdeckt, dass das `Archive Utility`, wenn man eine **zip-Datei als Login Item** festlegt, diese einfach an ihrem aktuellen Speicherort **entpackt**. Da der Ordner `LaunchAgents` in `~/Library` standardmäßig nicht erstellt wird, war es daher möglich, ein **plist in `LaunchAgents/~$escape.plist` zu zippen** und die **zip-Datei in `~/Library`** zu platzieren, sodass sie beim Entpacken das Persistence-Ziel erreicht.

Siehe den [**originalen Bericht hier**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Denken Sie daran, dass Word seit dem ersten Escape beliebige Dateien schreiben kann, deren Name mit `~$` beginnt.)

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existiert, weil ihn eine andere Software erstellt hat, würde sie fehlschlagen. Daher wurde hierfür eine andere Login-Items-Kette entdeckt.

Ein Angreifer konnte die Dateien **`.bash_profile`** und **`.zshenv`** mit dem auszuführenden Payload erstellen, sie anschließend zippen und das zip in den Benutzerordner des Opfers schreiben: **`~/~$escape.zip`**.

Anschließend wird die zip-Datei zu den **Login Items** und dann die **`Terminal`**-App hinzugefügt. Wenn sich der Benutzer erneut anmeldet, würde die zip-Datei im Benutzerordner entpackt, wobei **`.bash_profile`** und **`.zshenv`** überschrieben würden. Daher würde das Terminal eine dieser Dateien ausführen (abhängig davon, ob bash oder zsh verwendet wird).

Siehe den [**originalen Bericht hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Word Sandbox Bypass with Open and env variables

Von sandboxed processes aus ist es weiterhin möglich, andere Prozesse mit dem **`open`**-utility aufzurufen. Außerdem werden diese Prozesse **innerhalb ihrer eigenen Sandbox** ausgeführt.

Es wurde entdeckt, dass das open utility über die Option **`--env`** verfügt, um eine App mit **bestimmten env**-Variablen auszuführen. Daher war es möglich, die Datei **`.zshenv`** innerhalb eines Ordners **in der** **Sandbox** zu erstellen und `open` mit `--env` zu verwenden, um die Variable **`HOME`** auf diesen Ordner zu setzen und dadurch die `Terminal`-App zu öffnen, die dann die Datei `.zshenv` ausführt (aus irgendeinem Grund musste außerdem die Variable `__OSINSTALL_ENVIROMENT` gesetzt werden).

Siehe den [**originalen Bericht hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Word Sandbox Bypass with Open and stdin

Das **`open`**-utility unterstützte außerdem den Parameter **`--stdin`** (und nach dem vorherigen bypass war die Verwendung von `--env` nicht mehr möglich).

Der entscheidende Punkt ist, dass **`python`**, obwohl es von Apple signiert war, kein Script mit dem Attribut **`quarantine`** ausführt. Es war jedoch möglich, ihm ein Script über stdin zu übergeben, sodass nicht geprüft wurde, ob es quarantined war oder nicht:

1. Eine **`~$exploit.py`**-Datei mit beliebigen Python-Befehlen ablegen.
2. _open_ **`–stdin='~$exploit.py' -a Python`** ausführen, wodurch die Python-App mit der abgelegten Datei als Standardeingabe gestartet wird. Python führt unseren Code problemlos aus, und da es sich um einen Child-Prozess von _launchd_ handelt, unterliegt es nicht den Sandbox-Regeln von Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
