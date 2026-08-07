# Word Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass über Launch Agents

Die Anwendung verwendet eine **custom Sandbox** mit dem Entitlement **`com.apple.security.temporary-exception.sbpl`**. Diese custom Sandbox erlaubt das Schreiben von Dateien überall, solange der Dateiname mit `~$` beginnt: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Daher war das Escaping so einfach wie das **Schreiben einer `plist`** als LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Siehe den [**originalen Report hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass über Login Items und zip

Denke daran, dass Word nach dem ersten Escape beliebige Dateien schreiben kann, deren Namen mit `~$` beginnen, obwohl es nach dem Patch der vorherigen Vulnerability nicht mehr möglich war, in `/Library/Application Scripts` oder `/Library/LaunchAgents` zu schreiben.

Es wurde entdeckt, dass es innerhalb der Sandbox möglich ist, ein **Login Item** zu erstellen (Apps, die ausgeführt werden, wenn sich der Benutzer anmeldet). Diese Apps **werden jedoch nicht ausgeführt, solange sie nicht** **notarized** sind, und es ist **nicht möglich, Argumente hinzuzufügen** (man kann also nicht einfach eine reverse shell mit **`bash`** starten).

Nach dem vorherigen Sandbox bypass deaktivierte Microsoft die Option, Dateien in `~/Library/LaunchAgents` zu schreiben. Es wurde jedoch entdeckt, dass die `Archive Utility` eine **zip-Datei als Login Item** einfach an ihrem aktuellen Speicherort **entzippt**. Da der Ordner `LaunchAgents` in `~/Library` standardmäßig nicht erstellt wird, war es daher möglich, **eine plist in `LaunchAgents/~$escape.plist` zu zippen** und die **zip-Datei in `~/Library`** zu platzieren, sodass sie beim Dekomprimieren das Persistence-Ziel erreicht.

Siehe den [**originalen Report hier**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass über Login Items und .zshenv

(Denke daran, dass Word seit dem ersten Escape beliebige Dateien schreiben kann, deren Namen mit `~$` beginnen.)

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existiert, weil ihn eine andere Software erstellt hat, würde sie fehlschlagen. Daher wurde hierfür eine andere Login-Items-Kette entdeckt.

Ein Angreifer konnte die Dateien **`.bash_profile`** und **`.zshenv`** mit dem auszuführenden Payload erstellen, sie anschließend zippen und die **zip-Datei in das Benutzerverzeichnis des Opfers** schreiben: **`~/~$escape.zip`**.

Anschließend wird die zip-Datei zu den **Login Items** und danach die **`Terminal`**-App hinzugefügt. Wenn sich der Benutzer erneut anmeldet, wird die zip-Datei im Benutzerverzeichnis entpackt, wobei **`.bash_profile`** und **`.zshenv`** überschrieben werden. Dadurch führt das Terminal eine dieser Dateien aus (abhängig davon, ob bash oder zsh verwendet wird).

Siehe den [**originalen Report hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass mit Open und env-Variablen

Aus sandboxed Prozessen ist es weiterhin möglich, andere Prozesse mit dem **`open`**-Utility aufzurufen. Außerdem werden diese Prozesse **innerhalb ihrer eigenen Sandbox** ausgeführt.

Es wurde entdeckt, dass das open-Utility über die Option **`--env`** verfügt, um eine App mit **bestimmten env**-Variablen auszuführen. Daher war es möglich, die **`.zshenv`-Datei** innerhalb eines Ordners **in der** **Sandbox** zu erstellen und `open` mit `--env` zu verwenden, um die **`HOME`-Variable** auf diesen Ordner zu setzen und dadurch die `Terminal`-App zu öffnen, die dann die `.zshenv`-Datei ausführt (aus irgendeinem Grund musste außerdem die Variable `__OSINSTALL_ENVIROMENT` gesetzt werden).

Siehe den [**originalen Report hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass mit Open und stdin

Das **`open`**-Utility unterstützte außerdem den Parameter **`--stdin`** (nach dem vorherigen Bypass war die Verwendung von **`--env`** nicht mehr möglich).

Obwohl **`python`** von Apple signiert war, **führt es kein** Script mit dem **`quarantine`**-Attribut aus. Es war jedoch möglich, ihm ein Script über stdin zu übergeben, sodass nicht geprüft wurde, ob es unter Quarantäne stand:

1. Eine **`~$exploit.py`**-Datei mit beliebigen Python-Befehlen ablegen.
2. _open_ **`–stdin='~$exploit.py' -a Python`** ausführen. Dadurch wird die Python-App mit unserer abgelegten Datei als Standardeingabe ausgeführt. Python führt unseren Code problemlos aus, und da es sich um einen Child-Prozess von **`launchd`** handelt, ist es nicht an die Sandbox-Regeln von Word gebunden.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
