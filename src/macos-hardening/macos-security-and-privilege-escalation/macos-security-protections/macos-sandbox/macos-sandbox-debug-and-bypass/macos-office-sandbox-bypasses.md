# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Die folgenden Beispiele sind **historische Microsoft Office for Mac sandbox escapes**. Sie dokumentieren wiederverwendbare Fehler an Trust Boundaries. Bei gepatchten Office/macOS-Kombinationen sollte jedoch nicht von einer Verwundbarkeit ausgegangen werden, ohne die exakte Version und Policy zu reproduzieren.

### Word sandbox bypass via LaunchAgents

Die betroffene Anwendung verwendete eine benutzerdefinierte Sandbox-Regel über `com.apple.security.temporary-exception.sbpl`. Sie erlaubte reguläre Dateien, deren Basename mit `~$` begann: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Daher war das Escaping so einfach wie das **Schreiben eines `plist`**-LaunchAgents in `~/Library/LaunchAgents/~$escape.plist`.

Siehe den [**Originalbericht hier**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Denke daran, dass Word seit dem ersten Escape beliebige Dateien schreiben kann, deren Name mit `~$` beginnt, obwohl es nach dem Patch der vorherigen Schwachstelle nicht möglich war, in `/Library/Application Scripts` oder `/Library/LaunchAgents` zu schreiben.

Die betroffene Sandbox erlaubte die Erstellung eines **Login Item**, das beim Anmelden des Benutzers gestartet wird. Der demonstrierte Pfad erforderte eine zulässige signierte/notarisierte Anwendung und erlaubte keine beliebigen Argumente. Daher war das Hinzufügen von `bash` mit einem Reverse-Shell-Argument nicht ausreichend.<sup>[[2]](#references)</sup>

Nach dem vorherigen Sandbox bypass deaktivierte Microsoft die Option, Dateien in `~/Library/LaunchAgents` zu schreiben. Es wurde jedoch entdeckt, dass das **`Archive Utility`** eine **zip-Datei als Login Item** einfach an ihrem aktuellen Speicherort **entpackt**. Da der Ordner `LaunchAgents` in `~/Library` standardmäßig nicht erstellt wird, war es daher möglich, **ein plist in `LaunchAgents/~$escape.plist` zu zippen** und die ZIP-Datei in **`~/Library`** zu **platzieren**, sodass sie beim Dekomprimieren das Persistence-Ziel erreicht.

Siehe den [**Originalbericht hier**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Denke daran, dass Word seit dem ersten Escape beliebige Dateien schreiben kann, deren Name mit `~$` beginnt.)

Die vorherige Technik hatte jedoch eine Einschränkung: Wenn der Ordner **`~/Library/LaunchAgents`** existierte, weil ihn eine andere Software erstellt hatte, schlug sie fehl. Daher wurde hierfür eine andere Login-Items-Kette entdeckt.

Ein Angreifer konnte **`.bash_profile`** und **`.zshenv`** mit dem Payload erstellen, sie archivieren und die ZIP-Datei als **`~/~$escape.zip`** in das Home-Verzeichnis des **Opfers** schreiben.

Anschließend wurden die ZIP-Datei und **Terminal** als Login Items hinzugefügt. Bei der nächsten Anmeldung extrahiert das Archive Utility die Dotfiles in das Home-Verzeichnis des Benutzers, und die Shell von Terminal wertet die entsprechende Startup-Datei aus (`.bash_profile` für den demonstrierten Bash-Pfad oder `.zshenv` für Zsh).<sup>[[3]](#references)</sup>

Siehe den [**Originalbericht hier**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes konnten weiterhin über **`open`** das Starten von Anwendungen anfordern. Die gestartete Anwendung lief in ihrem eigenen Security Context, anstatt das exakte Sandbox-Profil von Word zu erben.<sup>[[4]](#references)</sup>

Das betroffene `open`-Utility verfügte über eine **`--env`**-Option zum Übergeben von Environment Variables. Der Exploit erstellte `.zshenv` innerhalb der Sandbox, setzte `HOME` auf dieses Verzeichnis und startete Terminal, sodass Zsh die Datei auswertete. Die gemeldete Chain setzte außerdem die falsch geschriebene private Variable `__OSINSTALL_ENVIROMENT`; bei der Reproduktion des historischen PoC muss diese exakte Schreibweise beibehalten werden.<sup>[[4]](#references)</sup>

Siehe den [**Originalbericht hier**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

Das **`open`**-Utility unterstützte auch den **`--stdin`**-Parameter (und nach dem vorherigen Bypass war die Verwendung von `--env` nicht mehr möglich).

Obwohl Apples Python-Anwendung eine quarantänisierte Script-Datei ablehnen würde, konnte der verwundbare Workflow dasselbe Script über die Standardeingabe zuführen und dadurch die dateibasierte Quarantine-Prüfung umgehen:<sup>[[5]](#references)</sup>

1. Eine **`~$exploit.py`**-Datei mit beliebigen Python-Befehlen ablegen.
2. `open --stdin='~$exploit.py' -a Python` ausführen. Die gestartete Python-Anwendung erhält den abgelegten Code über die Standardeingabe und läuft in den verwundbaren Versionen außerhalb der Word-Sandbox, da LaunchServices sie unter `launchd` erstellt.<sup>[[5]](#references)</sup>

## References

- [1] [Umgehen der Sandbox – Microsoft Office auf macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office-Drama auf macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365-MacOS-Sandbox-Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technische Analyse von CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Aufdeckung einer macOS-App-Sandbox-Escape-Schwachstelle: Eine ausführliche Analyse von CVE-2022-26706 – Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
