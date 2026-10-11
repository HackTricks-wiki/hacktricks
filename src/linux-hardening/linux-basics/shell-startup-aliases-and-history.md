# Shell-Start, Aliase und Verlauf

{{#include ../../banners/hacktricks-training.md}}

Ein Shell-Befehl kann sich anders verhalten als die gleichnamige ausführbare Datei, wenn ein Alias, eine Funktion, eine Startdatei oder eine Umgebungsvariable seine Ausführung verändert. Prüfe diese, bevor du der Ausgabe eines Befehls vertraust oder annimmst, dass ein Skript denselben PATH wie eine interaktive Sitzung verwendet.

## Aktuelle Shell untersuchen

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` und `command -V` zeigen, ob ein Name als Alias, Funktion, eingebauter Befehl oder Datei aufgelöst wird. `command -v` und `which` liefern bei Aliasen und Funktionen möglicherweise unterschiedliche Ergebnisse. Die Shell-History kann Befehle oder Zugangsdaten offenlegen, ist aber möglicherweise unvollständig, deaktiviert oder bleibt bis zum Ende der Sitzung im Arbeitsspeicher.

## Startup- und History-Dateien überprüfen

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Eine für Benutzer beschreibbare Startdatei kann bei einem späteren Shell-Start Befehle ausführen. Eine systemweite Startdatei oder die Startdatei eines privilegierten Benutzers ist sensibler, wenn ein Konto mit geringeren Berechtigungen sie ändern kann. Nicht-interaktive Bash kann auch die durch `BASH_ENV` angegebene Datei lesen; die Seite zu [Umgebungsvariablen](linux-environment-variables.md#bash_env--env) erläutert dieses Verhalten und weitere Interpreter-Hooks. Prüfe, welche Dateien die tatsächliche Shell bei Login-, interaktiven und nicht-interaktiven Sitzungen liest, bevor du einen Persistenzpfad annimmst.

Prüfe auch Dateien, die von einer globalen Startdatei eingebunden werden. Zum Beispiel wird ein wörtliches `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` die Aktivierungsdatei als Shell-Code ausführen, wenn eine Shell diese Startdatei tatsächlich liest. Prüfe die Aktivierungsdatei, die Berechtigungen für Symlinks und übergeordnete Verzeichnisse sowie ACLs; ein Benutzer mit geringeren Berechtigungen kann eine privilegierte Shell nur beeinflussen, wenn diese Shell oder eine privilegierte Aufgabe die Datei später einbindet. Wenn der Schreibzugriff von `sudoedit` abhängt, prüfe zuerst die genaue sudoers-Regel und das installierte, vom Anbieter gepatchte sudo-Paket; eine Upstream-Versionszeichenfolge allein belegt keine [sudoedit-Argument-Injection-Schwachstelle](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Prüfe den Verlauf, dotfiles und Backups auf Geheimnisse, wie unter [Benutzer und Sitzungen](../user-information/user-and-session-triage.md) beschrieben. Wenn ein privilegiertes Skript Befehle anhand ihres Namens auflöst, kombiniere diese Prüfung mit den [Hinweisen zu PATH-Hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
