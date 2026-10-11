# Shell-Start, Aliase und Verlauf

{{#include ../../banners/hacktricks-training.md}}

Ein Shell-Befehl kann sich anders verhalten als die gleichnamige ausführbare Datei, wenn ein Alias, eine Funktion, eine Startdatei oder eine Umgebungsvariable seine Ausführung verändert. Prüfe diese, bevor du der Ausgabe eines Befehls vertraust oder davon ausgehst, dass ein Skript denselben PATH wie eine interaktive Sitzung verwendet.

## Die aktuelle Shell untersuchen

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` und `command -V` zeigen, ob ein Name als Alias, Funktion, Builtin oder Datei aufgelöst wird. `command -v` und `which` liefern bei Aliasen und Funktionen möglicherweise unterschiedliche Ergebnisse. Die Shell-History kann Befehle oder Zugangsdaten offenlegen, aber unvollständig oder deaktiviert sein oder bis zum Ende der Sitzung im Speicher gehalten werden.

## Startup- und History-Dateien prüfen

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Eine vom Benutzer beschreibbare Startdatei kann bei einem zukünftigen Shell-Start Befehle ausführen. Eine systemweite Startdatei oder die Startdatei eines privilegierten Benutzers ist besonders kritisch, wenn ein Konto mit geringeren Berechtigungen sie ändern kann. Nicht-interaktives Bash kann auch die in `BASH_ENV` angegebene Datei einlesen; die Seite zu [Umgebungsvariablen](linux-environment-variables.md#bash_env--env) erklärt dieses Verhalten und weitere Interpreter-Hooks. Prüfen Sie, welche Dateien die tatsächlich verwendete Shell bei Login-, interaktiven und nicht-interaktiven Sitzungen einliest, bevor Sie einen Persistenzpfad behaupten.

Prüfen Sie auch Dateien, die von einer globalen Startdatei eingebunden werden. Ein wörtliches `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` führt beispielsweise die Aktivierungsdatei als Shell-Code aus, wenn eine Shell diese Startdatei tatsächlich einliest. Prüfen Sie die Aktivierungsdatei, die Berechtigungen für Symlinks und übergeordnete Verzeichnisse sowie ACLs. Ein Benutzer mit geringeren Berechtigungen kann eine privilegierte Shell nur beeinflussen, wenn diese Shell oder eine privilegierte Aufgabe die Datei später einbindet. Falls der Schreibzugriff von `sudoedit` abhängt, prüfen Sie zunächst die genaue sudoers-Regel und das installierte, vom Hersteller gepatchte sudo-Paket. Eine Upstream-Versionsangabe allein belegt keine [sudoedit-Angreifbarkeit durch Argument-Injection](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Prüfen Sie den Verlauf, Dotfiles und Backups auf Geheimnisse, wie unter [Benutzer und Sitzungen](../user-information/user-and-session-triage.md) beschrieben. Wenn ein privilegiertes Skript Befehle anhand ihres Namens auflöst, ergänzen Sie diese Prüfung um die Hinweise zu [PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
