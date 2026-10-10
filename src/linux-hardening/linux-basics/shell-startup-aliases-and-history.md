# Shell-Start, Aliases und Verlauf

{{#include ../../banners/hacktricks-training.md}}

Ein Shell-Befehl kann sich anders verhalten als die gleichnamige ausführbare Datei, wenn ein Alias, eine Funktion, eine Startup-Datei oder eine Umgebungsvariable seine Ausführung beeinflusst. Prüfe diese, bevor du der Ausgabe eines Befehls vertraust oder davon ausgehst, dass ein Skript denselben PATH wie eine interaktive Sitzung verwendet.

## Aktuelle Shell untersuchen

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` und `command -V` zeigen, ob ein Name auf ein Alias, eine Funktion, ein Builtin oder eine Datei verweist. `command -v` und `which` liefern bei Aliasen und Funktionen möglicherweise unterschiedliche Ergebnisse. Die Shell-History kann Befehle oder Zugangsdaten offenlegen, aber unvollständig oder deaktiviert sein oder bis zum Beenden der Sitzung im Speicher verbleiben.

## Startup- und History-Dateien überprüfen

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Eine vom Benutzer beschreibbare Startup-Datei kann bei einem späteren Shell-Start Befehle ausführen. Eine systemweite Startup-Datei oder die Startup-Datei eines privilegierten Benutzers ist besonders sensibel, wenn ein Konto mit geringeren Berechtigungen sie ändern kann. Nicht-interaktive Bash kann außerdem die durch `BASH_ENV` angegebene Datei lesen. Die Seite [Umgebungsvariablen](linux-environment-variables.md#bash_env--env) erläutert dieses Verhalten und weitere Interpreter-Hooks. Prüfen Sie, welche Dateien die tatsächlich verwendete Shell bei Login-, interaktiven und nicht-interaktiven Sitzungen liest, bevor Sie einen Persistenzpfad annehmen.

Prüfen Sie auch Dateien, die von einer globalen Startup-Datei eingebunden werden. Beispielsweise führt ein wörtliches `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` die Aktivierungsdatei als Shell-Code aus, wenn eine Shell diese Startup-Datei tatsächlich liest. Prüfen Sie die Aktivierungsdatei, die Berechtigungen für Symlinks und übergeordnete Verzeichnisse sowie ACLs. Ein Benutzer mit geringeren Berechtigungen kann eine privilegierte Shell nur beeinflussen, wenn diese Shell oder eine privilegierte Aufgabe die Datei später einbindet. Falls der Schreibzugriff von `sudoedit` abhängt, prüfen Sie zuerst die genaue sudoers-Regel und das installierte, vom Hersteller gepatchte sudo-Paket. Eine Upstream-Versionszeichenfolge allein belegt keine [Anfälligkeit für Argument-Injection bei sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Prüfen Sie den Verlauf, Dotfiles und Backups auf Geheimnisse, wie unter [Benutzer und Sitzungen](../user-information/user-and-session-triage.md) beschrieben. Wenn ein privilegiertes Skript Befehle anhand ihres Namens auflöst, ergänzen Sie diese Prüfung um die [Hinweise zur PATH-Hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
