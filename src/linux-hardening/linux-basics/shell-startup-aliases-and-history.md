# Shell-Start, Aliases und Verlauf

{{#include ../../banners/hacktricks-training.md}}

Ein Shell-Befehl kann sich anders verhalten als die gleichnamige ausführbare Datei, wenn ein Alias, eine Funktion, eine Startup-Datei oder eine Umgebungsvariable seine Ausführung verändert. Prüfe diese, bevor du der Ausgabe eines Befehls vertraust oder davon ausgehst, dass ein Skript denselben PATH wie eine interaktive Sitzung verwendet.

## Aktuelle Shell untersuchen

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` und `command -V` zeigen, ob ein Name als Alias, Funktion, Builtin oder Datei aufgelöst wird. `command -v` und `which` liefern bei Aliases und Funktionen möglicherweise unterschiedliche Ergebnisse. Die Shell-History kann Befehle oder Zugangsdaten offenlegen, aber unvollständig oder deaktiviert sein oder bis zum Ende der Sitzung im Arbeitsspeicher verbleiben.

## Startup- und History-Dateien prüfen

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Eine für einen Benutzer beschreibbare Startup-Datei kann bei einem späteren Shell-Start Befehle ausführen. Eine systemweite Startup-Datei oder die Startup-Datei eines privilegierten Benutzers ist besonders sensibel, wenn ein weniger privilegiertes Konto sie ändern kann. Nicht-interaktive Bash kann außerdem die durch `BASH_ENV` angegebene Datei lesen; die Seite [Umgebungsvariablen](linux-environment-variables.md#bash_env--env) erklärt dieses Verhalten und weitere Interpreter-Hooks. Prüfen Sie, welche Dateien die tatsächliche Shell bei Login-, interaktiven und nicht-interaktiven Sitzungen liest, bevor Sie einen Persistence-Pfad als möglich einstufen.

Prüfen Sie auch Dateien, die von einer globalen Startup-Datei eingebunden werden. Beispielsweise führt ein wörtliches `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` die Aktivierungsdatei als Shell-Code aus, wenn eine Shell diese Startup-Datei tatsächlich liest. Prüfen Sie die Aktivierungsdatei, die Berechtigungen für Symlinks und übergeordnete Verzeichnisse sowie ACLs; ein weniger privilegierter Benutzer kann eine privilegierte Shell nur beeinflussen, wenn diese Shell oder eine privilegierte Aufgabe die Datei später einbindet. Wenn der Schreibzugriff von `sudoedit` abhängt, prüfen Sie zuerst die genaue sudoers-Regel und das installierte, vom Anbieter gepatchte sudo-Paket; eine Versionsangabe des Upstream-Projekts allein belegt keine [sudoedit-Argument-Injection-Angreifbarkeit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Prüfen Sie den Verlauf, Dotfiles und Backups auf Secrets, wie unter [Benutzer und Sitzungen](../user-information/user-and-session-triage.md) beschrieben. Wenn ein privilegiertes Skript Befehle anhand ihres Namens auflöst, ergänzen Sie diese Prüfung um die [Anleitung zu PATH-Hijacking](linux-environment-variables.md#path).

## Zsh-Startup-Umleitung und kompilierte Dateien

Mit den standardmäßigen `RCS`-Einstellungen liest zsh vor normalen Aufrufen `$ZDOTDIR/.zshenv`, auch bei `zsh -c` und Skripten; ist `ZDOTDIR` nicht gesetzt, wird `$HOME` verwendet. Wenn ein Command-Runner eine Umgebungsvariablen-Map akzeptiert, prüfen Sie, ob er eine der beiden Variablen an einen privilegierten zsh-Prozess weitergibt. Eine beschreibbare `.zshenv` kann dann **vor** dem Befehlsrumpf ausgeführt werden, den der Runner überprüft oder auf eine Allowlist setzt. Dazu muss der privilegierte Prozess das umgeleitete Verzeichnis übernehmen; `zsh -f` überspringt benutzerseitige Startup-Dateien, jedoch nicht die globale `zshenv`-Datei (häufig `/etc/zshenv`, aber die Pfade variieren je nach Distribution). Die [macOS-Seite zu zsh-Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) enthält ein minimales `ZDOTDIR`-Beispiel.<sup>[[1]](#references)[[2]](#references)</sup>

Eine neuere, gültige `.zshenv.zwc`- oder `.zshrc.zwc`-Datei wird anstelle ihrer Klartext-Startup-Datei ausgeführt. Wenn Sie in das Startup-Verzeichnis schreiben können, kann das Kompilieren einer geänderten Datei und anschließende Wiederherstellen eines harmlos wirkenden Klartexts ausführbaren Code in der kompilierten Kopie zurücklassen. Das ist Verschleierung, keine Verschlüsselung. Der folgende Test in einer Wegwerf-Umgebung zeigt, weshalb die Prüfung nur der Textdatei nicht ausreicht; dabei wird kein echtes Home-Verzeichnis verändert.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Für ein reales Ziel sollten Sie dessen effektives `ZDOTDIR`/`HOME` ermitteln, sowohl die Textdateien als auch die `.zwc`-Dateien prüfen und Zeitstempel, Eigentümerschaft und beschreibbare übergeordnete Verzeichnisse kontrollieren. Eine `.zwc`-Datei muss mit der Quelldatei übereinstimmen und neuer sein, damit sie Vorrang hat.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh-Start- und -Beendigungsdateien](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Sicherheitshinweis zur Einschleusung in die Shell-Startumgebung](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh-Shell-Builtins: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Die .zshrc.zwc, die Sie zu überprüfen vergessen haben](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
