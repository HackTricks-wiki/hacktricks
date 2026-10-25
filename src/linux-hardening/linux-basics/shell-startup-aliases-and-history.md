# Shell-Start, Aliase und Verlauf

{{#include ../../banners/hacktricks-training.md}}

Ein Shell-Befehl kann sich anders verhalten als die gleichnamige ausführbare Datei, wenn ein Alias, eine Funktion, eine Startdatei oder eine Umgebungsvariable seine Ausführung verändert. Überprüfe diese, bevor du der Ausgabe eines Befehls vertraust oder davon ausgehst, dass ein Skript denselben PATH wie eine interaktive Sitzung verwendet.

## Aktuelle Shell untersuchen

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` und `command -V` zeigen, ob ein Name zu einem Alias, einer Funktion, einem Builtin oder einer Datei aufgelöst wird. `command -v` und `which` liefern bei Aliasen und Funktionen möglicherweise unterschiedliche Ergebnisse. Die Shell-History kann Befehle oder Zugangsdaten offenlegen, aber unvollständig oder deaktiviert sein oder bis zum Ende der Sitzung im Speicher gehalten werden.

Eine modifizierte `.bashrc` kann einen `sudo`-Alias definieren, der eine Passwortabfrage imitiert, die Eingabe aufzeichnet und sie an den echten Befehl weitergibt. So lässt sich das Abfangen von Zugangsdaten verschleiern, ohne die ausführbare `sudo`-Datei oder `PATH` zu ändern.<sup>[[5]](#references)</sup> Die Shell muss die modifizierte Startup-Datei einlesen und den Alias expandieren.<sup>[[7]](#references)</sup> Standardmäßig expandiert nicht-interaktives Bash keine Aliase, sofern `expand_aliases` nicht aktiviert ist.<sup>[[6]](#references)</sup>

## Startup- und History-Dateien prüfen

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Eine für Benutzer beschreibbare Startdatei kann bei einem späteren Shell-Start Befehle ausführen. Eine systemweite Startdatei oder die Startdatei eines privilegierten Benutzers ist besonders kritisch, wenn ein Konto mit geringeren Rechten sie ändern kann. Nicht-interaktive Bash kann außerdem die durch `BASH_ENV` angegebene Datei lesen. Die Seite zu [Umgebungsvariablen](linux-environment-variables.md#bash_env--env) erklärt dieses Verhalten und weitere Interpreter-Hooks. Prüfe, welche Dateien die tatsächlich verwendete Shell für Login-, interaktive und nicht-interaktive Sitzungen liest, bevor du einen Persistenzpfad annimmst.

Untersuche auch Dateien, die von einer globalen Startdatei eingebunden werden. Ein wörtliches `source /opt/app/venv/bin/activate` in `/etc/bash.bashrc` führt beispielsweise die Aktivierungsdatei als Shell-Code aus, wenn eine Shell diese Startdatei tatsächlich liest. Prüfe die Aktivierungsdatei, Symlink- und übergeordnete Verzeichnisberechtigungen sowie ACLs. Ein Benutzer mit geringeren Rechten kann eine privilegierte Shell nur beeinflussen, wenn diese Shell oder eine privilegierte Aufgabe die Datei später einbindet. Wenn der Schreibzugriff von `sudoedit` abhängt, prüfe zuerst die genaue sudoers-Regel und das installierte, vom Anbieter gepatchte sudo-Paket. Eine Upstream-Versionszeichenfolge allein belegt keine [sudoedit-Argument-Injection-Schwachstelle](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Prüfe den Verlauf, Dotfiles und Sicherungskopien auf Geheimnisse, wie unter [Benutzer und Sitzungen](../user-information/user-and-session-triage.md) beschrieben. Wenn ein privilegiertes Skript Befehle anhand ihres Namens auflöst, kombiniere diese Prüfung mit den [Hinweisen zum PATH-Hijacking](linux-environment-variables.md#path).

## Zsh-Startumleitung und kompilierte Dateien

Mit den standardmäßigen `RCS`-Einstellungen liest zsh vor normalen Aufrufen `$ZDOTDIR/.zshenv`, einschließlich bei `zsh -c` und Skripten. Ist `ZDOTDIR` nicht gesetzt, wird `$HOME` verwendet. Wenn ein Befehls-Runner eine Umgebungszuordnung akzeptiert, teste, ob er eine der beiden Variablen an einen privilegierten zsh-Prozess weitergibt. Eine beschreibbare `.zshenv` kann dann **vor** dem Befehlsrumpf ausgeführt werden, den der Runner prüft oder per Allowlist zulässt. Dazu muss der privilegierte Prozess das umgeleitete Verzeichnis übernehmen. `zsh -f` überspringt benutzerspezifische Startdateien, nicht aber die globale `zshenv` (häufig `/etc/zshenv`, wobei die Pfade je nach Distribution variieren). Die [macOS-Seite zu zsh-Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) enthält ein minimales `ZDOTDIR`-Beispiel.<sup>[[1]](#references)[[2]](#references)</sup>

Eine neuere, gültige `.zshenv.zwc` oder `.zshrc.zwc` wird anstelle der entsprechenden Klartext-Startdatei ausgeführt. Wenn du das Startverzeichnis beschreiben kannst, kannst du eine geänderte Datei kompilieren und anschließend den harmlos wirkenden Klartext wiederherstellen. So kann ausführbarer Code in der kompilierten Kopie zurückbleiben. Das ist Verschleierung, keine Verschlüsselung. Der folgende Test in einer Wegwerf-Umgebung zeigt, warum es nicht ausreicht, nur die Textdatei zu untersuchen. Er greift nicht auf ein echtes Home-Verzeichnis zu.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Für ein echtes Ziel ermitteln Sie das effektive `ZDOTDIR`/`HOME`, prüfen Sie sowohl die Textdateien als auch die `.zwc`-Dateien und kontrollieren Sie Zeitstempel, Eigentümer und beschreibbare übergeordnete Verzeichnisse. Eine `.zwc`-Datei muss zur Quelldatei passen und neuer sein, um Vorrang zu haben.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh-Start- und Beendigungsdateien](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Sicherheitshinweis zur Umgebungsinjektion beim Shell-Start](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh-Shell-Builtins: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Die vergessene .zshrc.zwc-Datei](https://dfir.ch/posts/compiled_zsh/)
- [5] [KI-gestützte Spionagekampagne zielt auf staatliche Linux-Infrastruktur](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash-Handbuch: Aliases](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash-Handbuch: Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
