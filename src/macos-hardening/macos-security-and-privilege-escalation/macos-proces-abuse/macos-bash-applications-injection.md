# Injection in macOS-Shell-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Wenn Bash nicht interaktiv gestartet wird, um ein Skript oder einen `-c`-Befehl auszuführen, erweitert es den Wert von `BASH_ENV` und lädt die resultierende Datei vor der Ausführung des angeforderten Befehls. Bash verwendet `PATH` nicht, um diese Datei zu finden. Ein Prozess, der nicht interaktive Bash mit vom Angreifer kontrollierten Umgebungsvariablen startet, kann daher dazu gebracht werden, zuerst eine lesbare Shell-Payload auszuführen.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Der Hook wird nur ausgeführt, wenn das Ziel tatsächlich Bash startet; `/bin/sh` auf einer anderen Plattform oder ein Programm, das einen Befehl ohne Shell ausführt, wird ihn nicht unbedingt berücksichtigen. Bash ignoriert `BASH_ENV` im privilegierten Modus. Wenn sich die effektiven und realen Benutzer-/Gruppen-IDs unterscheiden, überspringt Bash ebenfalls die Startup-Dateien und setzt die effektiven IDs zurück, sofern nicht `-p` angegeben wird; mit `-p` bleibt der privilegierte Modus aktiviert und `BASH_ENV` wird weiterhin ignoriert.<sup>[[1]](#references)[[2]](#references)</sup>

Unter macOS können `launchd`-Jobs geerbte oder jobspezifische Umgebungsvariablen definieren. Untersuchen Sie daher Plists und Launch-Kontexte, die privilegierte Skripte versorgen. Verlassen Sie sich nicht allein auf SIP, um Interpreter-Variablen zu bereinigen: Verwenden Sie eine minimale Umgebung (`env -i`), heben Sie `BASH_ENV` explizit auf, rufen Sie den vorgesehenen Interpreter über seinen absoluten Pfad auf und vermeiden Sie beschreibbare Startup-Dateien.

## zsh `ZDOTDIR`

zsh liest `$ZDOTDIR/.zshenv` für jede normale Shell, einschließlich nicht-interaktiver Shells; wenn `ZDOTDIR` nicht gesetzt ist, verwendet zsh `HOME`. Wird `ZDOTDIR` auf ein beschreibbares Verzeichnis umgeleitet, wird daher dessen `.zshenv` vor einem `zsh -c`-Befehl oder -Skript ausgeführt.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` hebt die Option `RCS` auf und überspringt diese Benutzer-Startdatei. Die globale `/etc/zshenv` wird weiterhin eingelesen und muss daher vertrauenswürdig und minimal bleiben.

## fish `XDG_CONFIG_HOME`

fish liest `$XDG_CONFIG_HOME/fish/conf.d/*.fish` und `$XDG_CONFIG_HOME/fish/config.fish` beim Start jeder Shell ein, nicht nur bei interaktiven Shells oder Login-Shells. Es führt außerdem `fish/vendor_conf.d/*.fish` unterhalb der Einträge in `XDG_DATA_DIRS` aus. Ein Angreifer, der eine dieser Variablen und ein lesbares Verzeichnis kontrolliert, kann daher Code ausführen, bevor ein fish-Skript oder ein `-c`-Befehl ausgeführt wird.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Verwende `fish --no-config` für einen vertrauenswürdigen Aufruf und lösche nicht vertrauenswürdige XDG-Pfadvariablen.

## References

- [1] [Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash aufrufen](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh-Start-/Beendigungsdateien](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish-Konfigurationsdateien](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
