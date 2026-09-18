# Injection in macOS-Shell-Anwendungen

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Wenn Bash nicht interaktiv gestartet wird, um ein Skript oder einen `-c`-Befehl auszuführen, erweitert es den Wert von `BASH_ENV` und lädt die resultierende Datei, bevor der angeforderte Befehl ausgeführt wird. Bash verwendet `PATH` nicht, um diese Datei zu finden. Ein Prozess, der eine nicht interaktive Bash mit vom Angreifer kontrollierten Umgebungsvariablen startet, kann daher dazu gebracht werden, zuerst eine lesbare Shell-Payload auszuführen.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Der Hook wird nur ausgeführt, wenn das Ziel tatsächlich Bash startet; `/bin/sh` auf einer anderen Plattform oder ein Programm, das einen Befehl ohne eine Shell ausführt, wird ihn nicht unbedingt berücksichtigen. Bash ignoriert `BASH_ENV` im privileged mode. Wenn sich die effektiven und tatsächlichen Benutzer-/Gruppen-IDs unterscheiden, überspringt Bash ebenfalls die startup files und setzt die effektiven IDs zurück, sofern nicht `-p` angegeben wird; mit `-p` bleibt der privileged mode aktiviert und `BASH_ENV` wird weiterhin ignoriert.<sup>[[1]](#references)[[2]](#references)</sup>

Auf macOS können `launchd`-Jobs vererbte oder jobspezifische Umgebungsvariablen definieren. Untersuchen Sie daher Plists und launch contexts, die privileged scripts versorgen. Verlassen Sie sich nicht allein auf SIP, um Interpretervariablen zu bereinigen: Verwenden Sie eine minimale Umgebung (`env -i`), heben Sie `BASH_ENV` ausdrücklich auf, rufen Sie den vorgesehenen Interpreter über einen absoluten Pfad auf und vermeiden Sie beschreibbare startup files.

## zsh `ZDOTDIR`

zsh liest für jede normale Shell, einschließlich nicht interaktiver Shells, `$ZDOTDIR/.zshenv`; wenn `ZDOTDIR` nicht gesetzt ist, verwendet zsh `HOME`. Wird `ZDOTDIR` auf ein beschreibbares Verzeichnis umgeleitet, wird dessen `.zshenv` daher vor einem `zsh -c`-Befehl oder -Skript ausgeführt.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` hebt die Option `RCS` auf und überspringt diese Benutzer-Startdatei. Die globale `/etc/zshenv` wird weiterhin eingelesen und muss daher vertrauenswürdig und minimal bleiben.

## fish `XDG_CONFIG_HOME`

fish liest `$XDG_CONFIG_HOME/fish/conf.d/*.fish` und `$XDG_CONFIG_HOME/fish/config.fish` beim Start jeder Shell ein, nicht nur bei interaktiven oder Login-Shells. Außerdem führt es `fish/vendor_conf.d/*.fish` unterhalb der Einträge in `XDG_DATA_DIRS` aus. Ein Angreifer, der eine dieser Variablen und ein lesbares Verzeichnis kontrolliert, kann daher Code ausführen, bevor ein fish-Skript oder ein `-c`-Befehl ausgeführt wird.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Verwende `fish --no-config` für eine vertrauenswürdige Ausführung und lösche nicht vertrauenswürdige XDG-Pfadvariablen.

## bash `PS4` + xtrace (`SHELLOPTS`)

Wenn Bash mit der Option **xtrace** ausgeführt wird, erweitert es `PS4` vor jedem aufgezeichneten Befehl und gibt es aus. `PS4` wird wie jeder Prompt erweitert, daher wird eine darin enthaltene **command substitution** ausgeführt. Sowohl der Wert von `PS4` **als auch die Aktivierung von xtrace** können vollständig aus der Umgebung stammen: Durch den Export von `SHELLOPTS=xtrace` wird xtrace für ein normales `bash script.sh` aktiviert (ohne dass ein `-x`-Flag erforderlich ist). Dadurch wird jedes Bash-Skript, das das Opfer ausführt, zu Code execution.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` allein bewirkt nichts, bis xtrace aktiviert wird (über `SHELLOPTS=xtrace`, `set -x` oder `bash -x`). Bash ignoriert `SHELLOPTS` im **privileged mode** (unterschiedliche reale/effektive IDs ohne `-p`-Verarbeitung), daher gelten dieselben setuid-Einschränkungen wie für `BASH_ENV`.

## POSIX `ENV`

Die POSIX-Shells (`/bin/sh`, `dash`, `ksh`) lesen die Variable `ENV`, expandieren sie und sourcen die resultierende Datei, wenn sie eine **interaktive** Shell starten. Sie ist das POSIX-Gegenstück zu `BASH_ENV` (das bei *nicht interaktivem* Bash greift). Die Kontrolle über `ENV` führt daher Code aus, wann immer ein Opfer eine interaktive `sh`/`dash` startet.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash aufrufen](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh-Start-/Beendigungsdateien](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish-Konfigurationsdateien](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash-Variablen — `PS4` und das Set-Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
