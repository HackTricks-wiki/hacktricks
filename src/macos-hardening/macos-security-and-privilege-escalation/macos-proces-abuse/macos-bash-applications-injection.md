# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Wanneer Bash nie-interaktief begin om ’n script of `-c`-opdrag uit te voer, brei dit die waarde van `BASH_ENV` uit en source dit die gevolglike lêer voordat dit die aangevraagde opdrag uitvoer. Bash gebruik nie `PATH` om hierdie lêer te vind nie. ’n Proses wat nie-interaktiewe Bash met aanvaller-beheerde omgewingsveranderlikes begin, kan dus gedwing word om eers ’n leesbare shell payload uit te voer.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Die hook loop slegs wanneer die teiken werklik Bash begin; `/bin/sh` op ’n ander platform of ’n program wat ’n command sonder ’n shell uitvoer, sal dit nie noodwendig respekteer nie. Bash in privileged mode ignoreer `BASH_ENV`. Wanneer die effective en real user/group IDs verskil, slaan Bash ook startup files oor en stel dit die effective IDs terug, tensy `-p` verskaf word; met `-p` bly privileged mode geaktiveer en word `BASH_ENV` steeds geïgnoreer.<sup>[[1]](#references)[[2]](#references)</sup>

Op macOS kan `launchd`-jobs geërfde of per-job environment variables definieer; ondersoek dus plists en launch contexts wat privileged scripts voed. Moenie slegs op SIP staatmaak om interpreter variables te sanitiseer nie: gebruik ’n minimale environment (`env -i`), unset `BASH_ENV` eksplisiet, roep die bedoelde interpreter met sy absolute path aan, en vermy writable startup files.

## zsh `ZDOTDIR`

zsh lees `$ZDOTDIR/.zshenv` vir elke normale shell, insluitend non-interactive shells; as `ZDOTDIR` unset is, gebruik dit `HOME`. Deur `ZDOTDIR` na ’n writable directory te herlei, word sy `.zshenv` dus uitgevoer voordat ’n `zsh -c` command of script loop.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` stel die `RCS`-opsie terug en slaan hierdie gebruiker se startup-lêer oor. Die globale `/etc/zshenv` word steeds gelees, dus moet dit vertrouenswaardig en minimaal bly.

## fish `XDG_CONFIG_HOME`

fish lees `$XDG_CONFIG_HOME/fish/conf.d/*.fish` en `$XDG_CONFIG_HOME/fish/config.fish` wanneer elke shell begin, nie net interaktiewe of login shells nie. Dit voer ook `fish/vendor_conf.d/*.fish` uit onder inskrywings in `XDG_DATA_DIRS`. ’n Aanvaller wat een van hierdie veranderlikes en ’n leesbare gids beheer, kan dus kode uitvoer voordat ’n fish script of `-c`-opdrag uitgevoer word.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Gebruik `fish --no-config` vir 'n trusted invocation en verwyder onbetroubare XDG-padveranderlikes.

## bash `PS4` + xtrace (`SHELLOPTS`)

Wanneer Bash met die **xtrace**-opsie loop, brei dit `PS4` voor elke traced command uit en druk dit. `PS4` word soos enige prompt uitgebrei, dus word 'n **command substitution** daarin uitgevoer. Beide die waarde van `PS4` **en** die manier waarop xtrace geaktiveer word, kan uitsluitlik uit die environment kom: deur `SHELLOPTS=xtrace` te exporteer, word xtrace vir 'n normale `bash script.sh` aangeskakel (geen `-x`-flag nodig nie). Dit verander enige Bash-script wat die slagoffer uitvoer in code execution.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` alleen doen niks totdat xtrace geaktiveer is (via `SHELLOPTS=xtrace`, `set -x`, of `bash -x`). Bash ignoreer `SHELLOPTS` in **privileged mode** (verskillende werklike/effektiewe ID's sonder `-p`-hantering), dus geld dieselfde setuid-waarskuwings as vir `BASH_ENV`.

## POSIX `ENV`

Die POSIX-styl shells (`/bin/sh`, `dash`, `ksh`) lees die `ENV`-veranderlike, evalueer dit en source die gevolglike lêer wanneer hulle ’n **interaktiewe** shell begin. Dit is die POSIX-eweknie van `BASH_ENV` (wat vir *nie-interaktiewe* Bash geaktiveer word), dus voer beheer oor `ENV` code uit wanneer ’n slagoffer ’n interaktiewe `sh`/`dash` begin.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash Opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash se Aanroep van Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Opstart-/Afsluitlêers](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Konfigurasielêers](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash-veranderlikes — `PS4` en die Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
