# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Wanneer Bash nie-interaktief begin word om 'n script of `-c`-opdrag uit te voer, brei dit die waarde van `BASH_ENV` uit en laai die gevolglike lêer in voordat dit die aangevraagde opdrag uitvoer. Bash gebruik nie `PATH` om hierdie lêer te vind nie. 'n Proses wat nie-interaktiewe Bash met aanvaller-beheerde omgewingsveranderlikes begin, kan dus gedwing word om eers 'n leesbare shell-payload uit te voer.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Die hook word slegs uitgevoer wanneer die target werklik Bash start; `/bin/sh` op ’n ander platform, of ’n program wat ’n command sonder ’n shell uitvoer, sal dit nie noodwendig respekteer nie. Bash in privileged mode ignoreer `BASH_ENV`. Wanneer die effective en real user/group IDs verskil, slaan Bash ook startup files oor en herstel dit die effective IDs, tensy `-p` verskaf word; met `-p` bly privileged mode enabled en word `BASH_ENV` steeds geïgnoreer.<sup>[[1]](#references)[[2]](#references)</sup>

Op macOS kan `launchd` jobs inherited of per-job environment variables definieer, dus moet jy plists en launch contexts ondersoek wat privileged scripts voorsien. Moenie slegs op SIP staatmaak om interpreter variables te sanitize nie: gebruik ’n minimal environment (`env -i`), unset `BASH_ENV` explicitly, invoke die bedoelde interpreter met ’n absolute path, en vermy writable startup files.

## zsh `ZDOTDIR`

zsh lees `$ZDOTDIR/.zshenv` vir elke normale shell, insluitend non-interactive shells; indien `ZDOTDIR` unset is, gebruik dit `HOME`. Deur `ZDOTDIR` na ’n writable directory te redirect, word die `.zshenv` daarvan dus uitgevoer voordat ’n `zsh -c` command of script uitgevoer word.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` deaktiveer die `RCS`-opsie en slaan hierdie gebruiker se startup-lêer oor. Die globale `/etc/zshenv` word steeds gelees, dus moet dit vertrouenswaardig en minimaal bly.

## fish `XDG_CONFIG_HOME`

fish lees `$XDG_CONFIG_HOME/fish/conf.d/*.fish` en `$XDG_CONFIG_HOME/fish/config.fish` tydens die startup van elke shell, nie net interaktiewe of login shells nie. Dit voer ook `fish/vendor_conf.d/*.fish` uit onder die inskrywings in `XDG_DATA_DIRS`. ’n Aanvaller wat een van hierdie veranderlikes en ’n leesbare gids beheer, kan dus kode laat loop voordat ’n fish-script of `-c`-command uitgevoer word.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Gebruik `fish --no-config` vir 'n vertroude invocation en verwyder onbetroubare XDG-padveranderlikes.

## References

- [1] [Bash-opstartlêers](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash: Bash aanroep](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh-opstart-/afsluitlêers](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish-konfigurasielêers](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
