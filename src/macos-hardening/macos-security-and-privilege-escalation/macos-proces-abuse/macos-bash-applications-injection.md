# Injection in Shell Applications on macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Quando Bash si avvia in modalità non interattiva per eseguire uno script o un comando `-c`, espande il valore di `BASH_ENV` e fa il source del file risultante prima di eseguire il comando richiesto. Bash non utilizza `PATH` per trovare questo file. Di conseguenza, un processo che avvia Bash non interattivo con variabili d'ambiente controllate dall'attaccante può essere indotto a eseguire prima un payload shell leggibile.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
L'hook viene eseguito solo quando il target avvia effettivamente Bash; `/bin/sh` su un'altra piattaforma o un programma che esegue un comando senza una shell non lo onorerà necessariamente. Bash in modalità privilegiata ignora `BASH_ENV`. Quando gli ID effettivo e reale dell'utente o del gruppo differiscono, Bash ignora inoltre i file di avvio e reimposta gli ID effettivi, a meno che non venga fornito `-p`; con `-p`, la modalità privilegiata rimane abilitata e `BASH_ENV` viene comunque ignorato.<sup>[[1]](#references)[[2]](#references)</sup>

Su macOS, i job `launchd` possono definire variabili d'ambiente ereditate o specifiche per job, quindi controlla i plist e i contesti di avvio che alimentano gli script privilegiati. Non fare affidamento solo su SIP per sanificare le variabili dell'interprete: usa un ambiente minimale (`env -i`), annulla esplicitamente `BASH_ENV`, invoca l'interprete previsto tramite percorso assoluto ed evita file di avvio scrivibili.

## zsh `ZDOTDIR`

zsh legge `$ZDOTDIR/.zshenv` per ogni shell normale, comprese le shell non interattive; se `ZDOTDIR` non è impostata, utilizza `HOME`. Reindirizzare `ZDOTDIR` a una directory scrivibile esegue quindi il relativo `.zshenv` prima di un comando o script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` disabilita l'opzione `RCS` e salta questo file di avvio dell'utente. Il file globale `/etc/zshenv` viene comunque letto, quindi deve rimanere affidabile e minimale.

## fish `XDG_CONFIG_HOME`

fish legge `$XDG_CONFIG_HOME/fish/conf.d/*.fish` e `$XDG_CONFIG_HOME/fish/config.fish` all'avvio di ogni shell, non solo delle shell interattive o di login. Esegue inoltre `fish/vendor_conf.d/*.fish` nelle directory elencate in `XDG_DATA_DIRS`. Un attacker che controlla una di queste variabili e una directory leggibile può quindi eseguire codice prima di uno script fish o di un comando `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Usa `fish --no-config` per un'invocazione attendibile e cancella le variabili di percorso XDG non attendibili.

## bash `PS4` + xtrace (`SHELLOPTS`)

Quando Bash viene eseguito con l'opzione **xtrace**, prima di ogni comando tracciato espande `PS4` e lo stampa. `PS4` viene espanso come qualsiasi prompt, quindi al suo interno viene eseguita una **command substitution**. Sia il valore di `PS4` **sia** il modo in cui xtrace viene abilitato possono provenire interamente dall'ambiente: esportare `SHELLOPTS=xtrace` abilita xtrace per un normale `bash script.sh` (senza bisogno del flag `-x`). Questo trasforma qualsiasi script Bash eseguito dalla vittima in code execution.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` da solo non fa nulla finché xtrace non viene abilitato (tramite `SHELLOPTS=xtrace`, `set -x` o `bash -x`). Bash ignora `SHELLOPTS` in **privileged mode** (ID reali/effettivi diversi senza la gestione di `-p`), quindi si applicano le stesse limitazioni setuid di `BASH_ENV`.

## POSIX `ENV`

Le shell in stile POSIX (`/bin/sh`, `dash`, `ksh`) leggono la variabile `ENV`, la espandono ed eseguono in modalità source il file risultante quando avviano una shell **interattiva**. È la controparte POSIX di `BASH_ENV` (che si attiva per Bash *non interattiva*), quindi il controllo di `ENV` esegue codice ogni volta che una vittima avvia una `sh`/`dash` interattiva.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocazione di Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [File di avvio/arresto di zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [File di configurazione di fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Variabili di Bash — `PS4` e il builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
