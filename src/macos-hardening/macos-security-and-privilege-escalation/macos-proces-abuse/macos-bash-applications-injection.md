# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Quando Bash si avvia in modalità non interattiva per eseguire uno script o un comando `-c`, espande il valore di `BASH_ENV` e carica il file risultante prima di eseguire il comando richiesto. Bash non usa `PATH` per trovare questo file. Un processo che avvia Bash non interattivo con variabili d'ambiente controllate dall'attaccante può quindi essere indotto a eseguire prima un payload shell leggibile.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
L'hook viene eseguito solo quando il target avvia effettivamente Bash; `/bin/sh` su un'altra piattaforma o un programma che esegue un comando senza una shell non lo onorerà necessariamente. Bash in modalità privilegiata ignora `BASH_ENV`. Quando gli ID utente/gruppo effettivi e reali differiscono, Bash salta inoltre i file di avvio e reimposta gli ID effettivi, a meno che non venga fornito `-p`; con `-p`, la modalità privilegiata rimane abilitata e `BASH_ENV` continua a essere ignorato.<sup>[[1]](#references)[[2]](#references)</sup>

Su macOS, i job di `launchd` possono definire variabili d'ambiente ereditate o specifiche per ciascun job; pertanto, esamina i plist e i contesti di avvio che alimentano gli script privilegiati. Non fare affidamento solo su SIP per sanificare le variabili dell'interprete: usa un ambiente minimale (`env -i`), annulla esplicitamente `BASH_ENV`, invoca l'interprete previsto tramite il percorso assoluto ed evita file di avvio scrivibili.

## zsh `ZDOTDIR`

zsh legge `$ZDOTDIR/.zshenv` per ogni shell normale, incluse le shell non interattive; se `ZDOTDIR` non è impostata, usa `HOME`. Reindirizzare quindi `ZDOTDIR` a una directory scrivibile esegue il relativo `.zshenv` prima di un comando o script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` disattiva l'opzione `RCS` e salta questo file di avvio dell'utente. Il file globale `/etc/zshenv` viene comunque letto, quindi deve rimanere affidabile e minimale.

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
Usa `fish --no-config` per un'invocazione affidabile e cancella le variabili di percorso XDG non attendibili.

## References

- [1] [File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocazione di Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [File di avvio/arresto di zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [File di configurazione di fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
