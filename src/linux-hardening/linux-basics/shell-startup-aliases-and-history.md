# Avvio della shell, alias e cronologia

{{#include ../../banners/hacktricks-training.md}}

Un comando della shell può comportarsi diversamente dall'eseguibile con lo stesso nome se un alias, una funzione, un file di avvio o una variabile d'ambiente ne modifica l'esecuzione. Verifica questi elementi prima di fidarti dell'output di un comando o di presumere che uno script usi lo stesso PATH di una sessione interattiva.

## Ispezionare la shell corrente

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` rivelano se un nome corrisponde a un alias, una funzione, un builtin o un file. `command -v` e `which` potrebbero non fornire le stesse informazioni per alias e funzioni. La cronologia della shell può esporre comandi o credenziali, ma potrebbe essere incompleta, disabilitata o conservata in memoria fino alla chiusura della sessione.

## Esamina i file di avvio e della cronologia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un file di avvio scrivibile dall'utente può eseguire comandi al successivo avvio della shell. Un file di avvio a livello di sistema o quello di un utente privilegiato è più sensibile se può essere modificato da un account con privilegi inferiori. Anche Bash non interattiva può leggere il file indicato da `BASH_ENV`; la pagina sulle [variabili d'ambiente](linux-environment-variables.md#bash_env--env) spiega questo comportamento e altri hook degli interpreti. Verifica quali file legge effettivamente la shell per le sessioni di login, interattive e non interattive prima di dichiarare un percorso di persistenza.

Esamina anche i file inclusi da un file di avvio globale. Ad esempio, un `source /opt/app/venv/bin/activate` letterale in `/etc/bash.bashrc` esegue il file di attivazione come codice shell quando una shell legge effettivamente quel file di avvio. Controlla il file di attivazione, i permessi del symlink e delle directory genitrici, nonché gli ACL; un utente con privilegi inferiori può influire su una shell privilegiata solo se quella shell o un'attività privilegiata lo include in seguito. Se l'accesso in scrittura dipende da `sudoedit`, verifica prima la regola sudoers esatta e il pacchetto sudo installato e aggiornato dal vendor; una stringa di versione upstream, da sola, non dimostra l'[esposizione a injection degli argomenti di sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Controlla la cronologia, i dotfile e i backup alla ricerca di segreti, come descritto in [utenti e sessioni](../user-information/user-and-session-triage.md). Se uno script privilegiato risolve i comandi usando il nome, abbina questa verifica alle [indicazioni sul PATH hijacking](linux-environment-variables.md#path).

## Reindirizzamento degli avvii di Zsh e file compilati

Con le impostazioni `RCS` predefinite, zsh legge `$ZDOTDIR/.zshenv` prima delle normali invocazioni, incluse `zsh -c` e gli script; se `ZDOTDIR` non è impostata, usa `$HOME`. Se un command runner accetta una mappa dell'ambiente, verifica se passa una di queste variabili a un processo zsh privilegiato. Un `.zshenv` scrivibile può quindi essere eseguito **prima** del corpo del comando che il runner verifica o inserisce nella allowlist. Ciò richiede che il processo privilegiato erediti la directory reindirizzata; `zsh -f` ignora i file di avvio dell'utente, ma non il file globale `zshenv` (spesso `/etc/zshenv`, ma i percorsi variano a seconda della distribuzione). La [pagina sull'injection di zsh in macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) contiene un esempio minimo con `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Un `.zshenv.zwc` o `.zshrc.zwc` valido e più recente viene eseguito al posto del corrispondente file di avvio in testo semplice. Se puoi scrivere nella directory di avvio, compilare un file modificato e poi ripristinare un file di testo dall'aspetto innocuo può lasciare codice eseguibile nella copia compilata. È offuscamento, non crittografia. Il test temporaneo qui sotto mostra perché ispezionare solo il file di testo non è sufficiente; non tocca una directory home reale.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Per un target reale, determina i valori effettivi di `ZDOTDIR`/`HOME`, esamina sia i file di testo sia quelli `.zwc` e controlla timestamp, proprietà e directory padre scrivibili. Un file `.zwc` deve corrispondere al file sorgente ed essere più recente per avere la precedenza.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [File di avvio e chiusura di Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Avviso sull’iniezione nell’ambiente di avvio della shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Comandi integrati della shell Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Il file .zshrc.zwc che hai dimenticato di controllare](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
