# Avvio della shell, alias e cronologia

{{#include ../../banners/hacktricks-training.md}}

Un comando della shell può comportarsi diversamente dall’eseguibile con lo stesso nome se un alias, una funzione, un file di avvio o una variabile d’ambiente ne modifica il funzionamento. Verifica questi elementi prima di fidarti dell’output di un comando o di presumere che uno script utilizzi lo stesso PATH di una sessione interattiva.

## Esamina la shell corrente

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` rivelano se un nome corrisponde a un alias, una funzione, un builtin o un file. `command -v` e `which` potrebbero non restituire le stesse informazioni per alias e funzioni. La cronologia della shell può esporre comandi o credenziali, ma potrebbe essere incompleta, disabilitata o conservata in memoria fino alla chiusura della sessione.

Un `.bashrc` modificato può definire un alias `sudo` che imita una richiesta di password, registra la risposta e la passa al comando reale. Questo può nascondere l'intercettazione delle credenziali senza modificare l'eseguibile `sudo` o `PATH`.<sup>[[5]](#references)</sup> La shell deve leggere il file di avvio modificato ed espandere l'alias.<sup>[[7]](#references)</sup> Per impostazione predefinita, Bash non interattiva non espande gli alias, a meno che non sia abilitata l'opzione `expand_aliases`.<sup>[[6]](#references)</sup>

## Esaminare i file di avvio e della cronologia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un file di avvio modificabile da un utente può eseguire comandi al successivo avvio di una shell. Un file di avvio valido per l'intero sistema o il file di avvio di un utente con privilegi è più sensibile se un account con privilegi inferiori può modificarlo. Anche Bash non interattiva può leggere il file indicato da `BASH_ENV`; la pagina sulle [variabili d'ambiente](linux-environment-variables.md#bash_env--env) spiega questo comportamento e altri hook degli interpreti. Prima di affermare che esiste un percorso di persistenza, verifica quali file vengono letti dalla shell effettiva nelle sessioni di login, interattive e non interattive.

Esamina anche i file inclusi da un file di avvio globale. Per esempio, un `source /opt/app/venv/bin/activate` letterale in `/etc/bash.bashrc` esegue il file di attivazione come codice shell quando una shell legge effettivamente quel file di avvio. Esamina il file di attivazione, i permessi del symlink e della directory padre e le ACL; un utente con privilegi inferiori può influire su una shell con privilegi solo se quella shell o un'attività con privilegi lo include successivamente. Se l'accesso in scrittura dipende da `sudoedit`, verifica prima la regola esatta di sudoers e il pacchetto sudo installato con le patch del fornitore; il solo numero di versione upstream non dimostra l'[esposizione all'injection degli argomenti di sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Controlla la cronologia, i file dot e i backup per individuare segreti, come descritto in [utenti e sessioni](../user-information/user-and-session-triage.md). Se uno script con privilegi risolve i comandi in base al nome, integra questa verifica con le [indicazioni sul dirottamento di PATH](linux-environment-variables.md#path).

## Reindirizzamento dell'avvio di Zsh e file compilati

Con le impostazioni predefinite di `RCS`, zsh legge `$ZDOTDIR/.zshenv` prima delle normali esecuzioni, incluse `zsh -c` e gli script; se `ZDOTDIR` non è impostata, usa `$HOME`. Quando un esecutore di comandi accetta una mappa di ambiente, verifica se inoltra una di queste variabili a un processo zsh con privilegi. Un `.zshenv` scrivibile può quindi essere eseguito **prima** del corpo del comando verificato o inserito nell'allowlist dall'esecutore. Ciò richiede che il processo con privilegi erediti la directory reindirizzata; `zsh -f` salta i file di avvio dell'utente, ma non il file globale `zshenv` (spesso `/etc/zshenv`, ma i percorsi variano a seconda della distribuzione). La [pagina sull'injection di zsh in macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) include un esempio minimo di `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Un `.zshenv.zwc` o `.zshrc.zwc` valido e più recente viene eseguito al posto del corrispondente file di avvio in testo semplice. Se puoi scrivere nella directory di avvio, compilare un file modificato e poi ripristinare un file di testo dall'aspetto innocuo può lasciare codice eseguibile nella copia compilata. È una forma di offuscamento, non di cifratura. Il test temporaneo riportato di seguito mostra perché non basta esaminare solo il file di testo; non interviene su una vera directory home.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

Per un target reale, determina il suo `ZDOTDIR`/`HOME` effettivo, esamina sia i file di testo sia quelli `.zwc` e controlla timestamp, proprietà e directory genitrici scrivibili. Un file `.zwc` deve corrispondere al file sorgente ed essere più recente per avere la precedenza.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [File di avvio e chiusura di Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Avviso sull'iniezione nell'ambiente di avvio della shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Comandi integrati della shell Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Il file .zshrc.zwc che hai dimenticato di controllare](https://dfir.ch/posts/compiled_zsh/)
- [5] [Campagna di spionaggio basata sull'IA prende di mira le infrastrutture Linux governative](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Manuale di Bash: alias](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Manuale di Bash: file di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
