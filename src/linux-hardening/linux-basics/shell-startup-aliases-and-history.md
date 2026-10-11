# Avvio della shell, alias e cronologia

{{#include ../../banners/hacktricks-training.md}}

Un comando della shell può comportarsi diversamente dall'eseguibile con lo stesso nome se un alias, una funzione, un file di avvio o una variabile d'ambiente ne modifica l'esecuzione. Verifica questi elementi prima di fidarti dell'output di un comando o di presumere che uno script usi lo stesso PATH di una sessione interattiva.

## Esamina la shell corrente

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` rivelano se un nome corrisponde a un alias, una funzione, un builtin o un file. `command -v` e `which` potrebbero non restituire lo stesso risultato per alias e funzioni. La cronologia della shell può esporre comandi o credenziali, ma potrebbe essere incompleta, disabilitata o conservata in memoria fino alla chiusura della sessione.

## Esamina i file di avvio e della cronologia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un file di avvio scrivibile da un utente può eseguire comandi al successivo avvio di una shell. Un file di avvio valido per tutto il sistema o appartenente a un utente privilegiato è più sensibile se un account con privilegi inferiori può modificarlo. Bash non interattiva può anche leggere il file indicato da `BASH_ENV`; la pagina sulle [variabili d'ambiente](linux-environment-variables.md#bash_env--env) spiega questo comportamento e altri hook degli interpreti. Verifica quali file legge effettivamente la shell per le sessioni di login, interattive e non interattive prima di affermare che un percorso consente la persistenza.

Esamina anche i file richiamati da un file di avvio globale. Per esempio, un `source /opt/app/venv/bin/activate` letterale in `/etc/bash.bashrc` esegue il file di attivazione come codice shell quando una shell legge effettivamente quel file di avvio. Esamina il file di attivazione, i permessi dei collegamenti simbolici e delle directory genitrici, e le ACL; un utente con privilegi inferiori può influire su una shell privilegiata solo se quella shell o un'attività privilegiata lo richiama in seguito. Se l'accesso in scrittura dipende da `sudoedit`, verifica prima la regola sudoers esatta e il pacchetto sudo installato, con le patch del vendor; una stringa di versione upstream, da sola, non dimostra l'esposizione a [injection degli argomenti di sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Controlla la cronologia, i dotfile e i backup per individuare eventuali segreti, come descritto in [utenti e sessioni](../user-information/user-and-session-triage.md). Se uno script privilegiato risolve i comandi tramite nome, integra questa verifica con le [indicazioni sull'hijacking di PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
