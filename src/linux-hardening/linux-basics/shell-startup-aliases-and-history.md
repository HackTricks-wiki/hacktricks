# Avvio della shell, alias e cronologia

{{#include ../../banners/hacktricks-training.md}}

Un comando della shell può comportarsi diversamente dall'eseguibile con lo stesso nome se un alias, una funzione, un file di avvio o una variabile d'ambiente ne modifica l'esecuzione. Controlla questi elementi prima di fidarti dell'output di un comando o di presumere che uno script usi lo stesso PATH di una sessione interattiva.

## Esaminare la shell corrente

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` mostrano se un nome corrisponde a un alias, una funzione, un builtin o un file. `command -v` e `which` potrebbero non restituire le stesse informazioni per alias e funzioni. La cronologia della shell può esporre comandi o credenziali, ma potrebbe essere incompleta, disabilitata o conservata in memoria fino alla chiusura della sessione.

## Esaminare i file di avvio e della cronologia

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Un file di avvio modificabile da un utente può eseguire comandi al successivo avvio di una shell. Un file di avvio valido per tutto il sistema o il file di avvio di un utente con privilegi è più sensibile se un account con privilegi inferiori può modificarlo. Anche Bash non interattiva può leggere il file indicato da `BASH_ENV`; la pagina sulle [variabili d'ambiente](linux-environment-variables.md#bash_env--env) spiega questo comportamento e altri hook degli interpreti. Prima di indicare un percorso di persistenza, verifica quali file vengono effettivamente letti dalla shell per le sessioni di login, interattive e non interattive.

Esamina anche i file inclusi da un file di avvio globale. Ad esempio, un `source /opt/app/venv/bin/activate` letterale in `/etc/bash.bashrc` esegue il file di attivazione come codice shell quando una shell legge effettivamente quel file di avvio. Esamina il file di attivazione, i permessi dei link simbolici e delle directory parent, nonché le ACL; un utente con privilegi inferiori può influire su una shell con privilegi solo se quella shell, o un'attività privilegiata, include successivamente il file. Se l'accesso in scrittura dipende da `sudoedit`, verifica prima la regola sudoers esatta e il pacchetto sudo installato e modificato dal vendor; il solo numero di versione upstream non dimostra l'[esposizione all'injection di argomenti di sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Controlla cronologia, dotfile e backup per individuare segreti, come descritto in [utenti e sessioni](../user-information/user-and-session-triage.md). Se uno script privilegiato risolve i comandi in base al nome, combina questa analisi con le [indicazioni sull'hijacking di PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
