# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Contesto

In Linux, per eseguire un programma, deve esistere come file, deve essere accessibile in qualche modo attraverso la gerarchia del file system (questo è proprio come funziona `execve()`). Questo file può risiedere su disco o in ram (tmpfs, memfd) ma hai bisogno di un percorso. Questo ha reso molto facile controllare cosa viene eseguito su un sistema Linux, rende facile rilevare minacce e strumenti dell'attaccante o prevenire che provino a eseguire qualsiasi cosa di loro (_e. g._ non consentire agli utenti non privilegiati di posizionare file eseguibili ovunque).

Ma questa tecnica è qui per cambiare tutto questo. Se non puoi avviare il processo che desideri... **allora dirotta uno già esistente**.

Questa tecnica ti consente di **bypassare tecniche di protezione comuni come read-only, noexec, whitelisting dei nomi dei file, whitelisting degli hash...**

## Dipendenze

Lo script finale dipende dai seguenti strumenti per funzionare, devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita li troverai ovunque):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## La tecnica

Se sei in grado di modificare arbitrariamente la memoria di un processo, allora puoi prenderne il controllo. Questo può essere utilizzato per dirottare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere questo sia utilizzando la syscall `ptrace()` (che richiede di avere la possibilità di eseguire syscall o di avere gdb disponibile sul sistema) o, più interessantemente, scrivendo in `/proc/$pid/mem`.

Il file `/proc/$pid/mem` è una mappatura uno a uno dell'intero spazio degli indirizzi di un processo (_e. g._ da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Questo significa che leggere o scrivere in questo file a un offset `x` è lo stesso che leggere o modificare i contenuti all'indirizzo virtuale `x`.

Ora, abbiamo quattro problemi di base da affrontare:

- In generale, solo root e il proprietario del programma del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere in un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore I/O.

Questi problemi hanno soluzioni che, sebbene non siano perfette, sono buone:

- La maggior parte degli interpreti di shell consente la creazione di descrittori di file che saranno poi ereditati dai processi figli. Possiamo creare un fd che punta al file `mem` della shell con permessi di scrittura... quindi i processi figli che utilizzano quel fd saranno in grado di modificare la memoria della shell.
- ASLR non è nemmeno un problema, possiamo controllare il file `maps` della shell o qualsiasi altro dal procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
- Quindi dobbiamo `lseek()` sul file. Dalla shell questo non può essere fatto a meno di utilizzare il famigerato `dd`.

### In maggior dettaglio

I passaggi sono relativamente facili e non richiedono alcun tipo di competenza per comprenderli:

- Analizza il binario che vogliamo eseguire e il loader per scoprire quali mappature necessitano. Poi crea un "shell"code che eseguirà, in linea di massima, gli stessi passaggi che il kernel esegue ad ogni chiamata a `execve()`:
- Crea le suddette mappature.
- Leggi i binari in esse.
- Imposta i permessi.
- Infine, inizializza lo stack con gli argomenti per il programma e posiziona il vettore ausiliario (necessario per il loader).
- Salta nel loader e lascia che faccia il resto (carica le librerie necessarie per il programma).
- Ottieni dal file `syscall` l'indirizzo a cui il processo tornerà dopo la syscall che sta eseguendo.
- Sovrascrivi quel luogo, che sarà eseguibile, con il nostro shellcode (attraverso `mem` possiamo modificare pagine non scrivibili).
- Passa il programma che vogliamo eseguire allo stdin del processo (sarà `read()` da detto "shell"code).
- A questo punto spetta al loader caricare le librerie necessarie per il nostro programma e saltare in esso.

**Controlla lo strumento in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Ci sono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito utilizzato per `lseek()` attraverso il file `mem` (che era l'unico scopo per utilizzare `dd`). Queste alternative sono:
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER` puoi cambiare il seeker utilizzato, _e. g._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque usarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Blocca questo, EDRs.

## Riferimenti

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}
