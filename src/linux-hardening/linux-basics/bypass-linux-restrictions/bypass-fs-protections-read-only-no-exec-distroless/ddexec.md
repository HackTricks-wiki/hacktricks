# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contesto

In Linux, per eseguire un programma questo deve esistere come file e deve essere accessibile in qualche modo attraverso la gerarchia del file system (è semplicemente così che funziona `execve()`). Questo file può risiedere su disco o nella RAM (tmpfs, memfd), ma è necessario un filepath. Ciò ha reso molto semplice controllare cosa viene eseguito su un sistema Linux, individuare le minacce e gli strumenti degli attacker oppure impedire loro del tutto di provare a eseguire qualcosa di proprio (_ad es._ non consentire agli utenti non privilegiati di inserire file eseguibili in alcun percorso).

Ma questa tecnica è qui per cambiare tutto ciò. Se non puoi avviare il processo che vuoi... **allora ne fai hijacking di uno già esistente**.

Questa tecnica consente di **bypassare tecniche di protezione comuni come read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dipendenze

Lo script finale dipende dai seguenti strumenti per funzionare; devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita li troverai praticamente ovunque):
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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere utilizzato per dirottare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere questo risultato utilizzando la syscall `ptrace()` (che richiede la possibilità di eseguire syscall o la disponibilità di gdb sul sistema) oppure, in modo più interessante, scrivendo in `/proc/$pid/mem`.

Il file `/proc/$pid/mem` è una mappatura uno-a-uno dell'intero spazio degli indirizzi di un processo (_ad es._ da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Ciò significa che leggere o scrivere in questo file all'offset `x` equivale a leggere o modificare i contenuti all'indirizzo virtuale `x`.

Ora dobbiamo affrontare quattro problemi fondamentali:

- In generale, solo root e il proprietario del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere a un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore di I/O.

Questi problemi hanno delle soluzioni che, sebbene non siano perfette, sono valide:

- La maggior parte degli interpreti di shell consente la creazione di file descriptor che verranno poi ereditati dai processi figli. Possiamo creare un fd che punti al file `mem` della shell con permessi di scrittura... in questo modo, i processi figli che utilizzano quel fd potranno modificare la memoria della shell.
- ASLR non è nemmeno un problema: possiamo controllare il file `maps` della shell o qualsiasi altro file di procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
- Dobbiamo quindi eseguire `lseek()` sul file. Dalla shell questo non è possibile se non utilizzando l'infame `dd`.

### Più in dettaglio

I passaggi sono relativamente semplici e non richiedono alcun tipo di competenza specifica per essere compresi:

- Analizzare il binary che vogliamo eseguire e il loader per scoprire quali mapping richiedono. Quindi creare una "shell"code che esegua, in linea generale, gli stessi passaggi effettuati dal kernel a ogni chiamata a `execve()`:
- Creare tali mapping.
- Leggere i binary al loro interno.
- Impostare i permessi.
- Inizializzare infine lo stack con gli argomenti del programma e inserire il vettore ausiliario (necessario al loader).
- Eseguire un jump verso il loader e lasciare che completi il resto (caricare le librerie necessarie al programma).
- Ottenere dal file `syscall` l'indirizzo a cui il processo tornerà dopo la syscall che sta eseguendo.
- Sovrascrivere quel punto, che sarà eseguibile, con la nostra shellcode (tramite `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà `read()` dalla suddetta "shell"code).
- A questo punto spetta al loader caricare le librerie necessarie al nostro programma ed eseguire un jump verso di esso.

**Dai un'occhiata al tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Esistono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito utilizzato per eseguire `lseek()` attraverso il file `mem` (che era l'unico scopo per cui veniva utilizzato `dd`). Tali alternative sono:
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER` puoi modificare il seeker utilizzato, _ad es._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque utilizzarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloccate questo, EDR.

## Riferimenti

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
