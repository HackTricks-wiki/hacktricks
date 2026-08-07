# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contesto

In Linux, per eseguire un programma questo deve esistere come file e deve essere accessibile in qualche modo attraverso la gerarchia del file system (è semplicemente il funzionamento di `execve()`). Questo file può trovarsi su disco o nella RAM (tmpfs, memfd), ma è necessario un filepath. Ciò ha reso molto semplice controllare cosa viene eseguito su un sistema Linux, rilevare le minacce e gli strumenti dell'attacker oppure impedire del tutto che questi provi a eseguire qualcosa di suo (_ad es._ non consentendo agli utenti non privilegiati di posizionare file eseguibili in alcun punto).

Ma questa tecnica serve a cambiare tutto ciò. Se non puoi avviare il processo che vuoi... **allora fai hijack di uno già esistente**.

Questa tecnica consente di **bypassare tecniche di protezione comuni come read-only, noexec, file-name whitelisting, hash whitelisting...**<sup>[[1]](#references)</sup>

## Dipendenze

Lo script finale dipende dai seguenti tool per funzionare; devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita li troverai ovunque):
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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere usato per hijackare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere questo risultato usando la syscall `ptrace()` (che richiede la possibilità di eseguire syscall o la presenza di gdb sul sistema) oppure, cosa più interessante, scrivendo in `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Il file `/proc/$pid/mem` è una mappatura uno-a-uno dell'intero address space di un processo (_e. g._ da `0x0000000000000000` a `0x7ffffffffffff000` su x86-64). Ciò significa che leggere o scrivere in questo file a un offset `x` equivale a leggere o modificare il contenuto del virtual address `x`.

Ora dobbiamo affrontare quattro problemi di base:

- In generale, solo root e il program owner del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere a un address non mappato nell'address space del programma, otterremo un errore di I/O.

Questi problemi hanno delle soluzioni che, sebbene non siano perfette, sono efficaci:

- La maggior parte degli interpreti di shell consente la creazione di file descriptor che verranno poi ereditati dai child process. Possiamo creare un fd che punti al file `mem` della shell con permessi di scrittura... quindi i child process che usano quell'fd potranno modificare la memoria della shell.
- ASLR non è nemmeno un problema: possiamo controllare il file `maps` della shell o qualsiasi altro file dal procfs per ottenere informazioni sull'address space del processo.
- Quindi dobbiamo eseguire `lseek()` sul file. Dalla shell questo non può essere fatto se non usando l'infamous `dd`.

### Più in dettaglio

I passaggi sono relativamente semplici e non richiedono alcun tipo di expertise per essere compresi:<sup>[[1]](#references)</sup>

- Analizzare il binary che vogliamo eseguire e il loader per scoprire quali mapping richiedono. Quindi creare una "shell"code che esegua, in termini generali, gli stessi passaggi effettuati dal kernel a ogni chiamata a `execve()`:
- Creare i mapping indicati.
- Leggere i binary al loro interno.
- Configurare i permessi.
- Infine inizializzare lo stack con gli argomenti del programma e posizionare l'auxiliary vector (necessario al loader).
- Eseguire un jump nel loader e lasciargli fare il resto (caricare le library necessarie al programma).
- Ottenere dal file `syscall` l'address al quale il processo tornerà dopo la syscall che sta eseguendo.
- Sovrascrivere quel punto, che sarà executable, con la nostra shellcode (tramite `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà `read()` dalla suddetta "shell"code).
- A questo punto spetta al loader caricare le library necessarie al nostro programma ed eseguire un jump al suo interno.

**Consulta il tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

Esistono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito usato per eseguire `lseek()` attraverso il file `mem` (che era l'unico scopo dell'uso di `dd`). Tali alternative sono:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER`, puoi cambiare il seeker utilizzato, _ad es._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque utilizzarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloccate questo, EDR.

## Riferimenti

- [1] [DDexec: A technique to run binaries filelessly and stealthily on Linux](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
