# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contesto

In Linux, per eseguire un programma questo deve esistere come file e deve essere accessibile in qualche modo attraverso la gerarchia del file system (è semplicemente il funzionamento di `execve()`). Questo file può risiedere sul disco o nella RAM (tmpfs, memfd), ma è necessario un filepath. Questo ha reso molto semplice controllare ciò che viene eseguito su un sistema Linux, rilevare le minacce e gli strumenti degli attacker oppure impedire loro del tutto di provare a eseguire qualcosa di loro (_ad es._ non consentendo agli utenti non privilegiati di inserire file eseguibili in alcun punto).

Ma questa tecnica serve a cambiare tutto questo. Se non puoi avviare il processo che vuoi... **allora hijacka uno già esistente**.

Questa tecnica consente di **bypassare tecniche di protezione comuni come read-only, noexec, file-name whitelisting e hash whitelisting**.<sup>[[1]](#references)</sup>

## Dipendenze

Lo script finale dipende dai seguenti tools per funzionare; devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita li troverai praticamente ovunque):
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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere usato per hijackare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere questo risultato usando la syscall `ptrace()` (che richiede la capacità di eseguire syscall o la presenza di gdb nel sistema) oppure, cosa più interessante, scrivendo su `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Il file `/proc/$pid/mem` è una mappatura uno-a-uno dell'intero address space di un processo (_es._ da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Ciò significa che leggere da questo file o scrivervi a un offset `x` equivale rispettivamente a leggere o modificare il contenuto all'indirizzo virtuale `x`.

Ora dobbiamo affrontare quattro problemi fondamentali:

- In generale, solo root e il proprietario del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere a un indirizzo non mappato nell'address space del programma, otterremo un errore di I/O.

Questi problemi hanno soluzioni che, sebbene non siano perfette, sono valide:

- La maggior parte degli interpreti shell consente di creare file descriptor che verranno poi ereditati dai processi figli. Possiamo creare un fd che punti al file `mem` della shell con permessi di scrittura... quindi i processi figli che usano quell'fd potranno modificare la memoria della shell.
- ASLR non è nemmeno un problema: possiamo controllare il file `maps` della shell o qualsiasi altro file dal procfs per ottenere informazioni sull'address space del processo.
- Dobbiamo quindi eseguire `lseek()` sul file. Dalla shell questo non è possibile, a meno di usare l'infame `dd`.

### Più in dettaglio

I passaggi sono relativamente semplici e non richiedono alcun tipo di competenza specifica per essere compresi:<sup>[[1]](#references)</sup>

- Analizzare il binary che vogliamo eseguire e il loader per scoprire quali mapping richiedono. Poi creare uno "shell"code che esegua, in linea generale, gli stessi passaggi che il kernel esegue a ogni chiamata a `execve()`:
- Creare tali mapping.
- Leggere i binary al loro interno.
- Configurare i permessi.
- Infine inizializzare lo stack con gli argomenti del programma e inserire l'auxiliary vector (necessario al loader).
- Saltare nel loader e lasciargli eseguire il resto (caricare le librerie necessarie al programma).
- Ottenere dal file `syscall` l'indirizzo al quale il processo ritornerà dopo la syscall che sta eseguendo.
- Sovrascrivere quel punto, che sarà eseguibile, con il nostro shellcode (tramite `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà `read()` dal suddetto "shell"code).
- A questo punto spetta al loader caricare le librerie necessarie al nostro programma e saltare al suo interno.

**Dai un'occhiata al tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Esistono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito usato per eseguire `lseek()` attraverso il file `mem` (che era l'unico scopo dell'uso di `dd`). Tali alternative sono:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER`, puoi modificare il seeker utilizzato, _ad es._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque usarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloccate questo, EDR.

## References

- [1] [DDexec: Una tecnica per eseguire file binari fileless e furtivamente su Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
