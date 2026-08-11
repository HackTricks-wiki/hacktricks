# DDexec / EverythingExec

## Contesto

In Linux, per eseguire un programma questo deve esistere come file e deve essere accessibile in qualche modo attraverso la gerarchia del file system (è semplicemente il funzionamento di `execve()`). Questo file può trovarsi su disco o nella RAM (tmpfs, memfd), ma è necessario un filepath. Ciò ha reso molto semplice controllare cosa viene eseguito su un sistema Linux, rilevare minacce e strumenti dell'attaccante oppure impedire loro del tutto di provare a eseguire qualcosa di proprio (_ad es._ non consentendo agli utenti non privilegiati di posizionare file eseguibili ovunque).

Ma questa tecnica è qui per cambiare tutto questo. Se non puoi avviare il processo che vuoi... **allora ne hijacki uno già esistente**.

Questa tecnica consente di **bypassare tecniche di protezione comuni come read-only, noexec, file-name whitelisting e hash whitelisting**.<sup>[[1]](#references)</sup>

## Dipendenze

Lo script finale dipende dai seguenti strumenti per funzionare; devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita li troverai ovunque):
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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere utilizzato per dirottare un processo già esistente e sostituirlo con un altro programma. Possiamo ottenere questo risultato usando la syscall `ptrace()` (che richiede la capacità di eseguire syscall o la disponibilità di gdb sul sistema) oppure, cosa più interessante, scrivendo su `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Il file `/proc/$pid/mem` è una mappatura uno-a-uno dell'intero spazio degli indirizzi di un processo (_ad es._ da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Ciò significa che leggere o scrivere su questo file a un offset `x` equivale a leggere o modificare il contenuto all'indirizzo virtuale `x`.

Ora dobbiamo affrontare quattro problemi fondamentali:

- In generale, solo root e il proprietario del programma possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere a un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore di I/O.

Questi problemi hanno soluzioni che, sebbene non siano perfette, sono valide:

- La maggior parte degli interpreti di shell consente la creazione di file descriptor che verranno poi ereditati dai processi figli. Possiamo creare un fd che punti al file `mem` della shell con permessi di scrittura... quindi i processi figli che utilizzano quell'fd saranno in grado di modificare la memoria della shell.
- ASLR non è nemmeno un problema: possiamo controllare il file `maps` della shell o qualsiasi altro file da procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
- Dobbiamo quindi eseguire `lseek()` sul file. Dalla shell non è possibile farlo, a meno di usare l'infamous `dd`.

### Più in dettaglio

I passaggi sono relativamente semplici e non richiedono alcuna particolare competenza per essere compresi:<sup>[[1]](#references)</sup>

- Analizzare il binary che vogliamo eseguire e il loader per scoprire quali mapping richiedono. Quindi creare uno "shell"code che, in termini generali, esegua gli stessi passaggi che il kernel compie a ogni chiamata a `execve()`:
- Creare i mapping indicati.
- Leggere i binary al loro interno.
- Impostare i permessi.
- Infine, inizializzare lo stack con gli argomenti del programma e inserire l'auxiliary vector (necessario al loader).
- Eseguire un jump nel loader e lasciargli fare il resto (caricare le librerie necessarie al programma).
- Ottenere dal file `syscall` l'indirizzo al quale il processo tornerà dopo la syscall che sta eseguendo.
- Sovrascrivere quel punto, che sarà eseguibile, con il nostro shellcode (tramite `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà `read()` dal suddetto "shell"code).
- A questo punto spetta al loader caricare le librerie necessarie al nostro programma e trasferire il controllo al suo interno.

**Dai un'occhiata al tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Esistono diverse alternative a `dd`, una delle quali, `tail`, è attualmente il programma predefinito utilizzato per eseguire `lseek()` attraverso il file `mem` (che era l'unico motivo per usare `dd`). Tali alternative sono:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Impostando la variabile `SEEKER` puoi cambiare il seeker utilizzato, _ad es._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se trovi un altro seeker valido non implementato nello script, puoi comunque usarlo impostando la variabile `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloccate questo, EDR.

## References

- [1] [DDexec: una tecnica per eseguire file binari fileless e in modo furtivo su Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}
