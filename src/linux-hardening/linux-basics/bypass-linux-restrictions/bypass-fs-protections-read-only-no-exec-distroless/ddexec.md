# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contesto

Linux normalmente esegue i programmi da file eseguibili archiviati su disco o in memoria. Può identificare un eseguibile tramite pathname o file descriptor, quindi non è sempre necessario un pathname normale del filesystem.<sup>[[2]](#references)</sup>

DDexec / EverythingExec usa la memoria di un **processo già in esecuzione**. La pagina [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) tratta l'esecuzione di file anonimi e le relative attività di rilevamento e raccolta forense; anche la panoramica [Memory Bypasses](index.html#memory-bypasses) rimanda a MemExec e Memdlopen.<sup>[[1]](#references)</sup>

Questa tecnica consente di **aggirare le tecniche di protezione comuni, come read-only, noexec, le whitelist dei nomi dei file e le whitelist degli hash**.<sup>[[1]](#references)</sup>

## Dipendenze

Lo script finale dipende dai seguenti strumenti per funzionare; devono essere accessibili nel sistema che stai attaccando (per impostazione predefinita, li troverai ovunque):

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

Se sei in grado di modificare arbitrariamente la memoria di un processo, puoi prenderne il controllo. Questo può essere usato per dirottare un processo già esistente e sostituirlo con un altro programma. Possiamo riuscirci usando la syscall `ptrace()` (che richiede la possibilità di eseguire syscall o che `gdb` sia disponibile sul sistema) oppure, cosa più interessante, scrivendo in `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

Il file `/proc/$pid/mem` è una mappatura uno a uno dell'intero spazio degli indirizzi di un processo (_ad es._ da `0x0000000000000000` a `0x7ffffffffffff000` in x86-64). Questo significa che leggere o scrivere in questo file all'offset `x` equivale a leggere o modificare i contenuti all'indirizzo virtuale `x`.

Ora dobbiamo affrontare quattro problemi fondamentali:

- In generale, solo root e il proprietario del file possono modificarlo.
- ASLR.
- Se proviamo a leggere o scrivere a un indirizzo non mappato nello spazio degli indirizzi del programma, otterremo un errore di I/O.

Questi problemi hanno soluzioni che, anche se non sono perfette, funzionano bene:

- La maggior parte degli interpreti di shell consente di creare file descriptor che verranno ereditati dai processi figli. Possiamo creare un fd che punta al file `mem` della shell con permessi di scrittura... così i processi figli che usano quel fd potranno modificare la memoria della shell.
- ASLR non è nemmeno un problema: possiamo controllare il file `maps` della shell o qualsiasi altro file di procfs per ottenere informazioni sullo spazio degli indirizzi del processo.
- Dobbiamo quindi usare `lseek()` sul file. Dalla shell questo non è possibile, a meno di usare il famigerato `dd`.

### Più nel dettaglio

I passaggi sono relativamente semplici e non richiedono competenze particolari per essere compresi:<sup>[[1]](#references)</sup>

- Analizzare il binario che vogliamo eseguire e il loader per scoprire quali mappature richiedono. Poi creare uno "shellcode" che esegua, in linea generale, gli stessi passaggi del kernel a ogni chiamata a `execve()`:
  - Creare le mappature indicate.
  - Leggere i binari al loro interno.
  - Impostare i permessi.
  - Infine, inizializzare lo stack con gli argomenti del programma e inserire l'auxiliary vector (necessario al loader).
  - Saltare al loader e lasciargli fare il resto (caricare le librerie necessarie al programma).
- Ottenere dal file `syscall` l'indirizzo a cui il processo tornerà dopo la syscall che sta eseguendo.
- Sovrascrivere quella posizione, che sarà eseguibile, con il nostro shellcode (tramite `mem` possiamo modificare pagine non scrivibili).
- Passare il programma che vogliamo eseguire allo stdin del processo (verrà letto con `read()` da quello "shellcode").
- A questo punto spetta al loader caricare le librerie necessarie al programma e saltare al suo interno.

**Dai un'occhiata al tool su** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Esistono diverse alternative a `dd`; una di queste, `tail`, è attualmente il programma predefinito usato per eseguire `lseek()` sul file `mem` (l'unico scopo per cui si usava `dd`). Le alternative sono:<sup>[[1]](#references)</sup>

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

Bloccate questo, EDRs.

## References

- [1] [DDexec: una tecnica per eseguire file binari senza file e in modo furtivo su Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — pagina del manuale Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
