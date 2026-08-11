# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variables d’identification de l’utilisateur

- **`ruid`** : Le **real user ID** désigne l’utilisateur qui a initié le processus.<sup>[[1]](#references)</sup>
- **`euid`** : Aussi appelé **effective user ID**, il représente l’identité utilisateur utilisée par le système pour déterminer les privilèges du processus. Généralement, `euid` est identique à `ruid`, sauf dans certains cas comme l’exécution d’un binaire SetUID (lorsque la transition set-user-ID est honorée), où `euid` prend l’identité du propriétaire du fichier, accordant ainsi des permissions opérationnelles spécifiques.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`** : Ce **saved user ID** est essentiel lorsqu’un processus hautement privilégié (s’exécutant généralement en tant que root) doit abandonner temporairement ses privilèges pour effectuer certaines tâches, puis récupérer son niveau de privilège élevé initial.<sup>[[1]](#references)</sup>

#### Remarque importante

Un processus non privilégié peut uniquement modifier son `euid` pour lui attribuer la valeur du `ruid`, `euid` ou `suid` actuel.<sup>[[3]](#references)</sup>

### Comprendre les fonctions set\*uid

- **`setuid`** : Contrairement à ce que l’on pourrait supposer, `setuid` définit l’`euid` du processus appelant. Pour un processus privilégié, elle définit également `ruid` et `suid` sur l’utilisateur spécifié ; après que tous les IDs ont été définis sur root, le processus ne peut pas récupérer une identité précédente avec `setuid`. Des informations détaillées sont disponibles dans la [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** et **`setresuid`** : `setreuid` modifie `ruid` et `euid`, tandis que `setresuid` modifie les trois IDs. Pour un processus non privilégié, `setresuid` limite chaque valeur cible au `ruid`, `euid` ou `suid` actuel ; `setreuid` limite `euid` à ces valeurs et `ruid` au `ruid` ou `euid` actuel. Un processus possédant `CAP_SETUID` peut attribuer des valeurs arbitraires aux IDs pris en charge par chaque appel. Plus d’informations sont disponibles dans la [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) et la [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ces fonctionnalités ne sont pas conçues comme un mécanisme de sécurité, mais pour faciliter le déroulement opérationnel prévu, par exemple lorsqu’un programme adopte l’identité d’un autre utilisateur en modifiant son effective user ID.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Il convient de noter qu’un appel privilégié à `setuid` peut définir les trois IDs, tandis que `setreuid` et `setresuid` offrent des contrôles différents ; distinguer ces fonctions est essentiel pour comprendre les transitions d’ID utilisateur.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mécanismes d’exécution des programmes sous Linux

#### **Appel système `execve`**

- **Fonctionnalité** : `execve` démarre un programme déterminé par le premier argument. Il prend deux arguments de type tableau, `argv` pour les arguments et `envp` pour l’environnement.<sup>[[5]](#references)</sup>
- **Comportement** : Il conserve l’espace mémoire de l’appelant, mais actualise les segments de pile, de tas et de données. Le code du programme est remplacé par celui du nouveau programme.<sup>[[5]](#references)</sup>
- **Préservation des User IDs** :
- `ruid` et les IDs de groupes supplémentaires restent inchangés.<sup>[[5]](#references)</sup>
- `euid` reste normalement inchangé, mais peut être modifié si le nouveau programme possède le bit SetUID.<sup>[[5]](#references)</sup>
- `suid` est mis à jour à partir de `euid` après l’exécution.<sup>[[5]](#references)</sup>
- **Documentation** : Des informations détaillées sont disponibles dans la [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Fonction `system`**

- **Fonctionnalité** : Contrairement à `execve`, `system` se comporte comme si elle créait un processus enfant avec `fork` et exécutait la commande dans ce processus enfant avec `execl`.<sup>[[6]](#references)</sup>
- **Exécution de la commande** : Exécute la commande via `sh` avec `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Comportement** : Comme `execl` est un appel de la famille `exec`, il fonctionne de manière similaire à `execve`, mais dans le contexte d’un nouveau processus enfant.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation** : Des informations supplémentaires sont disponibles dans la [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Comportement de `bash` et `sh` avec SUID**

- **`bash`** :
- Possède une option `-p` qui influence le traitement de `euid` et `ruid`.<sup>[[7]](#references)</sup>
- Sans `-p`, `bash` définit `euid` sur `ruid` s’ils sont initialement différents.<sup>[[7]](#references)</sup>
- Avec `-p`, l’`euid` initial est préservé.<sup>[[7]](#references)</sup>
- Plus de détails sont disponibles dans la [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`** :
- POSIX `sh` ne définit pas d’option de préservation des privilèges de type `-p` propre à Bash.<sup>[[8]](#references)</sup>
- Sa liste d’options POSIX inclut `-i`, qui sélectionne le mode interactif et peut être rejetée lorsque les IDs réels et effectifs diffèrent.<sup>[[8]](#references)</sup>
- Des informations supplémentaires sont disponibles dans la [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Ces mécanismes, distincts dans leur fonctionnement, offrent un éventail flexible d’options pour exécuter des programmes et effectuer des transitions entre eux, avec des nuances spécifiques concernant la gestion et la préservation des IDs utilisateur.

### Tester les comportements des User IDs lors des exécutions

Exemples tirés de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez cette page pour plus d’informations.<sup>[[1]](#references)</sup>

#### Cas 1 : Utiliser `setuid` avec `system`

**Objectif** : Comprendre l’effet de `setuid` en combinaison avec `system` et `bash` en tant que `sh`.

**Code C** :
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilation et permissions :**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `ruid` et `euid` commencent respectivement à 99 (nobody) et 1000 (frank).
- Dans ce contexte non privilégié, `setuid(1000)` laisse `ruid` à 99 et `euid` à 1000.<sup>[[1]](#references)</sup>
- `system` exécute `/bin/bash -c id` en raison du symlink de sh vers bash.
- `bash`, sans `-p`, ajuste `euid` pour qu’il corresponde à `ruid`, ce qui donne 99 (nobody) pour les deux.<sup>[[1]](#references)</sup>

#### Cas 2 : Utilisation de setreuid avec system

**C Code** :
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilation et Permissions:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `setreuid` définit ruid et euid sur 1000.
- `system` invoque bash, qui conserve les user IDs en raison de leur égalité, et fonctionne donc effectivement en tant que frank.<sup>[[1]](#references)</sup>

#### Cas 3 : Utilisation de setuid avec execve

Objectif : Explorer l’interaction entre setuid et execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `ruid` reste à 99, mais `euid` est défini sur 1000, conformément à l’effet de setuid.<sup>[[1]](#references)</sup>

**Exemple de code C 2 (Appel de Bash) :**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- Bien que `euid` soit défini sur 1000 par `setuid`, `bash` réinitialise `euid` à `ruid` (99) en raison de l'absence de `-p`.<sup>[[1]](#references)</sup>

**Exemple de code C 3 (Utilisation de bash -p) :**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - page de manuel setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - page de manuel setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - page de manuel setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - page de manuel execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - page de manuel system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - page de manuel bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - page de manuel POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
