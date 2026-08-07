# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variables d'identification de l'utilisateur

- **`ruid`** : Le **real user ID** désigne l'utilisateur qui a initié le processus.
- **`euid`** : Également appelé **effective user ID**, il représente l'identité utilisateur utilisée par le système pour déterminer les privilèges du processus. Généralement, `euid` correspond à `ruid`, sauf dans certains cas comme l'exécution d'un binaire SetUID, où `euid` prend l'identité du propriétaire du fichier, accordant ainsi des permissions opérationnelles spécifiques.
- **`suid`** : Ce **saved user ID** est essentiel lorsqu'un processus disposant de privilèges élevés (s'exécutant généralement en tant que root) doit temporairement abandonner ses privilèges pour effectuer certaines tâches, puis récupérer ultérieurement son statut élevé initial.

#### Remarque importante

Un processus ne s'exécutant pas sous root ne peut modifier son `euid` que pour le faire correspondre au `ruid`, `euid` ou `suid` actuel.

### Comprendre les fonctions set\*uid

- **`setuid`** : Contrairement à ce que l'on pourrait penser, `setuid` modifie principalement `euid` plutôt que `ruid`. Plus précisément, pour les processus privilégiés, elle aligne `ruid`, `euid` et `suid` sur l'utilisateur spécifié, souvent root, solidifiant ainsi effectivement ces IDs en raison de la valeur `suid` qui les remplace. Des informations détaillées sont disponibles dans la [page man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** et **`setresuid`** : Ces fonctions permettent d'ajuster précisément `ruid`, `euid` et `suid`. Toutefois, leurs capacités dépendent du niveau de privilèges du processus. Pour les processus non root, les modifications sont limitées aux valeurs actuelles de `ruid`, `euid` et `suid`. En revanche, les processus root ou ceux disposant de la capability `CAP_SETUID` peuvent attribuer des valeurs arbitraires à ces IDs. Plus d'informations sont disponibles dans la [page man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) et la [page man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ces fonctionnalités ne sont pas conçues comme un mécanisme de sécurité, mais pour faciliter le déroulement opérationnel prévu, notamment lorsqu'un programme adopte l'identité d'un autre utilisateur en modifiant son effective user ID.

Il convient de noter que, bien que `setuid` puisse être couramment utilisée pour l'élévation de privilèges vers root (puisqu'elle aligne tous les IDs sur root), la distinction entre ces fonctions est essentielle pour comprendre et manipuler le comportement des user IDs dans différents scénarios.

### Mécanismes d'exécution des programmes sous Linux

#### **Appel système `execve`**

- **Fonctionnalité** : `execve` lance un programme, déterminé par le premier argument. Elle prend deux arguments sous forme de tableaux, `argv` pour les arguments et `envp` pour l'environnement.
- **Comportement** : Elle conserve l'espace mémoire de l'appelant, mais actualise les segments de stack, de heap et de données. Le code du programme est remplacé par celui du nouveau programme.
- **Préservation des User IDs** :
- `ruid`, `euid` et les group IDs supplémentaires restent inchangés.
- `euid` peut subir des changements particuliers si le nouveau programme possède le bit SetUID.
- `suid` est mis à jour à partir de `euid` après l'exécution.
- **Documentation** : Des informations détaillées sont disponibles dans la [page man de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Fonction `system`**

- **Fonctionnalité** : Contrairement à `execve`, `system` crée un processus enfant avec `fork` et exécute une commande dans ce processus enfant à l'aide de `execl`.
- **Exécution de commandes** : Elle exécute la commande via `sh` avec `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportement** : Comme `execl` est une forme de `execve`, elle fonctionne de manière similaire, mais dans le contexte d'un nouveau processus enfant.
- **Documentation** : Des informations supplémentaires sont disponibles dans la [page man de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportement de `bash` et `sh` avec SUID**

- **`bash`** :
- Possède une option `-p` qui influence la manière dont `euid` et `ruid` sont traités.
- Sans `-p`, `bash` définit `euid` sur `ruid` s'ils sont initialement différents.
- Avec `-p`, la valeur initiale de `euid` est préservée.
- Plus de détails sont disponibles dans la [page man de `bash`](https://linux.die.net/man/1/bash).
- **`sh`** :
- Ne possède pas de mécanisme similaire à `-p` dans `bash`.
- Le comportement concernant les user IDs n'est pas explicitement mentionné, sauf avec l'option `-i`, qui met l'accent sur la préservation de l'égalité entre `euid` et `ruid`.
- Des informations supplémentaires sont disponibles dans la [page man de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ces mécanismes, distincts dans leur fonctionnement, offrent un éventail flexible d'options pour exécuter des programmes et passer de l'un à l'autre, avec des particularités concernant la gestion et la préservation des user IDs.

### Tester le comportement des User IDs lors des exécutions

Exemples tirés de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez cette page pour plus d'informations<sup>[[1]](#references)</sup>

#### Cas 1 : Utiliser `setuid` avec `system`

**Objectif** : Comprendre l'effet de `setuid` en combinaison avec `system` et `bash` en tant que `sh`.

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
- `setuid` aligne les deux sur 1000.
- `system` exécute `/bin/bash -c id` en raison du symlink de sh vers bash.
- `bash`, sans `-p`, ajuste `euid` pour qu'il corresponde à `ruid`, ce qui donne 99 (nobody) pour les deux.

#### Cas 2 : Utilisation de setreuid avec system

**Code C** :
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
**Compilation et permissions:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `setreuid` définit à la fois le ruid et l’euid sur 1000.
- `system` invoque bash, qui conserve les user IDs en raison de leur égalité, et s’exécute donc effectivement en tant que frank.

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

- `ruid` reste à 99, mais `euid` est défini sur 1000, conformément à l'effet de setuid.

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

- Bien que `euid` soit défini sur 1000 par `setuid`, `bash` réinitialise `euid` à `ruid` (99) en raison de l'absence de `-p`.

**Exemple de code C 3 (Using bash -p) :**
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
uid=99(nobody) gid=99(nobody) euid=100
```
## Références

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
