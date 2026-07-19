# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Variables d’identification de l’utilisateur

- **`ruid`** : Le **real user ID** désigne l’utilisateur qui a lancé le processus.
- **`euid`** : Également appelé **effective user ID**, il représente l’identité utilisateur utilisée par le système pour déterminer les privilèges du processus. Généralement, `euid` reflète `ruid`, sauf dans certains cas comme l’exécution d’un binaire SetUID, où `euid` adopte l’identité du propriétaire du fichier, accordant ainsi des permissions opérationnelles spécifiques.
- **`suid`** : Ce **saved user ID** est essentiel lorsqu’un processus disposant de privilèges élevés, généralement exécuté en tant que root, doit abandonner temporairement ses privilèges pour effectuer certaines tâches, puis récupérer ultérieurement son statut élevé initial.

#### Remarque importante

Un processus qui ne s’exécute pas avec les privilèges root peut uniquement modifier son `euid` pour lui attribuer la valeur actuelle de `ruid`, `euid` ou `suid`.

### Comprendre les fonctions set\*uid

- **`setuid`** : Contrairement à ce que l’on pourrait penser, `setuid` modifie principalement `euid` plutôt que `ruid`. Plus précisément, pour les processus privilégiés, elle aligne `ruid`, `euid` et `suid` sur l’utilisateur spécifié, souvent root, ce qui solidifie effectivement ces IDs en raison de la valeur dominante de `suid`. Des informations détaillées sont disponibles dans la [page man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** et **`setresuid`** : Ces fonctions permettent d’ajuster précisément `ruid`, `euid` et `suid`. Cependant, leurs capacités dépendent du niveau de privilèges du processus. Pour les processus non-root, les modifications sont limitées aux valeurs actuelles de `ruid`, `euid` et `suid`. En revanche, les processus root ou ceux disposant de la capacité `CAP_SETUID` peuvent attribuer des valeurs arbitraires à ces IDs. Plus d’informations sont disponibles dans la [page man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) et la [page man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ces fonctionnalités ne sont pas conçues comme un mécanisme de sécurité, mais pour faciliter le fonctionnement prévu, par exemple lorsqu’un programme adopte l’identité d’un autre utilisateur en modifiant son effective user ID.

Il convient de noter que, bien que `setuid` puisse être un choix courant pour élever les privilèges vers root (puisqu’elle aligne tous les IDs sur root), faire la distinction entre ces fonctions est essentiel pour comprendre et manipuler le comportement des user IDs dans différents scénarios.

### Mécanismes d’exécution des programmes sous Linux

#### **Appel système `execve`**

- **Fonctionnalité** : `execve` lance un programme, déterminé par son premier argument. Elle accepte deux arguments sous forme de tableaux : `argv` pour les arguments et `envp` pour l’environnement.
- **Comportement** : Elle conserve l’espace mémoire de l’appelant, mais actualise la stack, le heap et les segments de données. Le code du programme est remplacé par celui du nouveau programme.
- **Conservation des User IDs** :
- `ruid`, `euid` et les IDs des groupes supplémentaires restent inchangés.
- `euid` peut subir des modifications particulières si le nouveau programme possède le bit SetUID activé.
- `suid` est mis à jour à partir de `euid` après l’exécution.
- **Documentation** : Des informations détaillées sont disponibles sur la [page man de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Fonction `system`**

- **Fonctionnalité** : Contrairement à `execve`, `system` crée un processus enfant à l’aide de `fork` et exécute une commande dans ce processus enfant à l’aide de `execl`.
- **Exécution de la commande** : La commande est exécutée via `sh` avec `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportement** : Comme `execl` est une forme de `execve`, elle fonctionne de manière similaire, mais dans le contexte d’un nouveau processus enfant.
- **Documentation** : Des informations supplémentaires sont disponibles sur la [page man de `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportement de `bash` et `sh` avec SUID**

- **`bash`** :
- Possède une option `-p` qui influence le traitement de `euid` et `ruid`.
- Sans `-p`, `bash` définit `euid` sur `ruid` lorsqu’ils sont initialement différents.
- Avec `-p`, la valeur initiale de `euid` est conservée.
- Plus de détails sont disponibles sur la [page man de `bash`](https://linux.die.net/man/1/bash).
- **`sh`** :
- Ne possède pas de mécanisme similaire à `-p` dans `bash`.
- Le comportement concernant les user IDs n’est pas explicitement mentionné, sauf avec l’option `-i`, qui insiste sur la conservation de l’égalité entre `euid` et `ruid`.
- Des informations supplémentaires sont disponibles sur la [page man de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ces mécanismes, distincts dans leur fonctionnement, offrent un éventail flexible d’options pour exécuter des programmes et passer de l’un à l’autre, avec des particularités spécifiques concernant la gestion et la conservation des user IDs.

### Tester le comportement des User IDs lors des exécutions

Exemples tirés de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez cette page pour plus d’informations

#### Cas 1 : Utiliser `setuid` avec `system`

**Objectif** : Comprendre l’effet de `setuid` combiné à `system` et à `bash` utilisé comme `sh`.

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
- `system` exécute `/bin/bash -c id` en raison du lien symbolique de sh vers bash.
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
**Compilation et permissions :**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `setreuid` définit à la fois ruid et euid sur 1000.
- `system` invoque bash, qui conserve les identifiants utilisateur en raison de leur égalité, et fonctionne donc effectivement en tant que frank.

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

- `ruid` reste à 99, mais `euid` est défini sur 1000, conformément à l’effet de setuid.

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

- Bien que `euid` soit défini sur 1000 par `setuid`, `bash` réinitialise `euid` sur `ruid` (99) en raison de l’absence de `-p`.

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

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
