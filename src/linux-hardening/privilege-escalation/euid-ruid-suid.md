# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variables d'Identification de l'Utilisateur

- **`ruid`** : L'**ID utilisateur réel** désigne l'utilisateur qui a initié le processus.
- **`euid`** : Connu sous le nom d'**ID utilisateur effectif**, il représente l'identité utilisateur utilisée par le système pour déterminer les privilèges du processus. En général, `euid` reflète `ruid`, sauf dans des cas comme l'exécution d'un binaire SetUID, où `euid` prend l'identité du propriétaire du fichier, accordant ainsi des permissions opérationnelles spécifiques.
- **`suid`** : Cet **ID utilisateur sauvegardé** est essentiel lorsqu'un processus à privilèges élevés (généralement exécuté en tant que root) doit temporairement renoncer à ses privilèges pour effectuer certaines tâches, avant de retrouver ultérieurement son statut élevé initial.

#### Remarque Importante

Un processus ne fonctionnant pas sous root ne peut modifier son `euid` que pour correspondre à l'actuel `ruid`, `euid` ou `suid`.

### Comprendre les Fonctions set\*uid

- **`setuid`** : Contrairement aux hypothèses initiales, `setuid` modifie principalement `euid` plutôt que `ruid`. Plus précisément, pour les processus privilégiés, il aligne `ruid`, `euid` et `suid` avec l'utilisateur spécifié, souvent root, solidifiant ainsi ces IDs en raison du `suid` prévalent. Des informations détaillées peuvent être trouvées dans la [page de manuel setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** et **`setresuid`** : Ces fonctions permettent l'ajustement nuancé de `ruid`, `euid` et `suid`. Cependant, leurs capacités dépendent du niveau de privilège du processus. Pour les processus non-root, les modifications sont limitées aux valeurs actuelles de `ruid`, `euid` et `suid`. En revanche, les processus root ou ceux ayant la capacité `CAP_SETUID` peuvent attribuer des valeurs arbitraires à ces IDs. Plus d'informations peuvent être obtenues à partir de la [page de manuel setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) et de la [page de manuel setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ces fonctionnalités ne sont pas conçues comme un mécanisme de sécurité, mais pour faciliter le flux opérationnel prévu, comme lorsqu'un programme adopte l'identité d'un autre utilisateur en modifiant son ID utilisateur effectif.

Notamment, bien que `setuid` puisse être un recours courant pour l'élévation de privilèges à root (puisqu'il aligne tous les IDs sur root), il est crucial de différencier ces fonctions pour comprendre et manipuler les comportements des IDs utilisateurs dans divers scénarios.

### Mécanismes d'Exécution de Programmes sous Linux

#### **Appel Système `execve`**

- **Fonctionnalité** : `execve` initie un programme, déterminé par le premier argument. Il prend deux arguments de tableau, `argv` pour les arguments et `envp` pour l'environnement.
- **Comportement** : Il conserve l'espace mémoire de l'appelant mais rafraîchit la pile, le tas et les segments de données. Le code du programme est remplacé par le nouveau programme.
- **Préservation de l'ID Utilisateur** :
- `ruid`, `euid` et les IDs de groupe supplémentaires restent inchangés.
- `euid` peut avoir des changements nuancés si le nouveau programme a le bit SetUID activé.
- `suid` est mis à jour à partir de `euid` après l'exécution.
- **Documentation** : Des informations détaillées peuvent être trouvées sur la [page de manuel `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Fonction `system`**

- **Fonctionnalité** : Contrairement à `execve`, `system` crée un processus enfant en utilisant `fork` et exécute une commande dans ce processus enfant en utilisant `execl`.
- **Exécution de Commande** : Exécute la commande via `sh` avec `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportement** : Comme `execl` est une forme de `execve`, il fonctionne de manière similaire mais dans le contexte d'un nouveau processus enfant.
- **Documentation** : Des informations supplémentaires peuvent être obtenues à partir de la [page de manuel `system`](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportement de `bash` et `sh` avec SUID**

- **`bash`** :
- A une option `-p` influençant la manière dont `euid` et `ruid` sont traités.
- Sans `-p`, `bash` définit `euid` sur `ruid` s'ils diffèrent initialement.
- Avec `-p`, l'`euid` initial est préservé.
- Plus de détails peuvent être trouvés sur la [page de manuel `bash`](https://linux.die.net/man/1/bash).
- **`sh`** :
- Ne possède pas de mécanisme similaire à `-p` dans `bash`.
- Le comportement concernant les IDs utilisateurs n'est pas explicitement mentionné, sauf sous l'option `-i`, soulignant la préservation de l'égalité entre `euid` et `ruid`.
- Des informations supplémentaires sont disponibles sur la [page de manuel `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ces mécanismes, distincts dans leur fonctionnement, offrent une gamme polyvalente d'options pour exécuter et passer d'un programme à un autre, avec des nuances spécifiques dans la gestion et la préservation des IDs utilisateurs.

### Tester les Comportements des IDs Utilisateurs dans les Exécutions

Exemples tirés de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultez-le pour plus d'informations

#### Cas 1 : Utilisation de `setuid` avec `system`

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
**Compilation et Permissions :**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `ruid` et `euid` commencent respectivement à 99 (personne) et 1000 (frank).
- `setuid` les aligne tous deux à 1000.
- `system` exécute `/bin/bash -c id` en raison du lien symbolique de sh à bash.
- `bash`, sans `-p`, ajuste `euid` pour correspondre à `ruid`, ce qui fait que les deux deviennent 99 (personne).

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
**Compilation et Permissions :**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `setreuid` définit à la fois ruid et euid à 1000.
- `system` invoque bash, qui maintient les identifiants d'utilisateur en raison de leur égalité, fonctionnant effectivement comme frank.

#### Cas 3 : Utilisation de setuid avec execve

Objectif : Explorer l'interaction entre setuid et execve.
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
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- `ruid` reste 99, mais euid est fixé à 1000, conformément à l'effet de setuid.

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
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analyse :**

- Bien que `euid` soit défini sur 1000 par `setuid`, `bash` réinitialise euid à `ruid` (99) en raison de l'absence de `-p`.

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
**Exécution et Résultat :**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Références

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
