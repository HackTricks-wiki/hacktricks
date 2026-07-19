# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un **pattern de privesc du kernel Linux** utile consiste à transformer un **bug d'autorisation ptrace** en **vol de file descriptors** depuis un processus privilégié.

Dans l'étude de cas Qualys concernant `__ptrace_may_access()` (CVE-2026-46333), l'attaquant provoque une race avec un **processus privilégié qui se termine ou abandonne ses credentials** et utilise `pidfd_getfd()` pour dupliquer un FD dans le processus de l'attaquant.

## Idée principale

`pidfd_getfd()` duplique un file descriptor depuis un autre processus, mais vérifie d'abord les permissions de type ptrace sur la cible. Si cette autorisation est accordée à tort pendant une **fenêtre de teardown**, un attaquant non privilégié peut copier :

- des FDs vers des **fichiers sensibles** déjà ouverts par un helper privilégié
- des FDs vers des **canaux IPC authentifiés** déjà autorisés en tant que root

Cela transforme un bug d'autorisation côté kernel en une primitive userspace très pratique.

## Pourquoi la primitive est dangereuse

L'attaque n'a **pas besoin d'un bug dans le helper privilégié lui-même**. Le helper doit seulement conserver temporairement quelque chose de précieux :

- `/etc/shadow`
- `/etc/ssh/*_key`
- une connexion D-Bus / systemd privilégiée
- tout autre secret déjà ouvert ou canal autorisé

Une fois dupliqué dans le processus de l'attaquant, le kernel applique les opérations sur le **FD volé**, et non sur le pathname d'origine ou via un nouveau flux d'authentification.

## Pattern d'exploitation

1. Identifier un **binaire setuid / setgid / doté de file capabilities** ou un **daemon root** qui ouvre des fichiers sensibles ou conserve des connexions IPC utiles.
2. Établir une relation qui satisfait les vérifications de policy ptrace pertinentes pour le chemin ciblé (par exemple, être le **parent** d'un enfant privilégié créé avec des paramètres YAMA permissifs).
3. Provoquer une race avec le processus lorsqu'il est en train de **se terminer**, d'**abandonner ses credentials**, ou d'entrer dans un autre état dans lequel l'accès ptrace aurait dû devenir indisponible.
4. Utiliser `pidfd_open()` + `pidfd_getfd()` pour dupliquer le FD cible pendant l'étroite fenêtre d'autorisation.
5. Réutiliser le FD volé depuis le contexte non privilégié :
- `read()` des secrets depuis un file descriptor privilégié
- envoyer des requêtes via un canal IPC authentifié volé afin d'obtenir des **actions côté root**

Forme minimale de la primitive :
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Cibles pratiques à auditer

Priorisez les binaires et daemons qui, même brièvement, effectuent l’une de ces opérations :

- ouvrent des fichiers réservés à root avant de terminer les transitions de privilèges
- se connectent au **system bus** et conservent un canal déjà autorisé
- transmettent des FDs privilégiés entre des helpers
- effectuent des opérations sensibles du point de vue de la sécurité pendant une phase de teardown adjacente à `do_exit()`

Bons candidats à examiner :

- helpers de gestion des mots de passe / comptes
- helpers SSH
- helpers médiés par PolicyKit / D-Bus
- daemons root du bureau qui exposent des méthodes D-Bus

## YAMA comme barrière d’exploitation

`kernel.yama.ptrace_scope` constitue une barrière pratique majeure contre les abus de la famille ptrace :

- `0` : comportement ptrace classique pour un même UID
- `1` : autorise généralement le tracing parent -> enfant, ce qui peut maintenir accessibles certaines public exploit paths
- `2` : nécessite `CAP_SYS_PTRACE` pour les accès de type attach et bloque les abus non privilégiés de `pidfd_getfd()` dans ce path
- `3` : désactive complètement ptrace attach jusqu’au reboot

Pour cette technique, `ptrace_scope=2` constitue une **mitigation temporaire** efficace, car elle casse la public `pidfd_getfd()` exploitation path avec `-EPERM` pour les utilisateurs non privilégiés.

## Idées de détection / revue

Lors de l’audit de logiciels Linux privilégiés, recherchez les combinaisons suivantes :

- **processus enfant privilégié** + **parent contrôlé par l’attaquant**
- accès temporaire à des **fichiers ouverts de valeur**
- accès temporaire à des **canaux D-Bus/systemd authentifiés**
- décisions de sécurité qui réutilisent une **autorisation de type ptrace** en dehors de `ptrace(2)` classique
- APIs du kernel capables de **dupliquer, hériter ou réexporter** des FDs privilégiés existants

Lors de l’audit du kernel, considérez comme présentant un risque élevé tout path qui effectue une **autorisation équivalente à ptrace** pendant le **task teardown**, en particulier si sa réussite donne un accès direct à `task->files` ou à d’autres ressources de processus déjà autorisées.

## Références

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
