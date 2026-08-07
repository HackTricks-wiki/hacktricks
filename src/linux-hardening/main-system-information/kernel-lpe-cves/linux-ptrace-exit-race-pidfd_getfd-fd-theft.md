# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un **pattern de privesc du kernel Linux** utile consiste à transformer un **bug d'autorisation ptrace** en **vol de descripteur de fichier** depuis un processus privilégié.

Dans l'étude de cas Qualys sur `__ptrace_may_access()` (CVE-2026-46333), l'attaquant effectue une race avec un **processus privilégié en cours de terminaison ou d'abandon de privilèges** et utilise `pidfd_getfd()` pour dupliquer un FD dans le processus de l'attaquant.<sup>[[1]](#references)[[2]](#references)</sup>

## Idée principale

`pidfd_getfd()` duplique un descripteur de fichier depuis un autre processus, mais vérifie d'abord les permissions de type ptrace vis-à-vis de la cible. Si cette autorisation est accordée à tort pendant une **fenêtre de teardown**, un attaquant non privilégié peut copier :

- des FDs correspondant à des **fichiers sensibles** déjà ouverts par un helper privilégié
- des FDs correspondant à des **canaux IPC authentifiés** déjà autorisés en tant que root

Cela transforme un bug d'autorisation côté kernel en une primitive très pratique côté userspace.<sup>[[1]](#references)</sup>

## Pourquoi la primitive est dangereuse

L'attaque n'a **pas** besoin d'un bug dans le helper privilégié lui-même. Le helper doit seulement conserver temporairement quelque chose de précieux :

- `/etc/shadow`
- `/etc/ssh/*_key`
- une connexion D-Bus / systemd privilégiée
- tout autre secret déjà ouvert ou canal autorisé

Une fois dupliqué dans le processus de l'attaquant, le kernel applique les opérations au **FD volé**, et non au pathname d'origine ni à un nouveau flux d'authentification.<sup>[[1]](#references)</sup>

## Pattern d'exploitation

1. Identifier un **binaire setuid / setgid / doté de file capabilities** ou un **daemon root** qui ouvre des fichiers sensibles ou conserve des connexions IPC utiles.
2. Établir une relation qui satisfait les vérifications de policy ptrace pertinentes pour le chemin de la cible (par exemple, être le **parent** d'un enfant privilégié créé dans le cadre de paramètres YAMA permissifs).
3. Effectuer une race avec le processus pendant qu'il est **en cours de terminaison**, **abandonne ses privilèges** ou entre d'une autre manière dans un état où l'accès ptrace aurait dû devenir indisponible.
4. Utiliser `pidfd_open()` + `pidfd_getfd()` pour dupliquer le FD cible pendant la fenêtre d'autorisation étroite.
5. Réutiliser le FD volé depuis le contexte non privilégié :
- `read()` des secrets depuis un descripteur de fichier privilégié
- envoyer des requêtes sur un canal IPC authentifié volé afin d'obtenir des **actions côté root**<sup>[[1]](#references)</sup>

Forme minimale de la primitive :<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Cibles pratiques à auditer

Priorisez les binaires et les daemons qui, même brièvement, effectuent l'une de ces actions :<sup>[[1]](#references)</sup>

- ouvrent des fichiers réservés à root avant de terminer les transitions de privilèges
- se connectent au **system bus** et conservent un canal déjà autorisé
- transmettent des FDs privilégiés entre des helpers
- effectuent des opérations sensibles à la sécurité pendant la phase de teardown proche de `do_exit()`

Bons candidats à examiner :<sup>[[1]](#references)</sup>

- helpers de gestion des mots de passe / comptes
- helpers SSH
- helpers médiés par PolicyKit / D-Bus
- daemons desktop root qui exposent des méthodes D-Bus

## YAMA comme barrière d'exploitation

`kernel.yama.ptrace_scope` constitue une barrière pratique majeure contre les abus de la famille ptrace :<sup>[[4]](#references)</sup>

- `0` : comportement ptrace classique avec le même UID
- `1` : autorise généralement le tracing parent -> enfant, ce qui peut maintenir accessibles certains chemins d'exploitation publics
- `2` : nécessite `CAP_SYS_PTRACE` pour un accès de type attach et bloque les abus non privilégiés de `pidfd_getfd()` dans ce chemin
- `3` : désactive complètement l'attach ptrace jusqu'au reboot

Pour cette technique, `ptrace_scope=2` constitue une **mitigation temporaire** efficace, car elle interrompt le chemin d'exploitation public de `pidfd_getfd()` avec `-EPERM` pour les utilisateurs non privilégiés.<sup>[[1]](#references)</sup>

## Idées de détection / revue

Lors de l'audit de logiciels Linux privilégiés, recherchez les combinaisons suivantes :

- **processus enfant privilégié** + **parent contrôlé par l'attaquant**
- accès temporaire à des **fichiers ouverts importants**
- accès temporaire à des **canaux D-Bus/systemd authentifiés**
- décisions de sécurité qui réutilisent une **autorisation de type ptrace** en dehors de `ptrace(2)` classique
- API du kernel capables de **dupliquer, hériter ou réexporter** des FDs privilégiés existants

Lors de l'audit du kernel, considérez comme présentant un risque élevé tout chemin qui effectue une **autorisation équivalente à ptrace** pendant le **teardown d'une task**, en particulier si sa réussite donne un accès direct à `task->files` ou à d'autres ressources de processus déjà autorisées.

## Références

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}
