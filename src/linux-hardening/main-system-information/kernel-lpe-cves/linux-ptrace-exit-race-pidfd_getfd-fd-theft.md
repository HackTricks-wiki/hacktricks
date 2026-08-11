# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Un **pattern de privesc du Linux kernel** utile consiste à transformer un **bug d'autorisation ptrace** en **vol de file descriptors** depuis un processus privilégié.

Dans l'étude de cas Qualys sur `__ptrace_may_access()` (CVE-2026-46333), l'attaquant exploite une race avec un **processus privilégié en cours de terminaison ou d'abandon de credentials** et utilise `pidfd_getfd()` pour dupliquer un FD dans le processus de l'attaquant.<sup>[[1]](#references)[[2]](#references)</sup>

## Idée principale

`pidfd_getfd()` duplique un file descriptor depuis un autre processus, mais vérifie d'abord les permissions de type ptrace sur la cible.<sup>[[3]](#references)</sup> Si cette autorisation est accordée à tort pendant une **fenêtre de teardown**, un attaquant non privilégié peut copier :

- des FDs vers des **fichiers sensibles** déjà ouverts par un helper privilégié
- des FDs vers des **canaux IPC authentifiés** déjà autorisés en tant que root

Cela transforme un bug d'autorisation côté kernel en une primitive userspace très pratique.<sup>[[1]](#references)</sup>

## Pourquoi cette primitive est dangereuse

L'attaque ne nécessite **aucun bug dans le helper privilégié lui-même**. Le helper doit seulement conserver temporairement quelque chose de précieux :

- `/etc/shadow`
- `/etc/ssh/*_key`
- une connexion D-Bus / systemd privilégiée
- tout autre secret déjà ouvert ou canal autorisé

Une fois dupliqué dans le processus de l'attaquant, le duplicata fait référence à la même open file description. Les lectures ou requêtes IPC suivantes utilisent donc le FD déjà ouvert au lieu de rouvrir le pathname d'origine ou de démarrer un nouveau flux d'authentification.<sup>[[2]](#references)[[3]](#references)</sup>

## Pattern d'exploitation

1. Identifier un **binaire setuid / setgid / doté de file capabilities** ou un **daemon root** qui ouvre des fichiers sensibles ou conserve des connexions IPC utiles.<sup>[[2]](#references)</sup>
2. Établir une relation qui satisfait les vérifications de la politique ptrace pertinentes pour le chemin vers la cible (par exemple, être le **parent** d'un enfant privilégié lancé avec des paramètres YAMA permissifs).<sup>[[2]](#references)[[4]](#references)</sup>
3. Exploiter une race avec le processus pendant qu'il est **en cours de terminaison**, **abandonne ses credentials**, ou entre autrement dans un état où l'accès ptrace aurait dû devenir indisponible.<sup>[[2]](#references)</sup>
4. Utiliser `pidfd_open()` + `pidfd_getfd()` pour dupliquer le FD cible pendant la courte fenêtre d'autorisation.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Réutiliser le FD volé depuis le contexte non privilégié.<sup>[[2]](#references)</sup>
- Lire des secrets avec `read()` depuis un file descriptor privilégié
- Envoyer des requêtes via un canal IPC authentifié volé afin d'obtenir des **actions côté root**

Forme minimale de la primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Cibles pratiques à auditer

Priorisez les binaries et daemons qui, même brièvement, font l’une de ces choses :<sup>[[1]](#references)[[2]](#references)</sup>

- ouvrent des fichiers accessibles uniquement à root avant de terminer les transitions de privilèges
- se connectent au **system bus** et conservent un channel déjà autorisé
- transmettent des FDs privilégiés entre des helpers
- effectuent des opérations sensibles à la sécurité pendant un teardown adjacent à `do_exit()`

Bons candidats à examiner :<sup>[[1]](#references)</sup>

- helpers de gestion des mots de passe / comptes
- helpers SSH
- helpers médiés par PolicyKit / D-Bus
- daemons desktop root qui exposent des méthodes D-Bus

## YAMA comme gate d’exploit

`kernel.yama.ptrace_scope` est un gate pratique majeur contre les abus de la famille ptrace :<sup>[[3]](#references)[[4]](#references)</sup>

- `0` : comportement ptrace classique pour le même UID
- `1` : autorise généralement le tracing parent -> enfant, ce qui peut maintenir certains chemins d’exploit publics accessibles
- `2` : nécessite `CAP_SYS_PTRACE` pour un accès de type attach et bloque les abus non privilégiés de `pidfd_getfd()` dans ce chemin
- `3` : désactive complètement l’attach ptrace jusqu’au reboot

Pour cette technique, `ptrace_scope=2` constitue une **mitigation temporaire** forte, car elle casse le chemin d’exploitation public de `pidfd_getfd()` avec `-EPERM` pour les utilisateurs non privilégiés.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Idées de détection / revue

Lors de l’audit de software Linux privilégié, recherchez ces combinaisons :

- **processus enfant privilégié** + **parent contrôlé par l’attaquant**.<sup>[[2]](#references)[[4]](#references)</sup>
- accès temporaire à des **fichiers ouverts précieux**
- accès temporaire à des **channels D-Bus/systemd authentifiés**.<sup>[[2]](#references)</sup>
- décisions de sécurité qui réutilisent une **autorisation de type ptrace** en dehors du `ptrace(2)` classique
- APIs du kernel capables de **dupliquer, hériter ou réexporter** des FDs privilégiés existants

Lors de l’audit du kernel, considérez comme présentant un risque élevé tout chemin qui effectue une **autorisation équivalente à ptrace** pendant le **teardown d’une task**, en particulier si sa réussite fournit un accès direct à `task->files` ou à d’autres ressources de processus déjà autorisées.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333 : élévation locale de privilèges root et divulgation de credentials dans le chemin ptrace du kernel Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Advisory TXT de Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Page de manuel pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentation Yama du kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Page de manuel pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
