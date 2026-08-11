# Linux ptrace exit-race `pidfd_getfd()` vol de FD

Un **pattern de privesc du kernel Linux** utile consiste à transformer un **bug d'autorisation ptrace** en **vol de descripteur de fichier** depuis un processus privilégié.

Dans l'étude de cas Qualys sur `__ptrace_may_access()` (CVE-2026-46333), l'attaquant effectue une race avec un **processus privilégié qui se termine ou abandonne ses credentials** et utilise `pidfd_getfd()` pour dupliquer un FD dans le processus de l'attaquant.<sup>[[1]](#references)[[2]](#references)</sup>

## Idée principale

`pidfd_getfd()` duplique un descripteur de fichier depuis un autre processus, mais vérifie d'abord les permissions de type ptrace vis-à-vis de la cible.<sup>[[3]](#references)</sup> Si cette autorisation est accordée à tort pendant une **teardown window**, un attaquant non privilégié peut copier :

- Des FD de **fichiers sensibles** déjà ouverts par un helper privilégié
- Des FD de **canaux IPC authentifiés** déjà autorisés en tant que root

Cela transforme un bug d'autorisation côté kernel en une primitive userspace très pratique.<sup>[[1]](#references)</sup>

## Pourquoi la primitive est dangereuse

L'attaque n'a **pas** besoin d'un bug dans le helper privilégié lui-même. Le helper doit seulement conserver temporairement quelque chose de précieux :

- `/etc/shadow`
- `/etc/ssh/*_key`
- Une connexion D-Bus / systemd privilégiée
- Tout autre secret déjà ouvert ou canal autorisé

Une fois dupliqué dans le processus de l'attaquant, le duplicata fait référence à la même open file description. Les lectures ou requêtes IPC suivantes utilisent donc le FD déjà ouvert, au lieu de rouvrir le pathname d'origine ou de démarrer un nouveau flux d'authentification.<sup>[[2]](#references)[[3]](#references)</sup>

## Pattern d'exploitation

1. Identifier un **binaire setuid / setgid / à file-capability** ou un **daemon root** qui ouvre des fichiers sensibles ou conserve des connexions IPC utiles.<sup>[[2]](#references)</sup>
2. Établir une relation qui satisfait les vérifications de policy ptrace pertinentes pour le chemin vers la cible (par exemple, être le **parent** d'un enfant privilégié créé avec des paramètres YAMA permissifs).<sup>[[2]](#references)[[4]](#references)</sup>
3. Effectuer une race avec le processus pendant qu'il **se termine**, **abandonne ses credentials** ou entre autrement dans un état où l'accès ptrace aurait dû devenir indisponible.<sup>[[2]](#references)</sup>
4. Utiliser `pidfd_open()` + `pidfd_getfd()` pour dupliquer le FD cible pendant la courte fenêtre d'autorisation.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Réutiliser le FD volé depuis le contexte non privilégié.<sup>[[2]](#references)</sup>
- Lire des secrets avec `read()` depuis un descripteur de fichier privilégié
- Envoyer des requêtes via un canal IPC authentifié volé pour obtenir des **actions côté root**

Forme minimale de la primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Cibles pratiques à auditer

Priorisez les binaires et daemons qui, même brièvement, effectuent l’une de ces actions :<sup>[[1]](#references)[[2]](#references)</sup>

- ouvrir des fichiers accessibles uniquement à root avant de terminer les transitions de privilèges
- se connecter au **bus système** et conserver un canal déjà autorisé
- transmettre des FDs privilégiés entre des helpers
- effectuer des opérations sensibles à la sécurité pendant une phase de teardown adjacente à `do_exit()`

Bons candidats à examiner :<sup>[[1]](#references)</sup>

- helpers de gestion des mots de passe / comptes
- helpers SSH
- helpers médiés par PolicyKit / D-Bus
- daemons de bureau root qui exposent des méthodes D-Bus

## YAMA comme barrière d’exploitation

`kernel.yama.ptrace_scope` constitue une barrière pratique majeure contre les abus de la famille ptrace :<sup>[[3]](#references)[[4]](#references)</sup>

- `0` : comportement ptrace classique pour un même UID
- `1` : autorise généralement le traçage parent -> enfant, ce qui peut maintenir accessibles certaines exploit paths publiques
- `2` : nécessite `CAP_SYS_PTRACE` pour un accès de type attach et bloque les abus non privilégiés de `pidfd_getfd()` dans ce path
- `3` : désactive complètement l’attach ptrace jusqu’au redémarrage

Pour cette technique, `ptrace_scope=2` constitue une **mitigation temporaire** efficace, car elle casse la public `pidfd_getfd()` exploitation path avec `-EPERM` pour les utilisateurs non privilégiés.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Idées pour la détection / la revue

Lors de l’audit de logiciels Linux privilégiés, recherchez les combinaisons suivantes :

- **processus enfant privilégié** + **parent contrôlé par l’attaquant**.<sup>[[2]](#references)[[4]](#references)</sup>
- accès temporaire à des **fichiers ouverts de valeur**
- accès temporaire à des **canaux D-Bus/systemd authentifiés**.<sup>[[2]](#references)</sup>
- décisions de sécurité qui réutilisent une **autorisation de type ptrace** en dehors de `ptrace(2)` classique
- APIs du kernel capables de **dupliquer, hériter ou réexporter** des FDs privilégiés existants

Lors de l’audit du kernel, considérez comme présentant un risque élevé tout path qui effectue une **autorisation équivalente à ptrace** pendant le **teardown d’une task**, en particulier si la réussite fournit un accès direct à `task->files` ou à d’autres ressources de processus déjà autorisées.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333 : élévation locale de privilèges root et divulgation d’informations d’identification dans le path ptrace du kernel Linux (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Advisory TXT de Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Page de manuel pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Documentation Yama du kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Page de manuel pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}
