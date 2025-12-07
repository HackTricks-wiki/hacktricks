# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, **utilisateurs** et **objets** au sein d'un réseau. Il est conçu pour évoluer, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** est composée de trois couches principales : **domaines**, **arbres** et **forêts**. Un **domaine** englobe un ensemble d'objets, tels que des **utilisateurs** ou des **périphériques**, partageant une base de données commune. Les **arbres** sont des groupes de ces domaines liés par une structure commune, et une **forêt** représente la collection de plusieurs arbres, interconnectés par des **relations de confiance**, formant la couche la plus haute de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Concepts clés dans **Active Directory** :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités du répertoire, incluant **utilisateurs**, **groupes** ou **partages**.
3. **Domain** – Sert de conteneur pour les objets du répertoire ; plusieurs domaines peuvent coexister dans une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Regroupement de domaines partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **relations de confiance** entre eux.

**Active Directory Domain Services (AD DS)** englobe un ensemble de services essentiels pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre **utilisateurs** et **domaines**, y compris **l'authentification** et les fonctionnalités de **recherche**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications habilitées pour les annuaires via le protocole **LDAP**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs à travers plusieurs applications web dans une seule session.
5. **Rights Management** – Aide à protéger les œuvres soumises au droit d'auteur en régulant leur distribution et usage non autorisés.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez seulement accès à un environnement AD mais pas de credentials/sessions, vous pouvez :

- **Pentest le réseau :**
- Scanner le réseau, trouver des machines et des ports ouverts et tenter d'**exploit vulnerabilities** ou d'**extraire des credentials** depuis celles-ci (par exemple, [printers could be very interesting targets](ad-information-in-printers.md)).
- L'énumération DNS peut fournir des informations sur des serveurs clés du domaine comme web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour plus d'informations sur la manière de procéder.
- **Vérifiez l'accès null et Guest sur les services smb** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur l'énumération d'un serveur SMB se trouve ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Énumérer LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur l'énumération LDAP se trouve ici (faites **particulièrement attention à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Empoisonner le réseau**
- Récupérer des credentials en [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérer des credentials **en exposant** des [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire des noms d'utilisateurs/noms complets depuis des documents internes, réseaux sociaux, services (principalement web) à l'intérieur des environnements de domaine ainsi que depuis les sources publiques.
- Si vous trouvez les noms complets des employés, vous pouvez essayer différentes conventions de **AD username** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chacun), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum :** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Lorsqu'un **username invalide est demandé**, le serveur répondra avec le code d'erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d'utilisateur est invalide. Les **usernames valides** provoqueront soit un **TGT dans un AS-REP** en réponse soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
- **No Authentication against MS-NRPC** : Utilisation de auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après le binding de l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credential. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous avez trouvé l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **user enumeration** contre lui. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> Vous pouvez trouver des listes de noms d'utilisateur dans [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de recon que vous auriez dû effectuer avant ceci. Avec le nom et le prénom vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiels valides.

### Knowing one or several usernames

Ok, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mots de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md): Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_ vous pouvez **demander un message AS_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md): Essayez les mots de passe les plus **courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
- Notez que vous pouvez également **sprayer OWA servers** pour tenter d'obtenir l'accès aux serveurs mail des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être capable d'**obtenir** quelques **hashs** de challenge à craquer en faisant du poisoning sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer Active Directory vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour obtenir l'accès à l'environnement AD.

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou partages** avec l'utilisateur **null** ou **guest** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le craquer :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Pour cette phase vous devez avoir **compromis les identifiants ou une session d'un compte de domaine valide.** Si vous avez des identifiants valides ou un shell en tant qu'utilisateur de domaine, **souvenez-vous que les options données précédemment restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée vous devriez savoir ce qu'est le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir lancer l'**énumération d'Active Directory :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs potentiellement vulnérables, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) ce qui sera plus discret
- Vous pouvez également [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil incroyable pour la recon dans un active directory est [**BloodHound**](bloodhound.md). Il n'est **pas très discret** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous gêne pas**, vous devriez vraiment l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez également rechercher dans la base LDAP avec **ldapsearch** pour chercher des identifiants dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés tels que :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

C'est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` or `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` or `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration semble courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous soyez à l'aise. Pendant une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider que rien ne peut être fait.

### Kerberoast

Kerberoasting implique l'obtention de **TGS tickets** utilisés par des services liés à des comptes utilisateurs et le craquage de leur chiffrement — qui est basé sur les mots de passe utilisateurs — **hors ligne**.

Plus d'informations à ce sujet dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des identifiants, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des identifiants ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et de récupérer des identifiants**. En effet, ce n'est qu'avec des privilèges d'administrateur local que vous pourrez **dump les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre à propos de [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). Aussi, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **peu probable** que vous trouviez des **tickets** dans l'utilisateur actuel vous donnant la **permission d'accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous disposerez de **plus d'adresses e-mail et d'une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Maintenant que vous avez quelques credentials de base vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez faire cela manuellement mais c'est une tâche très ennuyeuse et répétitive (d'autant plus si vous trouvez des centaines de docs à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou shares** vous pourriez **placer des fichiers** (comme un SCF file) qui, s'ils sont consultés, **déclencheront une NTLM authentication contre vous** afin que vous puissiez **voler** le **NTLM challenge** pour le craquer :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Pour les techniques suivantes un domain user régulier ne suffit pas, vous avez besoin de certains privilèges/credentials spéciaux pour réaliser ces attaques.**

### Hash extraction

Espérons que vous avez réussi à **compromettre un compte local admin** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (y compris le relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps d'extraire tous les hashes en mémoire et localement.\
[**Lisez cette page pour les différentes manières d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **l'usurper**.\
Vous devez utiliser un **outil** qui va **effectuer** l'**NTLM authentication en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, ainsi lorsque n'importe quelle **NTLM authentication** est effectuée, ce **hash** sera utilisé. La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le NTLM hash d'un utilisateur pour demander des tickets Kerberos**, en alternative au Pass The Hash classique via le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans des réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **usurper l'utilisateur**, obtenant un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si vous avez le **hash** ou le **password** d'un **local administrator** vous devriez essayer de **vous connecter localement** à d'autres **PCs** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que ceci est assez **bruyant** et que **LAPS** permettrait de l'**atténuer**.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **accéder aux instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si le processus tourne en tant que SA), **voler** le hash **NetNTLM** ou même réaliser une **relay attack**.\
Aussi, si une instance MSSQL est trustée (database link) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données trustée, il pourra **utiliser la relation de confiance pour exécuter des requêtes également dans l'autre instance**. Ces trusts peuvent être chaînés et à un certain point l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent même à travers des forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Les suites tierces d'inventaire et de déploiement exposent souvent des chemins puissants vers des credentials et l'exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous avez des privilèges de domaine sur la machine, vous pourrez **dump TGTs** depuis la mémoire de tous les utilisateurs qui se connectent sur l'ordinateur.\
Donc, si un **Domain Admin se connecte sur la machine**, vous pourrez dumper son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation vous pourriez même **compromettre automatiquement un Print Server** (espérons que ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation", il pourra **usurper n'importe quel utilisateur pour accéder à certains services sur une machine**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur vous pourrez **usurper n'importe quel utilisateur** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le droit **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de **mouvoir** latéralement / **élever** des privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Découvrir un **service Spool à l'écoute** dans le domaine peut être **abusé** pour **acquérir de nouveaux credentials** et **escalader des privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des credentials depuis la mémoire** et même **injecter des beacons dans leurs processus** pour les usurper.\
Généralement les utilisateurs accèderont au système via RDP, voici donc comment réaliser quelques attaques sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe Administrator local** sur les machines jointes au domaine, en s'assurant qu'il est **randomisé**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs pour des utilisateurs autorisés uniquement. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres machines.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Récupérer des certificats** depuis la machine compromise peut être un moyen d'escalader les privilèges à l'intérieur de l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **templates vulnérables** sont configurés, il est possible de les abuser pour escalader des privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Une fois que vous obtenez des privilèges de **Domain Admin** ou mieux **Enterprise Admin**, vous pouvez **dump** la **base de données du domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistence.\
Par exemple, vous pourriez :

- Rendre des utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendre des utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Accorder des privilèges [**DCSync**](#dcsync) à un utilisateur

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attaque **Silver Ticket** crée un **Ticket Granting Service (TGS) légitime** pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est utilisée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** implique qu'un attaquant obtienne le **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, essentiels pour l'authentification dans le réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte de son choix (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ce sont comme des golden tickets forgés d'une manière qui **contourne les mécanismes de détection courants des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avoir les certificats d'un compte ou être capable de les demander** est une très bonne manière de persister dans le compte d'un utilisateur (même si celui-ci change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet aussi de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **ACL** standard à ces groupes pour empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger, peut donc se retourner contre l'environnement si elle n'est pas surveillée de près.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dans chaque **Domain Controller (DC)**, il existe un compte **local administrator**. En obtenant des droits admin sur une telle machine, le hash de l'Administrator local peut être extrait en utilisant **mimikatz**. Ensuite, une modification de registre est nécessaire pour **permettre l'utilisation de ce mot de passe**, autorisant l'accès à distance au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **accorder** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine qui permettront à cet utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'**un objet** possède **sur** un **objet**. Si vous pouvez simplement **faire** une **petite modification** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altérer **LSASS** en mémoire pour établir un **mot de passe universel**, donnant accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **clear text** les **credentials** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de DA** privilèges et d'être dans le **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez laids apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Précédemment nous avons discuté de la façon d'escalader des privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistence**.\
Vérifiez :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forest** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement mener à la compromission de toute la Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler. Lorsqu'un trust est établi, les domaines échangent et conservent des **clés** spécifiques au sein de leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité du trust.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine trusté**, il doit d'abord demander un ticket spécial connu sous le nom de **inter-realm TGT** au DC de son propre domaine. Ce TGT est chiffré avec une **clé** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine trusté** pour obtenir un ticket de service (**TGS**). Après validation réussie de l'inter-realm TGT par le DC du domaine trusté, ce dernier émet un TGS, accordant à l'utilisateur l'accès au service.

**Étapes**:

1. Un **client** dans le **Domain 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 délivre un nouveau TGT si le client est authentifié avec succès.
3. Le client demande alors un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources dans le **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre du trust bidirectionnel des domaines.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du Domain 2.
6. DC2 vérifie l'inter-realm TGT en utilisant sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domain 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domain 2.

### Different trusts

Il est important de noter qu'**un trust peut être unidirectionnel ou bidirectionnel**. Dans l'option à 2 voies, les deux domaines se font mutuellement confiance, mais dans la relation de trust **à sens unique** l'un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources dans le domaine trusting depuis le domaine trusted**.

Si le Domain A trust le Domain B, A est le domaine trusting et B est le trusted. De plus, dans **Domain A**, ce serait un **Outbound trust** ; et dans **Domain B**, ce serait un **Inbound trust**.

**Différents types de relations de trust**

- **Parent-Child Trusts** : Configuration courante au sein d'une même forest, où un child domain a automatiquement un trust transitive à deux sens avec son parent. Essentiellement, les requêtes d'authentification peuvent circuler sans friction entre le parent et l'enfant.
- **Cross-link Trusts** : Appelés "shortcut trusts", ils sont établis entre des child domains pour accélérer les processus de referral. Dans des forests complexes, les referrals d'authentification doivent typiquement monter jusqu'à la racine de la forest puis redescendre vers le domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement utile dans des environnements géographiquement dispersés.
- **External Trusts** : Mis en place entre différents domaines non liés et non-transitifs par nature. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d'un domaine extérieur à la forest courante qui n'est pas connecté par un forest trust. La sécurité est renforcée par le SID filtering avec les external trusts.
- **Tree-root Trusts** : Ces trusts sont automatiquement établis entre le domaine racine de la forest et une nouvelle tree root ajoutée. Bien que rarement rencontrés, les tree-root trusts sont importants pour ajouter de nouveaux domain trees à une forest, leur permettant de conserver un nom de domaine unique et assurant la transitivité bidirectionnelle. Plus d'informations sont disponibles dans le guide de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de trust est un trust transitive bidirectionnel entre deux forest root domains, appliquant également le SID filtering pour renforcer la sécurité.
- **MIT Trusts** : Ces trusts sont établis avec des domaines Kerberos non-Windows conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisés et servent des environnements nécessitant une intégration avec des systèmes Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, alors A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme un **bidirectional trust** (les deux se font confiance) ou comme un **one-way trust** (seul l'un fait confiance à l'autre).

### Attack Path

1. **Enumérer** les relations de trust
2. Vérifier si un **security principal** (user/group/computer) a **accès** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en faisant partie de groupes de l'autre domaine. Cherchez des **relations à travers les domaines** (le trust a probablement été créé pour cela).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** entre les domaines.

Les attaquants pourraient accéder aux ressources d'un autre domaine via trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” sur un serveur, leur octroyant un contrôle significatif sur cette machine.
- **Foreign Domain Group Membership** : Les principals peuvent aussi être membres de groupes dans le domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature du trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, particulièrement comme entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux qui veulent creuser la mécanique des ACLs, DACLs, et ACEs, le whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource inestimable.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ceux-ci seront des users/groups provenant **d'un domaine/forest externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou en utilisant **powerview**:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Autres façons d'énumérer les relations de confiance entre domaines :
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Il y a **2 trusted keys**, une pour _Child --> Parent_ et une autre pour _Parent_ --> _Child_.\
> Vous pouvez déterminer celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin to the child/parent domain abusing the trust with SID-History injection:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de référentiel central pour les données de configuration à travers une forest dans les environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) de la forest, les writable DCs conservant une copie modifiable du Configuration NC. Pour exploiter cela, il faut disposer de **SYSTEM privileges on a DC**, de préférence un child DC.

**Link GPO to root DC site**

Le conteneur Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forest AD. En opérant avec des privilèges SYSTEM sur n’importe quel DC, un attaquant peut lier des GPOs aux sites root DC. Cette action peut compromettre le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations détaillées, on peut consulter la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d’attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans le Configuration NC. Avec des privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la KDS Root key et de calculer les mots de passe de n’importe quel gMSA dans la forest.

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le AD Schema pour accorder à n’importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès non autorisé et au contrôle des objets AD nouvellement créés.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) pour créer un template de certificat permettant de s’authentifier en tant que n’importe quel utilisateur au sein de la forest. Comme les PKI objects résident dans le Configuration NC, compromettre un writable child DC permet d’exécuter des attaques ESC5.

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
Dans ce scénario, **votre domaine est approuvé** par un domaine externe, vous accordant des **autorisations indéterminées** sur celui-ci. Vous devrez découvrir **quelles entités de votre domaine disposent de quels accès sur le domaine externe** puis tenter d'en tirer parti :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe — unidirectionnel (sortant)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
Dans ce scénario **votre domaine** **trusting** some **privilèges** à un principal provenant d'un **domaine différent**.

Cependant, lorsque un **domain is trusted** par le **trusting domain**, le **trusted domain** **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le trusted password**. Ce qui signifie qu'il est possible de **utiliser un utilisateur du trusting domain pour accéder au trusted domain** afin de l'énumérer et tenter d'escalader davantage de privilèges :

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le trusted domain est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** du domain trust (ce qui n'est pas très courant).

Une autre façon de compromettre le trusted domain est d'attendre sur une machine où un **user from the trusted domain can access** se connecte via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de **RDP session** l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus liés aux trusts de domaine

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SID history à travers des forest trusts est atténué par SID Filtering, qui est activé par défaut sur tous les inter-forest trusts. Ceci repose sur l'hypothèse que les intra-forest trusts sont sûrs, la forêt étant considérée comme la frontière de sécurité plutôt que le domaine, selon la position de Microsoft.
- Cependant, il y a un inconvénient : SID Filtering peut perturber des applications et l'accès des utilisateurs, entraînant parfois sa désactivation.

### **Selective Authentication:**

- Pour les inter-forest trusts, l'utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des autorisations explicites sont nécessaires pour que les utilisateurs accèdent aux domaines et serveurs du trusting domain ou de la forêt.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du writable Configuration Naming Context (NC) ni contre les attaques visant le trust account.

[**Plus d'informations sur les trusts de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abus AD basé sur LDAP depuis des implants sur l'hôte

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD en x64 Beacon Object Files qui s'exécutent entièrement à l'intérieur d'un implant sur l'hôte (par ex., Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de connexion courant sur LDAP (389) avec signing/sealing ou LDAPS (636) avec auto certificate trust, donc aucun proxy socks ni artefact disque n'est requis.

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, et `get-groupmembers` résolvent les noms courts/chemins OU en DN complets et extraient les objets correspondants.
- `get-object`, `get-attribute`, et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité) ainsi que les métadonnées forêt/domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, et `get-rbcd` exposent les candidats au roasting, les paramètres de délégation, et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directement depuis LDAP.
- `get-acl` et `get-writable --detailed` analysent la DACL pour lister les trustees, les droits (GenericAll/WriteDACL/WriteOwner/attribute writes), et l'héritage, fournissant des cibles immédiates pour une escalade de privilèges via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d'écriture LDAP pour l'escalade et la persistance

- Les BOFs de création d'objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l'opérateur de préparer de nouveaux principals ou comptes machine partout où existent des droits sur les OU. `add-groupmember`, `set-password`, `add-attribute`, et `set-attribute` détournent directement les cibles dès que des droits write-property sont trouvés.
- Les commandes axées sur les ACL telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, et `add-dcsync` traduisent WriteDACL/WriteOwner sur n'importe quel objet AD en resets de mot de passe, contrôle d'appartenance à des groupes, ou privilèges de réplication DCSync sans laisser d'artefacts PowerShell/ADSI. Les contreparties `remove-*` permettent de nettoyer les ACE injectés.

### Délégation, roasting, et abus Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (UAC toggle) le marque pour AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent msDS-AllowedToDelegateTo, les flags UAC, ou msDS-AllowedToActOnBehalfOfOtherIdentity depuis le beacon, activant des chemins d'attaque constrained/unconstrained/RBCD et éliminant le besoin de PowerShell distant ou RSAT.

### Injection sidHistory, déplacement d'OU, et façonnage de la surface d'attaque

- `add-sidhistory` injecte des SIDs privilégiés dans la SID history d'un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant une héritation d'accès furtive entièrement via LDAP/LDAPS.
- `move-object` change le DN/OU des ordinateurs ou utilisateurs, permettant à un attaquant de déplacer des actifs dans des OUs où des droits délégués existent déjà avant d'abuser de `set-password`, `add-groupmember`, ou `add-spn`.
- Des commandes de suppression fortement ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après que l'opérateur a récolté des identifiants ou établi une persistance, minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Il est recommandé que les Domain Admins ne puissent se connecter qu'aux Domain Controllers, en évitant leur utilisation sur d'autres hôtes.
- **Service Account Privileges**: Les services ne devraient pas être exécutés avec les privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation**: Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Mettre en place du leurre implique d'installer des pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou marqués Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.
- Un exemple concret implique l'utilisation d'outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de leurre sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: Les indicateurs suspects incluent un ObjectSID atypique, des connexions peu fréquentes, les dates de création, et un faible nombre d'échecs de mot de passe.
- **General Indicators**: Comparer les attributs des objets potentiellement leurres avec ceux des objets réels peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier de telles tromperies.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Éviter l'énumération de sessions sur les Domain Controllers pour prévenir la détection par ATA.
- **Ticket Impersonation**: Utiliser des clés **aes** pour la création de tickets aide à échapper à la détection en n'abaissant pas vers NTLM.
- **DCSync Attacks**: Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)

{{#include ../../banners/hacktricks-training.md}}
