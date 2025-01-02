# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Come Funziona Spiegato

I processi possono essere aperti su host dove il nome utente e la password o l'hash sono noti attraverso l'uso di WMI. I comandi vengono eseguiti utilizzando WMI da Wmiexec, fornendo un'esperienza di shell semi-interattiva.

**dcomexec.py:** Utilizzando diversi endpoint DCOM, questo script offre una shell semi-interattiva simile a wmiexec.py, sfruttando specificamente l'oggetto DCOM ShellBrowserWindow. Attualmente supporta gli oggetti MMC20. Application, Shell Windows e Shell Browser Window. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Fondamenti di WMI

### Namespace

Strutturato in una gerarchia in stile directory, il contenitore di livello superiore di WMI è \root, sotto il quale sono organizzate ulteriori directory, chiamate namespace.  
Comandi per elencare i namespace:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Le classi all'interno di uno spazio dei nomi possono essere elencate utilizzando:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Classi**

Conoscere il nome di una classe WMI, come win32_process, e lo spazio dei nomi in cui si trova è fondamentale per qualsiasi operazione WMI.  
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

I metodi, che sono una o più funzioni eseguibili delle classi WMI, possono essere eseguiti.
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

### Stato del Servizio WMI

Comandi per verificare se il servizio WMI è operativo:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informazioni su Sistema e Processo

Raccolta di informazioni su sistema e processo tramite WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Per gli attaccanti, WMI è uno strumento potente per enumerare dati sensibili su sistemi o domini.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
La query remota di WMI per informazioni specifiche, come gli amministratori locali o gli utenti connessi, è fattibile con una costruzione attenta dei comandi.

### **Query WMI Remota Manuale**

L'identificazione furtiva degli amministratori locali su una macchina remota e degli utenti connessi può essere ottenuta attraverso query WMI specifiche. `wmic` supporta anche la lettura da un file di testo per eseguire comandi su più nodi contemporaneamente.

Per eseguire un processo in remoto tramite WMI, come il deployment di un agente Empire, viene impiegata la seguente struttura di comando, con l'esecuzione riuscita indicata da un valore di ritorno di "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Questo processo illustra la capacità di WMI per l'esecuzione remota e l'enumerazione del sistema, evidenziando la sua utilità sia per l'amministrazione di sistema che per il pentesting.

## Riferimenti

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Strumenti Automatici

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
