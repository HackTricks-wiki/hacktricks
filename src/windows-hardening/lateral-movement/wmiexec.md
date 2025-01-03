# WmiExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς Λειτουργεί

Διεργασίες μπορούν να ανοιχτούν σε hosts όπου το όνομα χρήστη και είτε ο κωδικός πρόσβασης είτε το hash είναι γνωστά μέσω της χρήσης WMI. Οι εντολές εκτελούνται χρησιμοποιώντας WMI από το Wmiexec, παρέχοντας μια ημι-διαδραστική εμπειρία shell.

**dcomexec.py:** Χρησιμοποιώντας διαφορετικά DCOM endpoints, αυτό το script προσφέρει μια ημι-διαδραστική shell παρόμοια με το wmiexec.py, εκμεταλλευόμενο συγκεκριμένα το αντικείμενο ShellBrowserWindow DCOM. Υποστηρίζει επί του παρόντος τα αντικείμενα MMC20. Application, Shell Windows και Shell Browser Window. (source: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Βασικές Αρχές WMI

### Namespace

Δομημένο σε ιεραρχία τύπου καταλόγου, το κορυφαίο επίπεδο του WMI είναι το \root, κάτω από το οποίο οργανώνονται πρόσθετοι κατάλογοι, που αναφέρονται ως namespaces.
Εντολές για την καταγραφή namespaces:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Οι κλάσεις εντός ενός ονόματος χώρου μπορούν να απαριθμηθούν χρησιμοποιώντας:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Κλάσεις**

Η γνώση ενός ονόματος κλάσης WMI, όπως το win32_process, και του ονόματος του χώρου ονομάτων στον οποίο βρίσκεται είναι κρίσιμη για οποιαδήποτε λειτουργία WMI.  
Εντολές για να καταγράψετε τις κλάσεις που αρχίζουν με `win32`:
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

Οι μέθοδοι, οι οποίες είναι μία ή περισσότερες εκτελέσιμες λειτουργίες των κλάσεων WMI, μπορούν να εκτελούνται.
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

Εντολές για να επαληθεύσετε αν η υπηρεσία WMI είναι λειτουργική:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Πληροφορίες Συστήματος και Διαδικασίας

Συγκέντρωση πληροφοριών συστήματος και διαδικασίας μέσω WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Για τους επιτιθέμενους, το WMI είναι ένα ισχυρό εργαλείο για την καταμέτρηση ευαίσθητων δεδομένων σχετικά με συστήματα ή τομείς.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Η απομακρυσμένη ερώτηση WMI για συγκεκριμένες πληροφορίες, όπως οι τοπικοί διαχειριστές ή οι συνδεδεμένοι χρήστες, είναι εφικτή με προσεκτική κατασκευή εντολών.

### **Μη αυτόματη Απομακρυσμένη Ερώτηση WMI**

Η διακριτική αναγνώριση τοπικών διαχειριστών σε μια απομακρυσμένη μηχανή και συνδεδεμένων χρηστών μπορεί να επιτευχθεί μέσω συγκεκριμένων ερωτήσεων WMI. Το `wmic` υποστηρίζει επίσης την ανάγνωση από ένα αρχείο κειμένου για την εκτέλεση εντολών σε πολλαπλούς κόμβους ταυτόχρονα.

Για να εκτελέσετε απομακρυσμένα μια διαδικασία μέσω WMI, όπως η ανάπτυξη ενός πράκτορα Empire, χρησιμοποιείται η παρακάτω δομή εντολής, με την επιτυχία της εκτέλεσης να υποδεικνύεται από μια τιμή επιστροφής "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Αυτή η διαδικασία απεικονίζει την ικανότητα του WMI για απομακρυσμένη εκτέλεση και αναγνώριση συστήματος, επισημαίνοντας τη χρησιμότητά του τόσο για τη διαχείριση συστημάτων όσο και για το pentesting.

## Αναφορές

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Αυτόματα Εργαλεία

- [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{{#include ../../banners/hacktricks-training.md}}
