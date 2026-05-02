# Mythic

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το Mythic;

Το Mythic είναι ένα open-source, modular, collaborative command and control (C2) framework σχεδιασμένο για red teaming. Επιτρέπει στους operators να διαχειρίζονται και να αναπτύσσουν agents (payloads) σε διαφορετικά λειτουργικά συστήματα, συμπεριλαμβανομένων των Windows, Linux και macOS. Το Mythic παρέχει ένα browser UI για multi-operator tasking, file handling, SOCKS/rpfwd management και payload generation.

Σε αντίθεση με τα monolithic frameworks, το ίδιο το repository του Mythic **δεν** περιλαμβάνει payload types ή C2 profiles. Agents, wrappers και C2 profiles εγκαθίστανται συνήθως ως external components και μπορούν να ενημερώνονται ανεξάρτητα από το Mythic core.

### Installation

Για να εγκαταστήσετε το Mythic, ακολουθήστε τις οδηγίες στο επίσημο **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ένα συνηθισμένο bootstrap από το Mythic directory είναι:
```bash
sudo make
sudo ./mythic-cli start
```
Αν το Mythic εκτελείται ήδη, συνήθως μπορείς να προσθέσεις ένα νέο agent ή profile με `./mythic-cli install github ...` και μετά είτε να επανεκκινήσεις το Mythic είτε απλώς να ξεκινήσεις απευθείας το νέο component.

### Agents

Το Mythic υποστηρίζει πολλαπλούς agents, οι οποίοι είναι τα **payloads που εκτελούν εργασίες στα compromised συστήματα**. Κάθε agent μπορεί να προσαρμοστεί σε συγκεκριμένες ανάγκες και μπορεί να εκτελεστεί σε διαφορετικά λειτουργικά συστήματα.

Από προεπιλογή το Mythic δεν έχει εγκατεστημένους agents. Οι open-source community agents βρίσκονται στο [**https://github.com/MythicAgents**](https://github.com/MythicAgents), και ο [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) είναι χρήσιμος για να ελέγξεις γρήγορα τα υποστηριζόμενα λειτουργικά συστήματα, payload formats, wrappers και C2 profiles.

Για να εγκαταστήσεις έναν agent από αυτό το org μπορείς να τρέξεις:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Η μορφή `sudo -E` είναι χρήσιμη όταν κάνετε εγκατάσταση από περιβάλλον χωρίς root. Μπορείτε να προσθέσετε νέα agents με την προηγούμενη εντολή ακόμα κι αν το Mythic ήδη εκτελείται.

### C2 Profiles

Τα C2 profiles στο Mythic ορίζουν **πώς οι agents επικοινωνούν με τον Mythic server**. Καθορίζουν το communication protocol, τις μεθόδους encryption και άλλες ρυθμίσεις. Μπορείτε να δημιουργήσετε και να διαχειριστείτε C2 profiles μέσω του Mythic web interface.

By default το Mythic εγκαθίσταται χωρίς profiles, ωστόσο είναι δυνατό να κατεβάσετε κάποια profiles από το repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) εκτελώντας:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): more flexible HTTP traffic with multiple callback domains, fail-over/round-robin rotation, custom headers/query parameters, and message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placed in cookies, headers, query parameters, or body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping when the static `http` profile is too recognizable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Το Apollo μπορεί επί του παρόντος να εκδίδει payloads `WinExe`, `Shellcode`, `Service` και `Source`.
- Τα πιο συνηθισμένα Apollo profiles είναι τα `http`, `httpx`, `smb`, `tcp` και `websocket`.
- Το `httpx` είναι συνήθως η πιο ευέλικτη επιλογή όταν χρειάζεσαι domain rotation, proxy support, custom message placement και message transforms αντί για το παλαιότερο static `http` profile.
- Το Apollo υποστηρίζει wrapper payloads όπως `service_wrapper` και `scarecrow_wrapper`.
- Τα `register_file` και `register_assembly` είναι τα staging primitives για `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` και `powerpick`. Στα τρέχοντα Apollo builds, αυτά τα staged artifacts αποθηκεύονται client-side ως DPAPI-protected AES256 blobs.
- Τα αποτελέσματα των `ls` και `ps` ενσωματώνονται ιδιαίτερα καλά με τα browser scripts του Mythic και με το file/process browser, κάτι που κάνει το operator triage αισθητά πιο γρήγορο σε collaborative operations.

Αυτό το agent έχει πολλές commands που το κάνουν πολύ παρόμοιο με το Beacon του Cobalt Strike, με μερικά extras. Μεταξύ αυτών, υποστηρίζει:

### Common actions

- `cat`: Εμφάνισε τα περιεχόμενα ενός αρχείου
- `cd`: Αλλαγή του τρέχοντος working directory
- `cp`: Αντιγραφή ενός αρχείου από μία τοποθεσία σε άλλη
- `ls`: Εμφάνισε αρχεία και directories στον τρέχοντα κατάλογο ή στο καθορισμένο path
- `ifconfig`: Λήψη πληροφοριών για network adapters και interfaces
- `netstat`: Λήψη πληροφοριών για TCP και UDP connections
- `pwd`: Εμφάνιση του τρέχοντος working directory
- `ps`: Εμφάνιση των running processes στο target system (με πρόσθετες πληροφορίες)
- `jobs`: Εμφάνιση όλων των running jobs που σχετίζονται με long-running tasking
- `download`: Λήψη ενός αρχείου από το target system στο local machine
- `upload`: Αποστολή ενός αρχείου από το local machine στο target system
- `reg_query`: Ερώτημα για registry keys και values στο target system
- `reg_write_value`: Εγγραφή μιας νέας τιμής σε ένα καθορισμένο registry key
- `sleep`: Αλλαγή του sleep interval του agent, το οποίο καθορίζει πόσο συχνά κάνει check in με τον Mythic server
- Και πολλά άλλα, χρησιμοποίησε το `help` για να δεις την πλήρη λίστα διαθέσιμων commands.

### Privilege escalation

- `getprivs`: Ενεργοποίηση όσο το δυνατόν περισσότερων privileges στο τρέχον thread token
- `getsystem`: Άνοιγμα handle σε winlogon και αντιγραφή του token, κάνοντας effectively privilege escalation σε επίπεδο SYSTEM
- `make_token`: Δημιουργία νέας logon session και εφαρμογή της στον agent, επιτρέποντας impersonation άλλου user
- `steal_token`: Κλοπή ενός primary token από άλλο process, επιτρέποντας στον agent να impersonate τον user εκείνου του process
- `pth`: Pass-the-Hash attack, επιτρέποντας στον agent να authenticate ως user χρησιμοποιώντας το NTLM hash του χωρίς να χρειάζεται το plaintext password
- `mimikatz`: Εκτέλεση Mimikatz commands για εξαγωγή credentials, hashes και άλλων ευαίσθητων πληροφοριών από memory ή από τη SAM database
- `rev2self`: Επαναφορά του token του agent στο primary token του, effectively ρίχνοντας τα privileges πίσω στο αρχικό επίπεδο
- `ppid`: Αλλαγή του parent process για post-exploitation jobs, καθορίζοντας νέο parent process ID, επιτρέποντας καλύτερο έλεγχο του job execution context
- `printspoofer`: Εκτέλεση PrintSpoofer commands για παράκαμψη των print spooler security measures, επιτρέποντας privilege escalation ή code execution
- `dcsync`: Συγχρονισμός των Kerberos keys ενός user στο local machine, επιτρέποντας offline password cracking ή περαιτέρω attacks
- `ticket_cache_add`: Προσθήκη ενός Kerberos ticket στην τρέχουσα logon session ή σε μια καθορισμένη, επιτρέποντας ticket reuse ή impersonation

### Process execution

- `assembly_inject`: Επιτρέπει την έγχυση ενός .NET assembly loader σε ένα remote process
- `blockdlls`: Αποκλείει τη φόρτωση μη-Microsoft signed DLLs σε post-exploitation jobs
- `execute_assembly`: Εκτελεί ένα .NET assembly στο context του agent
- `execute_coff`: Εκτελεί ένα COFF file στη memory, επιτρέποντας in-memory execution compiled code
- `execute_pe`: Εκτελεί ένα unmanaged executable (PE)
- `get_injection_techniques`: Εμφάνιση των διαθέσιμων injection techniques και της τρέχουσας επιλεγμένης
- `inline_assembly`: Εκτελεί ένα .NET assembly σε ένα disposable AppDomain, επιτρέποντας προσωρινή εκτέλεση code χωρίς να επηρεάζεται το main process του agent
- `register_assembly`: Καταχώριση ενός .NET assembly για μεταγενέστερη εκτέλεση
- `register_file`: Καταχώριση ενός αρχείου στο agent cache για μεταγενέστερο `execute_*` ή PowerShell tasking
- `run`: Εκτελεί ένα binary στο target system, χρησιμοποιώντας το system's PATH για να βρει το executable
- `set_injection_technique`: Αλλαγή του injection primitive που χρησιμοποιείται από post-exploitation jobs
- `shinject`: Injects shellcode σε ένα remote process, επιτρέποντας in-memory execution arbitrary code
- `inject`: Injects agent shellcode σε ένα remote process, επιτρέποντας in-memory execution του code του agent
- `spawn`: Δημιουργεί μια νέα agent session στο καθορισμένο executable, επιτρέποντας την εκτέλεση shellcode σε νέο process
- `spawnto_x64` και `spawnto_x86`: Αλλαγή του default binary που χρησιμοποιείται σε post-exploitation jobs σε καθορισμένο path αντί για το `rundll32.exe` χωρίς params, το οποίο είναι πολύ noisy.

### Mythic Forge

Αυτό επιτρέπει να **load COFF/BOF** files από το Mythic Forge, το οποίο είναι ένα repository από pre-compiled payloads και tools που μπορούν να εκτελεστούν στο target system. Με όλες τις commands που μπορούν να φορτωθούν, θα είναι δυνατό να εκτελούνται common actions τρέχοντάς τες στο current agent process ως BOFs (συνήθως με καλύτερο OPSEC από το να ανοίγει ξεχωριστό process).

Ξεκίνα την εγκατάστασή τους με:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Έπειτα, χρησιμοποίησε το `forge_collections` για να εμφανίσεις τα COFF/BOF modules από το Mythic Forge, ώστε να μπορείς να τα επιλέξεις και να τα φορτώσεις στη μνήμη του agent για εκτέλεση. Από προεπιλογή, οι παρακάτω 2 collections προστίθενται στο Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Αφού φορτωθεί ένα module, θα εμφανιστεί στη λίστα ως άλλη εντολή όπως `forge_bof_sa-whoami` ή `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Εισάγει ένα νέο PowerShell script (.ps1) στο agent cache για μεταγενέστερη εκτέλεση
- `powershell`: Εκτελεί μια PowerShell εντολή στο context του agent, επιτρέποντας προχωρημένο scripting και automation
- `powerpick`: Injects ένα PowerShell loader assembly σε ένα sacrificial process και εκτελεί μια PowerShell εντολή (without powershell logging).
- `psinject`: Εκτελεί PowerShell σε ένα καθορισμένο process, επιτρέποντας στοχευμένη εκτέλεση scripts στο context ενός άλλου process
- `shell`: Εκτελεί μια shell command στο context του agent, παρόμοια με την εκτέλεση μιας εντολής στο cmd.exe

### Lateral Movement

- `jump_psexec`: Χρησιμοποιεί την PsExec technique για να κινηθεί laterally σε έναν νέο host, αντιγράφοντας πρώτα το Apollo agent executable (apollo.exe) και εκτελώντας το.
- `jump_wmi`: Χρησιμοποιεί την WMI technique για να κινηθεί laterally σε έναν νέο host, αντιγράφοντας πρώτα το Apollo agent executable (apollo.exe) και εκτελώντας το.
- `link` and `unlink`: Δημιουργούν και καταργούν P2P links (για παράδειγμα over SMB/TCP) μεταξύ callbacks.
- `wmiexecute`: Εκτελεί μια command στο local ή στο καθορισμένο remote system χρησιμοποιώντας WMI, με προαιρετικά credentials για impersonation.
- `net_dclist`: Ανακτά μια λίστα από domain controllers για το καθορισμένο domain, χρήσιμη για τον εντοπισμό πιθανών targets για lateral movement.
- `net_localgroup`: Παραθέτει local groups στο καθορισμένο computer, με προεπιλογή το localhost αν δεν οριστεί computer.
- `net_localgroup_member`: Ανακτά το local group membership για ένα καθορισμένο group στο local ή remote computer, επιτρέποντας enumeration χρηστών σε συγκεκριμένες ομάδες.
- `net_shares`: Παραθέτει remote shares και τη διαθεσιμότητά τους στο καθορισμένο computer, χρήσιμη για τον εντοπισμό πιθανών targets για lateral movement.
- `socks`: Ενεργοποιεί ένα SOCKS 5 compliant proxy στο target network, επιτρέποντας tunneling της traffic μέσω του compromised host. Συμβατό με tools όπως proxychains.
- `rpfwd`: Ξεκινά να ακούει σε μια καθορισμένη port στο target host και προωθεί την traffic μέσω του Mythic σε ένα remote IP και port, επιτρέποντας remote access σε services στο target network.
- `listpipes`: Παραθέτει όλα τα named pipes στο local system, κάτι που μπορεί να είναι χρήσιμο για lateral movement ή privilege escalation μέσω αλληλεπίδρασης με IPC mechanisms.

Για τα lower-level WMI execution primitives που χρησιμοποιούνται από κάτω από τα `jump_wmi` ή `wmiexecute`, δες [WmiExec](lateral-movement/wmiexec.md). Για ευρύτερα pivoting patterns, δες [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Εμφανίζει λεπτομερείς πληροφορίες για συγκεκριμένες commands ή γενικές πληροφορίες για όλες τις διαθέσιμες commands στον agent.
- `clear`: Σημειώνει tasks ως 'cleared' ώστε να μην μπορούν να ανακτηθούν από agents. Μπορείς να ορίσεις `all` για να καθαρίσεις όλα τα tasks ή `task Num` για να καθαρίσεις ένα συγκεκριμένο task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Ο Poseidon είναι ένας Golang agent που μεταγλωττίζεται σε εκτελέσιμα **Linux and macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- Current Poseidon builds target Linux and macOS on both `x86_64` and `arm64`.
- Supported output formats include native executables plus shared-library style outputs such as `dylib` and `so`.
- Poseidon supports `http`, `websocket`, `tcp`, and `dynamichttp`, and current builders expose multi-egress settings such as `egress_order` and failover thresholds.
- Build-time options such as `proxy_bypass` and `garble` are worth checking when you need either cleaner network behavior or extra Go binary obfuscation.

For macOS-specific tradecraft around Mythic-backed operations, JAMF abuse, or MDM-as-C2 ideas, check [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Όταν χρησιμοποιείται σε Linux ή macOS έχει μερικές ενδιαφέρουσες εντολές:

### Common actions

- `cat`: Εκτύπωσε τα περιεχόμενα ενός αρχείου
- `cd`: Αλλαγή του τρέχοντος working directory
- `chmod`: Αλλαγή των permissions ενός αρχείου
- `config`: Προβολή τρέχουσας config και host information
- `cp`: Αντιγραφή ενός αρχείου από μια τοποθεσία σε άλλη
- `curl`: Εκτέλεση ενός μεμονωμένου web request με προαιρετικά headers και method
- `upload`: Ανεβάσε ένα αρχείο στον στόχο
- `download`: Κατέβασε ένα αρχείο από το target system στο τοπικό μηχάνημα
- Και πολλά ακόμα

### Search Sensitive Information

- `triagedirectory`: Βρες ενδιαφέροντα αρχεία μέσα σε έναν κατάλογο σε έναν host, όπως sensitive files ή credentials.
- `getenv`: Πάρε όλες τις τρέχουσες environment variables.

### Move laterally

- `ssh`: SSH σε host χρησιμοποιώντας τα καθορισμένα credentials και άνοιγμα PTY χωρίς spawning ssh.
- `sshauth`: SSH σε καθορισμένο host(s) χρησιμοποιώντας τα καθορισμένα credentials. Μπορείς επίσης να το χρησιμοποιήσεις για να εκτελέσεις μια συγκεκριμένη command στα remote hosts μέσω SSH ή να το χρησιμοποιήσεις για SCP files.
- `link_tcp`: Σύνδεση σε άλλο agent μέσω TCP, επιτρέποντας direct communication μεταξύ agents.
- `link_webshell`: Σύνδεση σε έναν agent χρησιμοποιώντας το webshell P2P profile, επιτρέποντας remote access στο web interface του agent.
- `rpfwd`: Εκκίνηση ή διακοπή ενός Reverse Port Forward, επιτρέποντας remote access σε υπηρεσίες στο target network.
- `socks`: Εκκίνηση ή διακοπή ενός SOCKS5 proxy στο target network, επιτρέποντας tunneling της κίνησης μέσω του compromised host. Συμβατό με tools όπως proxychains.
- `portscan`: Σάρωση host(s) για open ports, χρήσιμο για τον εντοπισμό πιθανών targets για lateral movement ή περαιτέρω attacks.

### Process execution

- `shell`: Εκτέλεση μιας μεμονωμένης shell command μέσω /bin/sh, επιτρέποντας direct execution εντολών στο target system.
- `run`: Εκτέλεση μιας command από το disk με arguments, επιτρέποντας την εκτέλεση binaries ή scripts στο target system.
- `pty`: Άνοιγμα ενός interactive PTY, επιτρέποντας direct interaction με το shell στο target system.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
