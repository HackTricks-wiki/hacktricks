# Mythic

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το Mythic;

Το Mythic είναι ένα open-source, modular, collaborative command and control (C2) framework σχεδιασμένο για red teaming. Επιτρέπει στους operators να διαχειρίζονται και να αναπτύσσουν agents (payloads) σε διαφορετικά λειτουργικά συστήματα, συμπεριλαμβανομένων των Windows, Linux και macOS. Το Mythic παρέχει ένα browser UI για multi-operator tasking, file handling, SOCKS/rpfwd διαχείριση και payload generation.

Σε αντίθεση με monolithic frameworks, το ίδιο το repository του Mythic **δεν** περιλαμβάνει payload types ή C2 profiles. Οι agents, wrappers και C2 profiles συνήθως εγκαθίστανται ως εξωτερικά components και μπορούν να ενημερώνονται ανεξάρτητα από τον core του Mythic.

### Εγκατάσταση

Για να εγκαταστήσετε το Mythic, ακολουθήστε τις οδηγίες στο επίσημο **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ένα συνηθισμένο bootstrap από το Mythic directory είναι:
```bash
sudo make
sudo ./mythic-cli start
```
Αν το Mythic ήδη εκτελείται, συνήθως μπορείς να προσθέσεις ένα νέο agent ή profile με `./mythic-cli install github ...` και μετά είτε να επανεκκινήσεις το Mythic είτε απλώς να ξεκινήσεις το νέο component απευθείας.

### Agents

Το Mythic υποστηρίζει πολλαπλά agents, τα οποία είναι τα **payloads που εκτελούν tasks στα compromised systems**. Κάθε agent μπορεί να προσαρμοστεί σε συγκεκριμένες ανάγκες και μπορεί να εκτελείται σε διαφορετικά operating systems.

Από προεπιλογή το Mythic δεν έχει εγκατεστημένα agents. Τα open-source community agents βρίσκονται στο [**https://github.com/MythicAgents**](https://github.com/MythicAgents), και το [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) είναι χρήσιμο για να ελέγξεις γρήγορα τα υποστηριζόμενα operating systems, payload formats, wrappers, και C2 profiles.

Για να εγκαταστήσεις ένα agent από εκείνο το org μπορείς να τρέξεις:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Η μορφή `sudo -E` είναι χρήσιμη όταν κάνετε εγκατάσταση από περιβάλλον χωρίς root. Μπορείτε να προσθέσετε νέα agents με την προηγούμενη εντολή ακόμη κι αν το Mythic εκτελείται ήδη.

### C2 Profiles

Τα C2 profiles στο Mythic ορίζουν **πώς οι agents επικοινωνούν με τον Mythic server**. Καθορίζουν το communication protocol, τις μεθόδους κρυπτογράφησης και άλλες ρυθμίσεις. Μπορείτε να δημιουργήσετε και να διαχειριστείτε C2 profiles μέσω του Mythic web interface.

Από προεπιλογή το Mythic εγκαθίσταται χωρίς profiles, ωστόσο είναι δυνατό να κατεβάσετε κάποια profiles από το repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) εκτελώντας:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Τρέχοντα operator-relevant profiles που πρέπει να έχεις υπόψη:

- [`http`](https://github.com/MythicC2Profiles/http): basic asynchronous GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): πιο ευέλικτο HTTP traffic με πολλαπλά callback domains, fail-over/round-robin rotation, custom headers/query parameters, και message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) τοποθετημένα σε cookies, headers, query parameters, ή body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): JSON/TOML-driven HTTP message shaping όταν το static `http` profile είναι πολύ αναγνωρίσιμο.

### Current platform notes

- Πολλά public agents και profiles πλέον εγκαθίστανται με pre-built remote container images.
Αν κάνεις fork ένα component ή το patchάρεις locally και το Mythic συνεχίζει να χρησιμοποιεί το παλιό
behavior, έλεγξε τις generated `.env` entries για `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, και `*_USE_VOLUME`· η ενεργοποίηση του
`*_USE_BUILD_CONTEXT="true"` είναι συνήθως αυτό που κάνει το Mythic να ξαναχτίσει από το
local Docker context σου αντί να επαναχρησιμοποιεί σιωπηλά το remote image.
- Τα Browser scripts είναι ένα από τα πιο υψηλής αξίας quality-of-life features του Mythic για operators:
μπορούν να μετατρέπουν raw command output σε πίνακες, screenshot
viewers, download links, και buttons που στέλνουν follow-on tasking απευθείας
από το UI. Αυτό είναι ιδιαίτερα χρήσιμο για επαναλαμβανόμενα `ls`, `ps`, triage,
και file-browser workflows.
- Τα νεότερα Mythic builds υποστηρίζουν επίσης interactive tasking και Push C2 patterns
που μειώνουν την ανάγκη για `sleep 0` polling κατά τη διάρκεια PTY/SOCKS/rpfwd-heavy
operations. Όταν ένα agent/profile το υποστηρίζει, αυτό συνήθως έχει μικρότερο overhead
από το να βομβαρδίζεις τον server με συνεχόμενα check-ins μόνο και μόνο για να παραμείνει
χρησιμοποιήσιμο ένα interactive channel.

### Wrapper payloads

Τα Wrapper payloads σου επιτρέπουν να κρατήσεις την ίδια agent logic ενώ αλλάζεις την on-disk representation που παραδίδεται ή γίνεται persistent.

- `service_wrapper`: μετατρέπει ένα άλλο payload σε Windows service executable, κάτι που είναι χρήσιμο όταν η execution path απαιτεί έγκυρο service binary.
- `scarecrow_wrapper`: τυλίγει compatible shellcode με τον ScareCrow loader για να δημιουργήσει loader-backed outputs όπως EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Το Apollo είναι ένα Windows agent γραμμένο σε C# χρησιμοποιώντας το 4.0 .NET Framework και σχεδιασμένο για χρήση σε SpecterOps training offerings.

Εγκατάστασέ το με:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Σημειώσεις τρέχοντος build/profile

- Το Apollo μπορεί προς το παρόν να παράγει payloads `WinExe`, `Shellcode`, `Service` και `Source`.
- Τα πιο συχνά χρησιμοποιούμενα Apollo profiles είναι `http`, `httpx`, `smb`, `tcp` και `websocket`.
- Το `httpx` είναι συνήθως η πιο ευέλικτη επιλογή όταν χρειάζεσαι domain rotation, proxy support, custom message placement και message transforms αντί για το παλιότερο στατικό `http` profile.
- Το Apollo υποστηρίζει wrapper payloads όπως `service_wrapper` και `scarecrow_wrapper`.
- Τα `register_file` και `register_assembly` είναι τα staging primitives για `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` και `powerpick`. Στα τρέχοντα Apollo builds, αυτά τα staged artifacts αποθηκεύονται στην πλευρά του client ως DPAPI-protected AES256 blobs.
- Τα αποτελέσματα των `ls` και `ps` ενσωματώνονται ιδιαίτερα καλά με τα browser scripts του Mythic και το file/process browser, κάτι που κάνει το triage του operator αισθητά πιο γρήγορο σε collaborative operations.
- Τα fork-and-run jobs του Apollo κληρονομούν τις ρυθμίσεις sacrificial process από το
`spawnto_x86` / `spawnto_x64`, κληρονομούν την επιλογή γονέα από το `ppid`, και
στη συνέχεια χρησιμοποιούν το currently selected injection primitive. Στην πράξη, αυτό σημαίνει
ότι το OPSEC tuning σου για μία εντολή συχνά επηρεάζει ταυτόχρονα το
`execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` και `spawn`.
- Τα current documented Apollo injection backends περιλαμβάνουν `CreateRemoteThread`,
`QueueUserAPC` (early-bird style) και `NtCreateThreadEx` μέσω syscalls. Χρησιμοποίησε
`get_injection_techniques` πριν από noisy post-exploitation και
`set_injection_technique` αν χρειάζεται να αλλάξεις από ένα primitive που
συγκρούεται με τον στόχο ή με την εντολή που θέλεις να εκτελέσεις.
- Το `blockdlls` επηρεάζει μόνο sacrificial processes που δημιουργούνται για post-exploitation
jobs. Σε συνδυασμό με έναν λιγότερο ύποπτο `spawnto_x64` στόχο από το default
bare `rundll32.exe`, αυτή είναι μία από τις πιο εύκολες αλλαγές στην πλευρά του Apollo
πριν από την εκτέλεση assembly/PowerShell-heavy tasking.

Αυτός ο agent έχει πολλές εντολές που τον κάνουν πολύ παρόμοιο με το Beacon του Cobalt Strike με μερικά extras. Μεταξύ αυτών, υποστηρίζει:

### Common actions

- `cat`: Εμφανίζει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει τον τρέχοντα working directory
- `cp`: Αντιγράφει ένα αρχείο από μια τοποθεσία σε άλλη
- `ls`: Εμφανίζει αρχεία και directories στον τρέχοντα κατάλογο ή στο καθορισμένο path
- `ifconfig`: Παίρνει network adapters και interfaces
- `netstat`: Παίρνει TCP και UDP connection information
- `pwd`: Εμφανίζει τον τρέχοντα working directory
- `ps`: Εμφανίζει τις διεργασίες που τρέχουν στο target system (με πρόσθετες πληροφορίες)
- `jobs`: Εμφανίζει όλα τα running jobs που σχετίζονται με long-running tasking
- `download`: Κατεβάζει ένα αρχείο από το target system στο local machine
- `upload`: Ανεβάζει ένα αρχείο από το local machine στο target system
- `reg_query`: Κάνει query registry keys και values στο target system
- `reg_write_value`: Γράφει μια νέα τιμή σε ένα καθορισμένο registry key
- `sleep`: Αλλάζει το sleep interval του agent, το οποίο καθορίζει πόσο συχνά κάνει check in με τον Mythic server
- Και πολλές άλλες, χρησιμοποίησε `help` για να δεις την πλήρη λίστα των διαθέσιμων εντολών.

### Privilege escalation

- `getprivs`: Ενεργοποιεί όσες περισσότερες privileges γίνεται στο current thread token
- `getsystem`: Ανοίγει ένα handle στο winlogon και αντιγράφει το token, ανεβάζοντας ουσιαστικά τα privileges σε επίπεδο SYSTEM
- `make_token`: Δημιουργεί ένα νέο logon session και το εφαρμόζει στον agent, επιτρέποντας impersonation άλλου χρήστη
- `steal_token`: Κλέβει ένα primary token από άλλη διεργασία, επιτρέποντας στον agent να impersonate τον χρήστη εκείνης της διεργασίας
- `pth`: Pass-the-Hash attack, επιτρέποντας στον agent να αυθεντικοποιηθεί ως χρήστης χρησιμοποιώντας το NTLM hash του χωρίς να χρειάζεται το plaintext password
- `mimikatz`: Τρέχει Mimikatz commands για εξαγωγή credentials, hashes και άλλων ευαίσθητων πληροφοριών από τη μνήμη ή τη SAM database
- `rev2self`: Επαναφέρει το token του agent στο primary token του, ρίχνοντας ουσιαστικά τα privileges πίσω στο αρχικό επίπεδο
- `ppid`: Αλλάζει το parent process για post-exploitation jobs καθορίζοντας ένα νέο parent process ID, επιτρέποντας καλύτερο έλεγχο στο execution context του job
- `printspoofer`: Εκτελεί PrintSpoofer commands για παράκαμψη των security measures του print spooler, επιτρέποντας privilege escalation ή code execution
- `dcsync`: Συγχρονίζει τα Kerberos keys ενός χρήστη στο local machine, επιτρέποντας offline password cracking ή περαιτέρω attacks
- `ticket_cache_add`: Προσθέτει ένα Kerberos ticket στο τρέχον logon session ή σε ένα καθορισμένο, επιτρέποντας ticket reuse ή impersonation

### Process execution

- `assembly_inject`: Επιτρέπει την έγχυση ενός .NET assembly loader σε μια remote process
- `blockdlls`: Αποκλείει τη φόρτωση μη Microsoft signed DLLs σε post-exploitation jobs
- `execute_assembly`: Εκτελεί ένα .NET assembly στο context του agent
- `execute_coff`: Εκτελεί ένα COFF file στη μνήμη, επιτρέποντας in-memory execution μεταγλωττισμένου κώδικα
- `execute_pe`: Εκτελεί ένα unmanaged executable (PE)
- `keylog_inject`: Εγχέει έναν keylogger σε άλλη διεργασία και στέλνει τα keystrokes πίσω στο keylog view του Mythic
- `screenshot` / `screenshot_inject`: Καταγράφει το τρέχον desktop απευθείας ή
με έγχυση ενός screenshot assembly σε target process/session
- `get_injection_techniques`: Εμφανίζει τις διαθέσιμες injection techniques και την currently selected μία
- `inline_assembly`: Εκτελεί ένα .NET assembly σε ένα disposable AppDomain, επιτρέποντας προσωρινή εκτέλεση κώδικα χωρίς να επηρεάζεται η κύρια διεργασία του agent
- `register_assembly`: Καταχωρεί ένα .NET assembly για μεταγενέστερη εκτέλεση
- `register_file`: Καταχωρεί ένα αρχείο στο agent cache για μεταγενέστερο `execute_*` ή PowerShell tasking
- `run`: Εκτελεί ένα binary στο target system, χρησιμοποιώντας το system's PATH για να βρει το executable
- `set_injection_technique`: Αλλάζει το injection primitive που χρησιμοποιείται από post-exploitation jobs
- `shinject`: Εγχέει shellcode σε μια remote process, επιτρέποντας in-memory execution arbitrary code
- `inject`: Εγχέει agent shellcode σε μια remote process, επιτρέποντας in-memory execution του κώδικα του agent
- `spawn`: Δημιουργεί ένα νέο agent session στο καθορισμένο executable, επιτρέποντας την εκτέλεση shellcode σε μια νέα διεργασία
- `spawnto_x64` and `spawnto_x86`: Αλλάζουν το default binary που χρησιμοποιείται σε post-exploitation jobs σε ένα καθορισμένο path αντί να χρησιμοποιούν το `rundll32.exe` χωρίς params, το οποίο είναι πολύ noisy.

### Mythic Forge

Αυτό επιτρέπει να **φορτώσεις COFF/BOF** files από το Mythic Forge, το οποίο είναι ένα repository από pre-compiled payloads και tools που μπορούν να εκτελεστούν στο target system. Με όλες τις εντολές που μπορούν να φορτωθούν, θα είναι δυνατό να εκτελεστούν common actions τρέχοντάς τες στην current agent process ως BOFs (συνήθως με καλύτερο OPSEC από το να εκκινείς ξεχωριστή διεργασία).

Ξεκίνα την εγκατάστασή τους με:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

For BOFs, remember that Forge does **not** just pass one flat argument string
to Apollo. It maps BOF parameters into Mythic's typed-array format and then
forwards them into Apollo's `execute_coff` flow. If a Forge-loaded BOF behaves
strangely, check the expected BOF argument types / entrypoint rather than only
the command line you typed.

### PowerShell & scripting execution

- `powershell_import`: Εισάγει ένα νέο PowerShell script (.ps1) στην cache του agent για μελλοντική εκτέλεση
- `powershell`: Εκτελεί μια PowerShell εντολή στο context του agent, επιτρέποντας προηγμένο scripting και αυτοματοποίηση
- `powerpick`: Εγχέει ένα PowerShell loader assembly σε ένα sacrificial process και εκτελεί μια PowerShell εντολή (χωρίς powershell logging).
- `psinject`: Εκτελεί PowerShell σε συγκεκριμένο process, για στοχευμένη εκτέλεση scripts στο context ενός άλλου process
- `shell`: Εκτελεί μια shell εντολή στο context του agent, παρόμοια με την εκτέλεση μιας εντολής στο cmd.exe

### Lateral Movement

- `jump_psexec`: Χρησιμοποιεί την τεχνική PsExec για να κινηθεί laterally σε έναν νέο host, πρώτα αντιγράφοντας το εκτελέσιμο του Apollo agent (apollo.exe) και εκτελώντας το.
- `jump_wmi`: Χρησιμοποιεί την τεχνική WMI για να κινηθεί laterally σε έναν νέο host, πρώτα αντιγράφοντας το εκτελέσιμο του Apollo agent (apollo.exe) και εκτελώντας το.
- `link` and `unlink`: Δημιουργούν και καταργούν P2P links (για παράδειγμα over SMB/TCP) μεταξύ callbacks.
- `wmiexecute`: Εκτελεί μια εντολή στο τοπικό ή στο καθορισμένο remote system χρησιμοποιώντας WMI, με προαιρετικά credentials για impersonation.
- `net_dclist`: Ανακτά μια λίστα από domain controllers για το καθορισμένο domain, χρήσιμο για τον εντοπισμό πιθανών στόχων για lateral movement.
- `net_localgroup`: Παραθέτει local groups στο καθορισμένο computer, με προεπιλογή το localhost αν δεν οριστεί computer.
- `net_localgroup_member`: Ανακτά τη συμμετοχή σε local group για ένα καθορισμένο group στο τοπικό ή remote computer, επιτρέποντας enumeration χρηστών σε συγκεκριμένα groups.
- `net_shares`: Παραθέτει remote shares και την προσβασιμότητά τους στο καθορισμένο computer, χρήσιμο για τον εντοπισμό πιθανών στόχων για lateral movement.
- `socks`: Ενεργοποιεί ένα SOCKS 5 compliant proxy στο target network, επιτρέποντας tunneling της κίνησης μέσω του compromised host. Συμβατό με tools όπως proxychains.
- `rpfwd`: Ξεκινά να ακούει σε μια καθορισμένη θύρα στο target host και προωθεί την κίνηση μέσω Mythic σε μια remote IP και θύρα, επιτρέποντας remote access σε services στο target network.
- `listpipes`: Παραθέτει όλα τα named pipes στο local system, που μπορεί να είναι χρήσιμο για lateral movement ή privilege escalation μέσω αλληλεπίδρασης με IPC mechanisms.

For the lower-level WMI execution primitives used underneath `jump_wmi` or `wmiexecute`, check [WmiExec](lateral-movement/wmiexec.md). For broader pivoting patterns, check [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Εμφανίζει λεπτομερείς πληροφορίες για συγκεκριμένες εντολές ή γενικές πληροφορίες για όλες τις διαθέσιμες εντολές στον agent.
- `clear`: Σημειώνει tasks ως 'cleared' ώστε να μην μπορούν να ανακτηθούν από agents. Μπορείς να ορίσεις `all` για να καθαρίσεις όλα τα tasks ή `task Num` για να καθαρίσεις ένα συγκεκριμένο task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon is a Golang agent that compiles into **Linux and macOS** executables.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Σημειώσεις τρέχοντος build/profile

- Τα τρέχοντα Poseidon builds στοχεύουν Linux και macOS τόσο σε `x86_64` όσο και σε `arm64`.
- Τα υποστηριζόμενα output formats περιλαμβάνουν native executables καθώς και shared-library style outputs όπως `dylib` και `so`.
- Το Poseidon υποστηρίζει `http`, `websocket`, `tcp`, και `dynamichttp`, και οι τρέχοντες builders εκθέτουν multi-egress ρυθμίσεις όπως `egress_order` και failover thresholds.
- Επιλογές build-time όπως `proxy_bypass` και `garble` αξίζει να τις ελέγχεις όταν χρειάζεσαι είτε πιο καθαρή συμπεριφορά δικτύου είτε επιπλέον Go binary obfuscation.
- Το `pty` είναι μία από τις πιο χρήσιμες νεότερες quality-of-life εντολές για Linux/macOS
operations γιατί ανοίγει ένα interactive PTY και μπορεί να εκθέσει ένα Mythic-side
port για πληρέστερη terminal αλληλεπίδραση χωρίς να καταφεύγεις στο παλιότερο `sleep 0`
+ SOCKS workaround.
- Τα τρέχοντα docs του Poseidon είναι ιδιαίτερα ενδιαφέροντα για macOS-heavy
tradecraft: το `jxa` εκτελεί JavaScript for Automation in-memory,
το `screencapture` παίρνει το logged-in desktop, το `clipboard_monitor` κάνει stream αλλαγές του pasteboard, το `execute_library` φορτώνει ένα local dylib και καλεί μια
function από αυτό, και το `libinject` αναγκάζει ένα remote process να φορτώσει ένα on-disk
dylib.
- Για long-running jobs, να θυμάσαι ότι το Poseidon εκτελεί post-exploitation work
σε goroutines/threads που είναι cooperative και όχι hard-killable. Τα docs επίσης αναφέρουν ρητά ότι προς το παρόν δεν υπάρχει built-in agent
obfuscation, οπότε το build/profile-level tradecraft μετρά περισσότερο από ό,τι με έντονα obfuscated commercial implants.

Για macOS-specific tradecraft γύρω από Mythic-backed operations, JAMF abuse, ή MDM-as-C2 ιδέες, δες [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Όταν χρησιμοποιείται σε Linux ή macOS έχει μερικές ενδιαφέρουσες εντολές:

### Κοινές ενέργειες

- `cat`: Εμφάνισε τα περιεχόμενα ενός αρχείου
- `cd`: Άλλαξε το τρέχον working directory
- `chmod`: Άλλαξε τα permissions ενός αρχείου
- `config`: Δες το τρέχον config και τις πληροφορίες host
- `cp`: Αντέγραψε ένα αρχείο από μια τοποθεσία σε άλλη
- `curl`: Εκτέλεσε ένα single web request με προαιρετικά headers και method
- `upload`: Ανέβασε ένα αρχείο στο target
- `download`: Κατέβασε ένα αρχείο από το target system στο local machine
- Και πολλά ακόμη

### Αναζήτηση ευαίσθητων πληροφοριών

- `triagedirectory`: Βρες ενδιαφέροντα αρχεία μέσα σε έναν directory σε έναν host, όπως ευαίσθητα αρχεία ή credentials.
- `getenv`: Πάρε όλες τις τρέχουσες environment variables.

### macOS-specific tradecraft

- `jxa`: Εκτέλεσε JavaScript for Automation in-memory μέσω `OSAScript`, κάτι που είναι
χρήσιμο για native macOS post-exploitation χωρίς να αφήνεις ξεχωριστά script
files.
- `clipboard_monitor`: Κάνε poll το pasteboard και ανέφερε τις αλλαγές πίσω στο Mythic,
κάτι που είναι χρήσιμο για credential/token theft workflows που βασίζονται σε copy/paste.
- `screencapture`: Κατέγραψε το user's desktop στο macOS.
- `execute_library`: Φόρτωσε ένα dylib από το disk και κάλεσε μια συγκεκριμένη exported function.
- `libinject`: Ένεσε ένα shellcode stub που αναγκάζει άλλο macOS process να φορτώσει ένα dylib από το disk.
- `persist_launchd`: Δημιούργησε LaunchAgent / LaunchDaemon persistence απευθείας από τον agent.

### Lateral movement

- `ssh`: Κάνε SSH σε host χρησιμοποιώντας τα καθορισμένα credentials και άνοιξε ένα PTY χωρίς να εκκινήσεις ssh.
- `sshauth`: Κάνε SSH στο καθορισμένο host(s) χρησιμοποιώντας τα καθορισμένα credentials. Μπορείς επίσης να το χρησιμοποιήσεις για να εκτελέσεις μια συγκεκριμένη εντολή στους remote hosts μέσω SSH ή για να κάνεις SCP files.
- `link_tcp`: Σύνδεσε με έναν άλλο agent μέσω TCP, επιτρέποντας άμεση επικοινωνία μεταξύ agents.
- `link_webshell`: Σύνδεσε με έναν agent χρησιμοποιώντας το webshell P2P profile, επιτρέποντας remote access στο web interface του agent.
- `rpfwd`: Ξεκίνα ή σταμάτα ένα Reverse Port Forward, επιτρέποντας remote access σε services στο target network.
- `socks`: Ξεκίνα ή σταμάτα ένα SOCKS5 proxy στο target network, επιτρέποντας tunneling της κίνησης μέσω του compromised host. Συμβατό με εργαλεία όπως το proxychains.
- `portscan`: Σάρωσε host(s) για ανοιχτά ports, χρήσιμο για τον εντοπισμό πιθανών targets για lateral movement ή περαιτέρω attacks.

### Εκτέλεση διεργασιών

- `shell`: Εκτέλεσε μια single shell command μέσω `/bin/sh`, επιτρέποντας άμεση εκτέλεση εντολών στο target system.
- `run`: Εκτέλεσε μια εντολή από το disk με arguments, επιτρέποντας την εκτέλεση binaries ή scripts στο target system.
- `pty`: Άνοιξε ένα interactive PTY, επιτρέποντας άμεση αλληλεπίδραση με το shell στο target system.




## Αναφορές

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
