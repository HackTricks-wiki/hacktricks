# Mythic

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το Mythic;

Το Mythic είναι ένα open-source, modular και συνεργατικό framework command and control (C2), σχεδιασμένο για red teaming. Επιτρέπει στους operators να διαχειρίζονται και να αναπτύσσουν agents (payloads) σε διαφορετικά λειτουργικά συστήματα, συμπεριλαμβανομένων των Windows, Linux και macOS. Το Mythic παρέχει ένα browser UI για tasking πολλαπλών operators, διαχείριση αρχείων, διαχείριση SOCKS/rpfwd και δημιουργία payloads.

Σε αντίθεση με τα monolithic frameworks, το ίδιο το repository του Mythic **δεν** περιλαμβάνει τύπους payloads ή C2 profiles. Οι agents, τα wrappers και τα C2 profiles εγκαθίστανται συνήθως ως εξωτερικά components και μπορούν να ενημερώνονται ανεξάρτητα από τον Mythic core.

### Εγκατάσταση

Για να εγκαταστήσετε το Mythic, ακολουθήστε τις οδηγίες στο επίσημο **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ένα συνηθισμένο bootstrap από τον κατάλογο Mythic είναι:
```bash
sudo make
sudo ./mythic-cli start
```
Εάν το Mythic εκτελείται ήδη, συνήθως μπορείτε να προσθέσετε ένα νέο agent ή profile με `./mythic-cli install github ...` και, στη συνέχεια, είτε να κάνετε restart το Mythic είτε απλώς να εκκινήσετε απευθείας το νέο component.

### Agents

Το Mythic υποστηρίζει πολλαπλά agents, τα οποία είναι τα **payloads που εκτελούν tasks στα compromised systems**. Κάθε agent μπορεί να προσαρμοστεί σε συγκεκριμένες ανάγκες και να εκτελεστεί σε διαφορετικά operating systems.

Από προεπιλογή, το Mythic δεν έχει εγκατεστημένους agents. Οι agents της open-source κοινότητας βρίσκονται στο [**https://github.com/MythicAgents**](https://github.com/MythicAgents), ενώ το [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) είναι χρήσιμο για τον γρήγορο έλεγχο των υποστηριζόμενων operating systems, payload formats, wrappers και C2 profiles.<sup>[[1]](#references)</sup>

Για να εγκαταστήσετε έναν agent από αυτό το org, μπορείτε να εκτελέσετε:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Η μορφή `sudo -E` είναι χρήσιμη όταν κάνετε εγκατάσταση από περιβάλλον που δεν είναι root. Μπορείτε να προσθέσετε νέους agents με την προηγούμενη εντολή, ακόμη και αν το Mythic εκτελείται ήδη.

### C2 Profiles

Τα C2 profiles στο Mythic καθορίζουν **τον τρόπο επικοινωνίας των agents με τον Mythic server**. Καθορίζουν το πρωτόκολλο επικοινωνίας, τις μεθόδους κρυπτογράφησης και άλλες ρυθμίσεις. Μπορείτε να δημιουργείτε και να διαχειρίζεστε C2 profiles μέσω του web interface του Mythic.

Από προεπιλογή, το Mythic εγκαθίσταται χωρίς profiles. Ωστόσο, μπορείτε να κατεβάσετε ορισμένα profiles από το repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) εκτελώντας:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Τρέχοντα profiles που είναι σχετικά για τους operators:

- [`http`](https://github.com/MythicC2Profiles/http): βασική ασύγχρονη κίνηση GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): πιο ευέλικτη HTTP κίνηση με πολλαπλά callback domains, fail-over/round-robin rotation, custom headers/query parameters και message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) που τοποθετούνται σε cookies, headers, query parameters ή body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): shaping HTTP messages μέσω JSON/TOML όταν το static `http` profile είναι υπερβολικά αναγνωρίσιμο.

### Τρέχουσες σημειώσεις πλατφόρμας

- Πολλά public agents και profiles εγκαθίστανται πλέον με pre-built remote container images.
Αν κάνετε fork ενός component ή εφαρμόσετε patch τοπικά και το Mythic συνεχίζει να χρησιμοποιεί την παλιά
συμπεριφορά, ελέγξτε τα generated `.env` entries για `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` και `*_USE_VOLUME`. Η ενεργοποίηση του
`*_USE_BUILD_CONTEXT="true"` είναι συνήθως αυτό που κάνει το Mythic να πραγματοποιεί rebuild από το
τοπικό Docker context σας, αντί να επαναχρησιμοποιεί σιωπηρά το remote image.
- Τα browser scripts είναι ένα από τα πιο χρήσιμα quality-of-life features του Mythic
για operators: μπορούν να μετατρέπουν raw command output σε tables, screenshot
viewers, download links, search links και buttons που εκδίδουν follow-on
tasking απευθείας από το UI. Τα τρέχοντα Mythic builds επιτρέπουν σε κάθε operator να διατηρεί
τα δικά του scripts, να τα ενεργοποιεί ή απενεργοποιεί global ή ανά task και να έχει καλύτερα αποτελέσματα
όταν οι agents επιστρέφουν structured JSON αντί για plaintext. Αυτό είναι ιδιαίτερα
χρήσιμο για επαναλαμβανόμενα `ls`, `ps`, triage και file-browser workflows.<sup>[[4]](#references)[[6]](#references)</sup>
- Τα νεότερα Mythic builds υποστηρίζουν επίσης interactive tasking και Push C2 patterns,
τα οποία μειώνουν την ανάγκη για polling με `sleep 0` κατά τη διάρκεια operations με PTY/SOCKS/rpfwd.
Όταν ένας agent/profile το υποστηρίζει, αυτό συνήθως έχει μικρότερο overhead
από το συνεχές hammering του server με check-ins, απλώς για να παραμένει usable ένα interactive
channel.<sup>[[3]](#references)</sup>
- Τα Mythic builders της εποχής 3.4 έχουν μεγαλύτερη επίγνωση του context από όσο υπονοούν παλαιότερα writeups:
οι build parameters μπορούν πλέον να ομαδοποιούνται ή να αποκρύπτονται ανάλογα με το επιλεγμένο OS
ή άλλες build options, τα payload types μπορούν να δηλώνουν αν υποστηρίζουν
πολλαπλά C2 profiles ή multiple instances του ίδιου C2 σε ένα build
και οι C2 parameter deviations επιτρέπουν σε έναν agent να αποκρύπτει fields που στην πράξη
δεν υλοποιεί. Αυτό έχει σημασία όταν εναλλάσσεστε μεταξύ `http`, `httpx`, `smb`,
`tcp` και `websocket`, επειδή το safe/valid build surface δεν είναι πλέον
μια επίπεδη static form.<sup>[[5]](#references)</sup>
- Αν δημιουργείτε ένα custom agent/profile pair και δεν θέλετε το JSON message format ή το default crypto του Mythic στο wire, χρησιμοποιήστε ένα
`translation_container`: το Mythic αφαιρεί το UUID, παραδίδει το encrypted blob και το key material στον translator μέσω gRPC και αναμένει agent-native bytes ως απάντηση. Αυτός είναι ο καθαρός τρόπος για την υποστήριξη binary protocols, custom framing ή agent-side encryption χωρίς να ξαναγράψετε ολόκληρο τον server.
- Να θυμάστε ότι τα linked/P2P callbacks δεν μεταφέρουν μόνο tasking. Το Mythic
`get_tasking` flow μπορεί επίσης να μεταφέρει responses μαζί με `delegates`,
`socks`, `rpfwd` και `interactive` data. Στην πράξη, ένα egress callback μπορεί να εξυπηρετεί inner callbacks και pivot channels στον ίδιο polling loop. Αν τα child
agents πραγματοποιούν τα δικά τους periodic check-ins, το `get_delegate_tasks=false` εμποδίζει το
parent να καταναλώσει κατά λάθος τα queued jobs του inner callback.

### Wrapper payloads

Τα wrapper payloads σας επιτρέπουν να διατηρείτε την ίδια agent logic, αλλάζοντας ταυτόχρονα την on-disk representation που παραδίδεται ή αποθηκεύεται.

- `service_wrapper`: μετατρέπει ένα άλλο payload σε Windows service executable, κάτι χρήσιμο όταν το execution path απαιτεί έγκυρο service binary.
- `scarecrow_wrapper`: τυλίγει συμβατό shellcode με τον ScareCrow loader για τη δημιουργία loader-backed outputs όπως EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Το Apollo είναι ένας Windows agent γραμμένος σε C#, με χρήση του 4.0 .NET Framework, σχεδιασμένος για χρήση σε SpecterOps training offerings.<sup>[[2]](#references)</sup>

Εγκαταστήστε το με:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Τρέχουσες σημειώσεις build/profile

- Το Apollo μπορεί επί του παρόντος να δημιουργεί payloads `WinExe`, `Shellcode`, `Service` και `Source`.
- Τα commonly used Apollo profiles είναι `http`, `httpx`, `smb`, `tcp` και `websocket`.
- Το `httpx` είναι συνήθως η πιο flexible επιλογή όταν χρειάζεστε domain rotation, proxy support, custom message placement και message transforms, αντί για το παλαιότερο static `http` profile.
- Το Apollo είναι ένα από τα πιο feature-complete community agents και επί του παρόντος εκθέτει Mythic-side integrations όπως browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 και P2P routing.
- Το Apollo υποστηρίζει wrapper payloads όπως `service_wrapper` και `scarecrow_wrapper`.
- Το Apollo υποστηρίζει dynamic command loading, ώστε να μπορείτε να διατηρείτε το αρχικό payload μικρό και να φορτώνετε αργότερα επιπλέον commands ή Forge modules, αντί να κάνετε compile κάθε post-ex capability στο πρώτο build.
- Κατά τη δημιουργία shellcode output, ο τρέχων builder του Apollo εκθέτει επίσης επιλογές Donut format (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) και Donut bypass behavior (`None`, `Abort on fail`, `Continue on fail`). Αυτό είναι χρήσιμο όταν ο τελικός στόχος είναι να κάνετε re-wrap το shellcode με `service_wrapper`, `scarecrow_wrapper` ή custom loader.
- Τα `register_file` και `register_assembly` είναι τα staging primitives για τα `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` και `powerpick`. Στα τρέχοντα Apollo builds, αυτά τα staged artifacts αποθηκεύονται σε client-side cache ως DPAPI-protected AES256 blobs.
- Τα αποτελέσματα των `ls` και `ps` ενσωματώνονται ιδιαίτερα καλά με τα browser scripts και το file/process browser του Mythic, γεγονός που κάνει το operator triage αισθητά ταχύτερο σε collaborative operations.
- Τα fork-and-run jobs του Apollo κληρονομούν τις ρυθμίσεις sacrificial process από τα
`spawnto_x86` / `spawnto_x64`, κληρονομούν την επιλογή parent από το `ppid` και
στη συνέχεια χρησιμοποιούν το τρέχον επιλεγμένο injection primitive. Στην πράξη, αυτό σημαίνει ότι το
OPSEC tuning για ένα command συχνά επηρεάζει ταυτόχρονα τα `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` και `spawn`.
- Τα τρέχοντα documented Apollo injection backends περιλαμβάνουν τα
`CreateRemoteThread`, `QueueUserAPC` (early-bird style) και
`NtCreateThreadEx` μέσω syscalls. Χρησιμοποιήστε το
`get_injection_techniques` πριν από noisy post-exploitation και το
`set_injection_technique` αν χρειάζεται να αλλάξετε από ένα primitive που
συγκρούεται με τον στόχο ή με το command που θέλετε να εκτελέσετε.
- Το `blockdlls` επηρεάζει μόνο τα sacrificial processes που δημιουργούνται για post-exploitation
jobs. Σε συνδυασμό με έναν λιγότερο ύποπτο στόχο `spawnto_x64` από το προεπιλεγμένο
bare `rundll32.exe`, αυτή είναι μία από τις ευκολότερες αλλαγές στην πλευρά του Apollo που μπορείτε να κάνετε
πριν εκτελέσετε assembly/PowerShell-heavy tasking.

Αυτός ο agent διαθέτει πολλά commands, γεγονός που τον κάνει πολύ παρόμοιο με το Beacon του Cobalt Strike, με ορισμένα extras. Μεταξύ άλλων, υποστηρίζει:

### Common actions

- `cat`: Εκτυπώνει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει τον τρέχοντα working directory
- `cp`: Αντιγράφει ένα αρχείο από μία τοποθεσία σε άλλη
- `ls`: Παραθέτει αρχεία και directories στον τρέχοντα directory ή στο specified path
- `ifconfig`: Λαμβάνει network adapters και interfaces
- `netstat`: Λαμβάνει πληροφορίες για TCP και UDP connections
- `pwd`: Εκτυπώνει τον τρέχοντα working directory
- `ps`: Παραθέτει τις running processes στο target system (με επιπλέον πληροφορίες)
- `jobs`: Παραθέτει όλα τα running jobs που σχετίζονται με long-running tasking
- `download`: Κατεβάζει ένα αρχείο από το target system στο local machine
- `upload`: Ανεβάζει ένα αρχείο από το local machine στο target system
- `reg_query`: Κάνει query σε registry keys και values στο target system
- `reg_write_value`: Γράφει ένα νέο value σε specified registry key
- `sleep`: Αλλάζει το sleep interval του agent, το οποίο καθορίζει πόσο συχνά επικοινωνεί με τον Mythic server
- Και πολλά άλλα, χρησιμοποιήστε το `help` για να δείτε την πλήρη λίστα των διαθέσιμων commands.

### Privilege escalation

- `getprivs`: Ενεργοποιεί όσο το δυνατόν περισσότερα privileges στο current thread token
- `getsystem`: Ανοίγει ένα handle στο winlogon και κάνει duplicate το token, αυξάνοντας αποτελεσματικά τα privileges στο επίπεδο SYSTEM
- `make_token`: Δημιουργεί ένα νέο logon session και το εφαρμόζει στον agent, επιτρέποντας impersonation άλλου user
- `steal_token`: Κλέβει ένα primary token από άλλη process, επιτρέποντας στον agent να κάνει impersonate τον user αυτής της process
- `pth`: Pass-the-Hash attack, που επιτρέπει στον agent να κάνει authenticate ως user χρησιμοποιώντας το NTLM hash του, χωρίς να χρειάζεται το plaintext password
- `mimikatz`: Εκτελεί Mimikatz commands για την εξαγωγή credentials, hashes και άλλων sensitive πληροφοριών από τη μνήμη ή τη SAM database
- `rev2self`: Επαναφέρει το token του agent στο primary token του, αφαιρώντας αποτελεσματικά τα privileges και επιστρέφοντας στο αρχικό επίπεδο
- `ppid`: Αλλάζει τη parent process για post-exploitation jobs, καθορίζοντας ένα νέο parent process ID και επιτρέποντας καλύτερο έλεγχο του job execution context
- `printspoofer`: Εκτελεί PrintSpoofer commands για την παράκαμψη security measures του print spooler, επιτρέποντας privilege escalation ή code execution
- `dcsync`: Συγχρονίζει τα Kerberos keys ενός user στο local machine, επιτρέποντας offline password cracking ή περαιτέρω attacks
- `ticket_cache_add`: Προσθέτει ένα Kerberos ticket στο current logon session ή σε ένα specified session, επιτρέποντας ticket reuse ή impersonation

### Process execution

- `assembly_inject`: Επιτρέπει την injection ενός .NET assembly loader σε remote process
- `blockdlls`: Εμποδίζει τη φόρτωση DLLs χωρίς Microsoft signature σε post-exploitation jobs
- `execute_assembly`: Εκτελεί ένα .NET assembly στο context του agent
- `execute_coff`: Εκτελεί ένα COFF file στη μνήμη, επιτρέποντας in-memory execution compiled code
- `execute_pe`: Εκτελεί ένα unmanaged executable (PE)
- `keylog_inject`: Κάνει injection ενός keylogger σε άλλη process και streamάρει τα keystrokes πίσω στο Mythic's keylog view
- `screenshot` / `screenshot_inject`: Καταγράφει το current desktop απευθείας ή
κάνοντας injection ενός screenshot assembly σε target process/session
- `get_injection_techniques`: Εμφανίζει τις διαθέσιμες injection techniques και την τρέχουσα επιλεγμένη
- `inline_assembly`: Εκτελεί ένα .NET assembly σε disposable AppDomain, επιτρέποντας προσωρινό code execution χωρίς να επηρεάζεται η main process του agent
- `register_assembly`: Κάνει register ένα .NET assembly για μεταγενέστερη εκτέλεση
- `register_file`: Κάνει register ένα file στο agent cache για μεταγενέστερο `execute_*` ή PowerShell tasking
- `run`: Εκτελεί ένα binary στο target system, χρησιμοποιώντας το system's PATH για να εντοπίσει το executable
- `set_injection_technique`: Αλλάζει το injection primitive που χρησιμοποιείται από τα post-exploitation jobs
- `shinject`: Κάνει injection shellcode σε remote process, επιτρέποντας in-memory execution arbitrary code
- `inject`: Κάνει injection agent shellcode σε remote process, επιτρέποντας in-memory execution του code του agent
- `spawn`: Δημιουργεί ένα νέο agent session στο specified executable, επιτρέποντας την εκτέλεση shellcode σε νέα process
- `spawnto_x64` και `spawnto_x86`: Αλλάζουν το default binary που χρησιμοποιείται σε post-exploitation jobs σε specified path, αντί να χρησιμοποιούν το `rundll32.exe` χωρίς params, το οποίο είναι πολύ noisy.

### Mythic Forge

Αυτό επιτρέπει το **load COFF/BOF** files από το Mythic Forge, το οποίο είναι repository από pre-compiled payloads και tools που μπορούν να εκτελεστούν στο target system. Με όλα τα commands που μπορούν να φορτωθούν, θα είναι δυνατή η εκτέλεση common actions στο current agent process ως BOFs (συνήθως με καλύτερο OPSEC από τη δημιουργία ξεχωριστής process).

Ξεκινήστε την εγκατάστασή τους με:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Στη συνέχεια, χρησιμοποιήστε το `forge_collections` για να εμφανίσετε τα COFF/BOF modules από το Mythic Forge, ώστε να μπορείτε να τα επιλέξετε και να τα φορτώσετε στη μνήμη του agent για εκτέλεση. Από προεπιλογή, οι ακόλουθες 2 collections προστίθενται στο Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Μετά τη φόρτωση ενός module, θα εμφανίζεται στη λίστα ως μια ακόμη εντολή, όπως `forge_bof_sa-whoami` ή `forge_bof_sa-netuser`.

Για τα BOFs, θυμηθείτε ότι το Forge **δεν** μεταβιβάζει απλώς ένα ενιαίο flat argument string στο Apollo. Αντιστοιχίζει τις παραμέτρους των BOF στη typed-array format του Mythic και στη συνέχεια τις προωθεί στη ροή `execute_coff` του Apollo. Αν ένα BOF που φορτώθηκε από το Forge συμπεριφέρεται παράξενα, ελέγξτε τους αναμενόμενους τύπους arguments / entrypoint του BOF και όχι μόνο τη γραμμή εντολών που πληκτρολογήσατε. Σημειώστε επίσης ότι ο νεότερος BOF loader του Apollo άλλαξε τον χειρισμό των arguments σε σχέση με πολύ παλαιότερα builds της εποχής του 2.3.1, επομένως παλιά BOFs ή collections μπορεί να αποτύχουν αποκλειστικά επειδή άλλαξαν οι απαιτήσεις marshaling.

### Εκτέλεση PowerShell & scripting

- `powershell_import`: Εισάγει ένα νέο PowerShell script (.ps1) στο cache του agent για μεταγενέστερη εκτέλεση
- `powershell`: Εκτελεί μια εντολή PowerShell στο context του agent, επιτρέποντας advanced scripting και automation
- `powerpick`: Εγχέει ένα PowerShell loader assembly σε μια sacrificial process και εκτελεί μια εντολή PowerShell (χωρίς powershell logging).
- `psinject`: Εκτελεί PowerShell σε μια καθορισμένη process, επιτρέποντας στοχευμένη εκτέλεση scripts στο context μιας άλλης process
- `shell`: Εκτελεί μια shell command στο context του agent, παρόμοια με την εκτέλεση μιας εντολής στο cmd.exe

### Lateral Movement

- `jump_psexec`: Χρησιμοποιεί την τεχνική PsExec για lateral movement σε νέο host, αντιγράφοντας πρώτα το executable του Apollo agent (apollo.exe) και εκτελώντας το.
- `jump_wmi`: Χρησιμοποιεί την τεχνική WMI για lateral movement σε νέο host, αντιγράφοντας πρώτα το executable του Apollo agent (apollo.exe) και εκτελώντας το.
- `link` και `unlink`: Δημιουργούν και τερματίζουν P2P links (για παράδειγμα μέσω SMB/TCP) μεταξύ callbacks.
- `wmiexecute`: Εκτελεί μια εντολή στο local ή στο καθορισμένο remote system χρησιμοποιώντας WMI, με προαιρετικά credentials για impersonation.
- `net_dclist`: Ανακτά μια λίστα με domain controllers για το καθορισμένο domain, χρήσιμη για τον εντοπισμό πιθανών targets για lateral movement.
- `net_localgroup`: Εμφανίζει τα local groups στον καθορισμένο computer, χρησιμοποιώντας ως προεπιλογή το localhost αν δεν καθοριστεί computer.
- `net_localgroup_member`: Ανακτά τα μέλη ενός local group για ένα καθορισμένο group στον local ή remote computer, επιτρέποντας την enumeration χρηστών σε συγκεκριμένα groups.
- `net_shares`: Εμφανίζει τα remote shares και την προσβασιμότητά τους στον καθορισμένο computer, χρήσιμο για τον εντοπισμό πιθανών targets για lateral movement.
- `socks`: Ενεργοποιεί έναν SOCKS 5 compliant proxy στο target network, επιτρέποντας το tunneling traffic μέσω του compromised host. Είναι συμβατό με tools όπως το proxychains.
- `rpfwd`: Ξεκινά να ακούει σε μια καθορισμένη port στο target host και προωθεί traffic μέσω του Mythic σε ένα remote IP και port, επιτρέποντας remote access σε services στο target network.
- `listpipes`: Εμφανίζει όλα τα named pipes στο local system, τα οποία μπορεί να φανούν χρήσιμα για lateral movement ή privilege escalation μέσω interaction με IPC mechanisms.

Για τα lower-level WMI execution primitives που χρησιμοποιούνται κάτω από τα `jump_wmi` ή `wmiexecute`, δείτε το [WmiExec](lateral-movement/wmiexec.md). Για ευρύτερα pivoting patterns, δείτε το [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Διάφορες εντολές
- `help`: Εμφανίζει detailed information για συγκεκριμένες εντολές ή γενικές πληροφορίες για όλες τις διαθέσιμες εντολές στον agent.
- `clear`: Σημειώνει τα tasks ως 'cleared', ώστε να μην μπορούν να παραληφθούν από agents. Μπορείτε να καθορίσετε `all` για την εκκαθάριση όλων των tasks ή `task Num` για την εκκαθάριση ενός συγκεκριμένου task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Το Poseidon είναι ένας Golang agent που μεταγλωττίζεται σε executables για **Linux και macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Τρέχουσες σημειώσεις build/profile

- Τα τρέχοντα builds του Poseidon στοχεύουν σε Linux και macOS τόσο σε `x86_64` όσο και σε `arm64`.
- Οι υποστηριζόμενες μορφές εξόδου περιλαμβάνουν native executables, καθώς και μορφές τύπου shared library, όπως `dylib` και `so`.
- Το Poseidon υποστηρίζει `http`, `websocket`, `tcp` και `dynamichttp`, ενώ οι τρέχοντες builders εκθέτουν ρυθμίσεις multi-egress, όπως `egress_order` και thresholds για failover.
- Τα τρέχοντα capability metadata του Poseidon διαφημίζουν επίσης browser scripts, ενσωμάτωση file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd και P2P. Επομένως, μπορεί να λειτουργήσει ως πραγματικός Linux/macOS pivot node και όχι απλώς ως απλό remote shell.
- Αξίζει να ελέγξετε build-time επιλογές όπως `proxy_bypass` και `garble` όταν χρειάζεστε είτε καθαρότερη network συμπεριφορά είτε επιπλέον Go binary obfuscation.
- Το `pty` είναι ένα από τα πιο χρήσιμα νεότερα quality-of-life commands για
λειτουργίες Linux/macOS, επειδή ανοίγει ένα interactive PTY και μπορεί να εκθέσει
μια Mythic-side port για πληρέστερη αλληλεπίδραση με το terminal, χωρίς να
καταφεύγετε στο παλαιότερο workaround `sleep 0`
+ SOCKS.
- Τα τρέχοντα docs του Poseidon είναι ιδιαίτερα ενδιαφέροντα για macOS-heavy
tradecraft: το `jxa` εκτελεί JavaScript for Automation in-memory,
το `screencapture` καταγράφει το logged-in desktop, το `clipboard_monitor`
μεταδίδει αλλαγές στο pasteboard, το `execute_library` φορτώνει ένα local dylib
και καλεί μια function από αυτό, ενώ το `libinject` αναγκάζει ένα remote process
να φορτώσει ένα dylib από τον δίσκο.
- Για jobs μεγάλης διάρκειας, θυμηθείτε ότι το Poseidon εκτελεί post-exploitation work
σε goroutines/threads που είναι cooperative και όχι hard-killable. Τα
docs σημειώνουν επίσης ρητά ότι επί του παρόντος δεν υπάρχει ενσωματωμένο agent
obfuscation, επομένως το build/profile-level tradecraft έχει μεγαλύτερη σημασία
σε σχέση με heavily obfuscated commercial implants.

Για macOS-specific tradecraft γύρω από Mythic-backed operations, JAMF abuse ή ιδέες MDM-as-C2, ελέγξτε το [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Όταν χρησιμοποιείται σε Linux ή macOS, διαθέτει ορισμένα ενδιαφέροντα commands:

### Common actions

- `cat`: Εκτυπώνει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει το τρέχον working directory
- `chmod`: Αλλάζει τα permissions ενός αρχείου
- `config`: Προβάλλει το τρέχον config και τις πληροφορίες του host
- `cp`: Αντιγράφει ένα αρχείο από μία τοποθεσία σε άλλη
- `curl`: Εκτελεί ένα μεμονωμένο web request με προαιρετικά headers και method
- `upload`: Ανεβάζει ένα αρχείο στον στόχο
- `download`: Κατεβάζει ένα αρχείο από το target system στο local machine
- Και πολλά ακόμη

### Αναζήτηση ευαίσθητων πληροφοριών

- `triagedirectory`: Εντοπίζει ενδιαφέροντα αρχεία μέσα σε έναν directory σε ένα host, όπως ευαίσθητα αρχεία ή credentials.
- `getenv`: Λαμβάνει όλες τις τρέχουσες environment variables.

### macOS-specific tradecraft

- `jxa`: Εκτελεί JavaScript for Automation in-memory μέσω του `OSAScript`, κάτι
που είναι χρήσιμο για native macOS post-exploitation χωρίς την απόθεση ξεχωριστών script
files.
- `clipboard_monitor`: Κάνει poll στο pasteboard και αναφέρει τις αλλαγές πίσω στο Mythic,
κάτι χρήσιμο για workflows κλοπής credentials/tokens που βασίζονται σε copy/paste.
- `screencapture`: Καταγράφει το desktop του χρήστη σε macOS.
- `execute_library`: Φορτώνει ένα dylib από τον δίσκο και καλεί μια συγκεκριμένη exported function.
- `libinject`: Κάνει inject ένα shellcode stub που αναγκάζει ένα άλλο macOS process να φορτώσει ένα dylib από τον δίσκο.
- `persist_launchd`: Δημιουργεί persistence μέσω LaunchAgent / LaunchDaemon απευθείας από τον agent.

### Lateral movement

- `ssh`: Κάνει SSH σε host χρησιμοποιώντας τα καθορισμένα credentials και ανοίγει ένα PTY χωρίς να κάνει spawn το ssh.
- `sshauth`: Κάνει SSH στους καθορισμένους host(s) χρησιμοποιώντας τα καθορισμένα credentials. Μπορείτε επίσης να το χρησιμοποιήσετε για την εκτέλεση συγκεκριμένου command στους remote hosts μέσω SSH ή για SCP files.
- `link_tcp`: Συνδέεται με έναν άλλο agent μέσω TCP, επιτρέποντας την άμεση επικοινωνία μεταξύ agents.
- `link_webshell`: Συνδέεται με έναν agent χρησιμοποιώντας το webshell P2P profile, επιτρέποντας remote access στο web interface του agent.
- `rpfwd`: Εκκινεί ή σταματά ένα Reverse Port Forward, επιτρέποντας remote access σε services στο target network.
- `socks`: Εκκινεί ή σταματά έναν SOCKS5 proxy στο target network, επιτρέποντας tunneling traffic μέσω του compromised host. Είναι συμβατό με tools όπως το proxychains.
- `portscan`: Κάνει scan σε host(s) για open ports, χρήσιμο για τον εντοπισμό πιθανών targets για lateral movement ή περαιτέρω attacks.

### Εκτέλεση processes

- `shell`: Εκτελεί ένα μεμονωμένο shell command μέσω του /bin/sh, επιτρέποντας την άμεση εκτέλεση commands στο target system.
- `run`: Εκτελεί ένα command από τον δίσκο με arguments, επιτρέποντας την εκτέλεση binaries ή scripts στο target system.
- `pty`: Ανοίγει ένα interactive PTY, επιτρέποντας την άμεση αλληλεπίδραση με το shell στο target system.

## Αναφορές

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
