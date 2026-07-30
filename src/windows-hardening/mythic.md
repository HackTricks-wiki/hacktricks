# Mythic

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το Mythic;

Το Mythic είναι ένα open-source, modular και συνεργατικό command and control (C2) framework σχεδιασμένο για red teaming. Επιτρέπει στους operators να διαχειρίζονται και να αναπτύσσουν agents (payloads) σε διαφορετικά λειτουργικά συστήματα, συμπεριλαμβανομένων των Windows, Linux και macOS. Το Mythic παρέχει ένα browser UI για tasking πολλαπλών operators, διαχείριση αρχείων, διαχείριση SOCKS/rpfwd και δημιουργία payloads.

Σε αντίθεση με τα monolithic frameworks, το ίδιο το Mythic repository **δεν** περιλαμβάνει τύπους payloads ή C2 profiles. Τα agents, wrappers και C2 profiles εγκαθίστανται συνήθως ως εξωτερικά components και μπορούν να ενημερώνονται ανεξάρτητα από το Mythic core.

### Εγκατάσταση

Για να εγκαταστήσετε το Mythic, ακολουθήστε τις οδηγίες στο επίσημο **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Ένα συνηθισμένο bootstrap από τον κατάλογο Mythic είναι:
```bash
sudo make
sudo ./mythic-cli start
```
Αν το Mythic εκτελείται ήδη, συνήθως μπορείτε να προσθέσετε ένα νέο agent ή profile με `./mythic-cli install github ...` και, στη συνέχεια, είτε να κάνετε επανεκκίνηση του Mythic είτε απλώς να εκκινήσετε απευθείας το νέο component.

### Agents

Το Mythic υποστηρίζει πολλαπλά agents, τα οποία είναι τα **payloads που εκτελούν εργασίες στα compromised systems**. Κάθε agent μπορεί να προσαρμοστεί σε συγκεκριμένες ανάγκες και να εκτελείται σε διαφορετικά λειτουργικά συστήματα.

Από προεπιλογή, το Mythic δεν έχει εγκατεστημένους agents. Οι agents της open-source κοινότητας βρίσκονται στο [**https://github.com/MythicAgents**](https://github.com/MythicAgents), ενώ το [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) είναι χρήσιμο για γρήγορο έλεγχο των υποστηριζόμενων λειτουργικών συστημάτων, payload formats, wrappers και C2 profiles.

Για να εγκαταστήσετε έναν agent από αυτό το org, μπορείτε να εκτελέσετε:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Η μορφή `sudo -E` είναι χρήσιμη όταν κάνετε εγκατάσταση από περιβάλλον χωρίς δικαιώματα root. Μπορείτε να προσθέσετε νέους agents με την προηγούμενη εντολή, ακόμη και αν το Mythic εκτελείται ήδη.

### C2 Profiles

Τα C2 profiles στο Mythic ορίζουν **τον τρόπο επικοινωνίας των agents με τον Mythic server**. Καθορίζουν το πρωτόκολλο επικοινωνίας, τις μεθόδους κρυπτογράφησης και άλλες ρυθμίσεις. Μπορείτε να δημιουργήσετε και να διαχειριστείτε C2 profiles μέσω του Mythic web interface.

Από προεπιλογή, το Mythic εγκαθίσταται χωρίς profiles. Ωστόσο, μπορείτε να κατεβάσετε ορισμένα profiles από το repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) εκτελώντας:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Τρέχοντα profiles που σχετίζονται με τους operators και πρέπει να έχετε υπόψη:

- [`http`](https://github.com/MythicC2Profiles/http): βασική ασύγχρονη κίνηση GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): πιο ευέλικτη HTTP κίνηση με πολλαπλά callback domains, fail-over/round-robin rotation, custom headers/query parameters και message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) τοποθετημένα σε cookies, headers, query parameters ή στο body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): HTTP message shaping βασισμένο σε JSON/TOML, όταν το static `http` profile είναι υπερβολικά αναγνωρίσιμο.

### Τρέχουσες σημειώσεις για τις πλατφόρμες

- Πολλά public agents και profiles εγκαθίστανται πλέον με pre-built remote container images.
Αν κάνετε fork ένα component ή το τροποποιήσετε τοπικά και το Mythic συνεχίζει να χρησιμοποιεί την παλιά
συμπεριφορά, ελέγξτε τα παραγόμενα entries στο `.env` για τα `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` και `*_USE_VOLUME`. Η ενεργοποίηση του
`*_USE_BUILD_CONTEXT="true"` είναι συνήθως αυτό που κάνει το Mythic να κάνει rebuild από το
τοπικό Docker context αντί να επαναχρησιμοποιεί σιωπηρά το remote image.
- Τα Browser scripts είναι ένα από τα πιο χρήσιμα quality-of-life features του Mythic
για operators: μπορούν να μετατρέψουν ακατέργαστο command output σε tables, screenshot
viewers, download links, search links και buttons που εκτελούν follow-on
tasking απευθείας από το UI. Τα τρέχοντα Mythic builds επιτρέπουν σε κάθε operator να διατηρεί
τα δικά του scripts, να τα ενεργοποιεί ή απενεργοποιεί συνολικά ή ανά task και προσφέρουν τα καλύτερα
αποτελέσματα όταν οι agents επιστρέφουν structured JSON αντί για plaintext. Αυτό είναι ιδιαίτερα
χρήσιμο για επαναλαμβανόμενα workflows με `ls`, `ps`, triage και file-browser.
- Τα νεότερα Mythic builds υποστηρίζουν επίσης interactive tasking και Push C2 patterns,
τα οποία μειώνουν την ανάγκη για polling με `sleep 0` κατά τη διάρκεια operations με PTY/SOCKS/rpfwd.
Όταν ένας agent/profile το υποστηρίζει, αυτό έχει συνήθως μικρότερο overhead από το συνεχές
hammering του server με check-ins, μόνο και μόνο για να παραμένει usable ένα interactive
channel.
- Οι τρέχοντες Mythic builders της εποχής 3.4 έχουν καλύτερη επίγνωση του context από ό,τι υπονοούν παλαιότερα writeups:
τα build parameters μπορούν πλέον να ομαδοποιούνται ή να αποκρύπτονται βάσει του επιλεγμένου OS
ή άλλων build options, οι payload types μπορούν να δηλώνουν αν υποστηρίζουν
multiple C2 profiles ή multiple instances του ίδιου C2 σε ένα build και τα
C2 parameter deviations επιτρέπουν σε έναν agent να αποκρύπτει fields που στην πραγματικότητα
δεν υλοποιεί. Αυτό έχει σημασία όταν εναλλάσσεστε μεταξύ `http`, `httpx`, `smb`,
`tcp` και `websocket`, επειδή το safe/valid build surface δεν είναι πλέον μια επίπεδη static form.
- Αν δημιουργείτε ένα custom agent/profile pair και δεν θέλετε το JSON message format ή το default crypto του Mythic
στο wire, χρησιμοποιήστε ένα `translation_container`: το Mythic αφαιρεί το UUID, παραδίδει το encrypted blob και το key material
στον translator μέσω gRPC και αναμένει agent-native bytes ως αποτέλεσμα. Αυτός είναι ο καθαρός τρόπος
για την υποστήριξη binary protocols, custom framing ή agent-side encryption χωρίς να ξαναγράψετε ολόκληρο τον server.
- Να θυμάστε ότι τα linked/P2P callbacks δεν προωθούν απλώς tasking. Η ροή
`get_tasking` του Mythic μπορεί επίσης να μεταφέρει responses μαζί με `delegates`,
`socks`, `rpfwd` και `interactive` data. Στην πράξη, ένα egress callback μπορεί να εξυπηρετεί inner
callbacks και pivot channels στον ίδιο polling loop. Αν οι child agents πραγματοποιούν τα δικά τους περιοδικά
check-ins, το `get_delegate_tasks=false` εμποδίζει το parent να καταναλώσει κατά λάθος τις jobs που βρίσκονται στην ουρά του inner callback.

### Wrapper payloads

Τα wrapper payloads σάς επιτρέπουν να διατηρείτε την ίδια λογική του agent, αλλάζοντας παράλληλα την on-disk αναπαράσταση που παραδίδεται ή αποθηκεύεται.

- `service_wrapper`: μετατρέπει ένα άλλο payload σε Windows service executable, κάτι χρήσιμο όταν το execution path απαιτεί έγκυρο service binary.
- `scarecrow_wrapper`: τυλίγει συμβατό shellcode με τον ScareCrow loader για τη δημιουργία loader-backed outputs όπως EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Το Apollo είναι ένας Windows agent γραμμένος σε C#, με χρήση του 4.0 .NET Framework, σχεδιασμένος για χρήση σε εκπαιδευτικά offerings της SpecterOps.

Εγκαταστήστε το με:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Σημειώσεις τρέχουσας έκδοσης/profile

- Το Apollo μπορεί επί του παρόντος να παράγει payloads `WinExe`, `Shellcode`, `Service` και `Source`.
- Τα profiles του Apollo που χρησιμοποιούνται συχνότερα είναι τα `http`, `httpx`, `smb`, `tcp` και `websocket`.
- Το `httpx` είναι συνήθως η πιο ευέλικτη επιλογή όταν χρειάζεστε domain rotation, υποστήριξη proxy, custom message placement και message transforms, αντί για το παλαιότερο static `http` profile.
- Το Apollo είναι ένα από τα πιο πλήρη community agents και επί του παρόντος παρέχει integrations στην πλευρά του Mythic, όπως browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 και P2P routing.
- Το Apollo υποστηρίζει wrapper payloads όπως `service_wrapper` και `scarecrow_wrapper`.
- Το Apollo υποστηρίζει dynamic command loading, επομένως μπορείτε να διατηρείτε το αρχικό payload μικρό και να φορτώνετε αργότερα επιπλέον commands ή Forge modules, αντί να κάνετε compile κάθε post-exploitation δυνατότητα στο πρώτο build.
- Κατά τη δημιουργία output τύπου shellcode, ο τρέχων builder του Apollo παρέχει επίσης επιλογές format του Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) και συμπεριφορά bypass του Donut (`None`, `Abort on fail`, `Continue on fail`). Αυτό είναι χρήσιμο όταν ο τελικός στόχος είναι να γίνει εκ νέου wrap το shellcode με `service_wrapper`, `scarecrow_wrapper` ή έναν custom loader.
- Τα `register_file` και `register_assembly` είναι τα staging primitives για τα `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` και `powerpick`. Στα τρέχοντα Apollo builds, αυτά τα staged artifacts αποθηκεύονται στην client-side cache ως DPAPI-protected AES256 blobs.
- Τα αποτελέσματα των `ls` και `ps` ενσωματώνονται ιδιαίτερα καλά με τα browser scripts και το file/process browser του Mythic, γεγονός που επιταχύνει αισθητά το operator triage σε collaborative operations.
- Τα fork-and-run jobs του Apollo κληρονομούν τις ρυθμίσεις του sacrificial process από τα
`spawnto_x86` / `spawnto_x64`, κληρονομούν την επιλογή parent από το `ppid` και
στη συνέχεια χρησιμοποιούν το injection primitive που είναι επιλεγμένο εκείνη τη στιγμή. Στην
πράξη, αυτό σημαίνει ότι το OPSEC tuning για ένα command συχνά επηρεάζει τα
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` και `spawn`
ταυτόχρονα.
- Τα τρέχοντα documented Apollo injection backends περιλαμβάνουν τα `CreateRemoteThread`,
`QueueUserAPC` (early-bird style) και `NtCreateThreadEx` μέσω syscalls. Χρησιμοποιήστε το
`get_injection_techniques` πριν από noisy post-exploitation και το
`set_injection_technique` αν χρειάζεται να αλλάξετε από ένα primitive που
συγκρούεται με τον στόχο ή με το command που θέλετε να εκτελέσετε.
- Το `blockdlls` επηρεάζει μόνο τα sacrificial processes που δημιουργούνται για post-exploitation
jobs. Σε συνδυασμό με έναν λιγότερο ύποπτο στόχο `spawnto_x64` από το προεπιλεγμένο
bare `rundll32.exe`, αυτή είναι μία από τις ευκολότερες αλλαγές στην πλευρά του Apollo που μπορείτε να κάνετε
πριν εκτελέσετε assembly/PowerShell-heavy tasking.

Αυτό το agent διαθέτει πολλά commands, γεγονός που το καθιστά πολύ παρόμοιο με το Beacon του Cobalt Strike, με ορισμένα επιπλέον χαρακτηριστικά. Μεταξύ άλλων, υποστηρίζει:

### Συνήθεις ενέργειες

- `cat`: Εκτυπώνει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει τον τρέχοντα working directory
- `cp`: Αντιγράφει ένα αρχείο από μία τοποθεσία σε άλλη
- `ls`: Εμφανίζει αρχεία και directories στον τρέχοντα directory ή στο specified path
- `ifconfig`: Λαμβάνει πληροφορίες για network adapters και interfaces
- `netstat`: Λαμβάνει πληροφορίες για TCP και UDP connections
- `pwd`: Εκτυπώνει τον τρέχοντα working directory
- `ps`: Εμφανίζει τις running processes στο target system (με πρόσθετες πληροφορίες)
- `jobs`: Εμφανίζει όλα τα running jobs που σχετίζονται με long-running tasking
- `download`: Κατεβάζει ένα αρχείο από το target system στο local machine
- `upload`: Ανεβάζει ένα αρχείο από το local machine στο target system
- `reg_query`: Κάνει query σε registry keys και values στο target system
- `reg_write_value`: Γράφει ένα νέο value σε specified registry key
- `sleep`: Αλλάζει το sleep interval του agent, το οποίο καθορίζει πόσο συχνά επικοινωνεί με τον Mythic server
- Και πολλά άλλα, χρησιμοποιήστε το `help` για να δείτε την πλήρη λίστα των διαθέσιμων commands.

### Privilege escalation

- `getprivs`: Ενεργοποιεί όσο το δυνατόν περισσότερα privileges στο current thread token
- `getsystem`: Ανοίγει ένα handle στο winlogon και κάνει duplicate το token, αυξάνοντας ουσιαστικά τα privileges στο επίπεδο SYSTEM
- `make_token`: Δημιουργεί ένα νέο logon session και το εφαρμόζει στον agent, επιτρέποντας impersonation άλλου user
- `steal_token`: Κλέβει ένα primary token από άλλη process, επιτρέποντας στον agent να κάνει impersonate τον user αυτής της process
- `pth`: Pass-the-Hash attack, που επιτρέπει στον agent να κάνει authenticate ως user χρησιμοποιώντας το NTLM hash του, χωρίς να χρειάζεται το plaintext password
- `mimikatz`: Εκτελεί Mimikatz commands για την εξαγωγή credentials, hashes και άλλων ευαίσθητων πληροφοριών από τη μνήμη ή τη SAM database
- `rev2self`: Επαναφέρει το token του agent στο primary token του, καταργώντας ουσιαστικά τα privileges και επιστρέφοντας στο αρχικό επίπεδο
- `ppid`: Αλλάζει το parent process για post-exploitation jobs, καθορίζοντας ένα νέο parent process ID και επιτρέποντας καλύτερο έλεγχο του context εκτέλεσης των jobs
- `printspoofer`: Εκτελεί PrintSpoofer commands για την παράκαμψη των security measures του print spooler, επιτρέποντας privilege escalation ή code execution
- `dcsync`: Συγχρονίζει τα Kerberos keys ενός user στο local machine, επιτρέποντας offline password cracking ή περαιτέρω attacks
- `ticket_cache_add`: Προσθέτει ένα Kerberos ticket στο current logon session ή σε ένα specified session, επιτρέποντας ticket reuse ή impersonation

### Process execution

- `assembly_inject`: Επιτρέπει την έγχυση ενός .NET assembly loader σε remote process
- `blockdlls`: Εμποδίζει τη φόρτωση DLLs χωρίς Microsoft signature στα post-exploitation jobs
- `execute_assembly`: Εκτελεί ένα .NET assembly στο context του agent
- `execute_coff`: Εκτελεί ένα COFF file στη μνήμη, επιτρέποντας in-memory execution compiled code
- `execute_pe`: Εκτελεί ένα unmanaged executable (PE)
- `keylog_inject`: Κάνει inject έναν keylogger σε άλλη process και μεταδίδει τα keystrokes πίσω στο keylog view του Mythic
- `screenshot` / `screenshot_inject`: Καταγράφει το τρέχον desktop απευθείας ή
κάνοντας inject ένα screenshot assembly σε target process/session
- `get_injection_techniques`: Εμφανίζει τις διαθέσιμες injection techniques και την τρέχουσα επιλεγμένη
- `inline_assembly`: Εκτελεί ένα .NET assembly σε disposable AppDomain, επιτρέποντας προσωρινή εκτέλεση code χωρίς να επηρεάζεται η main process του agent
- `register_assembly`: Κάνει register ένα .NET assembly για μεταγενέστερη εκτέλεση
- `register_file`: Κάνει register ένα file στο agent cache για μεταγενέστερο `execute_*` ή PowerShell tasking
- `run`: Εκτελεί ένα binary στο target system, χρησιμοποιώντας το system's PATH για να εντοπίσει το executable
- `set_injection_technique`: Αλλάζει το injection primitive που χρησιμοποιείται από τα post-exploitation jobs
- `shinject`: Κάνει inject shellcode σε remote process, επιτρέποντας in-memory execution arbitrary code
- `inject`: Κάνει inject το agent shellcode σε remote process, επιτρέποντας in-memory execution του code του agent
- `spawn`: Δημιουργεί ένα νέο agent session στο specified executable, επιτρέποντας την εκτέλεση shellcode σε νέα process
- `spawnto_x64` και `spawnto_x86`: Αλλάζουν το default binary που χρησιμοποιείται στα post-exploitation jobs σε specified path, αντί να χρησιμοποιούν το `rundll32.exe` χωρίς params, το οποίο είναι πολύ noisy.

### Mythic Forge

Αυτό επιτρέπει το **load COFF/BOF** files από το Mythic Forge, το οποίο είναι repository από pre-compiled payloads και tools που μπορούν να εκτελεστούν στο target system. Με όλα τα commands που μπορούν να φορτωθούν, θα είναι δυνατή η εκτέλεση κοινών ενεργειών, εκτελώντας τα στο current agent process ως BOFs (συνήθως με καλύτερο OPSEC από τη δημιουργία ξεχωριστής process).

Ξεκινήστε την εγκατάστασή τους με:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Στη συνέχεια, χρησιμοποιήστε το `forge_collections` για να εμφανίσετε τα COFF/BOF modules από το Mythic Forge, ώστε να μπορείτε να τα επιλέξετε και να τα φορτώσετε στη μνήμη του agent για εκτέλεση. Από προεπιλογή, οι ακόλουθες 2 συλλογές προστίθενται στο Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Μετά τη φόρτωση ενός module, θα εμφανιστεί στη λίστα ως μια ακόμη εντολή, όπως `forge_bof_sa-whoami` ή `forge_bof_sa-netuser`.

Για τα BOFs, θυμηθείτε ότι το Forge **δεν** περνά απλώς ένα ενιαίο flat argument string
στο Apollo. Αντιστοιχίζει τις παραμέτρους BOF στη typed-array μορφή του Mythic και στη συνέχεια τις προωθεί στη ροή `execute_coff` του Apollo. Αν ένα BOF που φορτώθηκε από το Forge συμπεριφέρεται παράξενα, ελέγξτε τους αναμενόμενους τύπους ορισμάτων BOF / entrypoint και όχι μόνο τη γραμμή εντολών που πληκτρολογήσατε. Σημειώστε επίσης ότι ο νεότερος BOF loader του Apollo άλλαξε τον χειρισμό των ορισμάτων σε σχέση με πολύ παλαιότερα builds της εποχής 2.3.1, επομένως παρωχημένα BOFs ή παλιές συλλογές μπορεί να αποτυγχάνουν αποκλειστικά επειδή άλλαξαν οι απαιτήσεις marshaling.

### PowerShell & εκτέλεση scripting

- `powershell_import`: Εισάγει ένα νέο PowerShell script (.ps1) στο cache του agent για μεταγενέστερη εκτέλεση
- `powershell`: Εκτελεί μια εντολή PowerShell στο context του agent, επιτρέποντας advanced scripting και automation
- `powerpick`: Κάνει inject ένα PowerShell loader assembly σε μια sacrificial process και εκτελεί μια εντολή PowerShell (χωρίς powershell logging).
- `psinject`: Εκτελεί PowerShell σε μια καθορισμένη process, επιτρέποντας στοχευμένη εκτέλεση scripts στο context μιας άλλης process
- `shell`: Εκτελεί μια shell command στο context του agent, παρόμοια με την εκτέλεση μιας εντολής στο cmd.exe

### Πλευρική κίνηση

- `jump_psexec`: Χρησιμοποιεί την τεχνική PsExec για πλευρική κίνηση σε νέο host, αντιγράφοντας πρώτα το εκτελέσιμο του Apollo agent (apollo.exe) και εκτελώντας το.
- `jump_wmi`: Χρησιμοποιεί την τεχνική WMI για πλευρική κίνηση σε νέο host, αντιγράφοντας πρώτα το εκτελέσιμο του Apollo agent (apollo.exe) και εκτελώντας το.
- `link` και `unlink`: Δημιουργούν και τερματίζουν P2P links (για παράδειγμα μέσω SMB/TCP) μεταξύ callbacks.
- `wmiexecute`: Εκτελεί μια εντολή στο local ή στο καθορισμένο remote system χρησιμοποιώντας WMI, με προαιρετικά credentials για impersonation.
- `net_dclist`: Ανακτά μια λίστα με τους domain controllers για το καθορισμένο domain, χρήσιμη για τον εντοπισμό πιθανών targets για πλευρική κίνηση.
- `net_localgroup`: Εμφανίζει τις local groups στον καθορισμένο computer, χρησιμοποιώντας ως προεπιλογή το localhost αν δεν καθοριστεί computer.
- `net_localgroup_member`: Ανακτά τα μέλη μιας local group για την καθορισμένη group στον local ή remote computer, επιτρέποντας την enumeration χρηστών σε συγκεκριμένες groups.
- `net_shares`: Εμφανίζει τα remote shares και την προσβασιμότητά τους στον καθορισμένο computer, χρήσιμο για τον εντοπισμό πιθανών targets για πλευρική κίνηση.
- `socks`: Ενεργοποιεί έναν SOCKS 5 compliant proxy στο target network, επιτρέποντας τη διοχέτευση traffic μέσω του compromised host. Είναι συμβατό με tools όπως το proxychains.
- `rpfwd`: Ξεκινά να ακούει σε μια καθορισμένη port στον target host και προωθεί traffic μέσω του Mythic σε ένα remote IP και port, επιτρέποντας remote πρόσβαση σε services στο target network.
- `listpipes`: Εμφανίζει όλα τα named pipes στο local system, τα οποία μπορεί να είναι χρήσιμα για πλευρική κίνηση ή privilege escalation μέσω interaction με IPC mechanisms.

Για τα lower-level WMI execution primitives που χρησιμοποιούνται κάτω από τα `jump_wmi` ή `wmiexecute`, ελέγξτε το [WmiExec](lateral-movement/wmiexec.md). Για ευρύτερα pivoting patterns, ελέγξτε το [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Διάφορες εντολές
- `help`: Εμφανίζει λεπτομερείς πληροφορίες για συγκεκριμένες εντολές ή γενικές πληροφορίες για όλες τις διαθέσιμες εντολές στον agent.
- `clear`: Επισημαίνει τα tasks ως 'cleared', ώστε να μην μπορούν να αναληφθούν από agents. Μπορείτε να καθορίσετε `all` για την εκκαθάριση όλων των tasks ή `task Num` για την εκκαθάριση ενός συγκεκριμένου task.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Το Poseidon είναι ένας Golang agent που γίνεται compile σε εκτελέσιμα για **Linux και macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Τρέχουσες σημειώσεις build/profile

- Τα τρέχοντα builds του Poseidon στοχεύουν Linux και macOS σε `x86_64` και `arm64`.
- Τα υποστηριζόμενα formats εξόδου περιλαμβάνουν native executables, καθώς και outputs τύπου shared library, όπως `dylib` και `so`.
- Το Poseidon υποστηρίζει `http`, `websocket`, `tcp` και `dynamichttp`, ενώ οι τρέχοντες builders εκθέτουν ρυθμίσεις multi-egress, όπως `egress_order` και thresholds για failover.
- Τα τρέχοντα capability metadata του Poseidon διαφημίζουν επίσης browser scripts, ενσωμάτωση file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd και P2P, επομένως μπορεί να λειτουργήσει ως πραγματικός Linux/macOS pivot node και όχι απλώς ως ένα απλό remote shell.
- Αξίζει να ελέγχετε build-time επιλογές όπως `proxy_bypass` και `garble` όταν χρειάζεστε είτε καθαρότερη network συμπεριφορά είτε επιπλέον Go binary obfuscation.
- Το `pty` είναι ένα από τα πιο χρήσιμα νεότερα quality-of-life commands για Linux/macOS
operations, επειδή ανοίγει ένα interactive PTY και μπορεί να εκθέσει μια
θύρα στην πλευρά του Mythic για πληρέστερη terminal interaction, χωρίς να
καταφεύγετε στο παλαιότερο workaround `sleep 0`
+ SOCKS.
- Τα τρέχοντα docs του Poseidon παρουσιάζουν ιδιαίτερο ενδιαφέρον για macOS-heavy
tradecraft: το `jxa` εκτελεί JavaScript for Automation in-memory,
το `screencapture` καταγράφει το logged-in desktop, το `clipboard_monitor`
μεταδίδει αλλαγές στο pasteboard, το `execute_library` φορτώνει ένα
τοπικό dylib και καλεί μια συνάρτηση από αυτό, ενώ το `libinject` αναγκάζει
μια απομακρυσμένη process να φορτώσει ένα dylib από τον δίσκο.
- Για jobs μεγάλης διάρκειας, να θυμάστε ότι το Poseidon εκτελεί post-exploitation work
σε goroutines/threads που είναι cooperative και όχι hard-killable. Τα docs
σημειώνουν επίσης ρητά ότι επί του παρόντος δεν υπάρχει ενσωματωμένο agent
obfuscation, επομένως το tradecraft σε επίπεδο build/profile έχει μεγαλύτερη
σημασία σε σχέση με heavily obfuscated commercial implants.

Για macOS-specific tradecraft γύρω από operations που υποστηρίζονται από Mythic, JAMF abuse ή ιδέες MDM-as-C2, δείτε το [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Όταν χρησιμοποιείται σε Linux ή macOS, διαθέτει ορισμένα ενδιαφέροντα commands:

### Συνήθεις ενέργειες

- `cat`: Εκτυπώνει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει το τρέχον working directory
- `chmod`: Αλλάζει τα permissions ενός αρχείου
- `config`: Εμφανίζει το τρέχον config και τις πληροφορίες του host
- `cp`: Αντιγράφει ένα αρχείο από μία τοποθεσία σε άλλη
- `curl`: Εκτελεί ένα μεμονωμένο web request με προαιρετικά headers και method
- `upload`: Κάνει upload ένα αρχείο στο target
- `download`: Κάνει download ένα αρχείο από το target system στο local machine
- Και πολλά άλλα

### Αναζήτηση ευαίσθητων πληροφοριών

- `triagedirectory`: Εντοπίζει ενδιαφέροντα αρχεία μέσα σε ένα directory σε έναν host, όπως ευαίσθητα αρχεία ή credentials.
- `getenv`: Λαμβάνει όλες τις τρέχουσες environment variables.

### macOS-specific tradecraft

- `jxa`: Εκτελεί JavaScript for Automation in-memory μέσω του `OSAScript`, κάτι
που είναι χρήσιμο για native macOS post-exploitation χωρίς τη δημιουργία
ξεχωριστών script files.
- `clipboard_monitor`: Κάνει poll στο pasteboard και αναφέρει τις αλλαγές πίσω στο Mythic,
κάτι χρήσιμο για workflows κλοπής credentials/tokens που βασίζονται σε copy/paste.
- `screencapture`: Καταγράφει το desktop του χρήστη σε macOS.
- `execute_library`: Φορτώνει ένα dylib από τον δίσκο και καλεί μια συγκεκριμένη exported function.
- `libinject`: Κάνει inject ένα shellcode stub που αναγκάζει μια άλλη macOS process να φορτώσει ένα dylib από τον δίσκο.
- `persist_launchd`: Δημιουργεί persistence μέσω LaunchAgent / LaunchDaemon απευθείας από τον agent.

### Lateral movement

- `ssh`: Κάνει SSH σε host χρησιμοποιώντας τα指定 credentials και ανοίγει ένα PTY χωρίς να κάνει spawn το ssh.
- `sshauth`: Κάνει SSH σε指定 host(s) χρησιμοποιώντας τα指定 credentials. Μπορείτε επίσης να το χρησιμοποιήσετε για την εκτέλεση συγκεκριμένου command στους remote hosts μέσω SSH ή για SCP αρχείων.
- `link_tcp`: Συνδέεται με άλλον agent μέσω TCP, επιτρέποντας την άμεση επικοινωνία μεταξύ agents.
- `link_webshell`: Συνδέεται με έναν agent χρησιμοποιώντας το webshell P2P profile, επιτρέποντας remote access στο web interface του agent.
- `rpfwd`: Ξεκινά ή σταματά ένα Reverse Port Forward, επιτρέποντας remote access σε services στο target network.
- `socks`: Ξεκινά ή σταματά έναν SOCKS5 proxy στο target network, επιτρέποντας tunneling της κίνησης μέσω του compromised host. Είναι συμβατό με εργαλεία όπως το proxychains.
- `portscan`: Κάνει scan σε host(s) για open ports, χρήσιμο για τον εντοπισμό πιθανών targets για lateral movement ή περαιτέρω attacks.

### Εκτέλεση processes

- `shell`: Εκτελεί ένα μεμονωμένο shell command μέσω `/bin/sh`, επιτρέποντας την άμεση εκτέλεση commands στο target system.
- `run`: Εκτελεί ένα command από τον δίσκο με arguments, επιτρέποντας την εκτέλεση binaries ή scripts στο target system.
- `pty`: Ανοίγει ένα interactive PTY, επιτρέποντας την άμεση αλληλεπίδραση με το shell στο target system.






## Αναφορές

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
