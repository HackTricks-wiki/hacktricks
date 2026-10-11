# Mythic

{{#include ../banners/hacktricks-training.md}}

## Τι είναι το Mythic;

Το Mythic είναι ένα αρθρωτό, συνεργατικό framework command and control (C2) ανοιχτού κώδικα, σχεδιασμένο για red teaming. Επιτρέπει στους operators να διαχειρίζονται και να αναπτύσσουν agents (payloads) σε διάφορα λειτουργικά συστήματα, όπως Windows, Linux και macOS. Το Mythic παρέχει ένα UI μέσω browser για tasking πολλαπλών operators, διαχείριση αρχείων, διαχείριση SOCKS/rpfwd και δημιουργία payloads.

Σε αντίθεση με τα μονολιθικά frameworks, το ίδιο το repository του Mythic **δεν** περιλαμβάνει τύπους payload ή C2 profiles. Οι agents, οι wrappers και τα C2 profiles εγκαθίστανται συνήθως ως εξωτερικά components και μπορούν να ενημερώνονται ανεξάρτητα από τον πυρήνα του Mythic.

### Εγκατάσταση

Για να εγκαταστήσετε το Mythic, ακολουθήστε τις οδηγίες στο επίσημο **[Mythic repo](https://github.com/its-a-feature/Mythic)**. Μια συνηθισμένη διαδικασία bootstrap από τον κατάλογο Mythic είναι:

```bash
sudo make
sudo ./mythic-cli start
```

Αν το Mythic εκτελείται ήδη, συνήθως μπορείτε να προσθέσετε έναν νέο agent ή profile με `./mythic-cli install github ...` και έπειτα είτε να επανεκκινήσετε το Mythic είτε απλώς να εκκινήσετε απευθείας το νέο component.

### Agents

Το Mythic υποστηρίζει πολλούς agents, δηλαδή τα **payloads που εκτελούν εργασίες στα παραβιασμένα συστήματα**. Κάθε agent μπορεί να προσαρμοστεί σε συγκεκριμένες ανάγκες και να εκτελείται σε διαφορετικά λειτουργικά συστήματα.

Από προεπιλογή, το Mythic δεν έχει εγκατεστημένους agents. Οι agents της κοινότητας ανοιχτού κώδικα βρίσκονται στο [**https://github.com/MythicAgents**](https://github.com/MythicAgents), ενώ ο [**πίνακας δυνατοτήτων της κοινότητας**](https://mythicmeta.github.io/overview/agent_matrix.html) είναι χρήσιμος για να ελέγξετε γρήγορα τα υποστηριζόμενα λειτουργικά συστήματα, τις μορφές payload, τα wrappers και τα C2 profiles.<sup>[[1]](#references)</sup>

Για να εγκαταστήσετε έναν agent από αυτόν τον οργανισμό, μπορείτε να εκτελέσετε:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

Η μορφή `sudo -E` είναι χρήσιμη όταν κάνετε εγκατάσταση από περιβάλλον χωρίς root. Μπορείτε να προσθέσετε νέους agents με την προηγούμενη εντολή, ακόμα κι αν το Mythic εκτελείται ήδη.

### C2 Profiles

Τα C2 profiles στο Mythic ορίζουν **τον τρόπο επικοινωνίας των agents με τον Mythic server**. Καθορίζουν το πρωτόκολλο επικοινωνίας, τις μεθόδους κρυπτογράφησης και άλλες ρυθμίσεις. Μπορείτε να δημιουργείτε και να διαχειρίζεστε C2 profiles μέσω του web interface του Mythic.

Από προεπιλογή, το Mythic εγκαθίσταται χωρίς profiles. Ωστόσο, μπορείτε να κατεβάσετε ορισμένα profiles από το repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) εκτελώντας:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Τρέχοντα προφίλ σχετικά με τον χειριστή που πρέπει να έχεις υπόψη:

- [`http`](https://github.com/MythicC2Profiles/http): βασική ασύγχρονη κίνηση GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): πιο ευέλικτη κίνηση HTTP με πολλαπλά callback domains, εναλλαγή fail-over/round-robin, προσαρμοσμένες κεφαλίδες/παραμέτρους query και μετασχηματισμούς μηνυμάτων (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) που τοποθετούνται σε cookies, κεφαλίδες, παραμέτρους query ή στο σώμα.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): διαμόρφωση μηνυμάτων HTTP μέσω JSON/TOML όταν το στατικό προφίλ `http` είναι υπερβολικά αναγνωρίσιμο.

### Τρέχουσες σημειώσεις πλατφόρμας

- Πολλοί δημόσιοι agents και profiles εγκαθίστανται πλέον με έτοιμα remote container images.
  Αν κάνεις fork ενός component ή το τροποποιήσεις τοπικά, αλλά το Mythic συνεχίζει να χρησιμοποιεί την παλιά
  συμπεριφορά, έλεγξε τις εγγραφές `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` και `*_USE_VOLUME` που δημιουργούνται στο `.env`.
  Συνήθως, η ενεργοποίηση του `*_USE_BUILD_CONTEXT="true"` είναι αυτή που κάνει το Mythic να κάνει rebuild
  από το τοπικό Docker context αντί να επαναχρησιμοποιεί σιωπηρά το remote image.
- Τα browser scripts είναι ένα από τα πιο χρήσιμα χαρακτηριστικά του Mythic για τη διευκόλυνση των χειριστών: μπορούν να μετατρέπουν ακατέργαστη έξοδο εντολών σε πίνακες, προβολείς screenshot, συνδέσμους λήψης, συνδέσμους αναζήτησης και κουμπιά που υποβάλλουν follow-on tasking απευθείας από το UI. Οι τρέχουσες εκδόσεις του Mythic επιτρέπουν σε κάθε χειριστή να διατηρεί τα δικά του scripts, να τα ενεργοποιεί ή να τα απενεργοποιεί καθολικά ή ανά task, ενώ τα καλύτερα αποτελέσματα επιτυγχάνονται όταν οι agents επιστρέφουν δομημένο JSON αντί για απλό κείμενο. Αυτό είναι ιδιαίτερα χρήσιμο για επαναλαμβανόμενες ροές εργασίας `ls`, `ps`, triage και file-browser.<sup>[[4]](#references)[[6]](#references)</sup>
- Οι νεότερες εκδόσεις του Mythic υποστηρίζουν επίσης interactive tasking και μοτίβα Push C2 που μειώνουν την ανάγκη για polling με `sleep 0` σε λειτουργίες με εκτεταμένη χρήση PTY/SOCKS/rpfwd. Όταν τα υποστηρίζει ο agent/profile, συνήθως έχουν μικρότερο overhead από τη συνεχή αποστολή αιτημάτων στον server για να παραμένει λειτουργικό ένα interactive channel.<sup>[[3]](#references)</sup>
- Οι builders του Mythic της εποχής 3.4 λαμβάνουν περισσότερο υπόψη το context από όσο υπονοούν παλαιότερα writeups: οι παράμετροι build μπορούν πλέον να ομαδοποιούνται ή να αποκρύπτονται με βάση το επιλεγμένο OS ή άλλες επιλογές build, οι τύποι payload μπορούν να δηλώνουν αν υποστηρίζουν πολλαπλά C2 profiles ή πολλαπλά instances του ίδιου C2 σε ένα build, ενώ οι αποκλίσεις παραμέτρων C2 επιτρέπουν σε έναν agent να αποκρύπτει πεδία που δεν υλοποιεί. Αυτό έχει σημασία όταν εναλλάσσεσαι μεταξύ `http`, `httpx`, `smb`,
  `tcp` και `websocket`, επειδή οι ασφαλείς/έγκυρες επιλογές build δεν περιορίζονται πλέον σε μια στατική φόρμα.<sup>[[5]](#references)</sup>
- Αν δημιουργείς ένα προσαρμοσμένο ζεύγος agent/profile και δεν θέλεις τη μορφή μηνυμάτων JSON του Mythic ή την προεπιλεγμένη κρυπτογράφηση στο wire, χρησιμοποίησε ένα
  `translation_container`: το Mythic αφαιρεί το UUID, παραδίδει το κρυπτογραφημένο blob και το υλικό κλειδιού στον translator μέσω gRPC και αναμένει να λάβει bytes στη μορφή του agent. Αυτός είναι ο καθαρός τρόπος να υποστηρίξεις binary protocols, custom framing ή κρυπτογράφηση στην πλευρά του agent χωρίς να ξαναγράψεις ολόκληρο τον server.
- Να θυμάσαι ότι τα linked/P2P callbacks δεν μεταφέρουν μόνο tasking. Η ροή `get_tasking` του Mythic μπορεί επίσης να μεταφέρει responses μαζί με δεδομένα `delegates`,
  `socks`, `rpfwd` και `interactive`. Στην πράξη, ένα egress callback μπορεί να εξυπηρετεί εσωτερικά callbacks και pivot channels στον ίδιο κύκλο polling· αν οι child agents κάνουν τα δικά τους περιοδικά check-ins, το `get_delegate_tasks=false` εμποδίζει τον parent να καταναλώσει κατά λάθος τις queued jobs του εσωτερικού callback.

## Wrapper payloads

Τα wrapper payloads σού επιτρέπουν να διατηρείς την ίδια λογική agent, αλλάζοντας παράλληλα την αναπαράσταση στο δίσκο του payload που παραδίδεται ή αποθηκεύεται.

- `service_wrapper`: μετατρέπει ένα άλλο payload σε εκτελέσιμο Windows service, κάτι χρήσιμο όταν η διαδρομή εκτέλεσης απαιτεί έγκυρο service binary.
- `scarecrow_wrapper`: περιτυλίγει συμβατό shellcode με τον loader ScareCrow, ώστε να δημιουργεί outputs που βασίζονται σε loader, όπως EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Το Apollo είναι ένας Windows agent γραμμένος σε C# με χρήση του .NET Framework 4.0, σχεδιασμένος για χρήση στα εκπαιδευτικά προγράμματα της SpecterOps.<sup>[[2]](#references)</sup>

Εγκατάστησέ το με:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Σημειώσεις για τις τρέχουσες εκδόσεις/profile

- Το Apollo μπορεί προς το παρόν να παράγει payloads `WinExe`, `Shellcode`, `Service` και `Source`.
- Τα profiles του Apollo που χρησιμοποιούνται συχνότερα είναι τα `http`, `httpx`, `smb`, `tcp` και `websocket`.
- Το `httpx` είναι συνήθως η πιο ευέλικτη επιλογή όταν χρειάζεστε εναλλαγή domain, υποστήριξη proxy, προσαρμοσμένη τοποθέτηση μηνυμάτων και μετασχηματισμούς μηνυμάτων, αντί για το παλαιότερο στατικό profile `http`.
- Το Apollo είναι ένας από τους πιο ολοκληρωμένους community agents και προς το παρόν παρέχει integrations στην πλευρά του Mythic, όπως browser scripts, προβολές περιήγησης αρχείων/διεργασιών, screenshots, keylogging, SOCKS, rpfwd, Push C2 και P2P routing.
- Το Apollo υποστηρίζει wrapper payloads όπως τα `service_wrapper` και `scarecrow_wrapper`.
- Το Apollo υποστηρίζει δυναμική φόρτωση εντολών, οπότε μπορείτε να διατηρήσετε μικρό το αρχικό payload και να φορτώσετε αργότερα επιπλέον εντολές ή Forge modules, αντί να μεταγλωττίσετε όλες τις δυνατότητες post-ex στο πρώτο build.
- Κατά τη δημιουργία εξόδου shellcode, ο τρέχων builder του Apollo παρέχει επίσης επιλογές μορφής Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) και συμπεριφορά παράκαμψης Donut (`None`, `Abort on fail`, `Continue on fail`). Αυτό είναι χρήσιμο αν ο τελικός στόχος είναι να γίνει ξανά wrap το shellcode με `service_wrapper`, `scarecrow_wrapper` ή έναν προσαρμοσμένο loader.
- Τα `register_file` και `register_assembly` είναι τα primitives προετοιμασίας για τα `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` και `powerpick`. Στις τρέχουσες εκδόσεις του Apollo, αυτά τα προετοιμασμένα artifacts αποθηκεύονται προσωρινά στην πλευρά του client ως blobs AES256 προστατευμένα με DPAPI.
- Τα αποτελέσματα των `ls` και `ps` ενσωματώνονται ιδιαίτερα καλά με τα browser scripts και την περιήγηση αρχείων/διεργασιών του Mythic, επιταχύνοντας αισθητά την αρχική διαλογή από τους operators σε συνεργατικές επιχειρήσεις.
- Οι εργασίες fork-and-run κληρονομούν τις ρυθμίσεις της sacrificial process από τα `spawnto_x86` / `spawnto_x64`, την επιλογή γονικής διεργασίας από το `ppid` και στη συνέχεια χρησιμοποιούν το τρέχον επιλεγμένο primitive injection. Στην πράξη, αυτό σημαίνει ότι η ρύθμιση OPSEC για μία εντολή συχνά επηρεάζει ταυτόχρονα τα `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` και `spawn`.
- Τα τρέχοντα τεκμηριωμένα backends injection του Apollo περιλαμβάνουν τα `CreateRemoteThread`, `QueueUserAPC` (τύπου early-bird) και `NtCreateThreadEx` μέσω syscalls. Χρησιμοποιήστε το `get_injection_techniques` πριν από θορυβώδες post-exploitation και το `set_injection_technique` αν χρειάζεται να αλλάξετε από ένα primitive που δεν ταιριάζει με τον στόχο ή την εντολή που θέλετε να εκτελέσετε.
- Το `blockdlls` επηρεάζει μόνο τις sacrificial processes που δημιουργούνται για εργασίες post-exploitation. Σε συνδυασμό με έναν λιγότερο ύποπτο στόχο `spawnto_x64` από το προεπιλεγμένο σκέτο `rundll32.exe`, αυτή είναι μία από τις ευκολότερες αλλαγές στην πλευρά του Apollo πριν από εργασίες με assembly/PowerShell.

### Pipeline build agent .NET με επίγνωση των detections

Ένα fork του Apollo με επίγνωση των detections πρέπει να αντιμετωπίζεται ως **πρόβλημα ολόκληρου του συστήματος build**, όχι ως ένα τελικό βήμα `obfuscate.exe`. Αυτή η μελέτη περίπτωσης συμπληρώνει τη γενική [μεθοδολογία αποφυγής AV](av-bypass.md) και τα [εργαλεία επιθεώρησης .NET](../reversing/reversing-tools-basic-methods/README.md): οι αλλαγές σε wire identifiers, IL metadata, πακετάρισμα dependencies, reflection και δυναμικά μεταγλωττισμένες εργασίες αποτελούν ένα ενιαίο όριο συμβατότητας.<sup>[[8]](#references)</sup>

#### Μεταβολή πρωτοκόλλου με επίγνωση των YARA

Ελέγξτε τους δημόσιους κανόνες για αρχεία/μνήμη πριν αλλάξετε κώδικα. Για παράδειγμα, ο κανόνας `Multi_Trojan_Mythic_4beb7e17` της Elastic κάνει match όταν υπάρχουν οποιεσδήποτε **7 από τις 11** συμβολοσειρές JSON/action του Mythic, μεταξύ των οποίων τα `task_id`, `post_response`, `c2_profile`, `get_tasking` και `get_delegate_tasks`. Η μετονομασία αρκετών πεδίων μπορεί να παρακάμψει αυτό το όριο, αλλά πρόκειται για τιμές πρωτοκόλλου και όχι για διακοσμητικά σύμβολα: ο agent και η αντίστοιχη υλοποίηση server/profile πρέπει να αλλάξουν μαζί.<sup>[[7]](#references)[[8]](#references)</sup>

Έτσι αφαιρείται μόνο ένα σύνολο στατικών χαρακτηριστικών. Ο ρυθμός check-in, η δομή των μηνυμάτων, η ροή εργασιών/απαντήσεων και η ανασύνθεση συμβολοσειρών κατά τον χρόνο εκτέλεσης μπορούν να παραμείνουν συμπεριφορικοί δείκτες ή δείκτες μνήμης· συνεπώς, επικυρώστε τόσο το artifact που δημιουργήθηκε όσο και ένα callback που έχει εκτελεστεί, αντί να θεωρείτε επιτυχία έναν καθαρό έλεγχο συμβολοσειρών.<sup>[[8]](#references)</sup>

#### Συγχώνευση πριν από την εφαρμογή καθολικών μετασχηματισμών

Η ενσωμάτωση πόρων με εργαλεία όπως το Costura αφήνει τις συνοδευτικές assemblies ως συμπιεσμένους πόρους. Έτσι, ένας obfuscator που επεξεργάζεται μόνο το εξωτερικό module παραλείπει τα ονόματα τύπων και τα metadata τους· ενώ η ανεξάρτητη obfuscation κάθε DLL μπορεί να αποδώσει ασύμβατα ονόματα σε συμβόλαια μεταξύ assemblies. Συγχωνεύστε πρώτα τα outputs του build σε επίπεδο IL (για παράδειγμα με το [ILRepack](https://github.com/gluck/il-repack)) και έπειτα εφαρμόστε έναν ενιαίο χάρτη μετονομασιών στο module που προκύπτει.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Ένα custom pass μπορεί να χρησιμοποιήσει το [dnlib](https://github.com/0xd4d/dnlib) για μετασχηματισμούς managed IL/metadata και το [AsmResolver](https://github.com/Washi1337/AsmResolver) για επιδιόρθωση PE/resources μετά την εγγραφή. Στη μελέτη περίπτωσης, επιλέξιμες εντολές `ldstr` μετατράπηκαν σε κλήσεις με integer token/decryptor, οι οποίες βασίζονταν σε ένα νέο κλειδί rolling-XOR 16 byte, ενώ τα σύμβολα και τα namespaces αντιστοιχίστηκαν σε ονόματα που έμοιαζαν εύλογα για περιβάλλον enterprise, αντί για σύντομα διαδοχικά αναγνωριστικά. Άλλα passes αφαίρεσαν επιλεγμένα compiler/debugger attributes, καθάρισαν αναφορές σε merger/embedding, μετονόμασαν resources και τροποποίησαν πληροφορίες έκδοσης. Δημιουργείτε νέα ονόματα, dead code και υλικό κρυπτογράφησης για κάθε ανεξάρτητο build: η αλλαγή του ciphertext αφαιρεί σταθερά bytes, αλλά ένας σταθερός decryptor ή ένα αναγνωρίσιμο μοτίβο μετασχηματισμού αποτελεί από μόνο του signature.<sup>[[8]](#references)</sup>

#### Διατηρήστε τον συγχρονισμό των dynamic tasks με το payload

Το Apollo μπορεί να κάνει compile τον κώδικα task στον server, να στείλει τα bytes του DLL και να τα φορτώσει με `Assembly.Load()`. Μόλις μετονομαστούν οι public τύποι του base agent, τα επόμενα tasks που γίνονται compile με βάση το αρχικό API δεν επιλύονται πλέον. Αντιμετωπίστε τον εξαγόμενο rename map ως ABI artifact ειδικό για το payload:<sup>[[8]](#references)</sup>

1. Συνδέστε το map και το type context με το ακριβές αναγνωριστικό payload/build.
2. Για κάθε build task, ανακτήστε αυτό το map και ξαναγράψτε ένα προσωρινό source tree.
3. Ξαναγράψτε μόνο επιλυμένες αναφορές σε namespace, τύπο, nested/generic τύπο, πεδίο και ιδιότητα και, στη συνέχεια, κάντε compile με βάση το obfuscated merged assembly.
4. Απορρίψτε ελλιπή ή ασύμβατα maps πριν από την παράδοση του task και εκτελέστε ένα initialization test μετά το compile.

Η τυφλή καθολική αντικατάσταση δεν είναι ασφαλής, επειδή ένα αναγνωριστικό μπορεί επίσης να εμφανίζεται σε string, local declaration, member access, framework type ή άσχετο namespace. Αν διατηρήσετε rewriter που βασίζεται σε κείμενο/regex, προστατέψτε ρητά αυτά τα contexts και κάντε regression test κάθε φορά που αλλάζει το schema του map ή κάποιο rename pass.<sup>[[8]](#references)</sup>

#### Κάντε τα συμβόλαια reflection ανεξάρτητα από το namespace

Κώδικας discovery που ελέγχει `t.FullName.StartsWith("Tasks.")` καθιστά το namespace απαραίτητο και αποτυγχάνει μετά την αντιστοίχιση του namespace σε νέο όνομα. Κάντε discovery με βάση μια σταθερή σχέση τύπων, διατηρώντας παράλληλα τα ονόματα των command classes αν το dispatch εξακολουθεί να χρησιμοποιεί το `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Διατήρησε μια ρητή allowlist με ονόματα ορατά μέσω reflection, πεδία serializer, σημεία εισόδου και API μεταξύ assemblies που δεν πρέπει να μετονομαστούν. Τέλος, κάνε decompile το αποτέλεσμα με ILSpy/dnSpy, σάρωσε τόσο τις αναπαραστάσεις σε αρχείο όσο και στη μνήμη και δοκίμασε κάθε διαδρομή command/loader σε ένα EDR lab· ένα build που ξεκινά επιτυχώς μπορεί και πάλι να περιέχει tasks που έχουν χαλάσει λόγω μετονομασίας ή συμπεριφοράς που ανιχνεύεται μόνο κατά την εκτέλεση.<sup>[[8]](#references)</sup>

Αυτός ο agent διαθέτει πολλές commands, γεγονός που τον κάνει πολύ παρόμοιο με το Beacon του Cobalt Strike, αλλά με μερικές επιπλέον δυνατότητες. Μεταξύ άλλων, υποστηρίζει:

### Συνήθεις ενέργειες

- `cat`: Εμφανίζει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει τον τρέχοντα working directory
- `cp`: Αντιγράφει ένα αρχείο από μία τοποθεσία σε άλλη
- `ls`: Εμφανίζει αρχεία και καταλόγους στον τρέχοντα κατάλογο ή σε καθορισμένη διαδρομή
- `ifconfig`: Εμφανίζει network adapters και interfaces
- `netstat`: Εμφανίζει πληροφορίες για συνδέσεις TCP και UDP
- `pwd`: Εμφανίζει τον τρέχοντα working directory
- `ps`: Εμφανίζει τις διεργασίες που εκτελούνται στο target system (με πρόσθετες πληροφορίες)
- `jobs`: Εμφανίζει όλες τις εργασίες που εκτελούνται και σχετίζονται με tasking μεγάλης διάρκειας
- `download`: Κατεβάζει ένα αρχείο από το target system στον τοπικό υπολογιστή
- `upload`: Ανεβάζει ένα αρχείο από τον τοπικό υπολογιστή στο target system
- `reg_query`: Αναζητά registry keys και values στο target system
- `reg_write_value`: Γράφει ένα νέο value σε καθορισμένο registry key
- `sleep`: Αλλάζει το διάστημα ύπνου του agent, το οποίο καθορίζει πόσο συχνά επικοινωνεί με τον Mythic server
- Και πολλές άλλες· χρησιμοποίησε την `help` για να δεις την πλήρη λίστα των διαθέσιμων commands.

### Κλιμάκωση προνομίων

- `getprivs`: Ενεργοποιεί όσο το δυνατόν περισσότερα privileges στο token του τρέχοντος thread
- `getsystem`: Ανοίγει ένα handle στο winlogon και αντιγράφει το token, κλιμακώνοντας ουσιαστικά τα privileges στο επίπεδο SYSTEM
- `make_token`: Δημιουργεί μια νέα logon session και την εφαρμόζει στον agent, επιτρέποντας την πλαστοπροσωπία άλλου χρήστη
- `steal_token`: Κλέβει ένα primary token από άλλη διεργασία, επιτρέποντας στον agent να πλαστοπροσωπήσει τον χρήστη αυτής της διεργασίας
- `pth`: Επίθεση Pass-the-Hash, η οποία επιτρέπει στον agent να πιστοποιηθεί ως χρήστης χρησιμοποιώντας το NTLM hash του, χωρίς να χρειάζεται τον κωδικό πρόσβασης σε απλό κείμενο
- `mimikatz`: Εκτελεί commands του Mimikatz για την εξαγωγή credentials, hashes και άλλων ευαίσθητων πληροφοριών από τη μνήμη ή τη SAM database
- `rev2self`: Επαναφέρει το token του agent στο primary token του, αφαιρώντας ουσιαστικά τα privileges και επαναφέροντάς τα στο αρχικό επίπεδο
- `ppid`: Αλλάζει τη γονική διεργασία για εργασίες post-exploitation, ορίζοντας νέο process ID γονικής διεργασίας και επιτρέποντας καλύτερο έλεγχο του περιβάλλοντος εκτέλεσης των εργασιών
- `printspoofer`: Εκτελεί commands του PrintSpoofer για την παράκαμψη των μέτρων ασφαλείας του print spooler, επιτρέποντας κλιμάκωση προνομίων ή εκτέλεση κώδικα
- `dcsync`: Συγχρονίζει τα Kerberos keys ενός χρήστη στον τοπικό υπολογιστή, επιτρέποντας offline password cracking ή περαιτέρω επιθέσεις
- `ticket_cache_add`: Προσθέτει ένα Kerberos ticket στην τρέχουσα ή σε καθορισμένη logon session, επιτρέποντας την επαναχρησιμοποίηση ticket ή την πλαστοπροσωπία

### Εκτέλεση διεργασιών

- `assembly_inject`: Επιτρέπει την εισαγωγή ενός .NET assembly loader σε απομακρυσμένη διεργασία
- `blockdlls`: Αποκλείει τη φόρτωση DLL που δεν φέρουν υπογραφή της Microsoft σε εργασίες post-exploitation
- `execute_assembly`: Εκτελεί ένα .NET assembly στο πλαίσιο του agent
- `execute_coff`: Εκτελεί ένα αρχείο COFF στη μνήμη, επιτρέποντας την εκτέλεση μεταγλωττισμένου κώδικα στη μνήμη
- `execute_pe`: Εκτελεί ένα unmanaged executable (PE)
- `keylog_inject`: Εισάγει ένα keylogger σε άλλη διεργασία και μεταδίδει τα keystrokes στην προβολή keylog του Mythic
- `screenshot` / `screenshot_inject`: Καταγράφει απευθείας την τρέχουσα επιφάνεια εργασίας ή
  εισάγει ένα screenshot assembly σε μια διεργασία/session-στόχο
- `get_injection_techniques`: Εμφανίζει τις διαθέσιμες τεχνικές injection και την τρέχουσα επιλεγμένη
- `inline_assembly`: Εκτελεί ένα .NET assembly σε disposable AppDomain, επιτρέποντας προσωρινή εκτέλεση κώδικα χωρίς να επηρεάζεται η κύρια διεργασία του agent
- `register_assembly`: Καταχωρίζει ένα .NET assembly για μελλοντική εκτέλεση
- `register_file`: Καταχωρίζει ένα αρχείο στο cache του agent για μεταγενέστερο `execute_*` ή PowerShell tasking
- `run`: Εκτελεί ένα binary στο target system, χρησιμοποιώντας το system PATH για να εντοπίσει το executable
- `set_injection_technique`: Αλλάζει το injection primitive που χρησιμοποιείται από εργασίες post-exploitation
- `shinject`: Εισάγει shellcode σε απομακρυσμένη διεργασία, επιτρέποντας την εκτέλεση αυθαίρετου κώδικα στη μνήμη
- `inject`: Εισάγει shellcode του agent σε απομακρυσμένη διεργασία, επιτρέποντας την εκτέλεση του κώδικα του agent στη μνήμη
- `spawn`: Δημιουργεί μια νέα agent session στο καθορισμένο executable, επιτρέποντας την εκτέλεση shellcode σε νέα διεργασία
- `spawnto_x64` και `spawnto_x86`: Αλλάζουν το προεπιλεγμένο binary που χρησιμοποιείται σε εργασίες post-exploitation σε καθορισμένη διαδρομή, αντί της χρήσης του `rundll32.exe` χωρίς παραμέτρους, η οποία δημιουργεί πολύ θόρυβο.

### Mythic Forge

Αυτό επιτρέπει τη **φόρτωση αρχείων COFF/BOF** από το Mythic Forge, ένα repository με προμεταγλωττισμένα payloads και εργαλεία που μπορούν να εκτελεστούν στο target system. Με όλες τις commands που μπορούν να φορτωθούν, θα είναι δυνατή η εκτέλεση συνηθισμένων ενεργειών μέσα από τον τρέχοντα agent process ως BOFs (συνήθως με καλύτερο OPSEC από την εκκίνηση ξεχωριστής διεργασίας).

Ξεκίνα εγκαθιστώντας τα με:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Στη συνέχεια, χρησιμοποιήστε το `forge_collections` για να εμφανίσετε τα modules COFF/BOF από το Mythic Forge, ώστε να μπορείτε να τα επιλέξετε και να τα φορτώσετε στη μνήμη του agent για εκτέλεση. Από προεπιλογή, προστίθενται στο Apollo οι ακόλουθες 2 συλλογές:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Αφού φορτωθεί ένα module, θα εμφανιστεί στη λίστα ως άλλη μία εντολή, όπως `forge_bof_sa-whoami` ή `forge_bof_sa-netuser`.

Για τα BOF, να θυμάστε ότι το Forge **δεν** προωθεί απλώς μία ενιαία συμβολοσειρά ορισμάτων στο Apollo. Αντιστοιχίζει τις παραμέτρους BOF στη μορφή typed-array του Mythic και, στη συνέχεια, τις προωθεί στη ροή `execute_coff` του Apollo. Αν ένα BOF που φορτώθηκε από το Forge συμπεριφέρεται παράξενα, ελέγξτε τους αναμενόμενους τύπους ορισμάτων BOF και το entrypoint, αντί να εξετάζετε μόνο τη γραμμή εντολών που πληκτρολογήσατε. Σημειώστε επίσης ότι ο νεότερος BOF loader του Apollo άλλαξε τον χειρισμό των ορισμάτων σε σχέση με πολύ παλαιότερες εκδόσεις της εποχής 2.3.1, επομένως παλιά BOF ή παλιές συλλογές ενδέχεται να αποτυγχάνουν αποκλειστικά λόγω αλλαγών στις απαιτήσεις marshaling.

### Εκτέλεση PowerShell και scripting

- `powershell_import`: Εισάγει ένα νέο script PowerShell (.ps1) στην cache του agent για μελλοντική εκτέλεση
- `powershell`: Εκτελεί μια εντολή PowerShell στο πλαίσιο του agent, επιτρέποντας προηγμένο scripting και αυτοματοποίηση
- `powerpick`: Εισάγει ένα assembly PowerShell loader σε μια θυσιαζόμενη διεργασία και εκτελεί μια εντολή PowerShell (χωρίς καταγραφή PowerShell).
- `psinject`: Εκτελεί PowerShell σε μια καθορισμένη διεργασία, επιτρέποντας τη στοχευμένη εκτέλεση scripts στο πλαίσιο μιας άλλης διεργασίας
- `shell`: Εκτελεί μια εντολή shell στο πλαίσιο του agent, όπως κατά την εκτέλεση μιας εντολής στο cmd.exe

### Πλευρική μετακίνηση

- `jump_psexec`: Χρησιμοποιεί την τεχνική PsExec για πλευρική μετακίνηση σε νέο host, αντιγράφοντας πρώτα το εκτελέσιμο του agent Apollo (apollo.exe) και εκτελώντας το.
- `jump_wmi`: Χρησιμοποιεί την τεχνική WMI για πλευρική μετακίνηση σε νέο host, αντιγράφοντας πρώτα το εκτελέσιμο του agent Apollo (apollo.exe) και εκτελώντας το.
- `link` και `unlink`: Δημιουργούν και καταργούν P2P συνδέσεις (για παράδειγμα μέσω SMB/TCP) μεταξύ callbacks.
- `wmiexecute`: Εκτελεί μια εντολή στο τοπικό ή σε καθορισμένο απομακρυσμένο σύστημα μέσω WMI, με προαιρετικά διαπιστευτήρια για impersonation.
- `net_dclist`: Ανακτά μια λίστα με domain controllers για τον καθορισμένο domain, χρήσιμη για τον εντοπισμό πιθανών στόχων πλευρικής μετακίνησης.
- `net_localgroup`: Παραθέτει τις τοπικές ομάδες στον καθορισμένο υπολογιστή· αν δεν καθοριστεί υπολογιστής, χρησιμοποιείται από προεπιλογή ο localhost.
- `net_localgroup_member`: Ανακτά τα μέλη μιας τοπικής ομάδας για μια καθορισμένη ομάδα στον τοπικό ή απομακρυσμένο υπολογιστή, επιτρέποντας την απαρίθμηση χρηστών σε συγκεκριμένες ομάδες.
- `net_shares`: Παραθέτει τα απομακρυσμένα shares και την προσβασιμότητά τους στον καθορισμένο υπολογιστή, χρήσιμη για τον εντοπισμό πιθανών στόχων πλευρικής μετακίνησης.
- `socks`: Ενεργοποιεί έναν συμβατό με SOCKS 5 proxy στο δίκτυο-στόχο, επιτρέποντας τη διοχέτευση κίνησης μέσω του παραβιασμένου host. Είναι συμβατό με εργαλεία όπως το proxychains.
- `rpfwd`: Ξεκινά την ακρόαση σε καθορισμένη θύρα στον host-στόχο και προωθεί την κίνηση μέσω του Mythic σε απομακρυσμένη IP και θύρα, επιτρέποντας την απομακρυσμένη πρόσβαση σε υπηρεσίες του δικτύου-στόχου.
- `listpipes`: Παραθέτει όλα τα named pipes στο τοπικό σύστημα, κάτι που μπορεί να φανεί χρήσιμο για πλευρική μετακίνηση ή κλιμάκωση προνομίων μέσω αλληλεπίδρασης με μηχανισμούς IPC.

Για τα primitives εκτέλεσης WMI χαμηλότερου επιπέδου που χρησιμοποιούνται από τα `jump_wmi` ή `wmiexecute`, δείτε το [WmiExec](lateral-movement/wmiexec.md). Για ευρύτερα μοτίβα pivoting, δείτε το [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Διάφορες εντολές
- `help`: Εμφανίζει λεπτομερείς πληροφορίες για συγκεκριμένες εντολές ή γενικές πληροφορίες για όλες τις διαθέσιμες εντολές του agent.
- `clear`: Σημειώνει tasks ως «cleared», ώστε να μην μπορούν να αναληφθούν από agents. Μπορείτε να καθορίσετε `all` για να εκκαθαρίσετε όλα τα tasks ή `task Num` για να εκκαθαρίσετε ένα συγκεκριμένο task.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Το Poseidon είναι agent γραμμένος σε Golang, ο οποίος μεταγλωττίζεται σε εκτελέσιμα για **Linux και macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Σημειώσεις για τα τρέχοντα builds/profiles

- Τα τρέχοντα Poseidon builds στοχεύουν σε Linux και macOS, τόσο σε `x86_64` όσο και σε `arm64`.
- Οι υποστηριζόμενες μορφές εξόδου περιλαμβάνουν native executables και outputs τύπου shared library, όπως `dylib` και `so`.
- Το Poseidon υποστηρίζει `http`, `websocket`, `tcp` και `dynamichttp`, ενώ τα τρέχοντα builders διαθέτουν ρυθμίσεις για πολλαπλά egress, όπως `egress_order` και όρια failover.
- Τα τρέχοντα capability metadata του Poseidon αναφέρουν επίσης browser scripts, ενσωμάτωση file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd και P2P, επομένως μπορεί να λειτουργήσει ως πραγματικός Linux/macOS pivot node και όχι απλώς ως ένα απλό remote shell.
- Αξίζει να ελέγχετε επιλογές build-time, όπως `proxy_bypass` και `garble`, όταν χρειάζεστε είτε πιο καθαρή συμπεριφορά δικτύου είτε επιπλέον Go binary obfuscation.
- Το `pty` είναι μία από τις πιο χρήσιμες νεότερες εντολές ποιότητας ζωής για επιχειρήσεις Linux/macOS, επειδή ανοίγει ένα interactive PTY και μπορεί να εκθέσει μια θύρα στην πλευρά του Mythic για πληρέστερη αλληλεπίδραση με το terminal, χωρίς να χρειάζεται το παλαιότερο workaround `sleep 0` + SOCKS.
- Τα τρέχοντα docs του Poseidon είναι ιδιαίτερα ενδιαφέροντα για tradecraft με επίκεντρο το macOS: το `jxa` εκτελεί JavaScript for Automation στη μνήμη, το `screencapture` καταγράφει την επιφάνεια εργασίας του συνδεδεμένου χρήστη, το `clipboard_monitor` μεταδίδει αλλαγές στο pasteboard, το `execute_library` φορτώνει ένα τοπικό dylib και καλεί μια συνάρτηση από αυτό, ενώ το `libinject` αναγκάζει μια remote process να φορτώσει ένα dylib από τον δίσκο.
- Για εργασίες μεγάλης διάρκειας, να θυμάστε ότι το Poseidon εκτελεί post-exploitation εργασίες σε goroutines/threads που είναι συνεργατικές και όχι δυνατό να τερματιστούν άμεσα. Τα docs σημειώνουν επίσης ρητά ότι προς το παρόν δεν υπάρχει ενσωματωμένο agent obfuscation, επομένως το tradecraft σε επίπεδο build/profile έχει μεγαλύτερη σημασία απ' ό,τι σε heavily obfuscated commercial implants.

Για tradecraft ειδικά για macOS σε επιχειρήσεις που βασίζονται στο Mythic, κατάχρηση JAMF ή ιδέες για MDM-as-C2, δείτε το [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Όταν χρησιμοποιείται σε Linux ή macOS, διαθέτει μερικές ενδιαφέρουσες εντολές:

### Συνήθεις ενέργειες

- `cat`: Εμφανίζει τα περιεχόμενα ενός αρχείου
- `cd`: Αλλάζει τον τρέχοντα working directory
- `chmod`: Αλλάζει τα permissions ενός αρχείου
- `config`: Εμφανίζει τις τρέχουσες πληροφορίες config και host
- `cp`: Αντιγράφει ένα αρχείο από μια τοποθεσία σε άλλη
- `curl`: Εκτελεί ένα μεμονωμένο web request με προαιρετικά headers και method
- `upload`: Ανεβάζει ένα αρχείο στον στόχο
- `download`: Κατεβάζει ένα αρχείο από το σύστημα-στόχο στον τοπικό υπολογιστή
- Και πολλά άλλα

### Αναζήτηση ευαίσθητων πληροφοριών

- `triagedirectory`: Εντοπίζει ενδιαφέροντα αρχεία σε έναν κατάλογο ενός host, όπως ευαίσθητα αρχεία ή credentials.
- `getenv`: Λαμβάνει όλες τις τρέχουσες environment variables.

### Tradecraft ειδικά για macOS

- `jxa`: Εκτελεί JavaScript for Automation στη μνήμη μέσω `OSAScript`, κάτι χρήσιμο για native macOS post-exploitation χωρίς την αποθήκευση ξεχωριστών script files.
- `clipboard_monitor`: Ελέγχει το pasteboard και αναφέρει τις αλλαγές στο Mythic, κάτι χρήσιμο σε workflows κλοπής credentials/token που βασίζονται σε copy/paste.
- `screencapture`: Καταγράφει την επιφάνεια εργασίας του χρήστη σε macOS.
- `execute_library`: Φορτώνει ένα dylib από τον δίσκο και καλεί μια συγκεκριμένη exported function.
- `libinject`: Κάνει inject ένα shellcode stub που αναγκάζει μια άλλη macOS process να φορτώσει ένα dylib από τον δίσκο.
- `persist_launchd`: Δημιουργεί persistence μέσω LaunchAgent / LaunchDaemon απευθείας από τον agent.

### Πλευρική μετακίνηση

- `ssh`: Συνδέεται με host μέσω SSH χρησιμοποιώντας τα καθορισμένα credentials και ανοίγει ένα PTY χωρίς να εκκινεί το ssh.
- `sshauth`: Συνδέεται με τους καθορισμένους host(s) μέσω SSH χρησιμοποιώντας τα καθορισμένα credentials. Μπορείτε επίσης να το χρησιμοποιήσετε για να εκτελέσετε μια συγκεκριμένη εντολή στους remote hosts μέσω SSH ή για να μεταφέρετε αρχεία μέσω SCP.
- `link_tcp`: Συνδέεται με άλλον agent μέσω TCP, επιτρέποντας άμεση επικοινωνία μεταξύ agents.
- `link_webshell`: Συνδέεται με έναν agent χρησιμοποιώντας το webshell P2P profile, παρέχοντας remote πρόσβαση στο web interface του agent.
- `rpfwd`: Εκκινεί ή σταματά ένα Reverse Port Forward, επιτρέποντας remote πρόσβαση σε υπηρεσίες στο δίκτυο-στόχο.
- `socks`: Εκκινεί ή σταματά έναν SOCKS5 proxy στο δίκτυο-στόχο, επιτρέποντας τη διοχέτευση traffic μέσω του compromised host. Είναι συμβατό με εργαλεία όπως το proxychains.
- `portscan`: Σαρώνει host(s) για ανοιχτές θύρες, χρήσιμο για τον εντοπισμό πιθανών στόχων για πλευρική μετακίνηση ή περαιτέρω επιθέσεις.

### Εκτέλεση διεργασιών

- `shell`: Εκτελεί μία εντολή shell μέσω `/bin/sh`, επιτρέποντας την άμεση εκτέλεση εντολών στο σύστημα-στόχο.
- `run`: Εκτελεί μια εντολή από τον δίσκο με arguments, επιτρέποντας την εκτέλεση binaries ή scripts στο σύστημα-στόχο.
- `pty`: Ανοίγει ένα interactive PTY, επιτρέποντας την άμεση αλληλεπίδραση με το shell στο σύστημα-στόχο.

## References

- [1] [Πίνακας χαρακτηριστικών agents της κοινότητας Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README του Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Κύρια σημεία του Mythic v3.2: Interactive Tasking, Push C2 και Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Τεκμηρίωση Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Ενημερώσεις Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Μεταμορφώνοντας τις επιχειρήσεις Red Team με τα κρυμμένα διαμάντια του Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Κανόνες YARA για Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Από fork σε framework: Τι μας δίδαξε η τροποποίηση του Apollo για την εισβολή agent](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
