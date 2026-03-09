# Διαφυγή από KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Έλεγχος φυσικής συσκευής

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Το κλείσιμο και το άνοιγμα της συσκευής μπορεί να εμφανίσει την οθόνη εκκίνησης |
| Power cable  | Ελέγξτε αν η συσκευή κάνει επανεκκίνηση όταν η τροφοδοσία κόβεται για λίγο |
| USB ports    | Συνδέστε φυσικό πληκτρολόγιο για περισσότερες συντομεύσεις           |
| Ethernet     | Σάρωση δικτύου ή sniffing μπορεί να επιτρέψει περαιτέρω εκμετάλλευση |

## Έλεγχος πιθανών ενεργειών μέσα στην GUI εφαρμογή

**Common Dialogs** είναι αυτές οι επιλογές όπως **αποθήκευση αρχείου**, **άνοιγμα αρχείου**, επιλογή γραμματοσειράς, χρώματος... Οι περισσότερες από αυτές θα **προσφέρουν πλήρη Explorer λειτουργικότητα**. Αυτό σημαίνει ότι θα μπορείτε να έχετε πρόσβαση σε λειτουργίες του Explorer αν μπορέσετε να αποκτήσετε πρόσβαση σε αυτές τις επιλογές:

- Κλείσιμο/Κλείσιμο ως
- Άνοιγμα/Άνοιγμα με
- Εκτύπωση
- Εξαγωγή/Εισαγωγή
- Αναζήτηση
- Σάρωση

Πρέπει να ελέγξετε αν μπορείτε να:

- Τροποποιήσετε ή δημιουργήσετε νέα αρχεία
- Δημιουργήσετε συμβολικούς συνδέσμους
- Αποκτήσετε πρόσβαση σε περιορισμένες περιοχές
- Εκτελέσετε άλλες εφαρμογές

### Εκτέλεση Εντολών

Ίσως **χρησιμοποιώντας την επιλογή `Open with`** μπορείτε να ανοίξετε/εκτελέσετε κάποιο shell.

#### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ βρείτε περισσότερα binaries που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και για μη αναμενόμενες ενέργειες) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Παράκαμψη περιορισμών διαδρομής

- **Environment variables**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που δείχνουν σε κάποιο path
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (άνοιγμα νέας συνεδρίας), CTRL+R (Εκτέλεση Εντολών), CTRL+SHIFT+ESC (Task Manager), Windows+E (άνοιγμα explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Διαδρομές για σύνδεση σε shared folders. Πρέπει να δοκιμάσετε να συνδεθείτε στο C$ της τοπικής μηχανής ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Χρησιμοποιήστε τα διαλόγους *Open/Save/Print-to-file* ως Explorer-lite. Δοκιμάστε `*.*` / `*.exe` στο πεδίο ονόματος αρχείου, δεξί κλικ σε φακέλους για **Open in new window**, και χρησιμοποιήστε **Properties → Open file location** για να επεκτείνετε την πλοήγηση.
- **Create execution paths from dialogs**: Δημιουργήστε νέο αρχείο και μετονομάστε το σε `.CMD` ή `.BAT`, ή δημιουργήστε συντόμευση που δείχνει σε `%WINDIR%\System32` (ή σε συγκεκριμένο binary όπως `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Εάν μπορείτε να περιηγηθείτε στο `cmd.exe`, δοκιμάστε **drag-and-drop** οποιουδήποτε αρχείου πάνω του για να εκκινήσετε ένα prompt. Εάν είναι προσβάσιμο το Task Manager (`CTRL+SHIFT+ESC`), χρησιμοποιήστε **Run new task**.
- **Task Scheduler bypass**: Εάν τα interactive shells είναι μπλοκαρισμένα αλλά επιτρέπεται ο προγραμματισμός, δημιουργήστε ένα task για να εκτελέσει `cmd.exe` (GUI `taskschd.msc` ή `schtasks.exe`).
- **Weak allowlists**: Εάν η εκτέλεση επιτρέπεται βάσει **filename/extension**, μετονομάστε το payload σας σε επιτρεπόμενο όνομα. Εάν επιτρέπεται βάσει **directory**, αντιγράψτε το payload σε έναν επιτρεπόμενο φάκελο προγράμματος και εκτελέστε το εκεί.
- **Find writable staging paths**: Ξεκινήστε με `%TEMP%` και εντοπίστε writeable φακέλους με Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Επόμενο βήμα**: Αν αποκτήσετε shell, pivot στο Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Κατεβάστε τα Binaries σας

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Πρόσβαση στο filesystem από τον browser

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Συντομεύσεις

- Sticky Keys – Πατήστε SHIFT 5 φορές
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Κρατήστε NUMLOCK πατημένο για 5 δευτερόλεπτα
- Filter Keys – Κρατήστε δεξί SHIFT πατημένο για 12 δευτερόλεπτα
- WINDOWS+F1 – Αναζήτηση των Windows
- WINDOWS+D – Εμφάνιση επιφάνειας εργασίας
- WINDOWS+E – Εκκίνηση Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen σε νεότερες εκδόσεις Windows
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Εναλλαγή πλήρους οθόνης εντός Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Κινήσεις (Swipes)

- Σαρώστε από την αριστερή προς τη δεξιά πλευρά για να δείτε όλα τα ανοικτά Windows, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση στο λειτουργικό σύστημα.
- Σαρώστε από τη δεξιά προς την αριστερή πλευρά για να ανοίξετε το Action Center, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση στο λειτουργικό σύστημα.
- Σαρώστε από την επάνω άκρη προς τα μέσα για να εμφανίσετε τη γραμμή τίτλου μιας εφαρμογής που είναι ανοιγμένη σε πλήρη οθόνη.
- Σαρώστε προς τα πάνω από το κάτω μέρος για να εμφανίσετε τη γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

### Internet Explorer Tricks

#### 'Image Toolbar'

Είναι μια toolbar που εμφανίζεται πάνω αριστερά στην εικόνα όταν την κάνετε κλικ. Θα μπορείτε να Save, Print, Mailto, Open "My Pictures" in Explorer. Το Kiosk πρέπει να χρησιμοποιεί Internet Explorer.

#### Shell Protocol

Πληκτρολογήστε αυτά τα URLs για να αποκτήσετε μια προβολή Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Εμφάνιση επεκτάσεων αρχείων

Δείτε αυτή τη σελίδα για περισσότερες πληροφορίες: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Κόλπα browser

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Δημιουργήστε ένα κοινό παράθυρο διαλόγου χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στο file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Χειρονομίες και κουμπιά

- Σαρώστε προς τα πάνω με τέσσερα (ή πέντε) δάχτυλα / Διπλό πάτημα κουμπιού Home: Για να δείτε την προβολή multitask και να αλλάξετε εφαρμογή
- Σαρώστε με τέσσερα ή πέντε δάχτυλα προς τη μια ή την άλλη πλευρά: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή
- Σφίξτε την οθόνη με πέντε δάχτυλα / Πατήστε το Home button / Σαρώστε γρήγορα προς τα πάνω με 1 δάχτυλο από το κάτω μέρος της οθόνης: Για να μεταβείτε στο Home
- Σαρώστε με ένα δάχτυλο από το κάτω μέρος της οθόνης μόλις 1-2 ίντσες (αργά): Το dock θα εμφανιστεί
- Σαρώστε προς τα κάτω από το πάνω μέρος της οθόνης με 1 δάχτυλο: Για να δείτε τις ειδοποιήσεις σας
- Σαρώστε προς τα κάτω με 1 δάχτυλο στην πάνω-δεξιά γωνία της οθόνης: Για να δείτε το control centre του iPad Pro
- Σαρώστε με 1 δάχτυλο από την αριστερή πλευρά της οθόνης 1-2 ίντσες: Για να δείτε την προβολή Today
- Σαρώστε γρήγορα με 1 δάχτυλο από το κέντρο της οθόνης προς τα δεξιά ή αριστερά: Για να αλλάξετε στην επόμενη/προηγούμενη εφαρμογή
- Πατήστε και κρατήστε το On/**Off**/Sleep button στην επάνω-δεξιά γωνία του **iPad +** Μετακινήστε το Slide to **power off** slider όλο δεξιά: Για να απενεργοποιήσετε
- Πατήστε το On/**Off**/Sleep button στην επάνω-δεξιά γωνία του **iPad και το Home button για μερικά δευτερόλεπτα**: Για να πραγματοποιήσετε σκληρή απενεργοποίηση
- Πατήστε το On/**Off**/Sleep button στην επάνω-δεξιά γωνία του **iPad και το Home button γρήγορα**: Για να τραβήξετε screenshot που θα εμφανιστεί κάτω αριστερά στην οθόνη. Πατήστε και τα δύο κουμπιά ταυτόχρονα πολύ σύντομα — αν τα κρατήσετε μερικά δευτερόλεπτα θα πραγματοποιηθεί σκληρή απενεργοποίηση.

### Συντομεύσεις

Πρέπει να έχετε πληκτρολόγιο iPad ή USB keyboard adaptor. Εδώ εμφανίζονται μόνο οι συντομεύσεις που μπορούν να βοηθήσουν στην έξοδο από την εφαρμογή.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Συντομεύσεις συστήματος

Αυτές οι συντομεύσεις αφορούν τις ρυθμίσεις οπτικού περιβάλλοντος και ήχου, ανάλογα με τη χρήση του iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Σκοτεινιάζει την οθόνη                                                          |
| F2       | Ανοίγει τη φωτεινότητα της οθόνης                                               |
| F7       | Πίσω ένα τραγούδι                                                               |
| F8       | Play/pause                                                                      |
| F9       | Προχώρηση τραγουδιού                                                            |
| F10      | Σίγαση                                                                          |
| F11      | Μείωση έντασης                                                                   |
| F12      | Αύξηση έντασης                                                                   |
| ⌘ Space  | Εμφανίζει λίστα διαθέσιμων γλωσσών· για να επιλέξετε μία, πατήστε ξανά το space. |

#### Πλοήγηση iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Πηγαίνει στο Home                                       |
| ⌘⇧H (Command-Shift-H)                              | Πηγαίνει στο Home                                       |
| ⌘ (Space)                                          | Ανοίγει το Spotlight                                    |
| ⌘⇥ (Command-Tab)                                   | Εμφανίζει τις δέκα τελευταίες εφαρμογές που χρησιμοποιήθηκαν |
| ⌘\~                                                | Πηγαίνει στην τελευταία εφαρμογή                        |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (εμφανίζεται κάτω αριστερά για αποθήκευση ή ενέργεια) |
| ⌘⇧4                                                | Screenshot και άνοιγμα στον editor                      |
| Press and hold ⌘                                   | Λίστα συντομεύσεων διαθέσιμων για την εφαρμογή         |
| ⌘⌥D (Command-Option/Alt-D)                         | Εμφανίζει το dock                                       |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | Εμφανίζει τη γραμμή multitask                            |
| ^⌥I (Control-Option-i)                             | Επιλογέας στοιχείων                                      |
| Escape                                             | Κουμπί επιστροφής                                       |
| → (Right arrow)                                    | Επόμενο στοιχείο                                        |
| ← (Left arrow)                                     | Προηγούμενο στοιχείο                                    |
| ↑↓ (Up arrow, Down arrow)                          | Επιλογή του επιλεγμένου στοιχείου                       |
| ⌥ ↓ (Option-Down arrow)                            | Κύλιση προς τα κάτω                                     |
| ⌥↑ (Option-Up arrow)                               | Κύλιση προς τα πάνω                                     |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Κύλιση αριστερά ή δεξιά                                 |
| ^⌥S (Control-Option-S)                             | Ενεργοποιεί ή απενεργοποιεί το VoiceOver speech        |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Εναλλαγή στην προηγούμενη εφαρμογή                      |
| ⌘⇥ (Command-Tab)                                   | Επιστροφή στην αρχική εφαρμογή                         |
| ←+→, then Option + ← or Option+→                   | Πλοήγηση μέσω του Dock                                  |

#### Συντομεύσεις Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Άνοιγμα πεδίου τοποθεσίας                        |
| ⌘T                      | Άνοιγμα νέας καρτέλας                            |
| ⌘W                      | Κλείσιμο της τρέχουσας καρτέλας                  |
| ⌘R                      | Ανανέωση της τρέχουσας καρτέλας                  |
| ⌘.                      | Σταματά τη φόρτωση της τρέχουσας καρτέλας        |
| ^⇥                      | Εναλλαγή στην επόμενη καρτέλα                    |
| ^⇧⇥ (Control-Shift-Tab) | Μετακίνηση στην προηγούμενη καρτέλα              |
| ⌘L                      | Επιλογή του πεδίου εισαγωγής/URL για επεξεργασία  |
| ⌘⇧T (Command-Shift-T)   | Άνοιγμα της τελευταίας κλειστής καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Επιστροφή μία σελίδα στο ιστορικό περιήγησης     |
| ⌘]                      | Προώθηση μία σελίδα στο ιστορικό περιήγησης      |
| ⌘⇧R                     | Ενεργοποίηση Reader Mode                         |

#### Συντομεύσεις Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Open Location                |
| ⌘T                         | Open a new tab               |
| ⌘W                         | Close the current tab        |
| ⌘R                         | Refresh the current tab      |
| ⌘.                         | Stop loading the current tab |
| ⌘⌥F (Command-Option/Alt-F) | Search in your mailbox       |

## References

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
