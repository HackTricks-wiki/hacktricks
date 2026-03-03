# Διαφυγή από KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Έλεγχος φυσικής συσκευής

| Συστατικό   | Ενέργεια                                                                 |
| ----------- | ------------------------------------------------------------------------ |
| Power button | Το να απενεργοποιήσετε και να ενεργοποιήσετε ξανά τη συσκευή μπορεί να εμφανίσει την αρχική οθόνη |
| Power cable  | Ελέγξτε εάν η συσκευή κάνει επανεκκίνηση όταν η τροφοδοσία διακοπεί προσωρινά |
| USB ports    | Συνδέστε φυσικό πληκτρολόγιο για περισσότερες συντομεύσεις                 |
| Ethernet     | Σάρωση δικτύου ή sniffing μπορεί να επιτρέψει περαιτέρω εκμετάλλευση      |

## Έλεγχος πιθανών ενεργειών μέσα στην εφαρμογή GUI

**Συνηθισμένα Παράθυρα Διαλόγου** είναι εκείνες οι επιλογές της **αποθήκευσης αρχείου**, **ανοίγματος αρχείου**, επιλογής γραμματοσειράς, χρώματος... Τα περισσότερα από αυτά θα **προσφέρουν πλήρη λειτουργικότητα του Explorer**. Αυτό σημαίνει ότι θα μπορείτε να αποκτήσετε πρόσβαση σε λειτουργίες του Explorer εάν μπορείτε να ανοίξετε αυτές τις επιλογές:

- Κλείσιμο/Κλείσιμο ως
- Άνοιγμα/Άνοιγμα με
- Εκτύπωση
- Εξαγωγή/Εισαγωγή
- Αναζήτηση
- Σάρωση

Πρέπει να ελέγξετε αν μπορείτε να:

- Τροποποιήσετε ή να δημιουργήσετε νέα αρχεία
- Δημιουργήσετε συμβολικούς συνδέσμους
- Αποκτήσετε πρόσβαση σε περιορισμένες περιοχές
- Εκτελέσετε άλλες εφαρμογές

### Εκτέλεση εντολών

Ίσως **χρησιμοποιώντας ένα `Open with`** option\*\* να μπορείτε να ανοίξετε/εκτελέσετε κάποιο είδος shell.

#### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ Βρείτε περισσότερα binaries που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και την εκτέλεση απροσδόκητων ενεργειών) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Παράκαμψη περιορισμών διαδρομών

- **Μεταβλητές περιβάλλοντος**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που δείχνουν σε διαδρομές
- **Άλλα πρωτόκολλα**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Συμβολικοί σύνδεσμοι**
- **Συντομεύσεις**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Κρυφό διοικητικό μενού: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Διαδρομές για σύνδεση σε κοινόχρηστους φακέλους. Πρέπει να δοκιμάσετε να συνδεθείτε στο C$ της τοπικής μηχανής ("\\\127.0.0.1\c$\Windows\System32")
- **Περισσότερες UNC διαδρομές:**

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

### Περιορισμένες διαφυγές επιφάνειας εργασίας (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Χρησιμοποιήστε τα *Open/Save/Print-to-file* παράθυρα διαλόγου ως Explorer-lite. Δοκιμάστε `*.*` / `*.exe` στο πεδίο ονόματος αρχείου, κάντε δεξί κλικ σε φακέλους για **Open in new window**, και χρησιμοποιήστε **Properties → Open file location** για να επεκτείνετε την πλοήγηση.
- **Create execution paths from dialogs**: Δημιουργήστε νέο αρχείο και μετονομάστε το σε `.CMD` ή `.BAT`, ή δημιουργήστε μια συντόμευση που δείχνει σε `%WINDIR%\System32` (ή σε ένα συγκεκριμένο binary όπως `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Αν μπορείτε να περιηγηθείτε σε `cmd.exe`, δοκιμάστε το **drag-and-drop** οποιουδήποτε αρχείου πάνω του για να ανοίξετε ένα prompt. Αν ο Task Manager είναι προσβάσιμος (`CTRL+SHIFT+ESC`), χρησιμοποιήστε **Run new task**.
- **Task Scheduler bypass**: Αν τα interactive shells είναι μπλοκαρισμένα αλλά επιτρέπεται ο προγραμματισμός, δημιουργήστε ένα task για να τρέξει `cmd.exe` (GUI `taskschd.msc` ή `schtasks.exe`).
- **Weak allowlists**: Αν η εκτέλεση επιτρέπεται βάσει **filename/extension**, μετονομάστε το payload σας σε επιτρεπόμενο όνομα. Αν επιτρέπεται βάσει **directory**, αντιγράψτε το payload σε έναν επιτρεπόμενο φάκελο προγράμματος και τρέξτε το εκεί.
- **Find writable staging paths**: Ξεκινήστε με `%TEMP%` και καταγράψτε εγγράψιμους φακέλους με Sysinternals AccessChk.
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

### Πρόσβαση στο filesystem από το πρόγραμμα περιήγησης

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
- Toggle Keys – Κρατήστε πατημένο το NUMLOCK για 5 δευτερόλεπτα
- Filter Keys – Κρατήστε πατημένο το δεξί SHIFT για 12 δευτερόλεπτα
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Εμφάνισε την Επιφάνεια Εργασίας
- WINDOWS+E – Άνοιγμα Windows Explorer
- WINDOWS+R – Εκτέλεση (Run)
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Αναζήτηση
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen σε νεότερες εκδόσεις Windows
- F1 – Βοήθεια F3 – Αναζήτηση
- F6 – Address Bar
- F11 – Εναλλαγή πλήρους οθόνης μέσα στο Internet Explorer
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – Νέα καρτέλα
- CTRL+N – Internet Explorer – Νέα σελίδα
- CTRL+O – Άνοιγμα αρχείου
- CTRL+S – Αποθήκευση CTRL+N – Νέο RDP / Citrix

### Swipe κινήσεις

- Σύρετε από την αριστερή πλευρά προς τα δεξιά για να δείτε όλα τα ανοιχτά Windows, ελαχιστοποιώντας την KIOSK εφαρμογή και αποκτώντας άμεση πρόσβαση σε ολόκληρο το OS;
- Σύρετε από τη δεξιά πλευρά προς τα αριστερά για να ανοίξετε το Action Center, ελαχιστοποιώντας την KIOSK εφαρμογή και αποκτώντας άμεση πρόσβαση σε ολόκληρο το OS;
- Σύρετε από την επάνω άκρη προς τα μέσα για να γίνει ορατή η γραμμή τίτλου για μια εφαρμογή που είναι ανοιχτή σε πλήρη οθόνη;
- Σύρετε προς τα πάνω από το κάτω μέρος για να εμφανιστεί η γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

### Κόλπα Internet Explorer

#### 'Image Toolbar'

Είναι μια γραμμή εργαλείων που εμφανίζεται πάνω αριστερά στην εικόνα όταν αυτή κλικαριστεί. Θα μπορείτε να Save, Print, Mailto, Open "My Pictures" in Explorer. Ο Kiosk πρέπει να χρησιμοποιεί Internet Explorer.

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

## Κόλπα προγραμμάτων περιήγησης

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Δημιουργήστε ένα κοινό παράθυρο διαλόγου χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στον file explorer: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Κινήσεις και κουμπιά

- Σαρώστε προς τα πάνω με τέσσερα (ή πέντε) δάχτυλα / Διπλό πάτημα στο Home button: Για προβολή του multitask view και αλλαγή App
- Σαρώστε με τέσσερα ή πέντε δάχτυλα προς τη μια ή την άλλη κατεύθυνση: Για αλλαγή στην επόμενη/προηγούμενη εφαρμογή
- Σμίξτε την οθόνη με πέντε δάχτυλα / Πατήστε το Home button / Σαρώστε προς τα πάνω με 1 δάχτυλο από το κάτω μέρος της οθόνης με γρήγορη κίνηση προς τα πάνω: Για πρόσβαση στο Home
- Σύρετε ένα δάχτυλο από το κάτω μέρος της οθόνης περίπου 1-2 ίντσες (αργά): Το dock θα εμφανιστεί
- Σύρετε προς τα κάτω από το πάνω μέρος της οθόνης με 1 δάχτυλο: Για να δείτε τις ειδοποιήσεις σας
- Σύρετε προς τα κάτω με 1 δάχτυλο την πάνω-δεξιά γωνία της οθόνης: Για να δείτε το control centre του iPad Pro
- Σύρετε 1 δάχτυλο από την αριστερή πλευρά της οθόνης 1-2 ίντσες: Για να δείτε την προβολή Today
- Σύρετε γρήγορα 1 δάχτυλο από το κέντρο της οθόνης προς τα δεξιά ή αριστερά: Για αλλαγή στην επόμενη/προηγούμενη εφαρμογή
- Πατήστε και κρατήστε πατημένο το On/**Off**/Sleep κουμπί στην πάνω-δεξιά γωνία του **iPad +** Μετακινήστε το Slide to **power off** ρυθμιστικό όλο δεξιά: Για απενεργοποίηση
- Πατήστε το On/**Off**/Sleep κουμπί στην πάνω-δεξιά γωνία του **iPad και το Home button για λίγα δευτερόλεπτα**: Για αναγκαστικό σβήσιμο
- Πατήστε το On/**Off**/Sleep κουμπί στην πάνω-δεξιά γωνία του **iPad και το Home button γρήγορα**: Για να τραβήξετε ένα screenshot που θα εμφανιστεί κάτω αριστερά στην οθόνη. Πατήστε και τα δύο κουμπιά ταυτόχρονα πολύ σύντομα — αν τα κρατήσετε για λίγα δευτερόλεπτα θα εκτελεστεί αναγκαστικό σβήσιμο.

### Συντομεύσεις

Θα πρέπει να έχετε ένα iPad keyboard ή έναν USB keyboard adaptor. Θα εμφανιστούν μόνο συντομεύσεις που μπορούν να βοηθήσουν στην έξοδο από την εφαρμογή.

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

Αυτές οι συντομεύσεις είναι για τις οπτικές ρυθμίσεις και τις ρυθμίσεις ήχου, ανάλογα με τη χρήση του iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Dim Sscreen                                                                    |
| F2       | Brighten screen                                                                |
| F7       | Back one song                                                                  |
| F8       | Play/pause                                                                     |
| F9       | Skip song                                                                      |
| F10      | Mute                                                                           |
| F11      | Decrease volume                                                                |
| F12      | Increase volume                                                                |
| ⌘ Space  | Εμφανίζει μια λίστα διαθέσιμων γλωσσών· για να επιλέξετε μια, πατήστε ξανά το space. |

#### Πλοήγηση iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Μετάβαση στο Home                                       |
| ⌘⇧H (Command-Shift-H)                              | Μετάβαση στο Home                                       |
| ⌘ (Space)                                          | Άνοιγμα Spotlight                                       |
| ⌘⇥ (Command-Tab)                                   | Λίστα με τις δέκα πιο πρόσφατες εφαρμογές               |
| ⌘\~                                                | Μετάβαση στην τελευταία εφαρμογή                        |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (εμφανίζεται κάτω αριστερά για αποθήκευση ή ενέργεια) |
| ⌘⇧4                                                | Screenshot και άνοιγμα στον editor                      |
| Press and hold ⌘                                   | Λίστα με τις διαθέσιμες συντομεύσεις για την εφαρμογή   |
| ⌘⌥D (Command-Option/Alt-D)                         | Εμφανίζει το dock                                       |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | Εμφάνιση multitask bar                                  |
| ^⌥I (Control-Option-i)                             | Επιλογέας αντικειμένων                                  |
| Escape                                             | Πλήκτρο πίσω                                           |
| → (Right arrow)                                    | Επόμενο στοιχείο                                        |
| ← (Left arrow)                                     | Προηγούμενο στοιχείο                                    |
| ↑↓ (Up arrow, Down arrow)                          | Ταυτόχρονο πάτημα στο επιλεγμένο στοιχείο               |
| ⌥ ↓ (Option-Down arrow)                            | Κύλιση προς τα κάτω                                     |
| ⌥↑ (Option-Up arrow)                               | Κύλιση προς τα πάνω                                     |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Κύλιση αριστερά ή δεξιά                                 |
| ^⌥S (Control-Option-S)                             | Ενεργοποιεί/απενεργοποιεί το VoiceOver speech          |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Εναλλαγή στην προηγούμενη εφαρμογή                      |
| ⌘⇥ (Command-Tab)                                   | Επιστροφή στην αρχική εφαρμογή                         |
| ←+→, then Option + ← or Option+→                   | Πλοήγηση μέσω του Dock                                  |

#### Συντομεύσεις Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Άνοιγμα τοποθεσίας (Location)                    |
| ⌘T                      | Άνοιγμα νέας καρτέλας                             |
| ⌘W                      | Κλείσιμο της τρέχουσας καρτέλας                  |
| ⌘R                      | Ανανέωση της τρέχουσας καρτέλας                  |
| ⌘.                      | Διακοπή φόρτωσης της τρέχουσας καρτέλας          |
| ^⇥                      | Εναλλαγή στην επόμενη καρτέλα                    |
| ^⇧⇥ (Control-Shift-Tab) | Μετάβαση στην προηγούμενη καρτέλα                |
| ⌘L                      | Επιλογή του πεδίου εισαγωγής/URL για επεξεργασία  |
| ⌘⇧T (Command-Shift-T)   | Άνοιγμα της τελευταίας κλειστής καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Επιστροφή μία σελίδα στο ιστορικό περιήγησης     |
| ⌘]                      | Προχώρημα μία σελίδα στο ιστορικό περιήγησης     |
| ⌘⇧R                     | Ενεργοποίηση Reader Mode                         |

#### Συντομεύσεις Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Άνοιγμα τοποθεσίας           |
| ⌘T                         | Άνοιγμα νέας καρτέλας        |
| ⌘W                         | Κλείσιμο της τρέχουσας καρτέλας |
| ⌘R                         | Ανανέωση της τρέχουσας καρτέλας |
| ⌘.                         | Διακοπή φόρτωσης της τρέχουσας καρτέλας |
| ⌘⌥F (Command-Option/Alt-F) | Αναζήτηση στο mailbox σας     |

## Αναφορές

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
