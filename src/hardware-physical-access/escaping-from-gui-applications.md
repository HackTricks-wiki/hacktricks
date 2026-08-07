# Διαφυγή από KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Έλεγχος φυσικής συσκευής

| Στοιχείο     | Ενέργεια                                                         |
| ------------ | ---------------------------------------------------------------- |
| Κουμπί λειτουργίας | Η απενεργοποίηση και επανενεργοποίηση της συσκευής μπορεί να εμφανίσει την οθόνη εκκίνησης |
| Καλώδιο τροφοδοσίας | Ελέγξτε αν η συσκευή επανεκκινείται όταν η τροφοδοσία διακοπεί για λίγο |
| Θύρες USB    | Συνδέστε φυσικό πληκτρολόγιο με περισσότερες συντομεύσεις         |
| Ethernet     | Η σάρωση δικτύου ή το sniffing μπορεί να επιτρέψει περαιτέρω εκμετάλλευση |

## Έλεγχος για πιθανές ενέργειες μέσα στην εφαρμογή GUI

Οι **Συνήθεις διάλογοι** είναι εκείνες οι επιλογές για **αποθήκευση ενός αρχείου**, **άνοιγμα ενός αρχείου**, επιλογή γραμματοσειράς, χρώματος... Οι περισσότεροι θα **προσφέρουν πλήρη λειτουργικότητα Explorer**. Αυτό σημαίνει ότι θα μπορείτε να αποκτήσετε πρόσβαση στις λειτουργίες του Explorer, αν μπορείτε να αποκτήσετε πρόσβαση σε αυτές τις επιλογές:

- Κλείσιμο/Κλείσιμο ως
- Άνοιγμα/Άνοιγμα με
- Εκτύπωση
- Εξαγωγή/Εισαγωγή
- Αναζήτηση
- Σάρωση

Θα πρέπει να ελέγξετε αν μπορείτε να:

- Τροποποιήσετε ή να δημιουργήσετε νέα αρχεία
- Δημιουργήσετε symbolic links
- Αποκτήσετε πρόσβαση σε περιορισμένες περιοχές
- Εκτελέσετε άλλες εφαρμογές

### Εκτέλεση εντολών

Ίσως **χρησιμοποιώντας την επιλογή `Open with`**\*\* να μπορείτε να ανοίξετε/εκτελέσετε κάποιο είδος shell.

#### Windows

Για παράδειγμα _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ βρείτε περισσότερα binaries που μπορούν να χρησιμοποιηθούν για την εκτέλεση εντολών (και την εκτέλεση απρόβλεπτων ενεργειών) εδώ: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Περισσότερα εδώ: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Παράκαμψη περιορισμών διαδρομών

- **Μεταβλητές περιβάλλοντος**: Υπάρχουν πολλές μεταβλητές περιβάλλοντος που παραπέμπουν σε κάποια διαδρομή
- **Άλλα πρωτόκολλα**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Συντομεύσεις**: CTRL+N (άνοιγμα νέας συνεδρίας), CTRL+R (Εκτέλεση εντολών), CTRL+SHIFT+ESC (Task Manager), Windows+E (άνοιγμα explorer), CTRL-B, CTRL-I (Αγαπημένα), CTRL-H (Ιστορικό), CTRL-L, CTRL-O (Διάλογος File/Open), CTRL-P (Διάλογος εκτύπωσης), CTRL-S (Αποθήκευση ως)
- Κρυφό Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Διαδρομές για σύνδεση σε shared folders. Θα πρέπει να δοκιμάσετε να συνδεθείτε στο C$ του τοπικού μηχανήματος ("\\\127.0.0.1\c$\Windows\System32")
- **Περισσότερα UNC paths:**

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

### Διαφυγές από Restricted Desktop (Citrix/RDS/VDI)

- **Pivoting μέσω dialog-box**: Χρησιμοποιήστε τους διαλόγους *Open/Save/Print-to-file* ως περιορισμένη έκδοση του Explorer. Δοκιμάστε `*.*` / `*.exe` στο πεδίο ονόματος αρχείου, κάντε δεξί κλικ σε φακέλους για **Open in new window** και χρησιμοποιήστε **Properties → Open file location** για να επεκτείνετε την πλοήγηση.<sup>[[1]](#references)</sup>
- **Δημιουργία paths εκτέλεσης από dialogs**: Δημιουργήστε ένα νέο αρχείο και μετονομάστε το σε `.CMD` ή `.BAT`, ή δημιουργήστε μια συντόμευση που δείχνει στο `%WINDIR%\System32` (ή σε ένα συγκεκριμένο binary όπως το `%WINDIR%\System32\cmd.exe`).
- **Pivots εκκίνησης shell**: Αν μπορείτε να περιηγηθείτε στο `cmd.exe`, δοκιμάστε **drag-and-drop** οποιουδήποτε αρχείου επάνω του για να εκκινήσετε ένα prompt. Αν είναι προσβάσιμο το Task Manager (`CTRL+SHIFT+ESC`), χρησιμοποιήστε το **Run new task**.
- **Παράκαμψη Task Scheduler**: Αν τα interactive shells είναι αποκλεισμένα αλλά επιτρέπεται ο προγραμματισμός, δημιουργήστε ένα task για την εκτέλεση του `cmd.exe` (GUI `taskschd.msc` ή `schtasks.exe`).
- **Αδύναμες allowlists**: Αν η εκτέλεση επιτρέπεται βάσει **ονόματος/επέκτασης**, μετονομάστε το payload σε επιτρεπόμενο όνομα. Αν επιτρέπεται βάσει **directory**, αντιγράψτε το payload σε έναν επιτρεπόμενο φάκελο προγραμμάτων και εκτελέστε το εκεί.
- **Εύρεση paths για writable staging**: Ξεκινήστε με το `%TEMP%` και απαριθμήστε writable φακέλους με το Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Επόμενο βήμα**: Αν αποκτήσετε shell, μεταβείτε στη λίστα ελέγχου Windows LPE:
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

- Sticky Keys – Πατήστε το SHIFT 5 φορές
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Κρατήστε πατημένο το NUMLOCK για 5 δευτερόλεπτα
- Filter Keys – Κρατήστε πατημένο το δεξί SHIFT για 12 δευτερόλεπτα
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Εμφάνιση Desktop
- WINDOWS+E – Εκκίνηση του Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – Splash screen σε νεότερες εκδόσεις των Windows
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Ενεργοποίηση/απενεργοποίηση πλήρους οθόνης στο Internet Explorer
- CTRL+H – Ιστορικό του Internet Explorer
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### Swipes

- Σύρετε από την αριστερή πλευρά προς τα δεξιά για να δείτε όλα τα ανοιχτά Windows, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση σε ολόκληρο το OS·
- Σύρετε από τη δεξιά πλευρά προς τα αριστερά για να ανοίξετε το Action Center, ελαχιστοποιώντας την εφαρμογή KIOSK και αποκτώντας άμεση πρόσβαση σε ολόκληρο το OS·
- Σύρετε από το επάνω άκρο για να εμφανίσετε τη γραμμή τίτλου μιας εφαρμογής που έχει ανοίξει σε λειτουργία πλήρους οθόνης·
- Σύρετε προς τα επάνω από το κάτω μέρος για να εμφανίσετε τη γραμμή εργασιών σε μια εφαρμογή πλήρους οθόνης.

### Tricks του Internet Explorer

#### 'Image Toolbar'

Πρόκειται για μια γραμμή εργαλείων που εμφανίζεται επάνω αριστερά στην εικόνα όταν αυτή επιλεγεί. Θα μπορείτε να κάνετε Save, Print, Mailto και να ανοίξετε το "My Pictures" στον Explorer. Το Kiosk πρέπει να χρησιμοποιεί τον Internet Explorer.

#### Shell Protocol

Πληκτρολογήστε αυτά τα URLs για να αποκτήσετε προβολή Explorer:

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

Ελέγξτε αυτήν τη σελίδα για περισσότερες πληροφορίες: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Tricks browsers

Backup εκδόσεις του iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Δημιουργήστε ένα common dialog χρησιμοποιώντας JavaScript και αποκτήστε πρόσβαση στον file explorer: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestures και bottoms

- Σύρετε προς τα επάνω με τέσσερα (ή πέντε) δάχτυλα / Πατήστε δύο φορές το κουμπί Home: Για να δείτε την προβολή multitask και να αλλάξετε App
- Σύρετε προς τη μία ή την άλλη κατεύθυνση με τέσσερα ή πέντε δάχτυλα: Για να μεταβείτε στην επόμενη/προηγούμενη App
- Κάντε pinch στην οθόνη με πέντε δάχτυλα / Πατήστε το κουμπί Home / Σύρετε προς τα επάνω με 1 δάχτυλο από το κάτω μέρος της οθόνης με γρήγορη κίνηση προς τα επάνω: Για πρόσβαση στο Home
- Σύρετε με ένα δάχτυλο από το κάτω μέρος της οθόνης κατά 1-2 ίντσες (αργά): Θα εμφανιστεί το dock
- Σύρετε προς τα κάτω από το επάνω μέρος της οθόνης με 1 δάχτυλο: Για να δείτε τις ειδοποιήσεις σας
- Σύρετε προς τα κάτω με 1 δάχτυλο από την επάνω δεξιά γωνία της οθόνης: Για να δείτε το control centre του iPad Pro
- Σύρετε με 1 δάχτυλο από την αριστερή πλευρά της οθόνης κατά 1-2 ίντσες: Για να δείτε την προβολή Today
- Σύρετε γρήγορα με 1 δάχτυλο από το κέντρο της οθόνης προς τα δεξιά ή τα αριστερά: Για να μεταβείτε στην επόμενη/προηγούμενη App
- Πατήστε παρατεταμένα το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad +** Μετακινήστε το ρυθμιστικό **power off** εντελώς προς τα δεξιά: Για απενεργοποίηση
- Πατήστε το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad και το κουμπί Home για μερικά δευτερόλεπτα**: Για forced hard power off
- Πατήστε το κουμπί On/**Off**/Sleep στην επάνω δεξιά γωνία του **iPad και το κουμπί Home γρήγορα**: Για λήψη screenshot που θα εμφανιστεί στην κάτω αριστερή γωνία της οθόνης. Πατήστε και τα δύο κουμπιά ταυτόχρονα για πολύ λίγο· αν τα κρατήσετε για μερικά δευτερόλεπτα, θα πραγματοποιηθεί hard power off.<sup>[[3]](#references)</sup>

### Συντομεύσεις

Θα πρέπει να διαθέτετε πληκτρολόγιο iPad ή USB keyboard adaptor. Εδώ εμφανίζονται μόνο οι συντομεύσεις που θα μπορούσαν να βοηθήσουν στην έξοδο από την εφαρμογή.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Αυτές οι συντομεύσεις αφορούν τις ρυθμίσεις εμφάνισης και ήχου, ανάλογα με τη χρήση του iPad.

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
| ⌘ Space  | Εμφάνιση λίστας διαθέσιμων γλωσσών· για να επιλέξετε μία, πατήστε ξανά το space bar. |

#### Πλοήγηση στο iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Μετάβαση στο Home                                       |
| ⌘⇧H (Command-Shift-H)                              | Μετάβαση στο Home                                       |
| ⌘ (Space)                                          | Άνοιγμα του Spotlight                                   |
| ⌘⇥ (Command-Tab)                                   | Λίστα των δέκα τελευταίων εφαρμογών                    |
| ⌘\~                                                | Μετάβαση στην τελευταία App                             |
| ⌘⇧3 (Command-Shift-3)                              | Screenshot (εμφανίζεται κάτω αριστερά για αποθήκευση ή ενέργεια) |
| ⌘⇧4                                                | Screenshot και άνοιγμα στον editor                      |
| Press and hold ⌘                                   | Λίστα των διαθέσιμων συντομεύσεων για την App           |
| ⌘⌥D (Command-Option/Alt-D)                         | Εμφάνιση του dock                                      |
| ^⌥H (Control-Option-H)                             | Κουμπί Home                                             |
| ^⌥H H (Control-Option-H-H)                         | Εμφάνιση της multitask bar                              |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Κουμπί Back                                             |
| → (Right arrow)                                    | Επόμενο στοιχείο                                        |
| ← (Left arrow)                                     | Προηγούμενο στοιχείο                                    |
| ↑↓ (Up arrow, Down arrow)                          | Ταυτόχρονο tap στο επιλεγμένο στοιχείο                  |
| ⌥ ↓ (Option-Down arrow)                            | Κύλιση προς τα κάτω                                     |
| ⌥↑ (Option-Up arrow)                               | Κύλιση προς τα επάνω                                     |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Κύλιση αριστερά ή δεξιά                                 |
| ^⌥S (Control-Option-S)                             | Ενεργοποίηση ή απενεργοποίηση της ομιλίας VoiceOver     |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Μετάβαση στην προηγούμενη εφαρμογή                      |
| ⌘⇥ (Command-Tab)                                   | Επιστροφή στην αρχική εφαρμογή                          |
| ←+→, then Option + ← or Option+→                   | Πλοήγηση στο Dock                                       |

#### Συντομεύσεις Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Άνοιγμα Location                                  |
| ⌘T                      | Άνοιγμα νέας καρτέλας                             |
| ⌘W                      | Κλείσιμο τρέχουσας καρτέλας                       |
| ⌘R                      | Ανανέωση τρέχουσας καρτέλας                       |
| ⌘.                      | Διακοπή φόρτωσης της τρέχουσας καρτέλας           |
| ^⇥                      | Μετάβαση στην επόμενη καρτέλα                     |
| ^⇧⇥ (Control-Shift-Tab) | Μετάβαση στην προηγούμενη καρτέλα                 |
| ⌘L                      | Επιλογή του πεδίου εισαγωγής κειμένου/URL για τροποποίηση |
| ⌘⇧T (Command-Shift-T)   | Άνοιγμα τελευταίας κλειστής καρτέλας (μπορεί να χρησιμοποιηθεί πολλές φορές) |
| ⌘\[                     | Μετάβαση μία σελίδα πίσω στο ιστορικό περιήγησης   |
| ⌘]                      | Μετάβαση μία σελίδα μπροστά στο ιστορικό περιήγησης |
| ⌘⇧R                     | Ενεργοποίηση Reader Mode                           |

#### Συντομεύσεις Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Άνοιγμα Location              |
| ⌘T                         | Άνοιγμα νέας καρτέλας         |
| ⌘W                         | Κλείσιμο τρέχουσας καρτέλας   |
| ⌘R                         | Ανανέωση τρέχουσας καρτέλας   |
| ⌘.                         | Διακοπή φόρτωσης τρέχουσας καρτέλας |
| ⌘⌥F (Command-Option/Alt-F) | Αναζήτηση στο mailbox σας     |

## Αναφορές

- [1] [Έξοδος από το Citrix και άλλα Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Δώσε μου έναν browser και θα σου δώσω ένα shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 gestures μόνο για iPad που πρέπει να γνωρίζετε](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [Οδηγός συντομεύσεων iPad](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Καλύτερες συντομεύσεις πληκτρολογίου iPad](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [Συντομεύσεις πληκτρολογίου iPad](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Εμφάνιση επεκτάσεων αρχείων στον Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
