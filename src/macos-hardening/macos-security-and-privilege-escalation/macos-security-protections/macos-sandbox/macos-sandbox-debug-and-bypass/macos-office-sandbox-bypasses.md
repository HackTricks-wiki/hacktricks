# Word Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

Τα παρακάτω είναι **ιστορικά Microsoft Office for Mac sandbox escapes**. Τεκμηριώνουν επαναχρησιμοποιήσιμα λάθη στα trust boundaries, αλλά δεν πρέπει να θεωρείται ότι συνδυασμοί patched Office/macOS είναι ευάλωτοι χωρίς αναπαραγωγή στην ακριβή έκδοση και πολιτική.

### Word sandbox bypass μέσω LaunchAgents

Η επηρεαζόμενη εφαρμογή χρησιμοποιούσε έναν custom sandbox rule μέσω του `com.apple.security.temporary-exception.sbpl`. Επέτρεπε regular files των οποίων το basename ξεκινούσε με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Επομένως, το escaping ήταν τόσο εύκολο όσο το **γράψιμο ενός `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Δείτε το [**original report εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass μέσω Login Items και zip

Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary files των οποίων το όνομα ξεκινά με `~$`, αν και μετά το patch του προηγούμενου vuln δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Το επηρεαζόμενο sandbox επέτρεπε τη δημιουργία ενός **Login Item**, το οποίο εκκινείται όταν ο χρήστης κάνει login. Η διαδρομή που παρουσιάστηκε απαιτούσε μια αποδεκτή signed/notarized εφαρμογή και δεν επέτρεπε arbitrary arguments, επομένως η προσθήκη του `bash` με reverse-shell argument δεν ήταν αρκετή.<sup>[[2]](#references)</sup>

Από το προηγούμενο Sandbox bypass, η Microsoft απενεργοποίησε την επιλογή εγγραφής αρχείων στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι αν τοποθετούσατε ένα **zip file ως Login Item**, το `Archive Utility` απλώς θα το έκανε **unzip** στην τρέχουσα τοποθεσία του. Έτσι, επειδή από προεπιλογή ο φάκελος `LaunchAgents` από το `~/Library` δεν έχει δημιουργηθεί, ήταν δυνατή η **συμπίεση ενός plist στο `LaunchAgents/~$escape.plist`** και η **τοποθέτηση** του zip file στο **`~/Library`**, ώστε κατά την αποσυμπίεση να φτάσει στον persistence προορισμό.

Δείτε το [**original report εδώ**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass μέσω Login Items και .zshenv

(Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary files των οποίων το όνομα ξεκινά με `~$`.)

Ωστόσο, η προηγούμενη τεχνική είχε έναν περιορισμό: αν ο φάκελος **`~/Library/LaunchAgents`** υπάρχει επειδή τον δημιούργησε κάποιο άλλο software, θα αποτύγχανε. Έτσι, ανακαλύφθηκε για αυτό μια διαφορετική αλυσίδα Login Items.

Ένας attacker μπορούσε να δημιουργήσει τα **`.bash_profile`** και **`.zshenv`** που περιείχαν το payload, να τα κάνει archive και να γράψει το ZIP στον home directory του **victim** ως **`~/~$escape.zip`**.

Στη συνέχεια, πρόσθετε το ZIP και το **Terminal** ως Login Items. Στο επόμενο login, το Archive Utility εξάγει τα dotfiles στον home directory του χρήστη και το shell του Terminal αξιολογεί το κατάλληλο startup file (`.bash_profile` για τη διαδρομή Bash που παρουσιάστηκε ή `.zshenv` για Zsh).<sup>[[3]](#references)</sup>

Δείτε το [**original report εδώ**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass με Open και env variables

Τα sandboxed processes μπορούσαν ακόμη να ζητήσουν launches εφαρμογών μέσω του **`open`**. Η εφαρμογή που εκκινήθηκε εκτελούνταν στο δικό της security context αντί να κληρονομεί το ακριβές sandbox profile του Word.<sup>[[4]](#references)</sup>

Το επηρεαζόμενο `open` utility διέθετε επιλογή **`--env`** για την παροχή environment variables. Το exploit δημιουργούσε το `.zshenv` μέσα στο sandbox, όριζε το `HOME` σε εκείνον τον directory και εκκινούσε το Terminal, ώστε το Zsh να το αξιολογήσει. Η αλυσίδα που αναφέρθηκε όριζε επίσης τη misspelled private variable `__OSINSTALL_ENVIROMENT`. Διατηρήστε αυτήν ακριβώς την ορθογραφία κατά την αναπαραγωγή του ιστορικού PoC.<sup>[[4]](#references)</sup>

Δείτε το [**original report εδώ**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass με Open και stdin

Το **`open`** utility υποστήριζε επίσης την παράμετρο **`--stdin`** (και μετά το προηγούμενο bypass δεν ήταν πλέον δυνατή η χρήση του `--env`).

Παρότι η Python application της Apple θα απέρριπτε ένα quarantined script file, το ευάλωτο workflow μπορούσε να τροφοδοτήσει το ίδιο script μέσω standard input, αποφεύγοντας τον file-based quarantine check:<sup>[[5]](#references)</sup>

1. Κάντε drop ένα **`~$exploit.py`** file με arbitrary Python commands.
2. Εκτελέστε `open --stdin='~$exploit.py' -a Python`. Η Python application που εκκινείται λαμβάνει τον κώδικα που έγινε drop μέσω standard input και, στις ευάλωτες versions, εκτελείται εκτός του sandbox του Word, επειδή το LaunchServices τη δημιουργεί υπό το `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping από το Sandbox – Microsoft Office σε macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama σε macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis του CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Αποκάλυψη μιας macOS App Sandbox escape ευπάθειας: Μια λεπτομερής ανάλυση του CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
