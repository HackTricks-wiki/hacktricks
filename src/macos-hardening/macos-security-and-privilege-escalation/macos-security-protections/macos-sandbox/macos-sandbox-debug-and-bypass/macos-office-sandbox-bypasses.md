# Bypasses του Sandbox του macOS Office

{{#include ../../../../../banners/hacktricks-training.md}}

### Bypass του Word Sandbox μέσω Launch Agents

Η εφαρμογή χρησιμοποιεί ένα **custom Sandbox** με το entitlement **`com.apple.security.temporary-exception.sbpl`** και αυτό το custom sandbox επιτρέπει την εγγραφή αρχείων οπουδήποτε, αρκεί το filename να ξεκινά με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Επομένως, το escaping ήταν τόσο απλό όσο η **εγγραφή ενός `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Δείτε την [**original report εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Bypass του Word Sandbox μέσω Login Items και zip

Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary αρχεία των οποίων το όνομα ξεκινά με `~$`, αν και μετά το patch του προηγούμενου vuln δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Ανακαλύφθηκε ότι μέσα από το sandbox είναι δυνατή η δημιουργία ενός **Login Item** (εφαρμογές που εκτελούνται όταν ο χρήστης κάνει login). Ωστόσο, αυτές οι εφαρμογές **δεν θα εκτελεστούν αν** δεν είναι **notarized** και **δεν είναι δυνατή η προσθήκη args** (οπότε δεν μπορείς απλώς να εκτελέσεις ένα reverse shell χρησιμοποιώντας το **`bash`**).

Από το προηγούμενο Sandbox bypass, η Microsoft απενεργοποίησε τη δυνατότητα εγγραφής αρχείων στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι αν τοποθετήσεις ένα **zip file ως Login Item**, το `Archive Utility` απλώς θα το **αποσυμπιέσει** στην τρέχουσα τοποθεσία του. Επομένως, επειδή από προεπιλογή ο φάκελος `LaunchAgents` μέσα στο `~/Library` δεν δημιουργείται, ήταν δυνατό να γίνει **zip ένα plist στο `LaunchAgents/~$escape.plist`** και να **τοποθετηθεί** το zip file στο **`~/Library`**, ώστε κατά την αποσυμπίεση να φτάσει στον προορισμό persistence.

Δείτε την [**original report εδώ**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Bypass του Word Sandbox μέσω Login Items και .zshenv

(Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary αρχεία των οποίων το όνομα ξεκινά με `~$`.)

Ωστόσο, η προηγούμενη technique είχε έναν περιορισμό: αν ο φάκελος **`~/Library/LaunchAgents`** υπάρχει επειδή τον δημιούργησε κάποιο άλλο software, θα αποτύγχανε. Έτσι, ανακαλύφθηκε ένα διαφορετικό chain μέσω Login Items.

Ένας attacker μπορούσε να δημιουργήσει τα αρχεία **`.bash_profile`** και **`.zshenv`** με το payload προς εκτέλεση, στη συνέχεια να τα κάνει zip και να **γράψει το zip στον φάκελο του victim**: **`~/~$escape.zip`**.

Έπειτα, να προσθέσει το zip file στα **Login Items** και στη συνέχεια την εφαρμογή **`Terminal`**. Όταν ο χρήστης έκανε relogin, το zip file θα αποσυμπιεζόταν στον φάκελο του χρήστη, αντικαθιστώντας τα **`.bash_profile`** και **`.zshenv`** και, επομένως, το terminal θα εκτελούσε ένα από αυτά τα αρχεία (ανάλογα με το αν χρησιμοποιείται bash ή zsh).

Δείτε την [**original report εδώ**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass με Open και env variables

Από sandboxed processes είναι ακόμη δυνατή η εκτέλεση άλλων processes μέσω του utility **`open`**. Επιπλέον, αυτά τα processes θα εκτελούνται **μέσα στο δικό τους sandbox**.

Ανακαλύφθηκε ότι το open utility διαθέτει την επιλογή **`--env`** για την εκτέλεση μιας εφαρμογής με **συγκεκριμένες env** variables. Επομένως, ήταν δυνατή η δημιουργία του αρχείου **`.zshenv`** μέσα σε έναν φάκελο **εντός** του **sandbox** και η χρήση του `open` με `--env`, θέτοντας τη μεταβλητή **`HOME`** σε αυτόν τον φάκελο και ανοίγοντας την εφαρμογή `Terminal`, η οποία θα εκτελούσε το αρχείο `.zshenv` (για κάποιο λόγο ήταν επίσης απαραίτητο να τεθεί η μεταβλητή `__OSINSTALL_ENVIROMENT`).

Δείτε την [**original report εδώ**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass με Open και stdin

Το utility **`open`** υποστήριζε επίσης την παράμετρο **`--stdin`** (και μετά το προηγούμενο bypass δεν ήταν πλέον δυνατή η χρήση του `--env`).

Το θέμα είναι ότι, ακόμη και αν το **`python`** ήταν signed από την Apple, **δεν θα εκτελούσε** ένα script με το attribute **`quarantine`**. Ωστόσο, ήταν δυνατή η μεταβίβαση ενός script μέσω stdin, ώστε να μην ελεγχθεί αν ήταν quarantined ή όχι:

1. Κάντε drop ένα αρχείο **`~$exploit.py`** με arbitrary Python commands.
2. Εκτελέστε _open_ **`–stdin='~$exploit.py' -a Python`**, το οποίο εκτελεί την εφαρμογή Python με το αρχείο που κάναμε drop να λειτουργεί ως standard input. Η Python εκτελεί κανονικά τον κώδικά μας και, επειδή είναι child process του **`launchd`**, δεν υπόκειται στους κανόνες του Word sandbox.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
