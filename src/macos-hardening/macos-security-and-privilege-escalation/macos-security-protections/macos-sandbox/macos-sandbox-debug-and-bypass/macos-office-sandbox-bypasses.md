# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass μέσω Launch Agents

Η εφαρμογή χρησιμοποιεί ένα **custom Sandbox** μέσω του entitlement **`com.apple.security.temporary-exception.sbpl`** και αυτό το custom sandbox επιτρέπει την εγγραφή αρχείων οπουδήποτε, αρκεί το όνομα αρχείου να ξεκινά με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Επομένως, το escaping ήταν τόσο εύκολο όσο η **εγγραφή ενός `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Δείτε την [**αρχική αναφορά εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass μέσω Login Items και zip

Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`, αν και μετά το patch του προηγούμενου vuln δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Ανακαλύφθηκε ότι μέσα από το sandbox είναι δυνατή η δημιουργία ενός **Login Item** (εφαρμογές που εκτελούνται όταν ο χρήστης κάνει login). Ωστόσο, αυτές οι εφαρμογές **δεν θα εκτελεστούν εκτός αν** είναι **notarized** και **δεν είναι δυνατή η προσθήκη args** (επομένως δεν μπορείτε απλώς να εκτελέσετε ένα reverse shell χρησιμοποιώντας το **`bash`**).

Από το προηγούμενο Sandbox bypass, η Microsoft απενεργοποίησε τη δυνατότητα εγγραφής αρχείων στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι αν τοποθετήσετε ένα **zip file ως Login Item**, το `Archive Utility` απλώς θα το **αποσυμπιέσει** στην τρέχουσα τοποθεσία του. Επομένως, επειδή από προεπιλογή ο φάκελος `LaunchAgents` από το `~/Library` δεν δημιουργείται, ήταν δυνατή η **συμπίεση ενός plist στο `LaunchAgents/~$escape.plist`** και η **τοποθέτηση** του zip file στο **`~/Library`**, ώστε κατά την αποσυμπίεσή του να φτάσει στον προορισμό persistence.

Δείτε την [**αρχική αναφορά εδώ**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass μέσω Login Items και .zshenv

(Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει αυθαίρετα αρχεία των οποίων το όνομα ξεκινά με `~$`).

Ωστόσο, η προηγούμενη τεχνική είχε έναν περιορισμό: αν ο φάκελος **`~/Library/LaunchAgents`** υπάρχει επειδή τον δημιούργησε κάποιο άλλο software, θα αποτύγχανε. Επομένως, ανακαλύφθηκε για αυτό ένα διαφορετικό Login Items chain.

Ένας attacker μπορούσε να δημιουργήσει τα αρχεία **`.bash_profile`** και **`.zshenv`** με το payload προς εκτέλεση και στη συνέχεια να τα συμπιέσει και να **γράψει το zip στον φάκελο του victim**: **`~/~$escape.zip`**.

Έπειτα, πρόσθετε το zip file στα **Login Items** και στη συνέχεια την εφαρμογή **`Terminal`**. Όταν ο χρήστης έκανε ξανά login, το zip file θα αποσυμπιεζόταν στον φάκελο του χρήστη, αντικαθιστώντας τα **`.bash_profile`** και **`.zshenv`** και, επομένως, το terminal θα εκτελούσε ένα από αυτά τα αρχεία (ανάλογα με το αν χρησιμοποιείται bash ή zsh).

Δείτε την [**αρχική αναφορά εδώ**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass με Open και env variables

Από sandboxed processes είναι ακόμη δυνατή η κλήση άλλων processes χρησιμοποιώντας το utility **`open`**. Επιπλέον, αυτά τα processes θα εκτελούνται **μέσα στο δικό τους sandbox**.

Ανακαλύφθηκε ότι το utility open διαθέτει την επιλογή **`--env`** για την εκτέλεση μιας εφαρμογής με **συγκεκριμένες env** variables. Επομένως, ήταν δυνατή η δημιουργία του **`.zshenv file`** μέσα σε έναν φάκελο **εντός** του **sandbox** και η χρήση του `open` με `--env`, ορίζοντας τη μεταβλητή **`HOME`** σε αυτόν τον φάκελο και ανοίγοντας την εφαρμογή `Terminal`, η οποία θα εκτελούσε το αρχείο `.zshenv` (για κάποιο λόγο ήταν επίσης απαραίτητο να οριστεί η μεταβλητή `__OSINSTALL_ENVIROMENT`).

Δείτε την [**αρχική αναφορά εδώ**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass με Open και stdin

Το utility **`open`** υποστήριζε επίσης την παράμετρο **`--stdin`** (και μετά το προηγούμενο bypass δεν ήταν πλέον δυνατή η χρήση του `--env`).

Το ζήτημα είναι ότι, παρόλο που το **`python`** ήταν signed από την Apple, **δεν θα εκτελούσε** ένα script με το attribute **`quarantine`**. Ωστόσο, ήταν δυνατή η μεταβίβαση ενός script από το stdin, ώστε να μην ελέγξει αν είχε quarantined attribute ή όχι:

1. Κάντε drop ένα αρχείο **`~$exploit.py`** με αυθαίρετες εντολές Python.
2. Εκτελέστε το _open_ **`–stdin='~$exploit.py' -a Python`**, το οποίο εκτελεί την εφαρμογή Python με το αρχείο που κάναμε drop να λειτουργεί ως standard input. Η Python εκτελεί κανονικά τον κώδικά μας και, καθώς είναι child process του **`launchd`**, δεν υπόκειται στους κανόνες sandbox του Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
