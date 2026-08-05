# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass μέσω Launch Agents

Η εφαρμογή χρησιμοποιεί ένα **custom Sandbox** με το entitlement **`com.apple.security.temporary-exception.sbpl`** και αυτό το custom sandbox επιτρέπει την εγγραφή αρχείων οπουδήποτε, αρκεί το filename να ξεκινά με `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Επομένως, το escaping ήταν τόσο απλό όσο η **εγγραφή ενός `plist`** LaunchAgent στο `~/Library/LaunchAgents/~$escape.plist`.

Δείτε το [**original report εδώ**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[1]</sup>

### Word Sandbox bypass μέσω Login Items και zip

Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary αρχεία των οποίων το όνομα ξεκινά με `~$`, αν και μετά το patch της προηγούμενης vuln δεν ήταν δυνατή η εγγραφή στο `/Library/Application Scripts` ή στο `/Library/LaunchAgents`.

Ανακαλύφθηκε ότι μέσα από το sandbox είναι δυνατή η δημιουργία ενός **Login Item** (apps που θα εκτελούνται όταν ο user κάνει login). Ωστόσο, αυτά τα apps **δεν θα εκτελεστούν εκτός αν** είναι **notarized** και **δεν είναι δυνατή η προσθήκη args** (επομένως δεν μπορείτε απλώς να εκτελέσετε ένα reverse shell χρησιμοποιώντας το **`bash`**).

Από το προηγούμενο Sandbox bypass, η Microsoft απενεργοποίησε την επιλογή εγγραφής αρχείων στο `~/Library/LaunchAgents`. Ωστόσο, ανακαλύφθηκε ότι αν τοποθετήσετε ένα **zip file ως Login Item**, το `Archive Utility` απλώς θα το **κάνει unzip** στην τρέχουσα τοποθεσία του. Επομένως, επειδή από προεπιλογή ο φάκελος `LaunchAgents` από το `~/Library` δεν δημιουργείται, ήταν δυνατή η **συμπίεση ενός plist στο `LaunchAgents/~$escape.plist`** και η **τοποθέτηση** του zip file στο **`~/Library`**, ώστε κατά την αποσυμπίεση να φτάσει στον προορισμό persistence.

Δείτε το [**original report εδώ**](https://objective-see.org/blog/blog_0x4B.html).<sup>[2]</sup>

### Word Sandbox bypass μέσω Login Items και .zshenv

(Θυμηθείτε ότι από το πρώτο escape, το Word μπορεί να γράφει arbitrary αρχεία των οποίων το όνομα ξεκινά με `~$`.)

Ωστόσο, η προηγούμενη technique είχε έναν περιορισμό: αν ο φάκελος **`~/Library/LaunchAgents`** υπάρχει επειδή τον δημιούργησε κάποιο άλλο software, θα αποτύγχανε. Επομένως, ανακαλύφθηκε ένα διαφορετικό chain από Login Items για αυτή την περίπτωση.

Ένας attacker θα μπορούσε να δημιουργήσει τα αρχεία **`.bash_profile`** και **`.zshenv`** με το payload προς εκτέλεση και στη συνέχεια να τα συμπιέσει και να **γράψει το zip στον φάκελο** του user του victim: **`~/~$escape.zip`**.

Στη συνέχεια, να προσθέσει το zip file στα **Login Items** και μετά την εφαρμογή **`Terminal`**. Όταν ο user κάνει ξανά login, το zip file θα αποσυμπιεστεί στον φάκελο του user, αντικαθιστώντας τα **`.bash_profile`** και **`.zshenv`**, και επομένως το terminal θα εκτελέσει ένα από αυτά τα αρχεία (ανάλογα με το αν χρησιμοποιείται bash ή zsh).

Δείτε το [**original report εδώ**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[3]</sup>

### Word Sandbox Bypass με Open και env variables

Από sandboxed processes εξακολουθεί να είναι δυνατή η invocation άλλων processes χρησιμοποιώντας το **`open`** utility. Επιπλέον, αυτά τα processes θα εκτελεστούν **μέσα στο δικό τους sandbox**.

Ανακαλύφθηκε ότι το open utility διαθέτει την επιλογή **`--env`** για την εκτέλεση ενός app με **συγκεκριμένες env** variables. Επομένως, ήταν δυνατή η δημιουργία του **`.zshenv` file** μέσα σε έναν φάκελο **στο εσωτερικό** του **sandbox** και η χρήση του `open` με **`--env`**, ορίζοντας τη μεταβλητή **`HOME`** σε αυτόν τον φάκελο και ανοίγοντας την εφαρμογή `Terminal`, η οποία θα εκτελούσε το `.zshenv` file (για κάποιο λόγο ήταν επίσης απαραίτητο να οριστεί η μεταβλητή `__OSINSTALL_ENVIROMENT`).

Δείτε το [**original report εδώ**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[4]</sup>

### Word Sandbox Bypass με Open και stdin

Το **`open`** utility υποστήριζε επίσης την παράμετρο **`--stdin`** (και μετά το προηγούμενο bypass δεν ήταν πλέον δυνατή η χρήση του `--env`).

Το θέμα είναι ότι, παρόλο που το **`python`** ήταν signed από την Apple, **δεν θα εκτελούσε** ένα script με το attribute **`quarantine`**. Ωστόσο, ήταν δυνατή η μεταβίβαση ενός script από το stdin, ώστε να μην ελεγχθεί αν βρισκόταν σε quarantine ή όχι:

1. Αποθέστε ένα αρχείο **`~$exploit.py`** με arbitrary Python commands.
2. Εκτελέστε το _open_ **`–stdin='~$exploit.py' -a Python`**, το οποίο εκτελεί το Python app με το dropped file να λειτουργεί ως standard input. Το Python εκτελεί κανονικά τον κώδικά μας και, επειδή είναι child process του _launchd_, δεν υπόκειται στους sandbox rules του Word.

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
