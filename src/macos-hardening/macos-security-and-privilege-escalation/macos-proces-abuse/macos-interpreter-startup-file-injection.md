# Εισαγωγή κώδικα σε αρχεία εκκίνησης διερμηνευτών του macOS

{{#include ../../../banners/hacktricks-training.md}}

Αυτές οι τεχνικές ειδικές για κάθε runtime χρησιμοποιούν μεταβλητές περιβάλλοντος που κληρονομούνται για να επιλέξουν τη διαμόρφωση εκκίνησης ή τον κώδικα που θα εκτελεστεί πριν από το προβλεπόμενο script. Η Lua υποστηρίζει επίσης μια παραλλαγή με inline κώδικα.

## Διαμόρφωση εκκίνησης της PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` και `auto_prepend_file`

Τα PHP CLI και CGI διαβάζουν τη διαμόρφωση σε κάθε εκτέλεση. Το `PHPRC` μπορεί να επιλέξει ένα `php.ini` που είναι αναγνώσιμο από τον επιτιθέμενο, ενώ το `PHP_INI_SCAN_DIR` μπορεί να ανακατευθύνει τον κατάλογο που σαρώνονται για πρόσθετα αρχεία `.ini`. Η οδηγία `auto_prepend_file` κάνει την PHP να αναλύσει ένα αρχείο πριν από το ζητούμενο script, οπότε αυτός ο συνδυασμός επιτρέπει την εκτέλεση κώδικα κατά την εκκίνηση.<sup>[[1]](#references)[[2]](#references)</sup>

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

Η επιλογή `-n` αγνοεί το `php.ini`· μια ρητά καθορισμένη αξιόπιστη διαδρομή `-c` έχει προτεραιότητα έναντι του `PHPRC`. Να θυμάστε ότι ένα μακρόβιο server SAPI συνήθως διαβάζει τις ρυθμίσεις κατά την εκκίνηση του web server, ενώ το CLI και το CGI τις διαβάζουν σε κάθε κλήση.<sup>[[1]](#references)</sup>

## Κώδικας εκκίνησης Lua

### `LUA_INIT`

Πριν από την επεξεργασία των επιλογών της γραμμής εντολών ή του script-στόχου, ο αυτόνομος Lua interpreter εκτελεί το `LUA_INIT_<major>_<minor>` ή, αν η μεταβλητή με την έκδοση δεν υπάρχει, το `LUA_INIT`. Μια τιμή που αρχίζει με `@` ορίζει ένα αρχείο· κάθε άλλη τιμή αξιολογείται απευθείας ως κώδικας Lua. Έτσι, είναι δυνατή η εκτέλεση κατά την εκκίνηση τόσο από αρχείο όσο και χωρίς αρχείο.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Το ακριβές όνομα με την έκδοση αλλάζει ανάλογα με τον interpreter, για παράδειγμα `LUA_INIT_5_4`. Το `lua -E` αγνοεί όλες τις μεταβλητές περιβάλλοντος, συμπεριλαμβανομένου του κώδικα εκκίνησης και των διαδρομών των Lua modules.

## Depot εκκίνησης Julia

### `JULIA_DEPOT_PATH` και `startup.jl`

Η Julia εκτελεί κανονικά το `config/startup.jl` από το πρώτο depot της κατά την εκκίνηση. Το `JULIA_DEPOT_PATH` ελέγχει τη λίστα των depot, επομένως, αν οριστεί σε ένα δέντρο στο οποίο έχει πρόσβαση ο attacker, ανακατευθύνεται το αρχείο εκκίνησης που φορτώνεται αυτόματα.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Το τελικό διαχωριστικό είναι χρήσιμο όταν το θύμα χρειάζεται ακόμη τα κανονικά του packages. Η εντολή `julia --startup-file=no` απενεργοποιεί αυτό το startup file. Διαγράψτε τη μεταβλητή πριν από την εκκίνηση, επειδή ελέγχει επίσης τα package registries, τα environments, τις caches και τις τοποθεσίες φόρτωσης κώδικα.

## Αρχεία εκκίνησης GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Το GNU Octave εκτελεί κατά την εκκίνηση διάφορα αρχεία που περιέχουν έγκυρες εντολές Octave. Η μεταβλητή `OCTAVE_SITE_INITFILE` παρακάμπτει το αρχείο εκκίνησης για ολόκληρο το σύστημα και η `OCTAVE_VERSION_INITFILE` παρακάμπτει το αρχείο της συγκεκριμένης έκδοσης, επιτρέποντας σε οποιαδήποτε από τις δύο μεταβλητές να ανακατευθύνει την αυτόματη εκτέλεση σε ένα αρχείο στο οποίο έχει πρόσβαση ο attacker.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` παρακάμπτει μόνο αρχεία χρήστη, όπως το `~/.octaverc`· **δεν** σταματά την παραπάνω παράκαμψη του site-file. Χρησιμοποιήστε το `--no-site-file` για τα site files ή τα `--norc` / `-f` για να απενεργοποιήσετε όλα τα αρχεία εκκίνησης.<sup>[[7]](#references)</sup>

## References

- [1] [Αρχείο διαμόρφωσης PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Αυτόνομος interpreter Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Διεπαφή γραμμής εντολών Julia: Αρχείο εκκίνησης](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Μεταβλητές περιβάλλοντος Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Αρχεία εκκίνησης GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Επιλογές γραμμής εντολών GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
