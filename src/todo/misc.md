{{#include ../banners/hacktricks-training.md}}

Σε μια απάντηση ping TTL:\
127 = Windows\
254 = Cisco\
Το υπόλοιπο, κάποιο linux

$1$- md5\
$2$ή $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

Αν δεν ξέρετε τι υπάρχει πίσω από μια υπηρεσία, προσπαθήστε να κάνετε ένα HTTP GET αίτημα.

**Σαρώσεις UDP**\
nc -nv -u -z -w 1 \<IP> 160-16

Ένα κενό πακέτο UDP αποστέλλεται σε μια συγκεκριμένη θύρα. Αν η θύρα UDP είναι ανοιχτή, δεν αποστέλλεται καμία απάντηση από τη στοχοθετημένη μηχανή. Αν η θύρα UDP είναι κλειστή, θα πρέπει να αποσταλεί ένα πακέτο ICMP port unreachable από τη στοχοθετημένη μηχανή.\

Η σάρωση θυρών UDP είναι συχνά αναξιόπιστη, καθώς οι τείχοι προστασίας και οι δρομολογητές μπορεί να απορρίψουν τα πακέτα ICMP.\
Αυτό μπορεί να οδηγήσει σε ψευδώς θετικά αποτελέσματα στη σάρωσή σας, και θα βλέπετε τακτικά\
σαρώσεις UDP να δείχνουν όλες τις θύρες UDP ανοιχτές σε μια σαρωμένη μηχανή.\
Οι περισσότερες σαρωτές θυρών δεν σαρώνονται όλες οι διαθέσιμες θύρες, και συνήθως έχουν μια προεπιλεγμένη λίστα\
"ενδιαφερόντων θυρών" που σαρώνονται.

# CTF - Τέχνες

Στο **Windows** χρησιμοποιήστε το **Winzip** για να αναζητήσετε αρχεία.\
**Εναλλακτικά ρεύματα δεδομένων**: _dir /r | find ":$DATA"_\
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> Ξεκινά με "_begin \<mode> \<filename>_" και περίεργους χαρακτήρες\
**Xxencoding** --> Ξεκινά με "_begin \<mode> \<filename>_" και B64\
\
**Vigenere** (ανάλυση συχνότητας) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (μετατόπιση χαρακτήρων) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> Κρύψε μηνύματα χρησιμοποιώντας κενά και tabs

# Characters

%E2%80%AE => RTL Character (γράφει payloads ανάποδα)

{{#include ../banners/hacktricks-training.md}}
