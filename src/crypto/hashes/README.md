# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνήθη μοτίβα CTF

- Το «Signature» είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Hashes κωδικών πρόσβασης χωρίς salt → ταχύτερο επαναλαμβανόμενο cracking και επιθέσεις αναζήτησης με προϋπολογισμένους πίνακες.
- Σύγχυση μεταξύ hash και MAC (hash != authentication).

## Αναζητήσεις MD5 hash με επιλεγμένη είσοδο

Αυτά τα παραδείγματα Python αναζητούν δύο διαφορετικά μοτίβα εξόδου: ένα επιλεγμένο επίθημα MD5 και μια τιμή MD5 που αρχίζει με `0e` και ακολουθείται μόνο από ψηφία. Το δεύτερο μοτίβο είναι σχετικό όταν μια εφαρμογή συγκρίνει αριθμητικές συμβολοσειρές με χαλαρό τρόπο· δείτε τη συμπεριφορά που αφορά ειδικά την PHP και τις επιφυλάξεις σχετικά με τις εκδόσεις στο [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force επιθέσεις σε επίθημα MD5 hash

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Δημιουργία hash MD5 0e για μη αυστηρές συγκρίσεις

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Τεχνική

Μια length-extension attack μπορεί να είναι εφικτή όταν ένας server υπολογίζει μια «υπογραφή» όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί μια συνάρτηση κατακερματισμού Merkle-Damgård, όπως οι MD5, SHA-1 ή SHA-256.

Αν γνωρίζεις:

- `message`
- `sig`
- τη συνάρτηση κατακερματισμού
- (ή μπορείς να κάνεις brute-force) το `len(secret)`

Τότε μπορείς να υπολογίσεις μια έγκυρη υπογραφή για:

`message || padding || appended_data`

χωρίς να γνωρίζεις το secret.<sup>[[1]](#references)</sup>

### Σημαντικός περιορισμός: το HMAC δεν επηρεάζεται

Οι length-extension attacks ισχύουν για ευάλωτες κατασκευές με πρόθεμα, όπως η `HASH(secret || message)`. Δεν επηρεάζουν την κατασκευή HMAC (για παράδειγμα, το HMAC-SHA256), η οποία συνδυάζει ένα κλειδί με ξεχωριστές εσωτερικές και εξωτερικές εφαρμογές της συνάρτησης κατακερματισμού.<sup>[[1]](#references)[[2]](#references)</sup>

### Εργαλεία

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings για το εργαλείο length-extension HashPump<sup>[[7]](#references)</sup>

### Καλή επεξήγηση

[Όλα όσα χρειάζεται να γνωρίζετε για τις length-extension attacks σε hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Αμφίσημη κατακερματισμένη τιμή πλειάδων και MAC

### Boundary-confusion attack

Τα incremental API κατακερματισμού δεν αυθεντικοποιούν τα όρια των κλήσεων. Οι κλήσεις `update(A); update(B)` κατακερματίζουν την ίδια συμβολοσειρά byte με την κλήση `update(A + B)`. Επομένως, ο κατακερματισμός ή η δημιουργία MAC πάνω σε ακατέργαστη συνένωση δεν αυθεντικοποιεί μια πλειάδα. Αν τα γειτονικά πεδία έχουν μεταβλητό μήκος, ένας attacker μπορεί να χωρίσει ξανά τα byte σε διαφορετική πλειάδα χωρίς να βρει collision στην υποκείμενη συνάρτηση κατακερματισμού:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Αυτό γίνεται εκμεταλλεύσιμο όταν ο verifier πιστεύει ότι το digest δεσμεύει τις σημασίες των πεδίων, αλλά η είσοδος που ελέγχει ο attacker μπορεί να φτάσει σε διαφορετικό parser ή βήμα πρωτοκόλλου που ορίζει διαφορετικά όρια. Οι δεσμεύσεις μπορεί να αποκτήσουν εναλλακτικά ανοίγματα και τα Fiat-Shamir transcripts μπορεί να ερμηνευτούν ως διαφορετικές δηλώσεις. Το HMAC αποτρέπει το [hash length extension](#hash-length-extension-attack), αλλά το `HMAC(K, A || B)` εξακολουθεί να έχει αυτή την αμφισημία κωδικοποίησης πλειάδων, επειδή και οι δύο πλειάδες παράγουν τα ίδια bytes μηνύματος.<sup>[[8]](#references)[[9]](#references)</sup>

Χρησιμοποιήστε αυτή τη ροή εργασίας ελέγχου για να διαπιστώσετε αν μια αμφίσημη κωδικοποίηση πλειάδας διασχίζει ένα όριο ασφαλείας.<sup>[[8]](#references)[[9]](#references)</sup>

1. Εντοπίστε τα `HASH(A || B)`, `HMAC(K, A || B)` και διαδοχικές κλήσεις `update()`/`Write()` για δύο ή περισσότερα πεδία.
2. Σημειώστε κάθε πεδίο που ελέγχεται από τον attacker ή έχει μεταβλητό μήκος. Δοκιμάστε να μετακινήσετε bytes από το ένα πεδίο στο άλλο, διατηρώντας αμετάβλητη την πλήρη συνένωση. Συμπεριλάβετε κενά πεδία.
3. Ελέγξτε τα σχήματα οριοθέτησης για byte οριοθέτη που μπορούν να περιέχουν οι είσοδοι, ασυμφωνίες στη διαφυγή χαρακτήρων και σχεδιασμούς που κωδικοποιούν το μήκος μόνο ορισμένων πεδίων.
4. Ιχνηλατήστε τον τρόπο με τον οποίο κάθε consumer αναλύει τα αυθεντικοποιημένα bytes. Μια υποψήφια περίπτωση έχει σημασία μόνο αν μια εναλλακτική κατάτμηση αλλάζει μια απόφαση ασφαλείας, μια δήλωση απόδειξης, μια εγγραφή, μια συναλλαγή ή ένα άνοιγμα δέσμευσης. Τα πεδία σταθερού πλάτους ή μια κανονική, ενέσιμη σειριοποίηση αποτρέπουν αυτή τη συγκεκριμένη επίθεση.
5. Ελέγξτε αν το ίδιο κωδικοποιημένο digest γίνεται αποδεκτό σε άλλη έκδοση πρωτοκόλλου, τύπο μηνύματος, γύρο ή εφαρμογή. Καθορίστε ρητά αυτά τα συμφραζόμενα αντί να βασίζεστε στους callers για να τα διαχωρίζουν.

### SequenceHash και SequenceMAC

Το SequenceHash είναι μια κατασκευή ανεξάρτητη από τον αλγόριθμο hash για ακολουθίες συμβολοσειρών byte. Κάθε λειτουργία `add()` είναι ατομική: προσαρτά την τιμή και ένα επίθημα μήκους σταθερού μεγέθους 16 byte, σε little-endian σειρά, στο εσωτερικό hash. Οι κενές τιμές παραμένουν διακριτά αντικείμενα. Ένα εξωτερικό hash αποτρέπει την έκθεση μιας εσωτερικής κατάστασης που επιδέχεται επέκταση μήκους, ενώ μια προαιρετική συμβολοσειρά προσαρμογής παρέχει διαχωρισμό domain. Μην αντικαθιστάτε το `add()` με τις συνήθεις εγγραφές του API του υποκείμενου hash.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Επιλέξτε το customizer ως μέρος του ορισμού του πρωτοκόλλου, συμπεριλαμβάνοντας αρκετές πληροφορίες ώστε να διακρίνονται η εφαρμογή, η έκδοση του πρωτοκόλλου, ο τύπος μηνύματος και ο γύρος. Το SequenceHash εξακολουθεί να απαιτεί από όλα τα μέρη να συμφωνούν ως προς τη σειρά των πεδίων, την κωδικοποίηση byte και την κανονική σειριοποίηση, ενώ δεν μπορεί να προστατεύσει ένα πεδίο που έχει παραλειφθεί. Οι υλοποιήσεις θα πρέπει να ελέγχονται με βάση τα ενδιάμεσα και τελικά test vectors του C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Για authentication, το SequenceMAC παρέχει το ίδιο περιβάλλον εργασίας για ατομική κωδικοποίηση και customization. Απαιτεί κλειδί τουλάχιστον 32 byte. Σε αντίθεση με την προεπεξεργασία κλειδιού του HMAC, οι κεφαλίδες του δεσμεύονται στο ακριβές μήκος του κλειδιού: ένα μεγάλο raw key δεν ισοδυναμεί με το prehash του, και η προσθήκη μηδενικών byte αλλάζει το κλειδί. Αυτή η διάκριση έχει σημασία όταν τα στοιχεία δέχονται διαφορετικές αναπαραστάσεις κλειδιού ή μεταδεδομένα μήκους.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Το Python API και οι αντίστοιχες υλοποιήσεις σε Go και Rust είναι διαθέσιμες ως αναφορές, αλλά οι υλοποιήσεις πρωτοκόλλων πρέπει να ακολουθούν την τρέχουσα προδιαγραφή C2SP και όχι να αναδημιουργούν την κωδικοποίηση από αυτήν τη σύνοψη.<sup>[[8]](#references)[[10]](#references)</sup>

## Κατακερματισμός και cracking κωδικών πρόσβασης

### Πρώτες ερωτήσεις<sup>[[4]](#references)</sup>

- Είναι **salted**; (αναζητήστε μορφές `salt$hash`)
- Είναι **fast hash** (MD5/SHA1/SHA256) ή **slow KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Έχετε κάποια **ένδειξη για τη μορφή** (λειτουργία hashcat / μορφή John);

### Πρακτική ροή εργασίας<sup>[[5]](#references)[[6]](#references)</sup>

1. Αναγνωρίστε το hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν δεν έχει salt και είναι συνηθισμένο: δοκιμάστε online DBs και εργαλεία αναγνώρισης από την ενότητα ροής εργασίας crypto.
3. Διαφορετικά, κάντε crack:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Συνήθη λάθη που μπορείτε να εκμεταλλευτείτε

- Ο ίδιος κωδικός πρόσβασης επαναχρησιμοποιείται από πολλούς χρήστες → κάντε crack έναν και μετά pivot.
- Περικομμένα hashes / custom μετασχηματισμοί → κανονικοποιήστε και δοκιμάστε ξανά.
- Αδύναμες παράμετροι KDF (π.χ. λίγες επαναλήψεις PBKDF2) → εξακολουθούν να μπορούν να γίνουν crack.

### Oracle bcrypt με επιλεγμένη είσοδο και προσαρτημένο μυστικό

Ένας callable helper που επιστρέφει `bcrypt(user_input || secret)` μπορεί να αποκαλύψει πληροφορίες για ένα προσαρτημένο μυστικό, αν η υλοποίηση bcrypt περικόπτει σιωπηρά την είσοδο μετά από 72 **bytes**. Ένα όριο πλήθους χαρακτήρων πριν από την κωδικοποίηση UTF-8 δεν επιβάλλει αυτό το όριο bytes: οι χαρακτήρες πολλών bytes μπορούν να γεμίσουν την είσοδο bcrypt, αφήνοντας χώρο μόνο για ένα μικρό πρόθεμα του μυστικού. Οι επιλεγμένες είσοδοι και τα hashes που επιστρέφονται μπορεί στη συνέχεια να επιτρέψουν offline ελέγχους υποψήφιων bytes επιθέματος. Αυτό απαιτεί έλεγχο της εισόδου του helper, γνώση του ακριβούς μετασχηματισμού και της κωδικοποίησής του, καθώς και υλοποίηση που πράγματι περικόπτει· ένας callable helper ή ένα hash bcrypt από μόνο του δεν αποδεικνύει ότι ισχύουν όλα τα παραπάνω. Το [pyca/bcrypt αναφέρει](https://github.com/pyca/bcrypt#maximum-password-length) ότι η τρέχουσα `hashpw` εγείρει σφάλμα για εισόδους μεγαλύτερες από 72 bytes, ενώ παλαιότερες εκδόσεις τις περικόπτουν σιωπηρά. Άλλα wrappers μπορεί να κάνουν prehash ή να απορρίπτουν μεγάλες εισόδους, επομένως επαληθεύστε την εγκατεστημένη υλοποίηση αντί να υποθέτετε ότι γίνεται περικοπή.

Η χρήση ενός ανακτημένου μυστικού σε διαφορετικό λογαριασμό απαιτεί επίσης αποδείξεις ότι το εκτεθειμένο hash δημιουργήθηκε με το **ίδιο** μυστικό και τον ίδιο μετασχηματισμό, καθώς και ξεχωριστή διαδρομή διαπιστευτηρίων ή σύνδεσης. Ένα hashing helper που εκτελείται ως root πρέπει να εξετάζεται ως oracle μόνο αν ο χρήστης με λιγότερα προνόμια μπορεί να το καλέσει βάσει της ισχύουσας πολιτικής· η παθητική απαρίθμηση του host δεν χρειάζεται να το καλέσει ή να υποβάλει επιλεγμένους κωδικούς πρόσβασης.

## References

- [1] [SkullSecurity - Όλα όσα χρειάζεται να γνωρίζετε για τις επιθέσεις επέκτασης μήκους hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Ο κώδικας επαλήθευσης μηνυμάτων με keyed hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Οδηγός αποθήκευσης κωδικών πρόσβασης](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Παραδείγματα hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Επιλογές γραμμής εντολών](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - Python bindings για το HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Προδιαγραφή SequenceHash και SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing για όλους](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Υλοποίηση SequenceHash σε Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Διανύσματα δοκιμών SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
