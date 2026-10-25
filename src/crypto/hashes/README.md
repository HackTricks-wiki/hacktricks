# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνήθη μοτίβα CTF

- Η «υπογραφή» είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Hashes κωδικών πρόσβασης χωρίς salt → ταχύτερο επαναλαμβανόμενο cracking και επιθέσεις με προϋπολογισμένες αναζητήσεις.
- Σύγχυση του hash με το MAC (hash != authentication).

## Αναζητήσεις hash MD5 με επιλεγμένη είσοδο

Αυτά τα παραδείγματα Python αναζητούν δύο διαφορετικά μοτίβα εξόδου: ένα επιλεγμένο επίθημα MD5 και μια τιμή MD5 που αρχίζει με `0e` και ακολουθείται μόνο από ψηφία. Το δεύτερο μοτίβο είναι σχετικό όταν μια εφαρμογή συγκρίνει αριθμητικές συμβολοσειρές με χαλαρούς κανόνες· δείτε τη συμπεριφορά και τις επιφυλάξεις ανά έκδοση που αφορούν ειδικά την PHP στις [χαλαρές συγκρίσεις PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force επιθήματος hash MD5

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

### Δημιουργία hash MD5 0e για χαλαρές συγκρίσεις

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

και χρησιμοποιεί hash Merkle-Damgård, όπως MD5, SHA-1 ή SHA-256.

Αν γνωρίζετε:

- `message`
- `sig`
- τη hash function
- (ή μπορείτε να κάνετε brute-force) το `len(secret)`

Τότε μπορείτε να υπολογίσετε μια έγκυρη υπογραφή για:

`message || padding || appended_data`

χωρίς να γνωρίζετε το secret.<sup>[[1]](#references)</sup>

### Σημαντικός περιορισμός: Το HMAC δεν επηρεάζεται

Οι length-extension attacks εφαρμόζονται σε ευάλωτες κατασκευές με prefix, όπως `HASH(secret || message)`. Δεν αποκαλύπτουν την κατασκευή HMAC (για παράδειγμα, HMAC-SHA256), η οποία συνδυάζει ένα κλειδί με ξεχωριστές εσωτερικές και εξωτερικές εφαρμογές hash.<sup>[[1]](#references)[[2]](#references)</sup>

Για το πώς να εντοπίζετε και να δοκιμάζετε αυτές τις υπογραφές σε web APIs, δείτε το [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Εργαλεία

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings για το εργαλείο length-extension HashPump<sup>[[7]](#references)</sup>

### Καλή επεξήγηση

[Όλα όσα χρειάζεται να γνωρίζετε για τις hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Αμφίσημο hashing tuple και MACs

### Boundary-confusion attack

Τα incremental hash APIs δεν πιστοποιούν τα όρια των κλήσεων. Τα `update(A); update(B)` κάνουν hash την ίδια συμβολοσειρά byte με το `update(A + B)`. Επομένως, το hashing ή το MACing μιας ακατέργαστης συνένωσης δεν πιστοποιεί ένα tuple. Αν τα γειτονικά πεδία έχουν μεταβλητό μήκος, ένας attacker μπορεί να ανακατανείμει τα byte σε διαφορετικό tuple, χωρίς να βρει collision στην υποκείμενη hash function:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Αυτό γίνεται εκμεταλλεύσιμο όταν ο verifier πιστεύει ότι το digest δεσμεύει τις σημασίες των πεδίων, αλλά είσοδος που ελέγχεται από τον attacker μπορεί να φτάσει σε διαφορετικό parser ή βήμα πρωτοκόλλου που ορίζει διαφορετικά όρια. Τα commitments μπορεί να αποκτήσουν εναλλακτικά openings και τα Fiat-Shamir transcripts να ερμηνευτούν ως διαφορετικές προτάσεις. Το HMAC αποτρέπει το [hash length extension](#hash-length-extension-attack), αλλά το `HMAC(K, A || B)` εξακολουθεί να έχει αυτή την ασάφεια κωδικοποίησης πλειάδων, επειδή και οι δύο πλειάδες παράγουν τα ίδια bytes μηνύματος.<sup>[[8]](#references)[[9]](#references)</sup>

Χρησιμοποιήστε αυτή τη ροή εργασιών ελέγχου για να εξετάσετε αν μια αμφίσημη κωδικοποίηση πλειάδας διασχίζει ένα όριο ασφαλείας.<sup>[[8]](#references)[[9]](#references)</sup>

1. Βρείτε `HASH(A || B)`, `HMAC(K, A || B)` και διαδοχικές κλήσεις `update()`/`Write()` με δύο ή περισσότερα πεδία.
2. Σημειώστε κάθε πεδίο που ελέγχεται από τον attacker ή έχει μεταβλητό μήκος. Δοκιμάστε να μετακινήσετε bytes πέρα από κάθε όριο, διατηρώντας αμετάβλητη την πλήρη συνένωση. Συμπεριλάβετε κενά πεδία.
3. Ελέγξτε τα σχήματα οριοθέτησης για bytes οριοθέτησης που μπορούν να περιέχονται στις εισόδους, ασυμφωνίες στην αντιμετώπιση διαφυγών και σχεδιασμούς που κωδικοποιούν το μήκος μόνο ορισμένων πεδίων.
4. Ανιχνεύστε τον τρόπο με τον οποίο κάθε consumer αναλύει τα authenticated bytes. Μια υποψήφια περίπτωση έχει σημασία μόνο αν μια εναλλακτική διαμέριση αλλάζει μια απόφαση ασφαλείας, μια πρόταση proof, μια εγγραφή, μια συναλλαγή ή ένα άνοιγμα commitment. Τα πεδία σταθερού πλάτους ή μια κανονική, ενέσιμη σειριοποίηση αποτρέπουν τη συγκεκριμένη επίθεση.
5. Ελέγξτε αν το ίδιο encoded digest γίνεται αποδεκτό σε άλλη έκδοση πρωτοκόλλου, τύπο μηνύματος, γύρο ή εφαρμογή. Συνδέστε ρητά αυτά τα συμφραζόμενα αντί να βασίζεστε στους callers για να τα διαχωρίζουν.

### SequenceHash και SequenceMAC

Το SequenceHash είναι μια κατασκευή ανεξάρτητη από τη συνάρτηση hash, για ακολουθίες συμβολοσειρών bytes. Κάθε λειτουργία `add()` είναι ατομική: προσαρτά την τιμή και ένα επίθημα μήκους σταθερού μεγέθους 16 bytes, σε little-endian μορφή, στο εσωτερικό hash. Οι κενές τιμές παραμένουν διακριτά αντικείμενα. Ένα εξωτερικό hash αποτρέπει την έκθεση μιας εσωτερικής κατάστασης που μπορεί να επεκταθεί μέσω μήκους, ενώ μια προαιρετική συμβολοσειρά customization παρέχει διαχωρισμό domain. Μην αντικαθιστάτε την `add()` με τις συνηθισμένες εγγραφές του υποκείμενου API hash.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Επιλέξτε τον customizer ως μέρος του ορισμού του πρωτοκόλλου, συμπεριλαμβάνοντας αρκετές πληροφορίες ώστε να διακρίνονται η εφαρμογή, η έκδοση του πρωτοκόλλου, ο τύπος μηνύματος και ο γύρος. Το SequenceHash εξακολουθεί να απαιτεί από όλα τα μέρη να συμφωνούν ως προς τη σειρά των πεδίων, την κωδικοποίηση byte και την κανονική σειριοποίηση, και δεν μπορεί να προστατεύσει ένα πεδίο που παραλείφθηκε. Οι υλοποιήσεις θα πρέπει να ελέγχονται με τα ενδιάμεσα και τελικά test vectors του C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Για την αυθεντικοποίηση, το SequenceMAC παρέχει την ίδια διεπαφή ατομικής κωδικοποίησης και customization. Απαιτεί κλειδί τουλάχιστον 32 byte. Σε αντίθεση με την προεπεξεργασία κλειδιών του HMAC, οι κεφαλίδες του δεσμεύονται κρυπτογραφικά στο ακριβές μήκος του κλειδιού: ένα μεγάλο ακατέργαστο κλειδί δεν ισοδυναμεί με το prehash του, ενώ η προσθήκη μηδενικών byte αλλάζει το κλειδί. Αυτή η διάκριση έχει σημασία όταν τα στοιχεία δέχονται διαφορετικές αναπαραστάσεις κλειδιών ή μεταδεδομένα μήκους.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Το Python API και οι αντίστοιχες υλοποιήσεις σε Go και Rust είναι διαθέσιμες ως αναφορές, αλλά οι υλοποιήσεις πρωτοκόλλων πρέπει να ακολουθούν την τρέχουσα προδιαγραφή C2SP αντί να αναπαράγουν την κωδικοποίηση από αυτή τη σύνοψη.<sup>[[8]](#references)[[10]](#references)</sup>

## Κατακερματισμός κωδικών πρόσβασης και cracking

### Πρώτες ερωτήσεις<sup>[[4]](#references)</sup>

- Είναι **salted**; (αναζητήστε μορφές `salt$hash`)
- Είναι **fast hash** (MD5/SHA1/SHA256) ή **slow KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Έχετε κάποια **ένδειξη για τη μορφή** (hashcat mode / John format);

### Πρακτική ροή εργασίας<sup>[[5]](#references)[[6]](#references)</sup>

1. Αναγνωρίστε το hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν δεν έχει salt και είναι συνηθισμένο: δοκιμάστε online DBs και εργαλεία αναγνώρισης από την ενότητα ροής εργασίας crypto.
3. Διαφορετικά, κάντε crack:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Συνηθισμένα λάθη που μπορείτε να εκμεταλλευτείτε

- Επαναχρησιμοποίηση του ίδιου κωδικού πρόσβασης από διαφορετικούς χρήστες → κάντε crack ενός και μετά pivot.
- Κομμένα hashes / custom transforms → κανονικοποιήστε και δοκιμάστε ξανά.
- Αδύναμες παράμετροι KDF (π.χ. λίγες επαναλήψεις PBKDF2) → εξακολουθούν να μπορούν να γίνουν crack.

### Oracle bcrypt με επιλεγμένη είσοδο και προσαρτημένο secret

Ένα callable helper που επιστρέφει `bcrypt(user_input || secret)` μπορεί να αποκαλύψει πληροφορίες για ένα προσαρτημένο secret, αν η υλοποίηση bcrypt περικόπτει σιωπηρά την είσοδο μετά από 72 **bytes**. Ένα όριο στον αριθμό χαρακτήρων πριν από την κωδικοποίηση UTF-8 δεν επιβάλλει αυτό το όριο σε bytes: οι χαρακτήρες πολλών bytes μπορούν να γεμίσουν την είσοδο bcrypt, αφήνοντας χώρο μόνο για ένα μικρό πρόθεμα του secret. Οι επιλεγμένες είσοδοι και τα hashes που επιστρέφονται μπορεί τότε να επιτρέψουν offline ελέγχους υποψήφιων bytes του επιθέματος. Αυτό απαιτεί έλεγχο της εισόδου του helper, γνώση του ακριβούς transform και της κωδικοποίησής του, καθώς και υλοποίηση που πράγματι περικόπτει· ένα callable helper ή ένα hash bcrypt από μόνο του δεν αποδεικνύει ότι ισχύουν όλα αυτά. Η [pyca/bcrypt τεκμηριώνει](https://github.com/pyca/bcrypt#maximum-password-length) ότι η τρέχουσα `hashpw` εγείρει σφάλμα για εισόδους άνω των 72 bytes, ενώ παλαιότερες εκδόσεις τις περικόπταν σιωπηρά. Άλλα wrappers μπορεί να κάνουν prehash ή να απορρίπτουν μεγάλες εισόδους, οπότε επαληθεύστε την εγκατεστημένη υλοποίηση αντί να υποθέτετε ότι γίνεται περικοπή.

Η χρήση ενός secret που ανακτήθηκε σε διαφορετικό λογαριασμό απαιτεί επίσης αποδεικτικά στοιχεία ότι το εκτεθειμένο hash δημιουργήθηκε με το **ίδιο** secret και transform, καθώς και ξεχωριστό credential ή login path. Ένα helper κατακερματισμού που εκτελείται ως root πρέπει να εξετάζεται ως oracle μόνο αν ο χρήστης με χαμηλότερα προνόμια μπορεί να το καλέσει βάσει της ισχύουσας πολιτικής· η παθητική αναγνώριση του host δεν χρειάζεται να το καλέσει ή να υποβάλει επιλεγμένους κωδικούς πρόσβασης.

## References

- [1] [SkullSecurity - Όσα πρέπει να γνωρίζετε για τις επιθέσεις επέκτασης μήκους hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Ο κώδικας αυθεντικοποίησης μηνυμάτων keyed-hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Σύντομος οδηγός αποθήκευσης κωδικών πρόσβασης](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat - Παραδείγματα hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper - Επιλογές γραμμής εντολών](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - Python bindings για το HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Προδιαγραφή SequenceHash και SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing για όλους](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Υλοποίηση SequenceHash σε Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Διανύσματα δοκιμών SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
