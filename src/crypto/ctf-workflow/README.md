# Ροή εργασίας Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Λίστα ελέγχου αρχικής αξιολόγησης

1. Προσδιορίστε τι έχετε: encoding, encryption, hash, signature ή MAC.
2. Προσδιορίστε τι ελέγχετε: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leak.
3. Κατηγοριοποιήστε: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Εφαρμόστε πρώτα τους ελέγχους με τη μεγαλύτερη πιθανότητα επιτυχίας: αποκωδικοποίηση επιπέδων, known-plaintext XOR, επαναχρησιμοποίηση nonce, κακή χρήση mode, συμπεριφορά oracle.
5. Προχωρήστε σε προηγμένες μεθόδους μόνο όταν χρειάζεται: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Διαδικτυακοί πόροι και βοηθητικά εργαλεία

Είναι χρήσιμα όταν η εργασία αφορά την αναγνώριση και την αφαίρεση επιπέδων ή όταν χρειάζεστε γρήγορη επιβεβαίωση μιας υπόθεσης.

### Αναζήτηση hash

- Αναζητήστε το hash μιας πρόκλησης όταν είναι γνωστό ότι είναι συνθετικό/δημόσιο.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- αναζήτηση στο hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Μην υποβάλλετε πραγματικά password hashes ή εμπιστευτικό υλικό πρόκλησης σε υπηρεσίες αναζήτησης τρίτων. Προτιμήστε επίθεση με offline wordlist/rule όταν υπάρχει ανησυχία για την αποκάλυψη, τους όρους χρήσης ή τους κανόνες του διαγωνισμού.

### Βοηθήματα αναγνώρισης

- CyberChef (Magic, αποκωδικοποίηση και μετατροπή).<sup>[[7]](#references)</sup>
- dCode (περιβάλλον δοκιμών cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solvers για substitution).<sup>[[9]](#references)</sup>

### Πλατφόρμες εξάσκησης / αναφορές

- CryptoHack (πρακτικές προκλήσεις κρυπτογραφίας).<sup>[[10]](#references)</sup>
- Cryptopals (κλασικές παγίδες της σύγχρονης κρυπτογραφίας).<sup>[[11]](#references)</sup>

### Αυτοματοποιημένη αποκωδικοποίηση

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (δοκιμάζει πολλές βάσεις/κωδικοποιήσεις).<sup>[[13]](#references)</sup>

Για πηγαίο κώδικα esoteric γλωσσών και προσαρμοσμένη κατάσταση interpreter, δείτε το [Crypto CTF Misc](../ctf-misc/).

## Κωδικοποιήσεις και κλασικά cipher

### Τεχνική

Πολλές εργασίες crypto σε CTF είναι μετασχηματισμοί σε επίπεδα: base encoding + απλή substitution + συμπίεση. Στόχος είναι να αναγνωρίσετε τα επίπεδα και να τα αφαιρέσετε με ασφάλεια.

### Κωδικοποιήσεις: δοκιμάστε πολλές βάσεις

Αν υποψιάζεστε κωδικοποίηση σε επίπεδα (base64 → base32 → …), δοκιμάστε:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Συνήθεις ενδείξεις:

- Base64: `A-Za-z0-9+/=` (το padding `=` είναι συνηθισμένο)
- Base32: `A-Z2-7=` (συχνά με πολύ padding `=`)
- Ascii85/Base85: πολλά σημεία στίξης· μερικές φορές περικλείεται σε `<~ ~>`

### Substitution / μονοαλφαβητική

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Ανάκτηση με known-plaintext ονομάτων αρχείων Base32 που έχουν υποστεί substitution

Όταν ένα συγκαλυμμένο όνομα αρχείου περιέχει μόνο `a-z2-7`, επεκτείνεται σε περίπου `ceil(8 * byte_length / 5)` χαρακτήρες αφού αφαιρεθεί ένα σταθερό επίθημα, και το ίδιο plaintext παράγει την ίδια έξοδο σε διαφορετικά αρχεία, δοκιμάστε **unpadded Base32 ακολουθούμενο από σταθερή substitution συμβόλων**. Αυτές οι ενδείξεις από μόνες τους δεν αποτελούν απόδειξη. Συγκεντρώστε προβλέψιμα ονόματα αρχείων και τα αντίστοιχα ciphertext τους, διατηρήστε τα πεζά/κεφαλαία, κωδικοποιήστε κάθε plaintext σε Base32 και ευθυγραμμίστε τα σύμβολα ανά θέση. Κάθε επαναλαμβανόμενο σύμβολο plaintext πρέπει να αντιστοιχεί στο ίδιο σύμβολο ciphertext, ενώ και η αντίστροφη αντιστοίχιση πρέπει να είναι μοναδική. Σε μια περίπτωση ransomware, τα `ntuser.ini` και `NTUSER.DAT` παρείχαν τέτοια ζεύγη· έτσι ανακτήθηκαν ονόματα αρχείων, **όχι περιεχόμενα αρχείων ή κλειδιά encryption**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Αν ένας στόχος περιέχει μη αντιστοιχισμένα σύμβολα, αποκτήστε περισσότερα γνωστά ζεύγη ή αναδιατάξτε μόνο τις αντιστοιχίσεις συμβόλων Base32 που δεν έχουν χρησιμοποιηθεί. Επαναφέρετε το padding ώστε το μήκος να είναι πολλαπλάσιο του οκτώ, απορρίψτε μη έγκυρο Base32 και ονόματα που αποκωδικοποιούνται σε μη εκτυπώσιμους χαρακτήρες και, στη συνέχεια, κωδικοποιήστε ξανά τους υποψήφιους που απομένουν και συγκρίνετέ τους με ολόκληρο το αρχικό ciphertext. Τα επαναλαμβανόμενα blocks ciphertext μπορούν να δώσουν επιπλέον εκτιμήσεις: στο παραπάνω παράδειγμα, το `3gpng2wv` αντιστοιχίστηκε ξανά στο Base32 `gaydambq`, το οποίο αποκωδικοποιείται σε πέντε ASCII μηδενικά. Ένας εκτυπώσιμος υποψήφιος από μόνος του δεν αποτελεί μοναδική απόδειξη.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Συχνά εμφανίζεται ως ομάδες των 5 bits ή 5 γραμμάτων:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Ρούνοι

Οι ρούνοι είναι συχνά αλφάβητα αντικατάστασης· αναζητήστε "futhark cipher" και δοκιμάστε πίνακες αντιστοίχισης.

## Συμπίεση σε challenges

### Τεχνική

Η συμπίεση εμφανίζεται συνεχώς ως επιπλέον επίπεδο (zlib/deflate/gzip/xz/zstd), μερικές φορές και εμφωλευμένη. Αν το αποτέλεσμα σχεδόν μπορεί να αναλυθεί, αλλά μοιάζει με ακατανόητα δεδομένα, υποψιαστείτε συμπίεση.

### Γρήγορη αναγνώριση

- `file <blob>`
- Αναζητήστε magic bytes:
  - gzip: `1f 8b`
  - zlib: συνήθως `78 01`, `78 5e`, `78 9c` ή `78 da` (το δεύτερο byte εξαρτάται από τις σημαίες συμπίεσης)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

Το CyberChef διαθέτει **Raw Deflate/Raw Inflate**, που είναι συχνά ο γρηγορότερος τρόπος όταν το blob μοιάζει συμπιεσμένο, αλλά το `zlib` αποτυγχάνει.

### Χρήσιμες εντολές CLI

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## Συνήθεις κρυπτογραφικές κατασκευές σε CTF

### Τεχνική

Εμφανίζονται συχνά επειδή αντιστοιχούν σε ρεαλιστικά λάθη προγραμματιστών ή σε συνηθισμένες βιβλιοθήκες που χρησιμοποιούνται λανθασμένα. Συνήθως, ο στόχος είναι η αναγνώριση και η εφαρμογή μιας γνωστής διαδικασίας εξαγωγής ή ανακατασκευής.

### Fernet

Τυπική υπόδειξη: δύο συμβολοσειρές Base64 (token + key).

- Αποκωδικοποιητής/σημειώσεις: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Σε Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Αν δείτε πολλαπλά shares και αναφέρεται ένα threshold `t`, πιθανότατα πρόκειται για Shamir.

- Online ανακατασκευαστής (μόνο για μη ευαίσθητα CTF shares).<sup>[[19]](#references)</sup>

### Μορφές OpenSSL με salt

Μερικές φορές τα CTF παρέχουν εξόδους `openssl enc` (η κεφαλίδα συχνά αρχίζει με `Salted__`).

Βοηθητικά εργαλεία bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Γενικό σύνολο εργαλείων

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Προτεινόμενη τοπική εγκατάσταση

Πρακτικό σύνολο εργαλείων για CTF:

- Python μαζί με `pycryptodome` για συμμετρικά primitives και γρήγορη ανάπτυξη πρωτοτύπων.<sup>[[25]](#references)</sup>
- SageMath για modular arithmetic, CRT, lattices και εργασία με RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 για προκλήσεις που βασίζονται σε περιορισμούς (όταν η κρυπτογραφία ανάγεται σε περιορισμούς).<sup>[[27]](#references)</sup>

Προτεινόμενα πακέτα Python:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [Αναζήτηση hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Εργαλειοθήκη Hash](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [Εργαλεία dCode](https://www.dcode.fr/tools-list)
- [9] [Εργαλεία αποκρυπτογράφησης κωδίκων Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Αυτόματος επιλυτής κρυπτογράφησης Caesar](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Κρυπτογράφημα Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Επιλυτής Vigenère της Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Αποκωδικοποιητής Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Ανακατασκευαστής μοιρασμένου μυστικού Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Τεκμηρίωση PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Παραβίαση σχημάτων κρυπτογράφησης με τον εύκολο τρόπο](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
