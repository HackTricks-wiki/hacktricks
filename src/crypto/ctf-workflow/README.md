# Ροή εργασίας Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Λίστα ελέγχου διαλογής

1. Προσδιορίστε τι έχετε: κωδικοποίηση, κρυπτογράφηση, hash, υπογραφή ή MAC.
2. Καθορίστε τι ελέγχεται: plaintext/ciphertext, IV/nonce, κλειδί, oracle (padding/error/timing), μερική διαρροή.
3. Κατηγοριοποιήστε: συμμετρικό (AES/CTR/GCM), δημόσιου κλειδιού (RSA/ECC), hash/MAC (SHA/MD5/HMAC), κλασικό (Vigenere/XOR).
4. Εφαρμόστε πρώτα τους ελέγχους με τη μεγαλύτερη πιθανότητα επιτυχίας: αποκωδικοποίηση επιπέδων, XOR με γνωστό plaintext, επαναχρησιμοποίηση nonce, κακή χρήση mode, συμπεριφορά oracle.
5. Προχωρήστε σε προηγμένες μεθόδους μόνο όταν χρειάζεται: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Διαδικτυακοί πόροι & βοηθητικά εργαλεία

Είναι χρήσιμα όταν η εργασία αφορά αναγνώριση και αφαίρεση επιπέδων ή όταν χρειάζεστε γρήγορη επιβεβαίωση μιας υπόθεσης.

### Αναζητήσεις hash

- Αναζητήστε ένα hash πρόκλησης όταν είναι γνωστό ότι είναι συνθετικό/δημόσιο.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Αναζήτηση στο hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Μην υποβάλλετε πραγματικά password hashes ή εμπιστευτικό υλικό πρόκλησης σε υπηρεσίες αναζήτησης τρίτων. Προτιμήστε offline επίθεση με wordlist/rule όταν υπάρχει ανησυχία για αποκάλυψη, όρους χρήσης ή κανόνες διαγωνισμού.

### Βοηθήματα αναγνώρισης

- CyberChef (Magic, αποκωδικοποίηση και μετατροπή).<sup>[[7]](#references)</sup>
- dCode (περιβάλλον δοκιμών cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solvers αντικατάστασης).<sup>[[9]](#references)</sup>

### Πλατφόρμες εξάσκησης / αναφορές

- CryptoHack (πρακτικές προκλήσεις κρυπτογραφίας).<sup>[[10]](#references)</sup>
- Cryptopals (κλασικές παγίδες σύγχρονης κρυπτογραφίας).<sup>[[11]](#references)</sup>

### Αυτοματοποιημένη αποκωδικοποίηση

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (δοκιμάζει πολλές βάσεις/κωδικοποιήσεις).<sup>[[13]](#references)</sup>

## Κωδικοποιήσεις & κλασικά cipher

### Τεχνική

Πολλές εργασίες crypto CTF αποτελούνται από διαδοχικούς μετασχηματισμούς: κωδικοποίηση βάσης + απλή αντικατάσταση + συμπίεση. Στόχος είναι να εντοπίσετε τα επίπεδα και να τα αφαιρέσετε με ασφάλεια.

### Κωδικοποιήσεις: δοκιμάστε πολλές βάσεις

Αν υποψιάζεστε διαδοχική κωδικοποίηση (base64 → base32 → …), δοκιμάστε:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Συνήθεις ενδείξεις:

- Base64: `A-Za-z0-9+/=` (συχνά υπάρχει padding `=`)
- Base32: `A-Z2-7=` (συχνά υπάρχει πολύ padding `=`)
- Ascii85/Base85: πυκνά σημεία στίξης· μερικές φορές περικλείεται σε `<~ ~>`

### Αντικατάσταση / μονοαλφαβητικό cipher

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Ανάκτηση με γνωστό plaintext ονομάτων αρχείων Base32 που έχουν υποστεί αντικατάσταση

Όταν ένα συγκεκαλυμμένο όνομα αρχείου χρησιμοποιεί μόνο `a-z2-7`, επεκτείνεται σε περίπου `ceil(8 * byte_length / 5)` χαρακτήρες αφού αφαιρεθεί ένα σταθερό επίθημα και το ίδιο plaintext παράγει την ίδια έξοδο σε διαφορετικά αρχεία, δοκιμάστε **unpadded Base32 ακολουθούμενο από σταθερή αντικατάσταση συμβόλων**. Αυτές οι ενδείξεις δεν αποτελούν από μόνες τους απόδειξη. Συγκεντρώστε προβλέψιμα ονόματα αρχείων και τα αντίστοιχα ciphertext, διατηρήστε τα πεζά/κεφαλαία, κωδικοποιήστε κάθε plaintext σε Base32 και ευθυγραμμίστε τα σύμβολα θέση προς θέση. Κάθε επαναλαμβανόμενο σύμβολο plaintext πρέπει να αντιστοιχεί στο ίδιο σύμβολο ciphertext, ενώ και η αντίστροφη αντιστοίχιση πρέπει να είναι μοναδική. Σε μία περίπτωση ransomware, τα `ntuser.ini` και `NTUSER.DAT` παρείχαν τέτοια ζεύγη· έτσι ανακτήθηκαν τα ονόματα αρχείων, **όχι τα περιεχόμενα των αρχείων ή τα κλειδιά κρυπτογράφησης**.<sup>[[28]](#references)</sup>

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

Αν ένας στόχος περιέχει μη αντιστοιχισμένα σύμβολα, αποκτήστε περισσότερα γνωστά ζεύγη ή μεταθέστε μόνο τις αντιστοιχίσεις των αχρησιμοποίητων συμβόλων Base32. Επαναφέρετε το padding ώστε το μήκος να είναι πολλαπλάσιο του οκτώ, απορρίψτε τα μη έγκυρα Base32 και τα ονόματα που αποκωδικοποιούνται σε μη εκτυπώσιμους χαρακτήρες και, στη συνέχεια, κωδικοποιήστε ξανά τους υποψήφιους που απομένουν και συγκρίνετέ τους με ολόκληρο το αρχικό ciphertext. Επαναλαμβανόμενα blocks ciphertext μπορούν να δώσουν επιπλέον ενδείξεις: στο παραπάνω παράδειγμα, το `3gpng2wv` αντιστοιχίστηκε ξανά στο Base32 `gaydambq`, το οποίο αποκωδικοποιείται σε πέντε μηδενικά ASCII. Ένας εκτυπώσιμος υποψήφιος από μόνος του δεν αποτελεί μοναδική απόδειξη.<sup>[[28]](#references)</sup>

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

### Ρουνικά σύμβολα

Τα ρουνικά σύμβολα είναι συχνά αλφάβητα αντικατάστασης· αναζητήστε «futhark cipher» και δοκιμάστε πίνακες αντιστοίχισης.

## Συμπίεση σε challenges

### Τεχνική

Η συμπίεση εμφανίζεται συνεχώς ως επιπλέον επίπεδο (zlib/deflate/gzip/xz/zstd), μερικές φορές σε εμφωλευμένη μορφή. Αν η έξοδος σχεδόν αναλύεται σωστά, αλλά μοιάζει με σκουπίδια, υποψιαστείτε συμπίεση.

### Γρήγορη αναγνώριση

- `file <blob>`
- Αναζητήστε magic bytes:
  - gzip: `1f 8b`
  - zlib: συνήθως `78 01`, `78 5e`, `78 9c` ή `78 da` (το δεύτερο byte εξαρτάται από τα flags συμπίεσης)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

Το CyberChef διαθέτει **Raw Deflate/Raw Inflate**, που είναι συχνά ο ταχύτερος τρόπος όταν το blob μοιάζει συμπιεσμένο, αλλά το `zlib` αποτυγχάνει.

### Χρήσιμα CLI

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

## Συνήθεις κατασκευές crypto σε CTF

### Τεχνική

Αυτές εμφανίζονται συχνά, επειδή οφείλονται σε ρεαλιστικά λάθη προγραμματιστών ή σε συνήθεις βιβλιοθήκες που χρησιμοποιούνται λανθασμένα. Συνήθως, ο στόχος είναι να τις αναγνωρίσετε και να εφαρμόσετε μια γνωστή διαδικασία εξαγωγής ή ανακατασκευής.

### Fernet

Τυπική ένδειξη: δύο συμβολοσειρές Base64 (token + key).

- Αποκωδικοποιητής/σημειώσεις: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Σε Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Αν δείτε πολλά μερίδια και αναφέρεται ένα κατώφλι `t`, πιθανότατα πρόκειται για Shamir.

- Online εργαλείο ανακατασκευής (μόνο για μη ευαίσθητα μερίδια CTF).<sup>[[19]](#references)</sup>

### Μορφές OpenSSL με salt

Μερικές φορές τα CTF παρέχουν εξόδους `openssl enc` (η επικεφαλίδα συχνά ξεκινά με `Salted__`).

Βοηθητικά εργαλεία για bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Γενικά εργαλεία

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Προτεινόμενη τοπική εγκατάσταση

Πρακτικό stack για CTF:

- Python μαζί με `pycryptodome` για συμμετρικά primitives και γρήγορη δημιουργία πρωτοτύπων.<sup>[[25]](#references)</sup>
- SageMath για modular αριθμητική, CRT, lattices και εργασίες RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 για προκλήσεις βασισμένες σε περιορισμούς (όταν το crypto ανάγεται σε περιορισμούς).<sup>[[27]](#references)</sup>

Προτεινόμενα πακέτα Python:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [αναζήτηση στο hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [εργαλεία dCode](https://www.dcode.fr/tools-list)
- [9] [εργαλεία αποκρυπτογράφησης κωδίκων Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Αυτόματος αποκωδικοποιητής κρυπτογραφήματος Caesar](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Κρυπτογράφημα Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Επίλυση κρυπτογραφήματος Vigenère από το Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - αποκωδικοποιητής Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Ανακατασκευή διαμοιρασμού μυστικού Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Τεκμηρίωση του PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Παραβίαση σχημάτων κρυπτογράφησης με τον εύκολο τρόπο](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
