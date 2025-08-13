# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

Πολλές συσκευές Synology (DSM/BSM NAS, BeeStation, …) διανέμουν το firmware και τα πακέτα εφαρμογών τους σε **κρυπτογραφημένα PAT / SPK αρχεία**. Αυτά τα αρχεία μπορούν να αποκρυπτογραφηθούν *offline* μόνο με τα δημόσια αρχεία λήψης χάρη σε σκληρά κωδικοποιημένα κλειδιά που είναι ενσωματωμένα μέσα στις επίσημες βιβλιοθήκες εξαγωγής.

Αυτή η σελίδα τεκμηριώνει, βήμα-βήμα, πώς λειτουργεί η κρυπτογραφημένη μορφή και πώς να ανακτήσετε πλήρως το καθαρό κείμενο **TAR** που βρίσκεται μέσα σε κάθε πακέτο. Η διαδικασία βασίζεται σε έρευνα της Synacktiv που πραγματοποιήθηκε κατά τη διάρκεια του Pwn2Own Ireland 2024 και υλοποιήθηκε στο εργαλείο ανοιχτού κώδικα [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Η μορφή είναι ακριβώς η ίδια και για τα `*.pat` (αναβάθμιση συστήματος) και `*.spk` (εφαρμογή) αρχεία – διαφέρουν μόνο στο ζευγάρι σκληρά κωδικοποιημένων κλειδιών που επιλέγονται.

---

## 1. Grab the archive

Η αναβάθμιση του firmware/εφαρμογής μπορεί κανονικά να ληφθεί από το δημόσιο portal της Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump the PAT structure (optional)

`*.pat` images are themselves a **cpio bundle** that embeds several files (boot loader, kernel, rootfs, packages…).  The free utility [`patology`](https://github.com/sud0woodo/patology) είναι βολικό για να επιθεωρήσετε αυτή τη συσκευασία:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Για `*.spk` μπορείτε να μεταβείτε απευθείας στο βήμα 3.

## 3. Εξαγωγή των βιβλιοθηκών εξαγωγής Synology

Η πραγματική λογική αποκρυπτογράφησης βρίσκεται σε:

* `/usr/syno/sbin/synoarchive`               → κύριος περιτύλιγμα CLI
* `/usr/lib/libsynopkg.so.1`                 → καλεί το περιτύλιγμα από το DSM UI
* `libsynocodesign.so`                       → **περιέχει την κρυπτογραφική υλοποίηση**

Και οι δύο δυαδικοί είναι παρόντες στο rootfs του συστήματος (`hda1.tgz`) **και** στο συμπιεσμένο init-rd (`rd.bin`). Αν έχετε μόνο το PAT μπορείτε να τα αποκτήσετε με αυτόν τον τρόπο:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Ανάκτηση των σκληρά κωδικοποιημένων κλειδιών (`get_keys`)

Μέσα στο `libsynocodesign.so`, η συνάρτηση `get_keys(int keytype)` απλά επιστρέφει δύο παγκόσμιες μεταβλητές 128-bit για την ζητούμενη οικογένεια αρχείων:
```c
case 0:            // PAT (system)
case 10:
case 11:
signature_key = qword_23A40;
master_key    = qword_23A68;
break;

case 3:            // SPK (applications)
signature_key = qword_23AE0;
master_key    = qword_23B08;
break;
```
* **signature_key** → Δημόσιο κλειδί Ed25519 που χρησιμοποιείται για την επαλήθευση της κεφαλίδας του αρχείου.
* **master_key**    → Ρίζα κλειδί που χρησιμοποιείται για την εξαγωγή του κλειδιού κρυπτογράφησης ανά αρχείο.

Πρέπει να εκτελέσετε την εξαγωγή αυτών των δύο σταθερών μόνο μία φορά για κάθε κύρια έκδοση DSM.

## 5. Δομή κεφαλίδας & επαλήθευση υπογραφής

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` εκτελεί τα εξής:

1. Διαβάστε το μαγικό (3 bytes) `0xBFBAAD` **ή** `0xADBEEF`.
2. Διαβάστε little-endian 32-bit `header_len`.
3. Διαβάστε `header_len` bytes + την επόμενη **0x40-byte Ed25519 υπογραφή**.
4. Επαναλάβετε όλες τις ενσωματωμένες δημόσιες κλειδιά μέχρι να επιτύχει το `crypto_sign_verify_detached()`.
5. Αποκωδικοποιήστε την κεφαλίδα με **MessagePack**, παράγοντας:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` αργότερα επιτρέπει στο libarchive να ελέγξει την ακεραιότητα κάθε αρχείου καθώς αποκρυπτογραφείται.

## 6. Παράγωγο του υποκλειδιού ανά αρχείο

Από το `data` blob που περιέχεται στην κεφαλίδα MessagePack:

* `subkey_id`  = little-endian `uint64` στη θέση 0x10
* `ctx`        = 7 bytes στη θέση 0x18

Το 32-byte **stream key** αποκτάται με libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Το προσαρμοσμένο **libarchive** backend της Synology

Η Synology περιλαμβάνει μια διορθωμένη έκδοση του libarchive που καταχωρεί μια ψεύτικη μορφή "tar" όποτε το magic είναι `0xADBEEF`:
```c
register_format(
"tar", spk_bid, spk_options,
spk_read_header, spk_read_data, spk_read_data_skip,
NULL, spk_cleanup, NULL, NULL);
```
### spk_read_header()
```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```
Ο αποκρυπτογραφημένος `tar_hdr` είναι μια **κλασική κεφαλίδα TAR POSIX**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Κάθε **0x18-byte nonce** προστίθεται πριν από το κρυπτογραφημένο κομμάτι.

Μόλις επεξεργαστούν όλες οι καταχωρίσεις, η libarchive παράγει ένα απολύτως έγκυρο **`.tar`** που μπορεί να αποσυμπιεστεί με οποιοδήποτε τυπικό εργαλείο.

## 8. Αποκρυπτογραφήστε τα πάντα με το synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` ανιχνεύει αυτόματα το PAT/SPK, φορτώνει τα σωστά κλειδιά και εφαρμόζει την πλήρη αλυσίδα που περιγράφεται παραπάνω.

## 9. Κοινές παγίδες

* Μην **ανταλλάξετε** το `signature_key` και το `master_key` – εξυπηρετούν διαφορετικούς σκοπούς.
* Το **nonce** έρχεται *πριν* από το ciphertext για κάθε μπλοκ (κεφαλίδα και δεδομένα).
* Το μέγιστο μέγεθος κρυπτογραφημένου τμήματος είναι **0x400000 + 0x11** (libsodium tag).
* Τα αρχεία που δημιουργούνται για μια γενιά DSM μπορεί να αλλάξουν σε διαφορετικά σκληρά κωδικοποιημένα κλειδιά στην επόμενη έκδοση.

## 10. Πρόσθετα εργαλεία

* [`patology`](https://github.com/sud0woodo/patology) – ανάλυση/εξαγωγή αρχείων PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – αποκρυπτογράφηση PAT/SPK/άλλων.
* [`libsodium`](https://github.com/jedisct1/libsodium) – αναφορά υλοποίησης του XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – σειριοποίηση κεφαλίδας.

## Αναφορές

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
