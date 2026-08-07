# Αποκρυπτογράφηση κρυπτογραφημένων αρχειοθηκών Synology PAT/SPK

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Αρκετές συσκευές Synology (DSM/BSM NAS, BeeStation, …) διανέμουν το firmware και τα πακέτα εφαρμογών τους σε **κρυπτογραφημένες αρχειοθήκες PAT / SPK**. Αυτές οι αρχειοθήκες μπορούν να αποκρυπτογραφηθούν *offline*, χρησιμοποιώντας αποκλειστικά τα δημόσια αρχεία λήψης, χάρη στα hard-coded κλειδιά που είναι ενσωματωμένα στις επίσημες βιβλιοθήκες extraction.

Αυτή η σελίδα τεκμηριώνει, βήμα προς βήμα, τον τρόπο λειτουργίας της κρυπτογραφημένης μορφής και τον τρόπο πλήρους ανάκτησης του clear-text **TAR** που περιέχεται σε κάθε πακέτο. Η διαδικασία βασίζεται στην έρευνα της Synacktiv που πραγματοποιήθηκε κατά το Pwn2Own Ireland 2024 και υλοποιήθηκε στο open-source εργαλείο [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Η μορφή είναι ακριβώς ίδια για τις αρχειοθήκες `*.pat` (ενημέρωση συστήματος) και `*.spk` (εφαρμογή) – διαφέρουν μόνο στο ζεύγος hard-coded κλειδιών που επιλέγεται.

---

## 1. Λήψη της αρχειοθήκης

Η ενημέρωση firmware/εφαρμογής μπορεί συνήθως να ληφθεί από τη δημόσια πύλη της Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Αποτύπωση της δομής PAT (προαιρετικό)

Τα `*.pat` images είναι τα ίδια ένα **cpio bundle** που ενσωματώνει αρκετά αρχεία (boot loader, kernel, rootfs, packages…). Το δωρεάν utility [`patology`](https://github.com/sud0woodo/patology) είναι βολικό για την επιθεώρηση αυτού του wrapper:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Για τα `*.spk` μπορείτε να μεταβείτε απευθείας στο βήμα 3.

## 3. Εξαγωγή των βιβλιοθηκών extraction της Synology

Η πραγματική λογική αποκρυπτογράφησης βρίσκεται στα:

* `/usr/syno/sbin/synoarchive`               → κύριο CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → καλεί το wrapper από το DSM UI
* `libsynocodesign.so`                       → **περιέχει την cryptographic implementation**

Και τα δύο binaries υπάρχουν στο system rootfs (`hda1.tgz`) **και** στο compressed init-rd (`rd.bin`).  Αν έχετε μόνο το PAT, μπορείτε να τα λάβετε ως εξής:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Ανάκτηση των hard-coded keys (`get_keys`)

Μέσα στο `libsynocodesign.so`, η συνάρτηση `get_keys(int keytype)` απλώς επιστρέφει δύο global μεταβλητές 128-bit για την ζητούμενη archive family:<sup>[[1]](#references)</sup>
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
* **signature_key** → Ed25519 δημόσιο κλειδί που χρησιμοποιείται για την επαλήθευση της κεφαλίδας του archive.
* **master_key**    → Root key που χρησιμοποιείται για την παραγωγή του encryption key ανά archive.

Χρειάζεται να κάνετε dump αυτές τις δύο σταθερές μόνο μία φορά για κάθε major version του DSM.

## 5. Δομή κεφαλίδας & επαλήθευση υπογραφής

Η `synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` εκτελεί τα ακόλουθα:<sup>[[1]](#references)</sup>

1. Ανάγνωση του magic (3 bytes) `0xBFBAAD` **ή** `0xADBEEF`.
2. Ανάγνωση του little-endian 32-bit `header_len`.
3. Ανάγνωση `header_len` bytes + της επόμενης **0x40-byte Ed25519 υπογραφής**.
4. Επανάληψη σε όλα τα ενσωματωμένα δημόσια κλειδιά μέχρι να επιτύχει η `crypto_sign_verify_detached()`.
5. Αποκωδικοποίηση της κεφαλίδας με **MessagePack**, με αποτέλεσμα:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
Το `entries` επιτρέπει αργότερα στο libarchive να ελέγχει την ακεραιότητα κάθε αρχείου καθώς αυτό αποκρυπτογραφείται.

## 6. Παράγωγο sub-key ανά archive

Από το blob `data` που περιέχεται στην κεφαλίδα MessagePack:

* `subkey_id`  = little-endian `uint64` στο offset 0x10
* `ctx`        = 7 bytes στο offset 0x18

Το **stream key** των 32 bytes λαμβάνεται με το libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Το custom **libarchive** backend της Synology

Η Synology περιλαμβάνει ένα patched libarchive που καταχωρεί ένα πλαστό format "tar" όταν το magic είναι `0xADBEEF`:<sup>[[1]](#references)</sup>
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
Η αποκρυπτογραφημένη `tar_hdr` είναι μια **κλασική κεφαλίδα POSIX TAR**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Κάθε **nonce μεγέθους 0x18 byte** τοποθετείται πριν από το κρυπτογραφημένο chunk.

Μόλις ολοκληρωθεί η επεξεργασία όλων των entries, το libarchive παράγει ένα πλήρως έγκυρο **`.tar`**, το οποίο μπορεί να αποσυμπιεστεί με οποιοδήποτε standard tool.

## 8. Αποκρυπτογράφηση των πάντων με το synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` εντοπίζει αυτόματα τα PAT/SPK, φορτώνει τα σωστά keys και εφαρμόζει ολόκληρη την αλυσίδα που περιγράφεται παραπάνω.<sup>[[2]](#references)</sup>

## 9. Συνήθεις παγίδες

* **Μην** αλλάζετε τις `signature_key` και `master_key` – εξυπηρετούν διαφορετικούς σκοπούς.
* Το **nonce** βρίσκεται *πριν* από το ciphertext για κάθε block (header και data).
* Το μέγιστο μέγεθος κρυπτογραφημένου chunk είναι **0x400000 + 0x11** (libsodium tag).
* Τα archives που δημιουργήθηκαν για μία γενιά DSM ενδέχεται να χρησιμοποιούν διαφορετικά hard-coded keys στην επόμενη release.

## 10. Πρόσθετα εργαλεία

* [`patology`](https://github.com/sud0woodo/patology) – parse/dump PAT archives.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decrypt PAT/SPK/others.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – υλοποίηση αναφοράς του XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – header serialisation.

## Αναφορές

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
