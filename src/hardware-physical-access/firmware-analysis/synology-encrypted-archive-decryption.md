# Decrittazione dell'Archivio Crittografato PAT/SPK di Synology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Diverse apparecchiature Synology (DSM/BSM NAS, BeeStation, …) distribuiscono il loro firmware e i pacchetti applicativi in **archivi PAT / SPK crittografati**. Questi archivi possono essere decrittografati *offline* con nient'altro che i file di download pubblici grazie a chiavi hard-coded incorporate all'interno delle librerie di estrazione ufficiali.

Questa pagina documenta, passo dopo passo, come funziona il formato crittografato e come recuperare completamente il **TAR** in chiaro che si trova all'interno di ciascun pacchetto. La procedura si basa sulla ricerca di Synacktiv effettuata durante Pwn2Own Irlanda 2024 e implementata nello strumento open-source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Il formato è esattamente lo stesso per gli archivi `*.pat` (aggiornamento di sistema) e `*.spk` (applicazione) – differiscono solo nella coppia di chiavi hard-coded selezionate.

---

## 1. Ottieni l'archivio

L'aggiornamento del firmware/applicazione può normalmente essere scaricato dal portale pubblico di Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump the PAT structure (opzionale)

`*.pat` immagini sono esse stesse un **cpio bundle** che incorpora diversi file (boot loader, kernel, rootfs, pacchetti…). L'utilità gratuita [`patology`](https://github.com/sud0woodo/patology) è comoda per ispezionare quel wrapper:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Per `*.spk` puoi saltare direttamente al passo 3.

## 3. Estrai le librerie di estrazione di Synology

La vera logica di decrittazione si trova in:

* `/usr/syno/sbin/synoarchive`               → wrapper principale della CLI
* `/usr/lib/libsynopkg.so.1`                 → chiama il wrapper dall'interfaccia DSM
* `libsynocodesign.so`                       → **contiene l'implementazione crittografica**

Entrambi i binari sono presenti nel rootfs di sistema (`hda1.tgz`) **e** nel init-rd compresso (`rd.bin`). Se hai solo il PAT puoi ottenerli in questo modo:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recupera le chiavi hard-coded (`get_keys`)

All'interno di `libsynocodesign.so`, la funzione `get_keys(int keytype)` restituisce semplicemente due variabili globali da 128 bit per la famiglia di archivi richiesta:
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
* **signature_key** → Chiave pubblica Ed25519 utilizzata per verificare l'intestazione dell'archivio.
* **master_key**    → Chiave radice utilizzata per derivare la chiave di crittografia per ogni archivio.

Devi solo estrarre queste due costanti una volta per ogni versione principale di DSM.

## 5. Struttura dell'intestazione e verifica della firma

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` esegue quanto segue:

1. Leggi magic (3 byte) `0xBFBAAD` **o** `0xADBEEF`.
2. Leggi little-endian 32-bit `header_len`.
3. Leggi `header_len` byte + la successiva **firma Ed25519 di 0x40 byte**.
4. Itera su tutte le chiavi pubbliche incorporate fino a quando `crypto_sign_verify_detached()` ha successo.
5. Decodifica l'intestazione con **MessagePack**, producendo:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` consente successivamente a libarchive di controllare l'integrità di ciascun file mentre viene decrittografato.

## 6. Derivare la sottochiave per archivio

Dal blob `data` contenuto nell'intestazione MessagePack:

* `subkey_id`  = little-endian `uint64` all'offset 0x10
* `ctx`        = 7 byte all'offset 0x18

La **chiave di stream** di 32 byte è ottenuta con libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend personalizzato di **libarchive** di Synology

Synology include una libarchive patchata che registra un formato "tar" falso ogni volta che il magic è `0xADBEEF`:
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
L'`tar_hdr` decrittografato è un **header TAR POSIX classico**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Ogni **nonce di 0x18 byte** è preceduto dal chunk crittografato.

Una volta che tutte le voci sono state elaborate, libarchive produce un **`.tar`** perfettamente valido che può essere estratto con qualsiasi strumento standard.

## 8. Decrittografa tutto con synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` rileva automaticamente PAT/SPK, carica le chiavi corrette e applica l'intera catena descritta sopra.

## 9. Errori comuni

* Non scambiare `signature_key` e `master_key` – servono a scopi diversi.
* Il **nonce** viene *prima* del ciphertext per ogni blocco (header e dati).
* La dimensione massima del chunk crittografato è **0x400000 + 0x11** (tag libsodium).
* Gli archivi creati per una generazione DSM possono passare a chiavi hard-coded diverse nella release successiva.

## 10. Strumenti aggiuntivi

* [`patology`](https://github.com/sud0woodo/patology) – analizza/dumpa archivi PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decripta PAT/SPK/altro.
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementazione di riferimento di XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serializzazione dell'header.

## Riferimenti

- [Estrazione di archivi crittografati Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt su GitHub](https://github.com/synacktiv/synodecrypt)
- [patology su GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
