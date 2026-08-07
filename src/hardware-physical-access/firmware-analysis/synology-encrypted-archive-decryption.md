# Decrittazione degli archivi crittografati PAT/SPK di Synology

{{#include ../../banners/hacktricks-training.md}}

## Panoramica

Diversi dispositivi Synology (NAS DSM/BSM, BeeStation, …) distribuiscono il firmware e i pacchetti applicativi in **archivi PAT / SPK crittografati**. Tali archivi possono essere decrittati *offline* utilizzando esclusivamente i file pubblici disponibili per il download, grazie a chiavi hard-coded incorporate nelle librerie ufficiali di estrazione.

Questa pagina documenta, passo dopo passo, il funzionamento del formato crittografato e come recuperare completamente il **TAR** in chiaro contenuto in ogni pacchetto. La procedura si basa sulla ricerca di Synacktiv condotta durante Pwn2Own Ireland 2024 e implementata nello strumento open-source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Il formato è esattamente lo stesso per entrambi gli archivi `*.pat` (aggiornamento del sistema) e `*.spk` (applicazione): differiscono solo nella coppia di chiavi hard-coded selezionata.

---

## 1. Scaricare l’archivio

L’aggiornamento del firmware/applicazione può normalmente essere scaricato dal portale pubblico di Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dump della struttura PAT (facoltativo)

Le immagini `*.pat` sono a loro volta un **bundle cpio** che incorpora diversi file (boot loader, kernel, rootfs, pacchetti…). L'utility gratuita [`patology`](https://github.com/sud0woodo/patology) è utile per ispezionare questo wrapper:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Per i file `*.spk` puoi passare direttamente al passaggio 3.

## 3. Estrai le librerie di estrazione di Synology

La vera logica di decrittazione si trova in:

* `/usr/syno/sbin/synoarchive`               → wrapper CLI principale
* `/usr/lib/libsynopkg.so.1`                 → richiama il wrapper dall'interfaccia DSM
* `libsynocodesign.so`                       → **contiene l'implementazione crittografica**

Entrambi i binari sono presenti nel rootfs di sistema (`hda1.tgz`) **e** nell'init-rd compresso (`rd.bin`).  Se hai soltanto il PAT, puoi ottenerli in questo modo:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recuperare le chiavi hard-coded (`get_keys`)

All'interno di `libsynocodesign.so`, la funzione `get_keys(int keytype)` restituisce semplicemente due variabili globali a 128 bit per la famiglia di archivi richiesta:<sup>[[1]](#references)</sup>
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
* **signature_key** → chiave pubblica Ed25519 utilizzata per verificare l'header dell'archivio.
* **master_key**    → chiave root utilizzata per derivare la chiave di cifratura per archivio.

È sufficiente eseguire il dump di queste due costanti una sola volta per ogni versione major di DSM.

## 5. Struttura dell'header e verifica della signature

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` esegue quanto segue:<sup>[[1]](#references)</sup>

1. Legge il magic (3 byte) `0xBFBAAD` **oppure** `0xADBEEF`.
2. Legge `header_len`, un valore a 32 bit little-endian.
3. Legge `header_len` byte + la successiva **signature Ed25519 di 0x40 byte**.
4. Esegue l'iterazione su tutte le chiavi pubbliche incorporate finché `crypto_sign_verify_detached()` non ha successo.
5. Decodifica l'header con **MessagePack**, ottenendo:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` consente successivamente a libarchive di verificare l'integrità di ogni file durante la decrittazione.

## 6. Derivare la sub-key per archivio

Dal blob `data` contenuto nell'header MessagePack:

* `subkey_id`  = `uint64` little-endian all'offset 0x10
* `ctx`        = 7 byte all'offset 0x18

La **stream key** di 32 byte viene ottenuta con libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Il backend **libarchive** personalizzato di Synology

Synology include una versione modificata di libarchive che registra un formato "tar" fittizio quando il valore magic è `0xADBEEF`:<sup>[[1]](#references)</sup>
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
L'`tar_hdr` decrittografato è una **classica intestazione TAR POSIX**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Ogni **nonce di 0x18 byte** viene anteposto al chunk cifrato.

Dopo aver elaborato tutte le entry, libarchive produce un **`.tar`** perfettamente valido che può essere estratto con qualsiasi strumento standard.

## 8. Decrittare tutto con synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` rileva automaticamente PAT/SPK, carica le chiavi corrette e applica l'intera catena descritta sopra.<sup>[[2]](#references)</sup>

## 9. Errori comuni

* **Non** scambiare `signature_key` e `master_key`: hanno scopi diversi.
* Il **nonce** viene *prima* del ciphertext per ogni blocco (header e dati).
* La dimensione massima del chunk cifrato è **0x400000 + 0x11** (tag di libsodium).
* Gli archivi creati per una generazione di DSM possono usare chiavi hard-coded diverse nella release successiva.

## 10. Strumenti aggiuntivi

* [`patology`](https://github.com/sud0woodo/patology) – analizza/esegue il dump degli archivi PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – decifra PAT/SPK/altri formati.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementazione di riferimento di XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serializzazione dell'header.

## Riferimenti

- [1] [Estrazione degli archivi cifrati Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt su GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology su GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
