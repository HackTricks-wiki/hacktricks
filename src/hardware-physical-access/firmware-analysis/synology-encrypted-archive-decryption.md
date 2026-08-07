# Entschlüsselung verschlüsselter Synology-PAT/SPK-Archive

{{#include ../../banners/hacktricks-training.md}}

## Überblick

Mehrere Synology-Geräte (DSM/BSM NAS, BeeStation, …) verteilen ihre Firmware- und Anwendungspakete in **verschlüsselten PAT-/SPK-Archiven**. Diese Archive können *offline* ausschließlich mit den öffentlich verfügbaren Download-Dateien entschlüsselt werden, da die offiziellen Extraction Libraries fest codierte Schlüssel enthalten.

Diese Seite dokumentiert Schritt für Schritt, wie das verschlüsselte Format funktioniert und wie das darin enthaltene Klartext-**TAR** vollständig aus jedem Paket extrahiert werden kann. Das Verfahren basiert auf der von Synacktiv während Pwn2Own Ireland 2024 durchgeführten Forschung und wurde im Open-Source-Tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt) implementiert.<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Das Format ist für `*.pat`- (Systemupdate) und `*.spk`- (Anwendung) Archive exakt gleich – sie unterscheiden sich lediglich durch das Paar fest codierter Schlüssel, das ausgewählt wird.

---

## 1. Archiv herunterladen

Das Firmware-/Anwendungsupdate kann normalerweise über das öffentliche Portal von Synology heruntergeladen werden:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Die PAT-Struktur dumpen (optional)

`*.pat`-Images sind selbst ein **cpio-Bundle**, das mehrere Dateien (Bootloader, Kernel, Rootfs, Packages …) einbettet. Das kostenlose Utility [`patology`](https://github.com/sud0woodo/patology) eignet sich zum Untersuchen dieses Wrappers:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Für `*.spk` kannst du direkt zu Schritt 3 springen.

## 3. Die Synology extraction libraries extrahieren

Die eigentliche Decryption-Logik befindet sich in:

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → ruft den wrapper aus der DSM UI auf
* `libsynocodesign.so`                       → **enthält die cryptographic implementation**

Beide Binaries sind im system rootfs (`hda1.tgz`) **und** im komprimierten init-rd (`rd.bin`) vorhanden. Wenn du nur die PAT hast, kannst du sie folgendermaßen erhalten:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Die hard-coded keys wiederherstellen (`get_keys`)

In `libsynocodesign.so` gibt die Funktion `get_keys(int keytype)` einfach zwei globale 128-Bit-Variablen für die angeforderte Archivfamilie zurück:<sup>[[1]](#references)</sup>
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
* **signature_key** → Öffentlicher Ed25519-Schlüssel zur Verifizierung des Archiv-Headers.
* **master_key**    → Root-Schlüssel zur Ableitung des Verschlüsselungsschlüssels pro Archiv.

Du musst diese beiden Konstanten nur einmal für jede DSM-Hauptversion ausgeben.

## 5. Header-Struktur und Signaturverifizierung

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` führt Folgendes aus:<sup>[[1]](#references)</sup>

1. Liest Magic (3 Bytes) `0xBFBAAD` **oder** `0xADBEEF`.
2. Liest `header_len` als 32-Bit-Little-Endian-Wert.
3. Liest `header_len` Bytes sowie die nachfolgende **0x40-Byte-Ed25519-Signatur**.
4. Iteriert über alle eingebetteten öffentlichen Schlüssel, bis `crypto_sign_verify_detached()` erfolgreich ist.
5. Dekodiert den Header mit **MessagePack** und erhält:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` ermöglicht es libarchive später, jede Datei während der Entschlüsselung auf Integrität zu prüfen.

## 6. Den Subkey pro Archiv ableiten

Aus dem im MessagePack-Header enthaltenen `data`-Blob:

* `subkey_id`  = little-endian `uint64` bei Offset 0x10
* `ctx`        = 7 Bytes bei Offset 0x18

Der 32-Byte-**Stream-Key** wird mit libsodium abgeleitet:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synologys benutzerdefiniertes **libarchive**-Backend

Synology bündelt ein gepatchtes libarchive, das ein gefälschtes „tar“-Format registriert, sobald die Magic `0xADBEEF` lautet:<sup>[[1]](#references)</sup>
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
Der entschlüsselte `tar_hdr` ist ein **klassischer POSIX-TAR-Header**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Jeder **0x18-Byte-Nonce** wird dem verschlüsselten Chunk vorangestellt.

Nachdem alle Einträge verarbeitet wurden, erstellt libarchive ein vollständig gültiges **`.tar`**, das mit jedem Standardtool entpackt werden kann.

## 8. Alles mit synodecrypt entschlüsseln
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` erkennt PAT/SPK automatisch, lädt die korrekten Schlüssel und wendet die oben beschriebene vollständige Kette an.<sup>[[2]](#references)</sup>

## 9. Häufige Fallstricke

* **Vertausche** `signature_key` und `master_key` **nicht** – sie erfüllen unterschiedliche Zwecke.
* Die **Nonce** steht bei jedem Block (Header und Daten) *vor* dem Ciphertext.
* Die maximale Größe eines verschlüsselten Chunks beträgt **0x400000 + 0x11** (libsodium-Tag).
* Für eine DSM-Generation erstellte Archive können in der nächsten Version auf andere hardcodierte Schlüssel wechseln.

## 10. Zusätzliche Tools

* [`patology`](https://github.com/sud0woodo/patology) – PAT-Archive parsen/dumpen.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/andere Archive entschlüsseln.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – Referenzimplementierung von XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – Serialisierung des Headers.

## Referenzen

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
