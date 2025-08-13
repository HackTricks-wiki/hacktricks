# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Übersicht

Mehrere Synology-Geräte (DSM/BSM NAS, BeeStation, …) verteilen ihre Firmware- und Anwendungs-Pakete in **verschlüsselten PAT / SPK Archiven**. Diese Archive können *offline* nur mit den öffentlichen Download-Dateien entschlüsselt werden, dank der in den offiziellen Extraktionsbibliotheken eingebetteten, fest codierten Schlüssel.

Diese Seite dokumentiert Schritt für Schritt, wie das verschlüsselte Format funktioniert und wie man den klaren **TAR**-Inhalt, der in jedem Paket enthalten ist, vollständig wiederherstellt. Das Verfahren basiert auf der Forschung von Synacktiv, die während Pwn2Own Irland 2024 durchgeführt wurde, und wurde im Open-Source-Tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt) implementiert.

> ⚠️  Das Format ist für sowohl `*.pat` (Systemupdate) als auch `*.spk` (Anwendung) Archive genau dasselbe – sie unterscheiden sich nur im Paar der ausgewählten fest codierten Schlüssel.

---

## 1. Archiv herunterladen

Das Firmware-/Anwendungsupdate kann normalerweise von Synologys öffentlichem Portal heruntergeladen werden:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Dumpen Sie die PAT-Struktur (optional)

`*.pat`-Images sind selbst ein **cpio-Bundle**, das mehrere Dateien (Bootloader, Kernel, rootfs, Pakete…) einbettet. Das kostenlose Tool [`patology`](https://github.com/sud0woodo/patology) ist praktisch, um diese Hülle zu inspizieren:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Für `*.spk` können Sie direkt zu Schritt 3 springen.

## 3. Extrahieren Sie die Synology-Extraktionsbibliotheken

Die eigentliche Entschlüsselungslogik befindet sich in:

* `/usr/syno/sbin/synoarchive`               → Haupt-CLI-Wrapper
* `/usr/lib/libsynopkg.so.1`                 → ruft den Wrapper aus der DSM-Benutzeroberfläche auf
* `libsynocodesign.so`                       → **enthält die kryptografische Implementierung**

Beide Binärdateien sind im System-Rootfs (`hda1.tgz`) **und** im komprimierten init-rd (`rd.bin`) vorhanden. Wenn Sie nur das PAT haben, können Sie sie auf diese Weise erhalten:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Wiederherstellung der fest codierten Schlüssel (`get_keys`)

Innerhalb von `libsynocodesign.so` gibt die Funktion `get_keys(int keytype)` einfach zwei 128-Bit globale Variablen für die angeforderte Archivfamilie zurück:
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
* **signature_key** → Ed25519-Öffentlicher Schlüssel, der verwendet wird, um den Archiv-Header zu verifizieren.
* **master_key**    → Wurzel-Schlüssel, der verwendet wird, um den pro-Archiv-Verschlüsselungsschlüssel abzuleiten.

Sie müssen diese beiden Konstanten nur einmal für jede DSM-Hauptversion dumpen.

## 5. Headerstruktur & Signaturverifizierung

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` führt Folgendes aus:

1. Lese Magic (3 Bytes) `0xBFBAAD` **oder** `0xADBEEF`.
2. Lese little-endian 32-Bit `header_len`.
3. Lese `header_len` Bytes + die nächsten **0x40-Byte Ed25519-Signatur**.
4. Iteriere über alle eingebetteten öffentlichen Schlüssel, bis `crypto_sign_verify_detached()` erfolgreich ist.
5. Dekodiere den Header mit **MessagePack**, was ergibt:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` ermöglicht es libarchive später, jede Datei während der Entschlüsselung auf Integrität zu überprüfen.

## 6. Leiten Sie den pro-Archiv Unter-Schlüssel ab

Aus dem `data` Blob, das im MessagePack-Header enthalten ist:

* `subkey_id`  = little-endian `uint64` bei Offset 0x10
* `ctx`        = 7 Bytes bei Offset 0x18

Der 32-Byte **Stream-Schlüssel** wird mit libsodium erhalten:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synologys benutzerdefinierter **libarchive**-Backend

Synology bündelt ein gepatchtes libarchive, das ein gefälschtes "tar"-Format registriert, wann immer das Magic `0xADBEEF` ist:
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
Der entschlüsselte `tar_hdr` ist ein **klassischer POSIX TAR-Header**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Jeder **0x18-Byte-Nonce** wird dem verschlüsselten Chunk vorangestellt.

Sobald alle Einträge verarbeitet sind, erzeugt libarchive ein vollkommen gültiges **`.tar`**, das mit jedem Standardwerkzeug entpackt werden kann.

## 8. Alles mit synodecrypt entschlüsseln
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` erkennt automatisch PAT/SPK, lädt die richtigen Schlüssel und wendet die oben beschriebene vollständige Kette an.

## 9. Häufige Fallstricke

* Tauschen Sie **nicht** `signature_key` und `master_key` – sie dienen unterschiedlichen Zwecken.
* Die **nonce** kommt *vor* dem Chiffretext für jeden Block (Header und Daten).
* Die maximale Größe des verschlüsselten Chunks beträgt **0x400000 + 0x11** (libsodium-Tag).
* Archive, die für eine DSM-Generation erstellt wurden, können in der nächsten Version zu anderen fest codierten Schlüsseln wechseln.

## 10. Zusätzliche Werkzeuge

* [`patology`](https://github.com/sud0woodo/patology) – PAT-Archive parsen/dumpen.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/andere entschlüsseln.
* [`libsodium`](https://github.com/jedisct1/libsodium) – Referenzimplementierung von XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – Header-Serialisierung.

## Referenzen

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
