# Descifrado de archivos PAT/SPK cifrados de Synology

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Varios dispositivos Synology (NAS DSM/BSM, BeeStation, …) distribuyen su firmware y paquetes de aplicaciones en **archivos PAT / SPK cifrados**. Estos archivos pueden descifrarse *offline* usando únicamente los archivos públicos de descarga, gracias a las claves hard-coded integradas en las librerías oficiales de extracción.

Esta página documenta, paso a paso, cómo funciona el formato cifrado y cómo recuperar completamente el **TAR** en texto claro que contiene cada paquete. El procedimiento se basa en la investigación de Synacktiv realizada durante Pwn2Own Ireland 2024 y está implementado en la herramienta open-source [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  El formato es exactamente el mismo tanto para los archivos `*.pat` (actualización del sistema) como para los archivos `*.spk` (aplicación); solo se diferencian en el par de claves hard-coded que se selecciona.

---

## 1. Descargar el archivo

La actualización del firmware/aplicación normalmente se puede descargar desde el portal público de Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Extraer la estructura PAT (opcional)

Las imágenes `*.pat` son en sí mismas un **bundle cpio** que incluye varios archivos (cargador de arranque, kernel, rootfs, paquetes…). La utilidad gratuita [`patology`](https://github.com/sud0woodo/patology) resulta práctica para inspeccionar ese wrapper:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Para `*.spk` puedes saltar directamente al paso 3.

## 3. Extraer las libraries de extracción de Synology

La lógica real de desencryption se encuentra en:

* `/usr/syno/sbin/synoarchive`               → wrapper principal de CLI
* `/usr/lib/libsynopkg.so.1`                 → llama al wrapper desde la interfaz de DSM
* `libsynocodesign.so`                       → **contiene la implementación criptográfica**

Ambos binarios están presentes en el rootfs del sistema (`hda1.tgz`) **y** en el init-rd comprimido (`rd.bin`). Si solo tienes el PAT, puedes obtenerlos de esta forma:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recuperar las claves hard-coded (`get_keys`)

Dentro de `libsynocodesign.so`, la función `get_keys(int keytype)` simplemente devuelve dos variables globales de 128 bits para la familia de archivos solicitada:<sup>[[1]](#references)</sup>
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
* **signature_key** → clave pública Ed25519 utilizada para verificar el header del archivo.
* **master_key**    → clave raíz utilizada para derivar la clave de cifrado por archivo.

Solo tienes que volcar esas dos constantes una vez por cada versión principal de DSM.

## 5. Estructura del header y verificación de la firma

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` realiza lo siguiente:<sup>[[1]](#references)</sup>

1. Lee el magic (3 bytes) `0xBFBAAD` **o** `0xADBEEF`.
2. Lee `header_len`, un valor de 32 bits en little-endian.
3. Lee `header_len` bytes + la siguiente **firma Ed25519 de 0x40 bytes**.
4. Itera sobre todas las claves públicas integradas hasta que `crypto_sign_verify_detached()` tiene éxito.
5. Decodifica el header con **MessagePack**, obteniendo:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` permite posteriormente que libarchive compruebe la integridad de cada archivo a medida que se descifra.

## 6. Derivar la subclave por archivo

Del blob `data` contenido en el encabezado MessagePack:

* `subkey_id`  = `uint64` little-endian en el offset 0x10
* `ctx`        = 7 bytes en el offset 0x18

La **stream key** de 32 bytes se obtiene con libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personalizado de Synology

Synology incluye un libarchive parcheado que registra un formato "tar" falso cuando el magic es `0xADBEEF`:<sup>[[1]](#references)</sup>
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
El `tar_hdr` descifrado es un **encabezado TAR POSIX clásico**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Cada **nonce de 0x18 bytes** se antepone al chunk cifrado.

Una vez procesadas todas las entradas, libarchive produce un **`.tar`** perfectamente válido que se puede desempaquetar con cualquier herramienta estándar.

## 8. Decrypt everything with synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` detecta automáticamente PAT/SPK, carga las claves correctas y aplica la cadena completa descrita anteriormente.<sup>[[2]](#references)</sup>

## 9. Errores comunes

* **No** intercambies `signature_key` y `master_key`: tienen propósitos diferentes.
* El **nonce** aparece *antes* del ciphertext en cada bloque (cabecera y datos).
* El tamaño máximo del chunk cifrado es **0x400000 + 0x11** (tag de libsodium).
* Los archives creados para una generación de DSM pueden cambiar a otras claves hard-coded en la siguiente versión.

## 10. Herramientas adicionales

* [`patology`](https://github.com/sud0woodo/patology) – analiza y vuelca archives PAT.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – descifra PAT/SPK/otros.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementación de referencia de secretstream XChaCha20-Poly1305.
* [`msgpack`](https://msgpack.org/) – serialización de la cabecera.

## Referencias

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
