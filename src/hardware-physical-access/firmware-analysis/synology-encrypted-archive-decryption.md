# Sinology PAT/SPK Desencriptación de Archivos Encriptados

{{#include ../../banners/hacktricks-training.md}}

## Descripción General

Varios dispositivos de Synology (DSM/BSM NAS, BeeStation, …) distribuyen su firmware y paquetes de aplicaciones en **archivos PAT / SPK encriptados**. Estos archivos pueden ser desencriptados *offline* con nada más que los archivos de descarga pública gracias a las claves codificadas en duro incrustadas dentro de las bibliotecas de extracción oficiales.

Esta página documenta, paso a paso, cómo funciona el formato encriptado y cómo recuperar completamente el **TAR** en texto claro que se encuentra dentro de cada paquete. El procedimiento se basa en la investigación de Synacktiv realizada durante Pwn2Own Irlanda 2024 e implementada en la herramienta de código abierto [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  El formato es exactamente el mismo para los archivos `*.pat` (actualización del sistema) y `*.spk` (aplicación) – solo difieren en el par de claves codificadas en duro que se seleccionan.

---

## 1. Obtener el archivo

La actualización del firmware/aplicación normalmente se puede descargar desde el portal público de Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Volcar la estructura PAT (opcional)

`*.pat` imágenes son en sí mismas un **cpio bundle** que incorpora varios archivos (cargador de arranque, kernel, rootfs, paquetes…). La utilidad gratuita [`patology`](https://github.com/sud0woodo/patology) es conveniente para inspeccionar ese contenedor:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Para `*.spk` puedes saltar directamente al paso 3.

## 3. Extraer las bibliotecas de extracción de Synology

La verdadera lógica de descifrado se encuentra en:

* `/usr/syno/sbin/synoarchive`               → envoltura principal de CLI
* `/usr/lib/libsynopkg.so.1`                 → llama a la envoltura desde la interfaz de usuario de DSM
* `libsynocodesign.so`                       → **contiene la implementación criptográfica**

Ambos binarios están presentes en el rootfs del sistema (`hda1.tgz`) **y** en el init-rd comprimido (`rd.bin`). Si solo tienes el PAT, puedes obtenerlos de esta manera:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Recuperar las claves codificadas (`get_keys`)

Dentro de `libsynocodesign.so`, la función `get_keys(int keytype)` simplemente devuelve dos variables globales de 128 bits para la familia de archivos solicitada:
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
* **signature_key** → Clave pública Ed25519 utilizada para verificar el encabezado del archivo.
* **master_key**    → Clave raíz utilizada para derivar la clave de cifrado por archivo.

Solo tienes que volcar esas dos constantes una vez para cada versión principal de DSM.

## 5. Estructura del encabezado y verificación de la firma

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` realiza lo siguiente:

1. Leer magia (3 bytes) `0xBFBAAD` **o** `0xADBEEF`.
2. Leer little-endian 32-bit `header_len`.
3. Leer `header_len` bytes + la siguiente **firma Ed25519 de 0x40 bytes**.
4. Iterar sobre todas las claves públicas incrustadas hasta que `crypto_sign_verify_detached()` tenga éxito.
5. Decodificar el encabezado con **MessagePack**, produciendo:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` permite que libarchive verifique la integridad de cada archivo a medida que se descifra.

## 6. Derivar la subclave por archivo

A partir del blob `data` contenido en el encabezado de MessagePack:

* `subkey_id`  = `uint64` en orden little-endian en el desplazamiento 0x10
* `ctx`        = 7 bytes en el desplazamiento 0x18

La clave de **stream** de 32 bytes se obtiene con libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Backend **libarchive** personalizado de Synology

Synology agrupa un libarchive parcheado que registra un formato "tar" falso siempre que el magic es `0xADBEEF`:
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
Cada **nonce de 0x18 bytes** se antepone al fragmento cifrado.

Una vez que se procesan todas las entradas, libarchive produce un **`.tar`** perfectamente válido que se puede descomprimir con cualquier herramienta estándar.

## 8. Desencriptar todo con synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` detecta automáticamente PAT/SPK, carga las claves correctas y aplica la cadena completa descrita arriba.

## 9. Errores comunes

* No **intercambie** `signature_key` y `master_key` – tienen diferentes propósitos.
* El **nonce** viene *antes* del texto cifrado para cada bloque (encabezado y datos).
* El tamaño máximo del fragmento cifrado es **0x400000 + 0x11** (etiqueta de libsodium).
* Los archivos creados para una generación de DSM pueden cambiar a diferentes claves codificadas de forma fija en la siguiente versión.

## 10. Herramientas adicionales

* [`patology`](https://github.com/sud0woodo/patology) – analizar/volcar archivos PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – descifrar PAT/SPK/otros.
* [`libsodium`](https://github.com/jedisct1/libsodium) – implementación de referencia de XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – serialización de encabezados.

## Referencias

- [Extracción de archivos cifrados de Synology – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt en GitHub](https://github.com/synacktiv/synodecrypt)
- [patology en GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
