# Розшифрування зашифрованих архівів Synology PAT/SPK

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Кілька пристроїв Synology (DSM/BSM NAS, BeeStation, …) поширюють свої firmware та application packages у **зашифрованих архівах PAT / SPK**. Ці архіви можна розшифрувати *offline*, маючи лише загальнодоступні файли для завантаження, завдяки hard-coded ключам, вбудованим в офіційні бібліотеки для розпакування.

На цій сторінці покроково описано, як працює зашифрований формат і як повністю відновити відкритий **TAR**, що міститься всередині кожного пакета. Процедура ґрунтується на дослідженні Synacktiv, виконаному під час Pwn2Own Ireland 2024, і реалізована у open-source інструменті [`synodecrypt`](https://github.com/synacktiv/synodecrypt).<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️ Формат абсолютно однаковий для архівів `*.pat` (оновлення системи) та `*.spk` (застосунок) — вони відрізняються лише парою hard-coded ключів, які вибираються.

---

## 1. Завантаження архіву

Оновлення firmware/application зазвичай можна завантажити з публічного порталу Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Збереження структури PAT (необов’язково)

`*.pat`-образи самі є **cpio-бандлом**, що містить кілька файлів (завантажувач, kernel, rootfs, пакети тощо). Безкоштовна утиліта [`patology`](https://github.com/sud0woodo/patology) зручна для перевірки цієї оболонки:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Для `*.spk` можна одразу перейти до кроку 3.

## 3. Витягування бібліотек розпакування Synology

Справжня логіка розшифрування міститься у:

* `/usr/syno/sbin/synoarchive`               → основна оболонка CLI
* `/usr/lib/libsynopkg.so.1`                 → викликає оболонку з інтерфейсу DSM
* `libsynocodesign.so`                       → **містить криптографічну реалізацію**

Обидва бінарні файли присутні в системному rootfs (`hda1.tgz`) **і** у стисненому init-rd (`rd.bin`). Якщо у вас є лише PAT, отримати їх можна так:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Відновлення жорстко закодованих ключів (`get_keys`)

У `libsynocodesign.so` функція `get_keys(int keytype)` просто повертає дві глобальні змінні розміром 128 біт для запитаного сімейства архівів:<sup>[[1]](#references)</sup>
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
* **signature_key** → Ed25519 public key used to verify the archive header.
* **master_key**    → Root key used to derive the per-archive encryption key.

You only have to dump those two constants once for each DSM major version.

## 5. Структура заголовка та перевірка підпису

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` виконує такі дії:<sup>[[1]](#references)</sup>

1. Read magic (3 bytes) `0xBFBAAD` **or** `0xADBEEF`.
2. Read little-endian 32-bit `header_len`.
3. Read `header_len` bytes + the next **0x40-byte Ed25519 signature**.
4. Iterate over all embedded public keys until `crypto_sign_verify_detached()` succeeds.
5. Decode the header with **MessagePack**, yielding:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` згодом дає libarchive змогу перевіряти цілісність кожного файлу під час його розшифрування.

## 6. Отримання sub-key для кожного archive

З `data` blob, що міститься в заголовку MessagePack:

* `subkey_id`  = little-endian `uint64` за offset 0x10
* `ctx`        = 7 bytes за offset 0x18

32-байтовий **stream key** отримується за допомогою libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Кастомний backend **libarchive** Synology

Synology постачає пропатчений libarchive, який реєструє фіктивний формат "tar", коли magic має значення `0xADBEEF`:<sup>[[1]](#references)</sup>
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
Розшифрований `tar_hdr` — це **класичний заголовок POSIX TAR**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Кожен **0x18-байтовий nonce** додається перед зашифрованим фрагментом.

Після обробки всіх записів libarchive створює повністю коректний **`.tar`**, який можна розпакувати будь-яким стандартним інструментом.

## 8. Розшифрувати все за допомогою synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` автоматично визначає PAT/SPK, завантажує правильні ключі та застосовує весь описаний вище ланцюжок.<sup>[[2]](#references)</sup>

## 9. Типові помилки

* **Не міняйте місцями** `signature_key` і `master_key` – вони мають різне призначення.
* **Nonce** розташований *перед* ciphertext для кожного блоку (заголовка та даних).
* Максимальний розмір зашифрованого фрагмента становить **0x400000 + 0x11** (тег libsodium).
* Архіви, створені для одного покоління DSM, у наступному релізі можуть використовувати інші hard-coded ключі.

## 10. Додаткові інструменти

* [`patology`](https://github.com/sud0woodo/patology) – аналіз і дамп PAT-архівів.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – розшифрування PAT/SPK/інших форматів.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – еталонна реалізація secretstream XChaCha20-Poly1305.
* [`msgpack`](https://msgpack.org/) – серіалізація заголовків.

## References

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
