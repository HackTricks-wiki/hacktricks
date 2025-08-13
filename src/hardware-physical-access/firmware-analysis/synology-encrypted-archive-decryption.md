# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Кілька пристроїв Synology (DSM/BSM NAS, BeeStation тощо) розповсюджують своє програмне забезпечення та пакети додатків у **зашифрованих архівах PAT / SPK**. Ці архіви можна розшифрувати *офлайн* лише за допомогою публічних файлів завантаження завдяки вбудованим у офіційні бібліотеки розпакування жорстко закодованим ключам.

Ця сторінка документує, крок за кроком, як працює зашифрований формат і як повністю відновити відкритий текст **TAR**, що знаходиться всередині кожного пакета. Процедура базується на дослідженнях Synacktiv, проведених під час Pwn2Own Ireland 2024, і реалізована в інструменті з відкритим кодом [`synodecrypt`](https://github.com/synacktiv/synodecrypt).

> ⚠️  Формат абсолютно однаковий для архівів `*.pat` (оновлення системи) та `*.spk` (додаток) – вони лише відрізняються парою жорстко закодованих ключів, які вибираються.

---

## 1. Завантажте архів

Оновлення програмного забезпечення/додатків зазвичай можна завантажити з публічного порталу Synology:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. Вивантажте структуру PAT (необов'язково)

`*.pat` зображення є **cpio пакетом**, який вміщує кілька файлів (завантажувач, ядро, rootfs, пакети…). Безкоштовна утиліта [`patology`](https://github.com/sud0woodo/patology) зручна для перевірки цього обгортання:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
Для `*.spk` ви можете безпосередньо перейти до кроку 3.

## 3. Витягніть бібліотеки витягання Synology

Справжня логіка розшифровки знаходиться в:

* `/usr/syno/sbin/synoarchive`               → основна обгортка CLI
* `/usr/lib/libsynopkg.so.1`                 → викликає обгортку з інтерфейсу DSM
* `libsynocodesign.so`                       → **містить криптографічну реалізацію**

Обидва бінарні файли присутні в кореневій файловій системі (`hda1.tgz`) **і** в стиснутому init-rd (`rd.bin`). Якщо у вас є тільки PAT, ви можете отримати їх таким чином:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Відновлення жорстко закодованих ключів (`get_keys`)

Всередині `libsynocodesign.so` функція `get_keys(int keytype)` просто повертає дві 128-бітні глобальні змінні для запитуваної архівної родини:
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
* **signature_key** → Ed25519 публічний ключ, що використовується для перевірки заголовка архіву.
* **master_key**    → Кореневий ключ, що використовується для отримання ключа шифрування для кожного архіву.

Вам потрібно скинути ці два константи лише один раз для кожної основної версії DSM.

## 5. Структура заголовка та перевірка підпису

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` виконує наступне:

1. Прочитати магічне число (3 байти) `0xBFBAAD` **або** `0xADBEEF`.
2. Прочитати 32-бітне `header_len` у малому порядку.
3. Прочитати `header_len` байтів + наступний **0x40-байтовий Ed25519 підпис**.
4. Ітерація по всіх вбудованих публічних ключах, поки `crypto_sign_verify_detached()` не завершиться успішно.
5. Декодувати заголовок за допомогою **MessagePack**, отримуючи:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` пізніше дозволяє libarchive перевіряти цілісність кожного файлу під час його розшифровки.

## 6. Виведення підключа ключа для архіву

З `data` блобу, що міститься в заголовку MessagePack:

* `subkey_id`  = little-endian `uint64` за зсувом 0x10
* `ctx`        = 7 байт за зсувом 0x18

32-байтовий **ключ потоку** отримується за допомогою libsodium:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Кастомний **libarchive** бекенд Synology

Synology включає патчений libarchive, який реєструє фальшивий формат "tar", коли магічне число дорівнює `0xADBEEF`:
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
Розшифрований `tar_hdr` є **класичним заголовком POSIX TAR**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Кожен **0x18-байтовий nonce** додається перед зашифрованим фрагментом.

Після обробки всіх записів libarchive створює абсолютно дійсний **`.tar`**, який можна розпакувати за допомогою будь-якого стандартного інструменту.

## 8. Розшифруйте все за допомогою synodecrypt
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` автоматично виявляє PAT/SPK, завантажує правильні ключі та застосовує повний ланцюг, описаний вище.

## 9. Загальні помилки

* Не **міняйте** `signature_key` та `master_key` – вони виконують різні функції.
* **nonce** йде *перед* шифротекстом для кожного блоку (заголовок і дані).
* Максимальний розмір зашифрованого фрагмента становить **0x400000 + 0x11** (мітка libsodium).
* Архіви, створені для одного покоління DSM, можуть перейти на інші жорстко закодовані ключі в наступному випуску.

## 10. Додаткові інструменти

* [`patology`](https://github.com/sud0woodo/patology) – парсити/вивантажувати архіви PAT.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – розшифровувати PAT/SPK/інше.
* [`libsodium`](https://github.com/jedisct1/libsodium) – референсна реалізація XChaCha20-Poly1305 secretstream.
* [`msgpack`](https://msgpack.org/) – серіалізація заголовків.

## Посилання

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
