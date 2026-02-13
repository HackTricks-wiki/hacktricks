# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Короткий огляд

"Carbonara" зловживає шляхом завантаження XFlash від MediaTek, щоб запустити змінений Download Agent stage 2 (DA2) незважаючи на перевірки цілісності DA1. DA1 зберігає очікуваний SHA-256 для DA2 у RAM і порівнює його перед переходом. У багатьох загрузчиків хост повністю контролює адресу/розмір завантаження DA2, що дає неконтрольований запис у пам'ять, який може перезаписати цей хеш у пам'яті й перенаправити виконання на довільні payload-и (до запуску ОС, з інвалідацією кешу, керованою DA).

## Межа довіри у XFlash (DA1 → DA2)

- **DA1** підписується/завантажується BootROM/Preloader. Коли Download Agent Authorization (DAA) увімкнено, має запускатися лише підписаний DA1.
- **DA2** відправляється через USB. DA1 отримує **size**, **load address**, та **SHA-256**, обчислює хеш отриманого DA2 і порівнює його з **очікуваним хешем, вбудованим у DA1** (скопійованим у RAM).
- **Слабке місце:** В незапатчених загрузчиках DA1 не санітує адресу/розмір завантаження DA2 і тримає очікуваний хеш записуваним у пам'яті, що дозволяє хосту підмінити перевірку.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Увійти в стадію DA1→DA2 (DA1 виділяє, готує DRAM і робить буфер очікуваного хешу доступним у RAM).
2. **Hash-slot overwrite:** Відправити малий payload, який сканує пам'ять DA1 для збереженого очікуваного хешу DA2 і перезаписує його на SHA-256 від модифікованого attacker DA2. Це використовує кероване користувачем завантаження, щоб доставити payload туди, де знаходиться хеш.
3. **Second `BOOT_TO` + digest:** Запустити ще один `BOOT_TO` з перепатченими метаданими DA2 і відправити сирий 32-байтовий digest, що відповідає модифікованому DA2. DA1 повторно обчислює SHA-256 по отриманому DA2, порівнює його з тепер перепатченим очікуваним хешем, і перехід вдається в код атакувальника.

Оскільки адреса/розмір завантаження контролюються атакувальником, той самий примітив може записувати куди завгодно в пам'ять (не лише в буфер хешу), дозволяючи імпланти раннього завантаження, помічники для обхід secure-boot або шкідливі rootkits.

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload` відтворює платний-tool blob, який патчить expected-hash buffer всередині DA1.
- `sha256(...).digest()` відправляє сирі байти (не hex), тож DA1 порівнює їх із запатченим буфером.
- DA2 може бути будь-яким образом, створеним атакуючим; вибір адреси/розміру завантаження дозволяє довільне розміщення в пам'яті, а інвалідація кешу обробляється DA.

## Примітки щодо триажу та посилення захисту

- Пристрої, де адреса/розмір DA2 не перевіряються і DA1 залишає expected hash записуваним, вразливі. Якщо пізніший Preloader/DA накладає обмеження адрес або робить хеш незмінним, Carbonara пом'якшується.
- Увімкнення DAA та забезпечення валідації DA1/Preloader параметрів BOOT_TO (межі + автентичність DA2) закриває примітив. Закриття лише патчу хешу без обмеження завантаження все ще залишає ризик довільного запису.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
