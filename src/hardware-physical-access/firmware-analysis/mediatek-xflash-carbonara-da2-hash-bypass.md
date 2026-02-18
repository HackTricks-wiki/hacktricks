# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Підсумок

"Carbonara" експлуатує шлях завантаження XFlash від MediaTek для запуску модифікованого Download Agent stage 2 (DA2), незважаючи на перевірки цілісності DA1. DA1 зберігає очікуваний SHA-256 для DA2 у RAM і порівнює його перед переходом. У багатьох лоадерах host повністю контролює адресу/розмір завантаження DA2, що дає unchecked memory write, який може перезаписати цей in-memory hash і перенаправити виконання на довільні payloads (pre-OS context with cache invalidation handled by DA).

## Межа довіри в XFlash (DA1 → DA2)

- **DA1** підписується/завантажується BootROM/Preloader. Коли Download Agent Authorization (DAA) увімкнено, має запускатися лише підписаний DA1.
- **DA2** надсилається через USB. DA1 отримує **size**, **load address**, і **SHA-256**, хешує прийнятий DA2 і порівнює його з **expected hash embedded in DA1** (скопійованим у RAM).
- **Слабкість:** На непатчених лоадерах DA1 не санітизує DA2 load address/size і тримає expected hash записуваним у пам'яті, що дозволяє host підробити перевірку.

## Потік Carbonara (трюк "two BOOT_TO")

1. **First `BOOT_TO`:** Увійти в DA1→DA2 staging flow (DA1 виділяє, готує DRAM і виставляє буфер expected-hash у RAM).
2. **Hash-slot overwrite:** Відправити невеликий payload, який сканує пам'ять DA1 у пошуках збереженого DA2-expected hash і перезаписує його SHA-256 від attacker-modified DA2. Це використовує user-controlled load, щоб розмістити payload там, де знаходиться хеш.
3. **Second `BOOT_TO` + digest:** Викликати ще один `BOOT_TO` з пропатченими метаданими DA2 і надіслати сирий 32-байтний digest, що відповідає модифікованому DA2. DA1 перемонтує SHA-256 від отриманого DA2, порівнює його з тепер пропатченим expected hash, і перехід відбувається в attacker code.

Оскільки load address/size контролюються attacker'ом, той самий примітив може записувати куди завгодно в пам'яті (не лише в буфер хешу), що дозволяє створювати early-boot implants, secure-boot bypass helpers або шкідливі rootkits.

## Мінімальний PoC pattern (mtkclient-style)
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
- `payload` відтворює paid-tool blob, який патчить буфер expected-hash всередині DA1.
- `sha256(...).digest()` відправляє сирі байти (не hex), тому DA1 порівнює їх із запатченим буфером.
- DA2 може бути будь-яким образом, створеним нападником; вибір адреси/розміру завантаження дозволяє довільне розміщення в пам'яті з інвалідизацією кешу, яку обробляє DA.

## Огляд патчів (укріплені завантажувачі)

- **Пом'якшення**: Оновлені DAs жорстко задають адресу завантаження DA2 в `0x40000000` і ігнорують адресу, яку надає хост, тож записи не можуть досягти слота хешу DA1 (~діапазон 0x200000). Хеш продовжує обчислюватися, але вже не є доступним для запису нападником.
- **Виявлення запатчених DAs**: mtkclient/penumbra сканують DA1 на предмет шаблонів, що вказують на address-hardening; якщо знайдено, Carbonara пропускається. Старі DAs відкривають записувані слоти хешу (звично навколо зсувів як `0x22dea4` у V5 DA1) і залишаються експлуатованими.
- **V5 vs V6**: Деякі V6 (XML) завантажувачі все ще приймають адреси, задані користувачем; новіші V6 бінарні файли зазвичай застосовують фіксовану адресу і стійкі до Carbonara, якщо їх не понизити.

## Примітка після Carbonara (heapb8)

MediaTek запатчила Carbonara; новіша вразливість, **heapb8**, націлена на DA2 USB file download handler у запатчених V6 завантажувачах, даючи виконання коду навіть коли `boot_to` захищений. Вона зловживає heap overflow під час chunked file transfers, щоб захопити керування потоком DA2. Експлойт публічний у Penumbra/mtk-payloads і демонструє, що виправлення Carbonara не закривають усю поверхню атаки DA.

## Примітки для триажу та посилення захисту

- Пристрої, де адреса/розмір DA2 не перевіряються і DA1 залишає expected-hash записуваним, вразливі. Якщо пізніший Preloader/DA накладає межі адрес або робить хеш незмінним, Carbonara усувається.
- Увімкнення DAA і забезпечення, що DA1/Preloader валідуюють параметри BOOT_TO (межі + достовірність DA2), закриває примітив. Закривання лише патчу хешу без обмеження завантаження все ще залишає ризик довільного запису.

## Посилання

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
