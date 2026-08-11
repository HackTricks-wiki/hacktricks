# MediaTek XFlash Carbonara обход Hash

{{#include ../../banners/hacktricks-training.md}}

## Підсумок

"Carbonara" зловживає шляхом завантаження MediaTek XFlash, щоб запустити модифікований етап 2 Download Agent (DA2), незважаючи на перевірки цілісності DA1. DA1 зберігає очікуваний SHA-256 DA2 у RAM і порівнює його перед передачею керування. У багатьох loader'ах host повністю контролює адресу/розмір завантаження DA2, що створює неперевірений запис у пам'ять, який може перезаписати цей hash у пам'яті та перенаправити виконання на довільні payload'и (у контексті pre-OS, з інвалідацією cache, яку обробляє DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Межа довіри в XFlash (DA1 → DA2)

- **DA1** підписується/завантажується BootROM/Preloader. Коли Download Agent Authorization (DAA) увімкнено, має виконуватися лише підписаний DA1.
- **DA2** надсилається через USB. DA1 отримує **розмір**, **адресу завантаження** та **SHA-256**, обчислює hash отриманого DA2 і порівнює його з **очікуваним hash, вбудованим у DA1** (скопійованим у RAM).
- **Вразливість:** У невиправлених loader'ах DA1 не санітизує адресу/розмір завантаження DA2 і залишає очікуваний hash доступним для запису в пам'яті, що дає змогу host втручатися в перевірку.<sup>[[1]](#references)[[2]](#references)</sup>

## Процес Carbonara (трюк із "двома BOOT_TO")

1. **Перший `BOOT_TO`:** Увійти в staging flow DA1→DA2 (DA1 виділяє пам'ять, готує DRAM і відкриває buffer очікуваного hash у RAM).
2. **Перезапис hash-слота:** Надіслати невеликий payload, який сканує пам'ять DA1, знаходить збережений очікуваний hash DA2 і перезаписує його на SHA-256 модифікованого зловмисником DA2. Це використовує контрольоване користувачем завантаження, щоб розмістити payload там, де міститься hash.
3. **Другий `BOOT_TO` + digest:** Запустити ще один `BOOT_TO` із пропатченими метаданими DA2 і надіслати необроблений 32-байтовий digest, що відповідає модифікованому DA2. DA1 повторно обчислює SHA-256 отриманого DA2, порівнює його з тепер уже пропатченим очікуваним hash, після чого перехід успішно передає керування коду зловмисника.

У вразливих loader'ах неперевірені адреса й розмір можуть надати зловмиснику примітив запису в пам'ять на вибрані ним адреси до запуску OS, що виходить за межі hash-слота. Залежно від memory map SoC і наступних етапів верифікації це може підтримувати implants на ранньому етапі boot, helpers для обходу secure boot або payload'и у стилі rootkit. Саме виконання коду DA не забезпечує автоматично persistence або повний обхід secure boot; також потрібні окремий механізм persistence і сумісний ланцюжок верифікації.<sup>[[1]](#references)[[2]](#references)</sup>

## Мінімальний шаблон PoC (у стилі mtkclient)
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
- 16-байтовий `payload` відтворює blob, який спостерігався у workflow платного інструмента та використовувався опублікованою реалізацією для patch очікуваного hash-буфера. Він специфічний для loader, а не є переносимим patch hash-слота для кожного SoC або DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` передає raw bytes (а не hex), щоб DA1 порівнював їх із пропатченим буфером.
- У вразливому loader із відповідним узгодженням DA2 може бути образом, створеним attacker, а вибрані load metadata керують його розміщенням у пам’яті. Перевіряйте комбінацію DA/SoC перед передаванням, оскільки неправильні адреси можуть зависити або пошкодити target.<sup>[[3]](#references)</sup>

## Ландшафт patch (hardened loaders)

- **Виявлена mitigation**: Досліджені дослідниками hardened DA примусово встановлюють адресу завантаження DA2 у `0x40000000` та ігнорують адресу, надану host, запобігаючи записам до спостережуваної hash-області DA1 поблизу `0x200000`. Вважайте обидві адреси специфічними для реалізації, а не архітектурними константами.
- **Виявлення пропатчених DA**: mtkclient/penumbra сканують DA1 на наявність патернів, що вказують на hardening адреси; якщо їх знайдено, Carbonara пропускається. Старі DA відкривають доступні для запису hash-слоти (зазвичай поблизу таких offsets, як `0x22dea4` у V5 DA1) і залишаються exploitable.
- **V5 проти V6**: Деякі V6 (XML) loaders все ще приймають адреси, надані user; новіші V6 binaries зазвичай застосовують фіксовану адресу та є immune до Carbonara, якщо не виконано downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Примітка щодо Post-Carbonara (heapb8)

MediaTek виправила Carbonara; новіша vulnerability, **heapb8**, targets DA2 USB file download handler у пропатчених V6 loaders, надаючи code execution навіть коли `boot_to` hardened. Вона використовує heap overflow під час chunked file transfers, щоб перехопити control flow DA2. Exploit опубліковано в Penumbra/mtk-payloads; він демонструє, що виправлення Carbonara не закривають усю attack surface DA.<sup>[[4]](#references)</sup>

## Примітки для triage та hardening

- Вразливими є пристрої, де адреса/розмір DA2 не перевіряються, а DA1 зберігає очікуваний hash доступним для запису. Якщо пізніший Preloader/DA застосовує перевірку меж адрес або зберігає hash незмінним, Carbonara mitigated.
- Увімкнення DAA та забезпечення перевірки DA1/Preloader параметрів BOOT_TO (межі + authenticity DA2) закриває primitive. Просте закриття hash patch без обмеження load усе ще залишає ризик arbitrary write.

## References

- [1] [Carbonara: The MediaTek exploit, який ніхто не обслуговував](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Документація Carbonara exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Вихідний код Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploitation пропатчених V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
