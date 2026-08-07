# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Резюме

"Carbonara" зловживає шляхом завантаження MediaTek XFlash, щоб запустити модифікований етап 2 Download Agent (DA2), незважаючи на перевірки цілісності DA1. DA1 зберігає очікуване значення SHA-256 для DA2 у RAM і порівнює його перед передачею керування. У багатьох loader хост повністю контролює адресу/розмір завантаження DA2, що дає можливість виконати неперевірений запис у пам'ять, перезаписати хеш у RAM і перенаправити виконання до довільних payload (у контексті pre-OS, з інвалідацією cache, яку виконує DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Межа довіри в XFlash (DA1 → DA2)

- **DA1** підписується/завантажується BootROM/Preloader. Коли Download Agent Authorization (DAA) увімкнено, має виконуватися лише підписаний DA1.
- **DA2** надсилається через USB. DA1 отримує **розмір**, **адресу завантаження** та **SHA-256**, обчислює хеш отриманого DA2 і порівнює його з **очікуваним хешем, вбудованим у DA1** (скопійованим у RAM).
- **Слабке місце:** у непатчених loader DA1 не санітизує адресу/розмір завантаження DA2 і залишає очікуваний хеш доступним для запису в пам'ять, що дає хосту змогу втручатися в перевірку.<sup>[[1]](#references)[[2]](#references)</sup>

## Потік Carbonara (трюк із "двома BOOT_TO")

1. **Перший `BOOT_TO`:** Увійти в staging-потік DA1→DA2 (DA1 виділяє пам'ять, готує DRAM і робить буфер очікуваного хешу доступним у RAM).
2. **Перезапис hash-slot:** Надіслати невеликий payload, який сканує пам'ять DA1 у пошуках збереженого очікуваного хешу DA2 і перезаписує його значенням SHA-256 модифікованого DA2, створеного атакувальником. Це використовує контроль користувача над завантаженням, щоб розмістити payload там, де знаходиться хеш.
3. **Другий `BOOT_TO` + digest:** Запустити інший `BOOT_TO` із пропатченими метаданими DA2 і надіслати необроблений 32-байтовий digest, що відповідає модифікованому DA2. DA1 повторно обчислює SHA-256 отриманого DA2, порівнює його з тепер уже пропатченим очікуваним хешем, і перехід до attacker code завершується успішно.

Оскільки адреса/розмір завантаження контролюються атакувальником, той самий primitive може записувати дані в будь-яке місце пам'яті (а не лише в буфер хешу), уможливлюючи early-boot implants, helpers для обходу secure-boot або malicious rootkits.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` відтворює blob із платного інструмента, який патчить buffer очікуваного hash усередині DA1.
- `sha256(...).digest()` передає raw bytes (не hex), щоб DA1 порівнював їх із пропатченим buffer.
- DA2 може бути будь-яким образом, створеним атакером; вибір load address/size дає змогу розмістити його довільно в пам’яті, а DA бере на себе інвалідацію cache.<sup>[[3]](#references)</sup>

## Ландшафт патчів (захищені loaders)

- **Mitigation**: Оновлені DAs жорстко задають load address DA2 як `0x40000000` та ігнорують адресу, яку передає host, тому записи не можуть досягти hash slot DA1 (приблизно в області `0x200000`). Hash і надалі обчислюється, але більше не може бути змінений атакером.
- **Виявлення пропатчених DAs**: mtkclient/penumbra сканують DA1 на наявність patterns, що вказують на hardening адреси; якщо їх знайдено, Carbonara пропускається. Старі DAs мають доступні для запису hash slots (зазвичай приблизно за offsets на кшталт `0x22dea4` у V5 DA1) і залишаються вразливими.
- **V5 проти V6**: Деякі V6 (XML) loaders іще приймають адреси, задані користувачем; новіші V6 binaries зазвичай примусово використовують фіксовану адресу та є невразливими до Carbonara, якщо не виконано downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Примітка щодо post-Carbonara (heapb8)

MediaTek виправила Carbonara; новіша вразливість, **heapb8**, атакує DA2 USB file download handler у пропатчених V6 loaders і забезпечує code execution, навіть коли `boot_to` захищений. Вона використовує heap overflow під час chunked file transfers, щоб отримати контроль над control flow DA2. Exploit є публічним у Penumbra/mtk-payloads і демонструє, що виправлення Carbonara не закривають усю attack surface DA.<sup>[[4]](#references)</sup>

## Примітки щодо triage та hardening

- Вразливими є пристрої, де address/size DA2 не перевіряються, а DA1 зберігає доступний для запису expected hash. Якщо пізніший Preloader/DA застосовує обмеження адрес або зберігає hash незмінним, Carbonara пом’якшено.
- Увімкнення DAA та забезпечення перевірки DA1/Preloader параметрів BOOT_TO (межі + authenticity DA2) усуває primitive. Якщо закрити лише patch hash без обмеження load, ризик довільного запису все одно зберігається.

## References

- [1] [Carbonara: MediaTek exploit, про який ніхто не розповідав](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Документація Carbonara exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Вихідний код Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploitation пропатчених V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
