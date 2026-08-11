# Forensics кешу Discord (дисковий кеш Chromium)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці описано triage артефактів кешу Discord Desktop для локально кешованих медіафайлів, webhook endpoints і кореляції активності. Desktop-клієнт Discord використовує Electron, а Electron зберігає дані сесії, зокрема дисковий кеш, у `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Де шукати (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Це стандартні шляхи, які використовує згаданий parser; Electron дозволяє застосунку перевизначати `sessionData`, тому під час acquisition підтвердьте фактичний шлях до профілю.<sup>[[2]](#references)[[4]](#references)</sup>

Структура `index` + `data_#` + `f_######` відповідає blockfile disk-cache backend Chromium; не позначайте її як Simple Cache без перевірки backend, оскільки Chromium документує окремі реалізації кешу.<sup>[[5]](#references)</sup>

Ключові структури на диску всередині `Cache_Data`:
- `index`: індекс Blockfile cache, який використовується для пошуку entries.
- `data_#`: файли блоків фіксованого розміру, які можуть містити metadata кешу, HTTP headers і response data.
- `f_######`: окремі файли, що використовуються для даних, розмір яких перевищує ліміт block-файлу; ці файли містять збережені дані без заголовків block-файлу.

Видалення повідомлень, каналів або серверів не гарантує видалення байтів, які вже були локально кешовані, але Chromium може в будь-який момент видалити або повторно створити файли кешу. Розглядайте артефакти, що збереглися, як opportunistic evidence, а час модифікації файлів використовуйте лише як приблизний сигнал локального запису, який необхідно корелювати з іншою telemetry.<sup>[[5]](#references)[[6]](#references)</sup>

## Що можна відновити

Залежно від того, що було завантажено й ще не видалено з кешу, triage може відновити cached attachments, медіафайли, URL і file hashes; сам кеш не доводить, що об’єкт було exfiltrated.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Attachments і thumbnails, на які посилаються Discord CDN URLs.
- Images, GIFs і videos (наприклад, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` і `.webm`).
- Webhook URLs, наприклад `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Discord API calls, наприклад `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 hashes відновлених медіафайлів для порівняння з відомими datasets або intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Швидкий triage (вручну)

- Виконайте Grep кешу для high-signal artifacts. Ці patterns відповідають URL expressions згаданого parser і є triage filters, а не вичерпними indicators.<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Відсортуйте cached entries за часом модифікації, щоб побудувати приблизну послідовність; mtime є файловим сигналом і сам по собі не встановлює, коли Discord object було завантажено або надіслано.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Parsing entries f_* (HTTP body + headers)

У blockfile layout файли `f_######` є окремими data streams і не гарантовано починаються з повної HTTP response. Якщо отриманий файл містить serialized HTTP headers, після яких іде `\r\n\r\n`, розділіть їх за першим delimiter і перевірте:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: для визначення типу медіа
- Content-Location або X-Original-URL: оригінальний remote URL для preview/correlation
- Content-Encoding: може бути gzip/deflate/br (Brotli).

Після цього медіа можна витягнути, розділивши headers і body та за потреби виконавши decompression відповідно до `Content-Encoding`; згаданий parser підтримує Brotli, gzip і deflate. Magic-byte sniffing корисний, коли `Content-Type` відсутній, але залишається heuristic.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: рекурсивно сканує cache folder Discord, знаходить webhook/API/attachment URLs, парсить `f_*` bodies, за потреби carves media і створює HTML- та CSV reports, а також optional chronological timeline із SHA-256 hashes.<sup>[[1]](#references)[[2]](#references)</sup>

Приклад використання CLI:
```powershell
# Acquire a copy of the cache for offline parsing, then run on Windows:
python discord_forensic_suite_cli `
--cache "$env:APPDATA\discord\Cache\Cache_Data" `
--outdir "C:\IR\discord-cache" `
--output discord_cache_report `
--format both `
--timeline `
--extra `
--carve `
--verbose
```
CLI визначає такі параметри та назви вихідних файлів:<sup>[[2]](#references)</sup>
- --cache: Шлях до каталогу Discord Cache_Data
- --format html|csv|both
- --timeline: Створює впорядковану CSV-часову шкалу (за часом модифікації)
- --extra: Також сканує сусідні Code Cache і GPUCache
- --carve: Витягує медіафайли з необроблених байтів кешу за допомогою розпізнаних сигнатур медіафайлів (зображення/відео)
- Вихідні файли: `<output>.html`, `<output>.csv`, необов'язковий `<output>_timeline.csv` і каталог `<output>_media` з витягнутими або вирізаними файлами.

## Поради аналітикам

- Співвідносите час модифікації (mtime) файлів `f_*` і `data_*` з періодами активності користувача або attacker та незалежною телеметрією; mtime не є безумовною позначкою часу події.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Хешуйте відновлені медіафайли (SHA-256) і порівнюйте їх із відомими шкідливими наборами даних або наборами даних exfiltration.<sup>[[1]](#references)[[2]](#references)</sup>
- Ставтеся до витягнутих URL webhook як до облікових даних. Не викликайте їх лише для перевірки доступності; безпечно зберігайте їх, координуйте відкликання або ротацію та використовуйте пов'язану мережеву телеметрію для ретро-пошуку.<sup>[[7]](#references)</sup>
- Видалення на стороні сервера не гарантує знищення локальних кешованих байтів. Якщо acquisition можливий, зберіть весь каталог `Cache` і пов'язані сусідні кеші (`Code Cache`, `GPUCache`) до їх очищення або повторного створення кешу.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Як Discord безперешкодно перевів мільйони користувачів на 64-бітну архітектуру](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Дисковий кеш](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord як C2 і кешовані докази, що залишилися](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Виконання Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
