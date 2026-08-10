# Forensics кешу Discord (дисковий кеш Chromium)

На цій сторінці підсумовано, як виконувати тріаж артефактів кешу Discord Desktop для локально кешованих медіафайлів, webhook endpoints і кореляції активності. Клієнт Discord для desktop використовує Electron, а Electron зберігає дані сеансу, зокрема дисковий кеш, у `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Де шукати (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Це стандартні шляхи, які використовує згаданий parser; Electron дозволяє застосунку перевизначати `sessionData`, тому під час збору даних підтвердьте фактичний шлях до профілю.<sup>[[2]](#references)[[4]](#references)</sup>

Структура `index` + `data_#` + `f_######` відповідає blockfile backend дискового кешу Chromium; не називайте її Simple Cache без перевірки backend, оскільки Chromium документує окремі реалізації кешу.<sup>[[5]](#references)</sup>

Основні структури на диску всередині `Cache_Data`:
- `index`: індекс blockfile-кешу, який використовується для пошуку записів.
- `data_#`: файли блоків фіксованого розміру, які можуть містити метадані кешу, HTTP-заголовки та дані відповідей.
- `f_######`: окремі файли, які використовуються для даних, розмір яких перевищує ліміт block-файлу; ці файли містять збережені дані без заголовків block-файлу.

Видалення повідомлень, каналів або серверів не гарантує видалення байтів, які вже були локально кешовані, однак Chromium у будь-який момент може видалити або повторно створити файли кешу. Розглядайте артефакти, що збереглися, як додаткові докази, а час модифікації файлів використовуйте лише як приблизні сигнали локального запису, які необхідно корелювати з іншою телеметрією.<sup>[[5]](#references)[[6]](#references)</sup>

## Що можна відновити

Залежно від того, що було отримано та ще не видалено з кешу, під час тріажу можна відновити кешовані вкладення, медіафайли, URL і хеші файлів; сам кеш не доводить, що об'єкт було exfiltrated.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Вкладення та мініатюри, на які посилаються URL Discord CDN.
- Зображення, GIF і відео (наприклад, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` і `.webm`).
- URL webhook, наприклад `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Виклики Discord API, наприклад `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256 хеші відновлених медіафайлів для порівняння з відомими наборами даних або intelligence feeds.<sup>[[1]](#references)[[2]](#references)</sup>

## Швидкий тріаж (вручну)

- Виконайте Grep кешу для пошуку артефактів із високою інформативністю. Ці шаблони відповідають URL-виразам згаданого parser і є фільтрами тріажу, а не вичерпними індикаторами.<sup>[[2]](#references)</sup>
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- URL вкладень/CDN:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Виклики Discord API:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Відсортуйте кешовані записи за часом модифікації, щоб побудувати приблизну послідовність; mtime є сигналом файлової системи й сам по собі не встановлює, коли об'єкт Discord було отримано або надіслано.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Парсинг записів f_* (тіло + заголовки HTTP)

У blockfile-структурі файли `f_######` є окремими потоками даних і не обов'язково починаються з повної HTTP-відповіді. Якщо отриманий файл містить серіалізовані HTTP-заголовки, за якими йде `\r\n\r\n`, розділіть його за першим роздільником і перевірте:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: для визначення типу медіа
- Content-Location або X-Original-URL: оригінальний віддалений URL для попереднього перегляду/кореляції
- Content-Encoding: може мати значення gzip/deflate/br (Brotli).

Після цього медіафайл можна витягнути, розділивши заголовки й тіло та за потреби розпакувавши його відповідно до `Content-Encoding`; згаданий parser обробляє Brotli, gzip і deflate. Аналіз magic bytes корисний, коли `Content-Type` відсутній, але залишається евристикою.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: рекурсивно сканує папку кешу Discord, знаходить URL webhook/API/вкладень, парсить тіла `f_*`, за потреби витягує медіафайли та створює HTML- і CSV-звіти, а також додаткову хронологічну timeline із SHA-256 хешами.<sup>[[1]](#references)[[2]](#references)</sup>

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
CLI визначає такі параметри та назви вихідних даних:<sup>[[2]](#references)</sup>
- --cache: шлях до каталогу Discord Cache_Data
- --format html|csv|both
- --timeline: створювати впорядковану CSV-часову шкалу (за часом зміни)
- --extra: також сканувати сусідні каталоги Code Cache і GPUCache
- --carve: витягувати медіафайли з необроблених байтів кешу за допомогою розпізнаних сигнатур медіа (зображення/відео)
- Output: `<output>.html`, `<output>.csv`, необов'язковий `<output>_timeline.csv` і каталог `<output>_media` з витягнутими або відновленими файлами.

## Поради аналітикам

- Співвідносити час зміни (mtime) файлів `f_*` і `data_*` з періодами активності користувача або атакувальника та незалежною телеметрією; mtime не є остаточною часовою позначкою події.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Хешувати відновлені медіафайли (SHA-256) і порівнювати їх із відомими шкідливими наборами даних або наборами даних ексфільтрації.<sup>[[1]](#references)[[2]](#references)</sup>
- Розглядати витягнуті URL-адреси webhook як облікові дані. Не викликати їх лише для перевірки доступності; безпечно зберегти їх, скоординувати відкликання або ротацію та використовувати пов'язану мережеву телеметрію для ретро-пошуку.<sup>[[7]](#references)</sup>
- Видалення на стороні сервера не гарантує знищення локально кешованих байтів. Якщо отримання можливе, зібрати весь каталог `Cache` і пов'язані сусідні кеші (`Code Cache`, `GPUCache`) до їхнього очищення або повторного створення кешу.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Як Discord безперешкодно перевів мільйони користувачів на 64-бітну архітектуру](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Дисковий кеш](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord як C2 і кешовані докази, що залишаються після нього](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – виконання webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
